"""
Test bundle B robustness fixes against an in-process mock APIsec server.

Run inside the scanner image:
  docker run --rm -v "$PWD:/test" --workdir /apisec --entrypoint sh \
    apisec-cicd:5.1.2.1-fix3 -c 'python3 /test/test_robustness.py'
"""
import json as _json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# In-container path
sys.path.insert(0, "/apisec")
# Local fallback: source dir is the parent of tests/. Only add if it actually
# contains the scanner sources, to avoid prepending bogus paths in Docker.
_local_src = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if os.path.isfile(os.path.join(_local_src, "main.py")):
    sys.path.insert(0, _local_src)

import utils  # noqa: E402  (sys.path adjusted above for in-container + local execution)
from models import ScanConfig  # noqa: E402
from scanner import Scanner  # noqa: E402
from table import Table  # noqa: E402

PASSED = []
FAILED = []

def expect(label, ok, detail=""):
    (PASSED if ok else FAILED).append((label, detail))
    icon = "✓" if ok else "✗"
    print(f"{icon} {label}" + (f"  -- {detail}" if detail and not ok else ""))


# ------------------------------------------------------------------
# Mock APIsec server
# ------------------------------------------------------------------
class MockHandler(BaseHTTPRequestHandler):
    # state shared across requests
    counters = {"flaky": 0}

    def log_message(self, *a, **kw):
        return  # silence

    def _send_json(self, code, payload):
        body = _json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_raw(self, code, ctype, body):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_request(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        # Routes encode the test scenario in the application_id segment.
        # /v1/applications/<scenario>/instances/<x>/scans[/<scan_id>]
        parts = path.strip("/").split("/")
        scenario = parts[2] if len(parts) > 2 else ""
        if scenario == "paginated-findings":
            # Two-page response: page 1 returns nextToken, page 2 doesn't.
            # Each page carries a Critical (CVSS>=8) finding so a working
            # parser sees 2 errors total; a broken parser stops at page 1
            # (or zero, depending on the bug).
            next_token = (query.get("nextToken") or [None])[0]
            base = {"scanId": "scan-123", "status": "Complete"}
            if not next_token:
                return self._send_json(200, {
                    **base,
                    "vulnerabilities": [{
                        "method": "GET", "resource": "/p1",
                        "scanFindings": [{
                            "testResult": {"cvssScore": 9.5, "cvssQualifier": "Critical"},
                            "testDetails": {"categoryName": "A", "categoryTestName": "B"},
                            "testStatus": {"description": "page1-finding"},
                        }],
                    }],
                    "nextToken": "tok-p2",
                })
            if next_token == "tok-p2":
                return self._send_json(200, {
                    **base,
                    "vulnerabilities": [{
                        "method": "POST", "resource": "/p2",
                        "scanFindings": [{
                            "testResult": {"cvssScore": 8.5, "cvssQualifier": "High"},
                            "testDetails": {"categoryName": "A", "categoryTestName": "B"},
                            "testStatus": {"description": "page2-finding"},
                        }],
                    }],
                    # last page: no nextToken
                })
            return self._send_json(400, {"error": f"unexpected nextToken {next_token!r}"})
        if scenario == "happy-init":
            return self._send_json(200, {"scanId": "scan-123", "status": "Queued"})
        if scenario == "init-no-scanid":
            return self._send_json(200, {"status": "Queued"})
        if scenario == "init-non-json":
            return self._send_raw(200, "text/html", "<html>not json</html>")
        if scenario == "poll-failed":
            return self._send_json(200, {"scanId": "scan-123", "status": "Failed"})
        if scenario == "poll-missing-status":
            return self._send_json(200, {"scanId": "scan-123"})
        if scenario == "poll-404":
            return self._send_json(404, {"error": "scan not found"})
        if scenario == "poll-non-json":
            return self._send_raw(200, "text/html", "<html>oops</html>")
        if scenario == "flaky-502":
            MockHandler.counters["flaky"] += 1
            if MockHandler.counters["flaky"] <= 2:
                return self._send_raw(502, "text/html", "Bad Gateway")
            return self._send_json(200, {"scanId": "scan-123", "status": "Complete"})
        if scenario == "slow":
            time.sleep(120)  # exceed 60s read timeout
            return self._send_json(200, {})
        return self._send_json(200, {"ok": True})

    def do_GET(self): self.do_request()
    def do_POST(self):
        # consume body
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self.do_request()


def start_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 8000), MockHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
def make_cfg(scenario):
    # bypass _validate_base_url so we can use http://localhost
    return ScanConfig(
        application_id=scenario,
        instance_id="inst",
        authentication_id=None,
        access_token="dummy-token",
        apisec_base_url="http://127.0.0.1:8000",
        fail_on_vulnerability_threshold=0,
        fail_on_severity_exceeds_threshold=8,
        print_summary=False,
        print_full=False,
    )


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------
def test_unit_safe_json_html():
    class Fake:
        status_code = 502
        text = "<html>Bad Gateway</html>"
        def json(self): import json; return json.loads(self.text)
    out = utils.safe_json(Fake())
    expect("safe_json returns None on non-JSON", out is None)


def test_unit_check_complete_missing_status():
    try:
        done = utils.check_complete({"scanId": "x"}, "x")
        expect("check_complete handles missing status", done is False)
    except KeyError as e:
        expect("check_complete handles missing status", False, f"KeyError {e}")


def test_unit_check_complete_empty_dict():
    try:
        done = utils.check_complete({}, "x")
        expect("check_complete handles empty dict", done is False)
    except Exception as e:
        expect("check_complete handles empty dict", False, repr(e))


def test_unit_add_vulnerability_drift():
    t = Table()
    # API drift: missing testStatus, null cvssScore, missing testDetails
    drift = {
        "method": "GET",
        "resource": "/x",
        "scanFindings": [
            {"testResult": {"cvssScore": None, "cvssQualifier": "Critical"}},
            {"testResult": {"cvssScore": 9.5, "cvssQualifier": "High"},
             "testDetails": {"categoryName": "A", "categoryTestName": "B"},
             "testStatus": {"description": "ok"}},
        ],
    }
    try:
        t.add_vulnerability(drift)
        expect("add_vulnerability survives missing/null fields",
               len(t.method) == 2 and "Critical" in t.qual_counts)
    except Exception as e:
        expect("add_vulnerability survives missing/null fields", False, repr(e))


def test_unit_evaluate_scan_skips_null_cvss():
    import main
    cfg = make_cfg("x")
    fake = {"vulnerabilities": [
        {"method": "GET", "resource": "/x", "scanFindings": [
            {"testResult": {"cvssScore": None, "cvssQualifier": "Critical"},
             "testDetails": {"categoryName": "A", "categoryTestName": "B"},
             "testStatus": {"description": "y"}}
        ]},
        {"method": "GET", "resource": "/y", "scanFindings": [
            {"testResult": {"cvssScore": 9.5, "cvssQualifier": "Critical"},
             "testDetails": {"categoryName": "A", "categoryTestName": "B"},
             "testStatus": {"description": "y"}}
        ]},
    ]}
    try:
        main.evaluate_scan(cfg, fake)
        expect("evaluate_scan tolerates null cvssScore", False, "did not exit")
    except SystemExit as e:
        # one valid critical (>=8) → exit 1 with threshold=0; null score skipped not crashed
        expect("evaluate_scan tolerates null cvssScore (exit 1)", e.code == 1)


def test_scanner_retry_recovers_502():
    MockHandler.counters["flaky"] = 0
    cfg = make_cfg("flaky-502")
    s = Scanner(cfg)
    r = s.scan("scan-123")
    expect("Scanner retries 502 then succeeds 200",
           r.status_code == 200 and MockHandler.counters["flaky"] == 3,
           f"status={r.status_code} attempts={MockHandler.counters['flaky']}")


def test_scanner_404_passes_through():
    cfg = make_cfg("poll-404")
    s = Scanner(cfg)
    r = s.scan("scan-123")
    expect("Scanner returns 404 (does not retry)", r.status_code == 404)


def test_scanner_session_has_auth_and_ua():
    cfg = make_cfg("happy-init")
    s = Scanner(cfg)
    expect("Session sets Authorization header",
           s.session.headers.get("Authorization") == "Bearer dummy-token")
    expect("Session sets User-Agent",
           "apisec-cicd" in (s.session.headers.get("User-Agent") or ""))


def test_scanner_does_not_print_url():
    import io, contextlib
    cfg = make_cfg("happy-init")
    s = Scanner(cfg)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        s.init()
    expect("scanner.init() no longer prints request URL (ID leak)",
           "applications" not in buf.getvalue())


def test_scanner_scan_forwards_next_token():
    """Scanner.scan(next_token=...) must forward it as ?nextToken=... so
    the API returns the next page instead of page 1."""
    cfg = make_cfg("paginated-findings")
    s = Scanner(cfg)
    r1 = utils.safe_json(s.scan("scan-123")) or {}
    expect("Page 1 (no token) returns nextToken=tok-p2",
           r1.get("nextToken") == "tok-p2",
           f"got {r1.get('nextToken')!r}")
    r2 = utils.safe_json(s.scan("scan-123", next_token="tok-p2")) or {}
    expect("Page 2 (with token) returns no nextToken",
           r2.get("nextToken") is None,
           f"got {r2.get('nextToken')!r}")
    expect("Page 2 returns its own page-2 vulnerabilities entry",
           any(v.get("resource") == "/p2" for v in (r2.get("vulnerabilities") or [])),
           f"vulns={r2.get('vulnerabilities')}")


def test_collect_all_findings_walks_pagination():
    """main.collect_all_findings must follow nextToken until exhausted and
    return a merged dict whose 'vulnerabilities' contains every page's findings."""
    import main
    cfg = make_cfg("paginated-findings")
    s = Scanner(cfg)
    first = utils.safe_json(s.scan("scan-123")) or {}
    merged = main.collect_all_findings(s, "scan-123", first)
    vulns = merged.get("vulnerabilities") or []
    expect("Merged vulnerabilities span both pages",
           len(vulns) == 2,
           f"got {len(vulns)} entries")
    expect("Merged dict preserves status/scanId from first page",
           merged.get("status") == "Complete" and merged.get("scanId") == "scan-123")
    expect("Merged dict drops the trailing nextToken",
           merged.get("nextToken") is None)


def test_scanner_timeout_short():
    """Verify that a slow server doesn't hang forever — connect timeout = 10s, read timeout = 60s.
    We'll use a non-routable address to trigger a connect timeout fast."""
    cfg = ScanConfig(
        application_id="x", instance_id="y", authentication_id=None,
        access_token="t",
        apisec_base_url="http://10.255.255.1:8000",  # blackhole
        fail_on_vulnerability_threshold=0, fail_on_severity_exceeds_threshold=8,
        print_summary=False, print_full=False,
    )
    s = Scanner(cfg)
    start = time.time()
    try:
        s.scan("x")
        expect("Scanner times out on unreachable host", False, "no exception")
    except Exception as e:
        elapsed = time.time() - start
        # connect timeout 10s × (1 initial + 3 connect retries) with backoff = ~30-90s budget
        # main thing: must not hang past a few minutes
        expect(f"Scanner errors out on unreachable host within 180s (took {elapsed:.1f}s)",
               elapsed < 180, repr(e))


# ------------------------------------------------------------------
# Run
# ------------------------------------------------------------------
def main():
    srv = start_server()
    try:
        test_unit_safe_json_html()
        test_unit_check_complete_missing_status()
        test_unit_check_complete_empty_dict()
        test_unit_add_vulnerability_drift()
        test_unit_evaluate_scan_skips_null_cvss()
        test_scanner_retry_recovers_502()
        test_scanner_404_passes_through()
        test_scanner_session_has_auth_and_ua()
        test_scanner_does_not_print_url()
        test_scanner_scan_forwards_next_token()
        test_collect_all_findings_walks_pagination()
        test_scanner_timeout_short()
    finally:
        srv.shutdown()
    print()
    print(f"Passed: {len(PASSED)}  Failed: {len(FAILED)}")
    if FAILED:
        for label, detail in FAILED:
            print(f"  ✗ {label}: {detail}")
        sys.exit(1)


if __name__ == "__main__":
    main()
