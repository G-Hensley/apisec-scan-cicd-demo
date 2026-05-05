"""
Robustness tests for cicd-latest-fetch against an in-process mock APIsec server.

This image fetches the latest Completed scan for an app/instance and applies
the same threshold gate as cicd-scanner. It does NOT trigger scans.

Run inside the image:
  docker run --rm -v "$PWD/cicd-latest-fetch/tests:/test:ro" \
    --workdir /apisec --entrypoint sh apisec-cicd-latest-fetch:test \
    -c 'python3 /test/test_robustness.py'
"""
import json as _json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# In-container path
sys.path.insert(0, "/apisec")
# Local fallback: source dir is the parent of tests/. Only add if it actually
# contains the sources, to avoid prepending bogus paths in Docker.
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
    counters = {"flaky": 0, "list_pages": 0}

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
        # Routes:
        #   /v1/applications/<scenario>/instances/<x>/scans          → list
        #   /v1/applications/<scenario>/instances/<x>/scans/<id>     → detail
        parts = path.strip("/").split("/")
        scenario = parts[2] if len(parts) > 2 else ""
        is_list_endpoint = parts[-1] == "scans" if parts else False
        scan_id_seg = parts[-1] if parts and not is_list_endpoint else None

        if scenario == "latest-happy":
            # Three scans: latest is Processing, next is Complete (winner),
            # earliest is Complete (older). pick_latest_complete should
            # return the middle one, then the script fetches its details.
            if is_list_endpoint:
                return self._send_json(200, {"scans": [
                    {"scanId": "older",
                     "status": "Complete",
                     "lastUpdateTime": "2024-01-01T00:00:00",
                     "startTime":      "2024-01-01T00:00:00"},
                    {"scanId": "newest-processing",
                     "status": "Processing",
                     "lastUpdateTime": "2024-01-03T00:00:00",
                     "startTime":      "2024-01-03T00:00:00"},
                    {"scanId": "winner",
                     "status": "Complete",
                     "lastUpdateTime": "2024-01-02T00:00:00",
                     "startTime":      "2024-01-02T00:00:00"},
                ]})
            if scan_id_seg == "winner":
                return self._send_json(200, {
                    "scanId": "winner", "status": "Complete",
                    "vulnerabilities": [{
                        "method": "GET", "resource": "/critical",
                        "scanFindings": [{
                            "testResult": {"cvssScore": 9.5, "cvssQualifier": "Critical"},
                            "testDetails": {"categoryName": "A", "categoryTestName": "B"},
                            "testStatus": {"description": "x"},
                        }],
                    }],
                })
            # Wrong scan picked → make the test fail loudly
            return self._send_json(500, {"error": f"unexpected scan_id {scan_id_seg}"})

        if scenario == "latest-empty":
            if is_list_endpoint:
                return self._send_json(200, {"scans": []})
            return self._send_json(500, {"error": "should not fetch detail when no scans"})

        if scenario == "latest-none-complete":
            if is_list_endpoint:
                return self._send_json(200, {"scans": [
                    {"scanId": "p1", "status": "Processing"},
                    {"scanId": "f1", "status": "Failed"},
                ]})
            return self._send_json(500, {"error": "should not fetch detail when none Complete"})

        if scenario == "latest-list-paginated":
            # List endpoint paginates: page 1 returns nextToken, page 2 the winner.
            if is_list_endpoint:
                next_token = (query.get("nextToken") or [None])[0]
                if not next_token:
                    return self._send_json(200, {
                        "scans": [
                            {"scanId": "page1-only-processing", "status": "Processing",
                             "lastUpdateTime": "2024-02-01T00:00:00"},
                        ],
                        "nextToken": "list-tok-p2",
                    })
                if next_token == "list-tok-p2":
                    return self._send_json(200, {
                        "scans": [
                            {"scanId": "page2-winner", "status": "Complete",
                             "lastUpdateTime": "2024-02-02T00:00:00"},
                        ],
                    })
                return self._send_json(400, {"error": f"unexpected nextToken {next_token!r}"})
            if scan_id_seg == "page2-winner":
                return self._send_json(200, {
                    "scanId": "page2-winner", "status": "Complete",
                    "vulnerabilities": [],
                })
            return self._send_json(500, {"error": f"unexpected scan_id {scan_id_seg}"})

        if scenario == "paginated-findings":
            # Re-used from cicd-scanner: scan-detail pagination.
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
                })
            return self._send_json(400, {"error": f"unexpected nextToken {next_token!r}"})

        if scenario == "poll-404":
            return self._send_json(404, {"error": "scan not found"})
        if scenario == "poll-non-json":
            return self._send_raw(200, "text/html", "<html>oops</html>")
        if scenario == "flaky-502":
            MockHandler.counters["flaky"] += 1
            if MockHandler.counters["flaky"] <= 2:
                return self._send_raw(502, "text/html", "Bad Gateway")
            return self._send_json(200, {"scanId": "scan-123", "status": "Complete"})
        return self._send_json(200, {"ok": True})

    def do_GET(self): self.do_request()
    def do_POST(self):
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
def make_cfg(scenario, error_threshold=0, severity_threshold=8):
    """Build a ScanConfig pointing at the in-process mock."""
    return ScanConfig(
        application_id=scenario,
        instance_id="inst",
        access_token="dummy-token",
        apisec_base_url="http://127.0.0.1:8000",
        fail_on_vulnerability_threshold=error_threshold,
        fail_on_severity_exceeds_threshold=severity_threshold,
        print_summary=False,
        print_full=False,
    )


# ------------------------------------------------------------------
# Tests — shared utility behaviour
# ------------------------------------------------------------------
def test_unit_safe_json_html():
    class Fake:
        status_code = 502
        text = "<html>Bad Gateway</html>"
        def json(self):
            import json
            return json.loads(self.text)
    expect("safe_json returns None on non-JSON", utils.safe_json(Fake()) is None)


def test_unit_add_vulnerability_drift():
    t = Table()
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


# ------------------------------------------------------------------
# Tests — Scanner
# ------------------------------------------------------------------
def test_scanner_session_has_auth_and_ua():
    cfg = make_cfg("anything")
    s = Scanner(cfg)
    expect("Session sets Authorization header",
           s.session.headers.get("Authorization") == "Bearer dummy-token")
    expect("Session sets User-Agent",
           "apisec-cicd-latest-fetch" in (s.session.headers.get("User-Agent") or ""))


def test_scanner_scans_forwards_next_token():
    """Scanner.scans(next_token=...) must forward as ?nextToken=... so the
    list endpoint paginates."""
    cfg = make_cfg("latest-list-paginated")
    s = Scanner(cfg)
    r1 = utils.safe_json(s.scans()) or {}
    expect("List page 1 returns nextToken=list-tok-p2",
           r1.get("nextToken") == "list-tok-p2",
           f"got {r1.get('nextToken')!r}")
    r2 = utils.safe_json(s.scans(next_token="list-tok-p2")) or {}
    expect("List page 2 returns no nextToken",
           r2.get("nextToken") is None,
           f"got {r2.get('nextToken')!r}")


def test_scanner_scan_forwards_next_token():
    cfg = make_cfg("paginated-findings")
    s = Scanner(cfg)
    r1 = utils.safe_json(s.scan("scan-123")) or {}
    expect("Detail page 1 returns nextToken=tok-p2",
           r1.get("nextToken") == "tok-p2")
    r2 = utils.safe_json(s.scan("scan-123", next_token="tok-p2")) or {}
    expect("Detail page 2 returns no nextToken", r2.get("nextToken") is None)


def test_scanner_retry_recovers_502():
    MockHandler.counters["flaky"] = 0
    cfg = make_cfg("flaky-502")
    s = Scanner(cfg)
    r = s.scans()
    expect("Scanner retries 502 then succeeds 200",
           r.status_code == 200 and MockHandler.counters["flaky"] == 3)


def test_scanner_404_passes_through():
    cfg = make_cfg("poll-404")
    s = Scanner(cfg)
    expect("Scanner returns 404 (does not retry)", s.scans().status_code == 404)


# ------------------------------------------------------------------
# Tests — pick_latest_complete (NEW behaviour)
# ------------------------------------------------------------------
def test_pick_latest_complete_empty():
    import main
    expect("pick_latest_complete([]) → None", main.pick_latest_complete([]) is None)


def test_pick_latest_complete_none_complete():
    import main
    scans = [
        {"scanId": "p", "status": "Processing"},
        {"scanId": "f", "status": "Failed"},
    ]
    expect("pick_latest_complete with no Complete entries → None",
           main.pick_latest_complete(scans) is None)


def test_pick_latest_complete_skips_processing_in_front():
    """If the most recent scan is Processing but an earlier one is Complete,
    return the Complete one."""
    import main
    scans = [
        {"scanId": "older", "status": "Complete",
         "lastUpdateTime": "2024-01-01T00:00:00"},
        {"scanId": "newest-processing", "status": "Processing",
         "lastUpdateTime": "2024-01-03T00:00:00"},
        {"scanId": "winner", "status": "Complete",
         "lastUpdateTime": "2024-01-02T00:00:00"},
    ]
    selected = main.pick_latest_complete(scans)
    expect("Selected scan skips the newer Processing one",
           selected and selected.get("scanId") == "winner",
           f"got {selected}")


def test_pick_latest_complete_picks_latest_among_completes():
    import main
    scans = [
        {"scanId": "old",    "status": "Complete", "lastUpdateTime": "2024-01-01"},
        {"scanId": "newest", "status": "Complete", "lastUpdateTime": "2024-03-01"},
        {"scanId": "mid",    "status": "Complete", "lastUpdateTime": "2024-02-01"},
    ]
    selected = main.pick_latest_complete(scans)
    expect("pick_latest_complete returns highest lastUpdateTime among Completes",
           selected and selected.get("scanId") == "newest",
           f"got {selected}")


# ------------------------------------------------------------------
# Tests — collect_all_scans (NEW behaviour, list-endpoint pagination)
# ------------------------------------------------------------------
def test_collect_all_scans_walks_list_pagination():
    import main
    cfg = make_cfg("latest-list-paginated")
    s = Scanner(cfg)
    scans, status = main.collect_all_scans(s)
    expect("collect_all_scans returns 200",
           status == 200, f"status={status}")
    seen = {x["scanId"] for x in scans}
    expect("collect_all_scans merges across list pages",
           len(scans) == 2 and seen == {"page1-only-processing", "page2-winner"},
           f"got {[x.get('scanId') for x in scans]}")


# ------------------------------------------------------------------
# Tests — collect_all_findings (re-used from cicd-scanner)
# ------------------------------------------------------------------
def test_collect_all_findings_walks_pagination():
    import main
    cfg = make_cfg("paginated-findings")
    s = Scanner(cfg)
    first = utils.safe_json(s.scan("scan-123")) or {}
    merged = main.collect_all_findings(s, "scan-123", first)
    vulns = merged.get("vulnerabilities") or []
    expect("Merged vulnerabilities span both pages",
           len(vulns) == 2,
           f"got {len(vulns)} entries")


# ------------------------------------------------------------------
# Tests — run() integration (NEW: end-to-end orchestration)
# ------------------------------------------------------------------
def test_run_picks_latest_complete_and_evaluates():
    import main
    cfg = make_cfg("latest-happy")
    try:
        main.run(cfg)
        expect("run() exits when a Critical is found", False, "did not exit")
    except SystemExit as e:
        # winner has 1 Critical → error_count=1 > threshold=0 → exit 1
        expect("run() exits 1 on Critical (latest-happy)", e.code == 1, f"got {e.code}")


def test_run_exits_when_no_scans():
    import main
    cfg = make_cfg("latest-empty")
    try:
        main.run(cfg)
        expect("run() exits on no scans", False, "did not exit")
    except SystemExit as e:
        expect("run() exits 1 when no scans exist", e.code == 1, f"got {e.code}")


def test_run_exits_when_no_complete_scan():
    import main
    cfg = make_cfg("latest-none-complete")
    try:
        main.run(cfg)
        expect("run() exits when none Complete", False, "did not exit")
    except SystemExit as e:
        expect("run() exits 1 when no Complete scan available",
               e.code == 1, f"got {e.code}")


def test_run_walks_list_pagination_to_find_winner():
    import main
    cfg = make_cfg("latest-list-paginated")
    try:
        main.run(cfg)
        # The page-2 winner has no findings → exit 0
        expect("run() reaches a page-2 winner via list pagination", False,
               "did not exit")
    except SystemExit as e:
        expect("run() succeeds (exit 0) when latest Complete is on page 2",
               e.code == 0, f"got {e.code}")


# ------------------------------------------------------------------
# Run
# ------------------------------------------------------------------
def main():
    srv = start_server()
    try:
        test_unit_safe_json_html()
        test_unit_add_vulnerability_drift()
        test_scanner_session_has_auth_and_ua()
        test_scanner_scans_forwards_next_token()
        test_scanner_scan_forwards_next_token()
        test_scanner_retry_recovers_502()
        test_scanner_404_passes_through()
        test_pick_latest_complete_empty()
        test_pick_latest_complete_none_complete()
        test_pick_latest_complete_skips_processing_in_front()
        test_pick_latest_complete_picks_latest_among_completes()
        test_collect_all_scans_walks_list_pagination()
        test_collect_all_findings_walks_pagination()
        test_run_picks_latest_complete_and_evaluates()
        test_run_exits_when_no_scans()
        test_run_exits_when_no_complete_scan()
        test_run_walks_list_pagination_to_find_winner()
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
