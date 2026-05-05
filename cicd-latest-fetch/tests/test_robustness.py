"""
Robustness tests for cicd-latest-fetch against an in-process mock APIsec server.

This image fetches the latest scan id off the application metadata
(`GET /v1/applications/{appId}` → instances[].latestScanStats.scanId), then
fetches that scan's findings (paginated via nextToken), and applies the
same threshold gate as cicd-scanner. It does NOT trigger scans.

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
# Local fallback: source dir is the parent of tests/. Only added if it
# actually contains the sources, to avoid prepending bogus paths in Docker.
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
        # Routes:
        #   /v1/applications/<scenario>                              → app metadata
        #   /v1/applications/<scenario>/instances/<x>/scans/<id>     → scan detail
        parts = path.strip("/").split("/")
        scenario = parts[2] if len(parts) > 2 else ""
        is_application_route = len(parts) == 3 and parts[1] == "applications"
        is_scan_detail_route = len(parts) >= 7 and parts[5] == "scans"
        scan_id_seg = parts[6] if is_scan_detail_route else None

        if scenario == "latest-happy":
            # Application has one instance whose latestScanStats points to a
            # Complete scan with one Critical finding.
            if is_application_route:
                return self._send_json(200, {
                    "applicationId": scenario,
                    "applicationName": "Happy app",
                    "instances": [
                        {"instanceId": "inst",
                         "hostUrl": "http://example",
                         "latestScanStats": {
                             "scanId": "winner",
                             "status": "Complete",
                         }},
                    ],
                })
            if is_scan_detail_route and scan_id_seg == "winner":
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
            return self._send_json(500, {"error": f"unexpected route: {path}"})

        if scenario == "latest-no-stats":
            # Instance exists but has no scans yet.
            if is_application_route:
                return self._send_json(200, {
                    "applicationId": scenario,
                    "instances": [
                        {"instanceId": "inst", "latestScanStats": None},
                    ],
                })
            return self._send_json(500, {"error": "should not fetch detail"})

        if scenario == "latest-instance-missing":
            # Application exists but our instance_id is not among instances[].
            if is_application_route:
                return self._send_json(200, {
                    "applicationId": scenario,
                    "instances": [
                        {"instanceId": "some-other-instance",
                         "latestScanStats": {"scanId": "x", "status": "Complete"}},
                    ],
                })
            return self._send_json(500, {"error": "should not fetch detail"})

        if scenario == "latest-processing":
            # latestScanStats points to a still-Processing scan.
            if is_application_route:
                return self._send_json(200, {
                    "applicationId": scenario,
                    "instances": [
                        {"instanceId": "inst",
                         "latestScanStats": {
                             "scanId": "still-running",
                             "status": "Processing",
                         }},
                    ],
                })
            if is_scan_detail_route and scan_id_seg == "still-running":
                return self._send_json(200, {
                    "scanId": "still-running",
                    "status": "Processing",
                })
            return self._send_json(500, {"error": "unexpected route"})

        if scenario == "paginated-findings":
            # Application points to scan-123, which paginates findings
            # across two pages.
            if is_application_route:
                return self._send_json(200, {
                    "applicationId": scenario,
                    "instances": [
                        {"instanceId": "inst",
                         "latestScanStats": {
                             "scanId": "scan-123",
                             "status": "Complete",
                         }},
                    ],
                })
            if is_scan_detail_route and scan_id_seg == "scan-123":
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
                                "testStatus": {"description": "page1"},
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
                                "testStatus": {"description": "page2"},
                            }],
                        }],
                    })
                return self._send_json(400, {"error": f"unexpected nextToken {next_token!r}"})
            return self._send_json(500, {"error": "unexpected route"})

        if scenario == "app-403":
            # Mimic the 403 we saw in production when a token couldn't list scans.
            if is_application_route:
                return self._send_json(403, {"error": "forbidden"})
            return self._send_json(500, {"error": "unexpected route"})

        if scenario == "poll-404":
            return self._send_json(404, {"error": "not found"})
        if scenario == "flaky-502":
            MockHandler.counters["flaky"] += 1
            if MockHandler.counters["flaky"] <= 2:
                return self._send_raw(502, "text/html", "Bad Gateway")
            return self._send_json(200, {"applicationId": scenario, "instances": []})

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
    cfg = make_cfg("latest-happy")
    s = Scanner(cfg)
    expect("Session sets Authorization header",
           s.session.headers.get("Authorization") == "Bearer dummy-token")
    expect("Session sets User-Agent",
           "apisec-cicd-latest-fetch" in (s.session.headers.get("User-Agent") or ""))


def test_scanner_get_application_returns_data():
    cfg = make_cfg("latest-happy")
    s = Scanner(cfg)
    response = s.get_application()
    expect("get_application() returns 200", response.status_code == 200)
    body = utils.safe_json(response) or {}
    expect("get_application() body has instances list",
           isinstance(body.get("instances"), list))


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
    r = s.get_application()
    expect("Scanner retries 502 then succeeds 200",
           r.status_code == 200 and MockHandler.counters["flaky"] == 3)


def test_scanner_404_passes_through():
    cfg = make_cfg("poll-404")
    s = Scanner(cfg)
    expect("Scanner returns 404 (does not retry)",
           s.get_application().status_code == 404)


# ------------------------------------------------------------------
# Tests — find_instance helper (NEW behaviour)
# ------------------------------------------------------------------
def test_find_instance_returns_match():
    import main
    body = {"instances": [
        {"instanceId": "a"}, {"instanceId": "target"}, {"instanceId": "c"},
    ]}
    inst = main.find_instance(body, "target")
    expect("find_instance returns the matching dict",
           inst and inst.get("instanceId") == "target",
           f"got {inst}")


def test_find_instance_returns_none_when_missing():
    import main
    body = {"instances": [{"instanceId": "a"}, {"instanceId": "b"}]}
    expect("find_instance returns None when no match",
           main.find_instance(body, "missing") is None)


def test_find_instance_handles_missing_instances_key():
    import main
    expect("find_instance handles missing instances list",
           main.find_instance({}, "anything") is None)


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
# Tests — run() integration (NEW orchestration)
# ------------------------------------------------------------------
def test_run_picks_latest_scan_id_from_application_and_evaluates():
    import main
    cfg = make_cfg("latest-happy")
    try:
        main.run(cfg)
        expect("run() exits when a Critical is found", False, "did not exit")
    except SystemExit as e:
        # winner has 1 Critical → error_count=1 > threshold=0 → exit 1
        expect("run() exits 1 on Critical (latest-happy)",
               e.code == 1, f"got {e.code}")


def test_run_evaluates_paginated_findings():
    import main
    cfg = make_cfg("paginated-findings")
    try:
        main.run(cfg)
        expect("run() exits when paginated findings include a Critical",
               False, "did not exit")
    except SystemExit as e:
        expect("run() exits 1 when paginated findings include a Critical",
               e.code == 1, f"got {e.code}")


def test_run_exits_when_no_latest_scan_stats():
    import main
    cfg = make_cfg("latest-no-stats")
    try:
        main.run(cfg)
        expect("run() exits when latestScanStats is null", False, "did not exit")
    except SystemExit as e:
        expect("run() exits 1 when no scan has completed yet",
               e.code == 1, f"got {e.code}")


def test_run_exits_when_instance_missing():
    import main
    cfg = make_cfg("latest-instance-missing")
    try:
        main.run(cfg)
        expect("run() exits when instance not in app", False, "did not exit")
    except SystemExit as e:
        expect("run() exits 1 when configured instance is not in app",
               e.code == 1, f"got {e.code}")


def test_run_exits_when_latest_scan_is_processing():
    import main
    cfg = make_cfg("latest-processing")
    try:
        main.run(cfg)
        expect("run() exits when latest scan is Processing",
               False, "did not exit")
    except SystemExit as e:
        expect("run() exits 1 when the latest scan is not Complete",
               e.code == 1, f"got {e.code}")


def test_run_exits_on_403_from_application_endpoint():
    import main
    cfg = make_cfg("app-403")
    try:
        main.run(cfg)
        expect("run() exits on 403", False, "did not exit")
    except SystemExit as e:
        expect("run() exits 1 with a clear message on 403",
               e.code == 1, f"got {e.code}")


# ------------------------------------------------------------------
# Run
# ------------------------------------------------------------------
def main():
    srv = start_server()
    try:
        test_unit_safe_json_html()
        test_unit_add_vulnerability_drift()
        test_scanner_session_has_auth_and_ua()
        test_scanner_get_application_returns_data()
        test_scanner_scan_forwards_next_token()
        test_scanner_retry_recovers_502()
        test_scanner_404_passes_through()
        test_find_instance_returns_match()
        test_find_instance_returns_none_when_missing()
        test_find_instance_handles_missing_instances_key()
        test_collect_all_findings_walks_pagination()
        test_run_picks_latest_scan_id_from_application_and_evaluates()
        test_run_evaluates_paginated_findings()
        test_run_exits_when_no_latest_scan_stats()
        test_run_exits_when_instance_missing()
        test_run_exits_when_latest_scan_is_processing()
        test_run_exits_on_403_from_application_endpoint()
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
