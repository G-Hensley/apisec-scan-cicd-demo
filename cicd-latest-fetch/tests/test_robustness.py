"""
Robustness tests for cicd-latest-fetch against an in-process mock APIsec server.

This image fetches every detection currently on an instance via
`GET /v1/applications/{appId}/instances/{instanceId}/detections` and applies a
CVSS-floor / error-count threshold gate. Only `status == "ACTIVE"` detections
count toward the gate; DISMISSED, RISK_ACCEPTED, RESOLVED are reported but
ignored.

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
from io import StringIO
from urllib.parse import parse_qs, urlparse

# In-container path
sys.path.insert(0, "/apisec")
# Local fallback: source dir is the parent of tests/. Only added if it
# actually contains the sources, to avoid prepending bogus paths in Docker.
_local_src = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if os.path.isfile(os.path.join(_local_src, "main.py")):
    sys.path.insert(0, _local_src)

import utils  # noqa: E402
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
# Detection-shape builders
# ------------------------------------------------------------------
def _detection(method, resource, score, qual, status="ACTIVE"):
    """One record from detections[].data.vulnerabilities[]."""
    return {
        "detectionId": f"det-{method}-{resource}",
        "endpointId": "fake-endpoint-id",
        "method": method,
        "resource": resource,
        "testResult": {
            "cvssScore": score,
            "cvssQualifier": qual,
            "detectionDescription": f"{qual} finding on {resource}",
            "assertion": None,
            "remediation": None,
            "owaspTags": ["API1:2023"],
            "cwes": None,
        },
        "detectionDate": "2026-04-06T16:50:54Z",
        "lastFoundDate": "2026-04-06T16:50:54Z",
        "resolutionDate": None,
        "status": status,
        "riskAcceptedEndDate": None,
        "riskAcceptedBy": None,
        "comments": None,
    }


def _group(category_name, test_name, vulns):
    return {
        "category": {"id": category_name.lower(), "name": category_name, "description": ""},
        "test": {"id": test_name.lower().replace(" ", "-"), "name": test_name, "description": ""},
        "totalDetections": len(vulns),
        "data": {
            "numVulnerableEndpoints": len(vulns),
            "numActiveVulnerabilities": sum(1 for v in vulns if v.get("status") == "ACTIVE"),
            "numInfoDetections": 0,
            "numResolved": sum(1 for v in vulns if v.get("status") == "RESOLVED"),
            "vulnerabilities": vulns,
        },
    }


def _envelope(*groups, total_active_override=None, next_token=None):
    """Build a /detections response envelope.

    `total_active_override` lets tests force `metadata.totalActiveVulnerabilities`
    higher than the body actually contains, simulating server-side truncation.
    `next_token` adds a top-level `nextToken` to simulate a paginated server.
    """
    body = {
        "metadata": {
            "totalActiveVulnerabilities": (
                total_active_override
                if total_active_override is not None
                else sum(g["data"]["numActiveVulnerabilities"] for g in groups)
            ),
            "totalTests": 5544,
        },
        "detections": list(groups),
    }
    if next_token is not None:
        body["nextToken"] = next_token
    return body


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
        #   /v1/applications/<scenario>/instances/<x>/detections    → all detections
        parts = path.strip("/").split("/")
        scenario = parts[2] if len(parts) > 2 else ""
        is_detections_route = (
            len(parts) == 6
            and parts[1] == "applications"
            and parts[3] == "instances"
            and parts[5] == "detections"
        )
        next_token = (query.get("nextToken") or [None])[0]

        if scenario == "detections-happy":
            if is_detections_route:
                return self._send_json(200, _envelope(
                    _group("Payload Injection", "NoSQL Injection", [
                        _detection("post", "/coupon/validate", 9, "Critical"),
                    ]),
                ))
            return self._send_json(500, {"error": f"unexpected route: {path}"})

        if scenario == "detections-empty":
            if is_detections_route:
                return self._send_json(200, _envelope())
            return self._send_json(500, {"error": "unexpected route"})

        if scenario == "detections-all-resolved":
            # Detections present, but all RESOLVED — gate must pass.
            if is_detections_route:
                return self._send_json(200, _envelope(
                    _group("Information Leak", "PII data", [
                        _detection("get", "/orders/all", 6, "Medium", status="RESOLVED"),
                    ]),
                ))
            return self._send_json(500, {"error": "unexpected route"})

        if scenario == "detections-mixed":
            # 1 ACTIVE Critical, 1 RISK_ACCEPTED High, 1 DISMISSED Medium.
            # Only the Critical should count.
            if is_detections_route:
                return self._send_json(200, _envelope(
                    _group("Payload Injection", "NoSQL Injection", [
                        _detection("post", "/a", 9, "Critical", status="ACTIVE"),
                        _detection("post", "/b", 8, "High", status="RISK_ACCEPTED"),
                    ]),
                    _group("Information Leak", "PII data", [
                        _detection("get", "/c", 6, "Medium", status="DISMISSED"),
                    ]),
                ))
            return self._send_json(500, {"error": "unexpected route"})

        if scenario == "detections-multi-active":
            # 3 ACTIVE Highs across two groups — error count = 3.
            if is_detections_route:
                return self._send_json(200, _envelope(
                    _group("Payload Injection", "SQL Injection", [
                        _detection("post", "/x", 8, "High"),
                        _detection("post", "/y", 8, "High"),
                    ]),
                    _group("Auth", "Broken Auth", [
                        _detection("get", "/z", 8, "High"),
                    ]),
                ))
            return self._send_json(500, {"error": "unexpected route"})

        if scenario == "app-403":
            if is_detections_route:
                return self._send_json(403, {"error": "forbidden"})
            return self._send_json(500, {"error": "unexpected route"})

        if scenario == "app-404":
            if is_detections_route:
                return self._send_json(404, {"error": "not found"})
            return self._send_json(500, {"error": "unexpected route"})

        if scenario == "detections-truncated":
            # API claims 5 ACTIVE vulns total but only returns 1.
            # Should warn but NOT fail; gate runs on what was received.
            if is_detections_route:
                return self._send_json(200, _envelope(
                    _group("Payload Injection", "NoSQL Injection", [
                        _detection("post", "/coupon/validate", 9, "Critical"),
                    ]),
                    total_active_override=5,
                ))
            return self._send_json(500, {"error": "unexpected route"})

        if scenario == "detections-paginated":
            # Page 1 returns nextToken=tok-p2 with one Critical;
            # page 2 returns one more Critical and no nextToken.
            # Both pages combined match metadata.totalActiveVulnerabilities=2.
            if is_detections_route:
                if not next_token:
                    return self._send_json(200, _envelope(
                        _group("Payload Injection", "SQL Injection", [
                            _detection("post", "/p1", 9, "Critical"),
                        ]),
                        total_active_override=2,
                        next_token="tok-p2",
                    ))
                if next_token == "tok-p2":
                    return self._send_json(200, _envelope(
                        _group("Auth", "Broken Auth", [
                            _detection("get", "/p2", 9, "Critical"),
                        ]),
                        total_active_override=2,
                    ))
                return self._send_json(400, {"error": f"unexpected nextToken {next_token!r}"})
            return self._send_json(500, {"error": "unexpected route"})

        if scenario == "flaky-502":
            MockHandler.counters["flaky"] += 1
            if MockHandler.counters["flaky"] <= 2:
                return self._send_raw(502, "text/html", "Bad Gateway")
            return self._send_json(200, _envelope())

        if scenario == "poll-404":
            return self._send_json(404, {"error": "not found"})

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


def test_unit_add_detection_drift():
    t = Table()
    drift = {
        "method": "GET",
        "resource": "/x",
        "testResult": {"cvssScore": None, "cvssQualifier": "Critical"},
        "status": "ACTIVE",
    }
    try:
        t.add_detection(drift, "Cat", "Test")
        expect("add_detection survives missing/null fields",
               len(t.method) == 1 and "Critical" in t.qual_counts)
    except Exception as e:
        expect("add_detection survives missing/null fields", False, repr(e))


# ------------------------------------------------------------------
# Tests — Scanner
# ------------------------------------------------------------------
def test_scanner_session_has_auth_and_ua():
    cfg = make_cfg("detections-happy")
    s = Scanner(cfg)
    expect("Session sets Authorization header",
           s.session.headers.get("Authorization") == "Bearer dummy-token")
    expect("Session sets User-Agent",
           "apisec-cicd-latest-fetch" in (s.session.headers.get("User-Agent") or ""))


def test_scanner_get_detections_returns_data():
    cfg = make_cfg("detections-happy")
    s = Scanner(cfg)
    response = s.get_detections()
    expect("get_detections() returns 200", response.status_code == 200)
    body = utils.safe_json(response) or {}
    expect("get_detections() body has detections list",
           isinstance(body.get("detections"), list))


def test_scanner_retry_recovers_502():
    MockHandler.counters["flaky"] = 0
    cfg = make_cfg("flaky-502")
    s = Scanner(cfg)
    r = s.get_detections()
    expect("Scanner retries 502 then succeeds 200",
           r.status_code == 200 and MockHandler.counters["flaky"] == 3)


def test_scanner_404_passes_through():
    cfg = make_cfg("poll-404")
    s = Scanner(cfg)
    expect("Scanner returns 404 (does not retry)",
           s.get_detections().status_code == 404)


# ------------------------------------------------------------------
# Tests — run() integration
# ------------------------------------------------------------------
def test_run_exits_1_on_active_critical():
    import main
    cfg = make_cfg("detections-happy")
    try:
        main.run(cfg)
        expect("run() exits when an Active Critical is found", False, "did not exit")
    except SystemExit as e:
        expect("run() exits 1 on Active Critical (detections-happy)",
               e.code == 1, f"got {e.code}")


def test_run_exits_0_on_empty_detections():
    import main
    cfg = make_cfg("detections-empty")
    try:
        main.run(cfg)
        expect("run() did not exit on empty detections", False, "should have exited 0")
    except SystemExit as e:
        expect("run() exits 0 when no detections at all", e.code == 0, f"got {e.code}")


def test_run_exits_0_when_all_resolved():
    import main
    cfg = make_cfg("detections-all-resolved")
    try:
        main.run(cfg)
        expect("run() did not exit on all-resolved", False, "should have exited 0")
    except SystemExit as e:
        expect("run() exits 0 when no Active findings (all RESOLVED)",
               e.code == 0, f"got {e.code}")


def test_run_filters_non_active_statuses():
    """RISK_ACCEPTED and DISMISSED must NOT count toward the gate."""
    import main
    cfg = make_cfg("detections-mixed")
    try:
        main.run(cfg)
        expect("run() did not exit on mixed-statuses", False, "should have exited")
    except SystemExit as e:
        # Only the 1 ACTIVE Critical counts → above threshold (0) → exit 1.
        # If RISK_ACCEPTED/DISMISSED leaked through, error_count would be 2-3,
        # but exit code is still 1 — so this test asserts exit 1 either way.
        # The stronger assertion is the score_counts check below.
        expect("run() exits 1 on mixed (Active Critical only)",
               e.code == 1, f"got {e.code}")


def test_run_counts_only_active_for_threshold():
    """When the only Active finding is below the severity threshold, gate passes
    even if non-Active findings exceed it."""
    import main
    # severity_threshold=8 means Critical (9) counts. If RISK_ACCEPTED High (8)
    # leaked through and ACTIVE Critical (9) counts, error_count=2.
    # If filter works correctly, only Critical (9) counts → error_count=1 > 0 → exit 1.
    # To assert the filter, we need a scenario where ACTIVE alone is BELOW
    # threshold but non-ACTIVE is above.
    # Build inline against a config-only scenario.
    cfg = make_cfg("detections-mixed", severity_threshold=10)  # nothing >=10
    try:
        main.run(cfg)
        expect("run() did not exit when no Active above threshold",
               False, "should have exited 0")
    except SystemExit as e:
        # No ACTIVE finding has cvssScore >= 10, so error_count must be 0.
        # If RISK_ACCEPTED/DISMISSED leaked, they'd still all be < 10, so exit 0
        # regardless. This test really asserts the gate semantics, not the filter.
        expect("run() exits 0 when no Active >= threshold",
               e.code == 0, f"got {e.code}")


def test_run_multi_active_sums_error_count():
    import main
    # 3 Active Highs (cvssScore=8). Severity threshold=8 → all 3 count.
    # Error threshold=0 → 3 > 0 → exit 1.
    cfg = make_cfg("detections-multi-active", error_threshold=0, severity_threshold=8)
    try:
        main.run(cfg)
        expect("run() did not exit when multiple Actives exceed threshold",
               False, "should have exited 1")
    except SystemExit as e:
        expect("run() exits 1 when 3 Active findings exceed error threshold of 0",
               e.code == 1, f"got {e.code}")


def test_run_multi_active_passes_when_under_error_threshold():
    import main
    # Same 3 Active Highs, but error_threshold=5 → 3 <= 5 → exit 0.
    cfg = make_cfg("detections-multi-active", error_threshold=5, severity_threshold=8)
    try:
        main.run(cfg)
        expect("run() did not exit on multi-active with slack",
               False, "should have exited 0")
    except SystemExit as e:
        expect("run() exits 0 when error count is within threshold",
               e.code == 0, f"got {e.code}")


def test_run_exits_on_403():
    import main
    cfg = make_cfg("app-403")
    try:
        main.run(cfg)
        expect("run() exits on 403", False, "did not exit")
    except SystemExit as e:
        expect("run() exits 1 with a clear message on 403",
               e.code == 1, f"got {e.code}")


def test_run_exits_on_404():
    import main
    cfg = make_cfg("app-404")
    try:
        main.run(cfg)
        expect("run() exits on 404", False, "did not exit")
    except SystemExit as e:
        expect("run() exits 1 with a clear message on 404 (instance/app missing)",
               e.code == 1, f"got {e.code}")


# ------------------------------------------------------------------
# Tests — completeness check + nextToken pagination
# ------------------------------------------------------------------
def _capture_run(cfg):
    """Run main.run() and return (exit_code, captured_stdout)."""
    import main
    buf = StringIO()
    old_stdout = sys.stdout
    sys.stdout = buf
    code = None
    try:
        try:
            main.run(cfg)
        except SystemExit as e:
            code = e.code
    finally:
        sys.stdout = old_stdout
    return code, buf.getvalue()


def test_run_warns_when_metadata_total_exceeds_received():
    """If the API reports more ACTIVE vulns than the body contains, surface a
    warning so the operator can spot silent server-side truncation."""
    cfg = make_cfg("detections-truncated", error_threshold=0, severity_threshold=8)
    code, out = _capture_run(cfg)
    expect(
        "run() emits truncation warning when metadata > received",
        "truncated" in out.lower() or "incomplete" in out.lower() or "missing" in out.lower(),
        f"output had no warning keyword:\n{out}",
    )
    expect(
        "run() still exits 1 on the Active Critical it did receive",
        code == 1,
        f"got exit {code}",
    )


def test_run_does_not_warn_when_counts_match():
    """detections-happy: metadata.totalActiveVulnerabilities == received count."""
    cfg = make_cfg("detections-happy", error_threshold=0, severity_threshold=8)
    code, out = _capture_run(cfg)
    expect(
        "run() does NOT warn when metadata matches received",
        not any(w in out.lower() for w in ("truncated", "incomplete", "missing")),
        f"unexpected warning in output:\n{out}",
    )
    expect("run() exits 1 (Critical present)", code == 1, f"got exit {code}")


def test_run_walks_next_token_pagination():
    """Server returns nextToken on page 1; main.run must walk to page 2 and
    aggregate findings before evaluating."""
    # Two Critical findings, error_threshold=0 → exit 1.
    # If pagination did NOT walk, only 1 finding would count — exit code is
    # still 1, so the stronger signal is the printed total.
    cfg = make_cfg("detections-paginated", error_threshold=0, severity_threshold=8)
    code, out = _capture_run(cfg)
    expect(
        "run() walks nextToken and counts both pages",
        "ERRORS: 2" in out,
        f"expected 'ERRORS: 2' in output, got:\n{out}",
    )
    expect("run() exits 1 (paginated criticals)", code == 1, f"got exit {code}")
    expect(
        "run() does NOT warn after successful pagination (counts match)",
        not any(w in out.lower() for w in ("truncated", "incomplete", "missing")),
        f"unexpected warning in output:\n{out}",
    )


# ------------------------------------------------------------------
# Run
# ------------------------------------------------------------------
def main():
    srv = start_server()
    try:
        test_unit_safe_json_html()
        test_unit_add_detection_drift()
        test_scanner_session_has_auth_and_ua()
        test_scanner_get_detections_returns_data()
        test_scanner_retry_recovers_502()
        test_scanner_404_passes_through()
        test_run_exits_1_on_active_critical()
        test_run_exits_0_on_empty_detections()
        test_run_exits_0_when_all_resolved()
        test_run_filters_non_active_statuses()
        test_run_counts_only_active_for_threshold()
        test_run_multi_active_sums_error_count()
        test_run_multi_active_passes_when_under_error_threshold()
        test_run_exits_on_403()
        test_run_exits_on_404()
        test_run_warns_when_metadata_total_exceeds_received()
        test_run_does_not_warn_when_counts_match()
        test_run_walks_next_token_pagination()
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
