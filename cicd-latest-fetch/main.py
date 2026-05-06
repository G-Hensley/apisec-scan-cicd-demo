#!/usr/bin/env python3
"""APIsec CI/CD gate that reads the current detections on an
application/instance and applies CVSS-severity / error-count thresholds.

Unlike the sibling `cicd-scanner` image, this one does NOT trigger a scan or
poll for completion. It just reads the detection state already on the
instance.

Behaviour:
  1. GET /v1/applications/{appId}/instances/{instanceId}/detections
     — returns every detection grouped by category/test, including status
     and CVSS score per finding.
  2. Filter to `status == "ACTIVE"` (DISMISSED / RISK_ACCEPTED / RESOLVED
     are reported but do not count toward the gate).
  3. Run the same threshold gate as cicd-scanner.

Inputs (env vars, identical to cicd-scanner minus INPUT_AUTHENTICATION_ID):
  INPUT_APPLICATION_ID         APIsec application id (required)
  INPUT_INSTANCE_ID            APIsec instance id (required)
  INPUT_ACCESS_TOKEN           bearer token (required)
  INPUT_APISEC_BASE_URL        defaults to https://api.apisecapps.com
  INPUT_FAIL_ON_SEVERITY_THRESHOLD   CVSS floor for "error" (default sys.maxsize)
  INPUT_FAIL_ON_ERROR_THRESHOLD      max acceptable errors (default sys.maxsize)
  INPUT_PRINT_SUMMARY          truthy/falsy, default false
  INPUT_PRINT_FULL             truthy/falsy, default false
"""
import sys

import utils
from colors import Colors
from dotenv import load_dotenv
from models import ScanConfig
from scanner import Scanner

MAX_PAGINATION_PAGES = 100


def collect_all_detections(scanner: Scanner, first_body: dict) -> dict:
    """Walk top-level `nextToken` pagination if the server ever returns one.

    The /detections endpoint is not documented as paginated, but if a
    nextToken does appear we follow it defensively so a tenant with enough
    findings to trigger pagination doesn't silently get a partial gate.
    """
    if not isinstance(first_body, dict):
        first_body = {}
    merged_groups = list(first_body.get('detections') or [])
    next_token = first_body.get('nextToken')
    page = 1
    while next_token and page < MAX_PAGINATION_PAGES:
        page += 1
        response = scanner.get_detections(next_token=next_token)
        if response.status_code != 200:
            print(
                f"{Colors.YELLOW}Detections pagination page {page} returned "
                f"HTTP {response.status_code}; stopping.{Colors.END}"
            )
            break
        body = utils.safe_json(response) or {}
        merged_groups.extend(body.get('detections') or [])
        next_token = body.get('nextToken')
    if next_token:
        print(
            f"{Colors.YELLOW}Detections pagination cap of {MAX_PAGINATION_PAGES} "
            f"pages reached; some findings may be missing.{Colors.END}"
        )
    merged = dict(first_body)
    merged['detections'] = merged_groups
    merged.pop('nextToken', None)
    return merged


def warn_if_truncated(body: dict):
    """Compare metadata.totalActiveVulnerabilities against the count of
    ACTIVE findings actually present in the body. If the API claims more
    than we received, print a yellow warning so silent server-side
    truncation surfaces in CI logs."""
    metadata = body.get('metadata') or {}
    expected = metadata.get('totalActiveVulnerabilities')
    if not isinstance(expected, int):
        return
    received = 0
    for group in body.get('detections') or []:
        if not isinstance(group, dict):
            continue
        for det in (group.get('data') or {}).get('vulnerabilities') or []:
            if isinstance(det, dict) and det.get('status') == 'ACTIVE':
                received += 1
    if received < expected:
        print(
            f"{Colors.YELLOW}Detections response appears truncated: API "
            f"reports {expected} active vulnerabilities but only {received} "
            f"were returned. Gate is running against the {received} that "
            f"were received — surface this to APIsec if it persists.{Colors.END}"
        )


def evaluate_detections(scanconfig: ScanConfig, body: dict):
    results_table = utils.print_detection_report(
        body, scanconfig.print_summary, scanconfig.print_full
    )
    threshold = float(scanconfig.fail_on_severity_exceeds_threshold)
    error_count = 0
    for score_key, count in results_table.score_counts.items():
        try:
            if float(score_key) >= threshold:
                error_count += count
        except (TypeError, ValueError):
            print(
                f"{Colors.YELLOW}Skipping non-numeric CVSS score in counts: "
                f"{score_key!r}{Colors.END}"
            )
    print(f"Total Errors at Severity {threshold} or higher: {error_count}")
    if error_count > scanconfig.fail_on_vulnerability_threshold:
        print(
            f"{Colors.RED}API scan failed! Number of ERRORS: {error_count} "
            f"(Exceeded threshold of {scanconfig.fail_on_vulnerability_threshold}){Colors.END}"
        )
        sys.exit(1)
    print(
        f"{Colors.GREEN}API scan passed! Number of ERRORS: {error_count} "
        f"(Within threshold of {scanconfig.fail_on_vulnerability_threshold}){Colors.END}"
    )
    sys.exit(0)


def run(scanconfig: ScanConfig):
    """Orchestration entry point — testable without env vars."""
    scanner = Scanner(scanconfig)

    response = scanner.get_detections()
    if response.status_code != 200:
        print(
            f"{Colors.RED}Failed to fetch detections for "
            f"{scanconfig.application_id}/{scanconfig.instance_id}: "
            f"HTTP {response.status_code}.{Colors.END}"
        )
        sys.exit(1)

    first_body = utils.safe_json(response) or {}
    full_body = collect_all_detections(scanner, first_body)
    warn_if_truncated(full_body)
    evaluate_detections(scanconfig, full_body)


def main():
    scanconfig = ScanConfig.from_harness_execution_environment()
    run(scanconfig)


if __name__ == "__main__":
    load_dotenv()
    main()
