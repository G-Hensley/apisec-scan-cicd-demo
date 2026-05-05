#!/usr/bin/env python3
"""APIsec CI/CD gate that reads the latest scan recorded against an
application/instance and applies CVSS-severity / error-count thresholds.

Unlike the sibling `cicd-scanner` image, this one does NOT trigger a scan or
poll for completion. It just reads what already exists.

Behaviour:
  1. GET /v1/applications/{applicationId} — returns app metadata including
     each instance's `latestScanStats`.
  2. Find the configured instance, read latestScanStats.scanId, and require
     that the latest scan is `Complete`. If it's Processing or Failed, exit 1
     with a clear message (the API does not expose a list endpoint to fall
     back to a previous Complete scan).
  3. GET /v1/applications/{appId}/instances/{instanceId}/scans/{scanId}
     paginated via `nextToken`, then run the same threshold gate as
     cicd-scanner.

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


def find_instance(application_body, instance_id:str) -> dict | None:
    """Locate the instance dict matching `instance_id` inside the
    application metadata returned by GET /v1/applications/{appId}.
    Returns None if no match (or if the response shape is unexpected)."""
    if not isinstance(application_body, dict):
        return None
    instances = application_body.get('instances') or []
    if not isinstance(instances, list):
        return None
    for inst in instances:
        if isinstance(inst, dict) and inst.get('instanceId') == instance_id:
            return inst
    return None


def collect_all_findings(scanner:Scanner, scan_id:str, first_body:dict) -> dict:
    """Walk the scan-detail nextToken pagination and merge every page's
    `vulnerabilities` into one dict."""
    if not isinstance(first_body, dict):
        first_body = {}
    merged_vulns = list(first_body.get('vulnerabilities') or [])
    next_token = first_body.get('nextToken')
    page = 1
    while next_token and page < MAX_PAGINATION_PAGES:
        page += 1
        response = scanner.scan(scan_id, next_token=next_token)
        if response.status_code != 200:
            print(
                f"{Colors.YELLOW}Findings pagination page {page} returned "
                f"HTTP {response.status_code}; stopping.{Colors.END}"
            )
            break
        body = utils.safe_json(response) or {}
        merged_vulns.extend(body.get('vulnerabilities') or [])
        next_token = body.get('nextToken')
    if next_token:
        print(
            f"{Colors.YELLOW}Findings pagination cap of {MAX_PAGINATION_PAGES} "
            f"pages reached; some findings may be missing.{Colors.END}"
        )
    merged = dict(first_body)
    merged['vulnerabilities'] = merged_vulns
    merged.pop('nextToken', None)
    return merged


def evaluate_scan(scanconfig:ScanConfig, json:dict):
    results_table = utils.print_scan_report(json, scanconfig.print_summary, scanconfig.print_full)
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


def run(scanconfig:ScanConfig):
    """Orchestration entry point — testable without env vars."""
    scanner = Scanner(scanconfig)

    # 1. Fetch application metadata
    app_response = scanner.get_application()
    if app_response.status_code != 200:
        print(
            f"{Colors.RED}Failed to fetch application "
            f"{scanconfig.application_id}: HTTP {app_response.status_code}.{Colors.END}"
        )
        sys.exit(1)
    app_body = utils.safe_json(app_response) or {}

    # 2. Locate our instance
    instance = find_instance(app_body, scanconfig.instance_id)
    if not instance:
        print(
            f"{Colors.RED}Instance {scanconfig.instance_id} was not found in "
            f"application {scanconfig.application_id}.{Colors.END}"
        )
        sys.exit(1)

    # 3. Pull the latest scan id from latestScanStats
    stats = instance.get('latestScanStats')
    if not stats:
        print(
            f"{Colors.RED}No latestScanStats on instance — has any scan "
            f"completed yet?{Colors.END}"
        )
        sys.exit(1)

    scan_id = stats.get('scanId') if isinstance(stats, dict) else None
    if not scan_id:
        print(
            f"{Colors.RED}latestScanStats is present but missing scanId. "
            f"Got: {stats!r}.{Colors.END}"
        )
        sys.exit(1)

    print(f"Latest scan id from application metadata: {scan_id}")

    # 4. Fetch the scan detail (first page only here; pagination walked next)
    detail_response = scanner.scan(scan_id)
    if detail_response.status_code != 200:
        print(
            f"{Colors.RED}Failed to fetch scan details for {scan_id}: "
            f"HTTP {detail_response.status_code}.{Colors.END}"
        )
        sys.exit(1)
    first_body = utils.safe_json(detail_response) or {}

    # 5. Refuse to gate against a non-Complete scan
    status = first_body.get('status')
    if status != 'Complete':
        print(
            f"{Colors.RED}Latest scan {scan_id} is in state {status!r}, not "
            f"Complete. Cannot gate. Wait for the scan to finish or trigger "
            f"a new one.{Colors.END}"
        )
        sys.exit(1)

    # 6. Walk pagination and evaluate
    full_results = collect_all_findings(scanner, scan_id, first_body)
    evaluate_scan(scanconfig, full_results)


def main():
    scanconfig = ScanConfig.from_harness_execution_environment()
    run(scanconfig)


if __name__ == "__main__":
    load_dotenv()
    main()
