#!/usr/bin/env python3
"""APIsec CI/CD gate that reads the latest *Completed* scan for an
application/instance and applies CVSS-severity / error-count thresholds.

Unlike the sibling `cicd-scanner` image, this one does NOT trigger a scan or
poll for completion. It just reads what already exists.

Behaviour:
  1. List all scans for (application_id, instance_id), walking nextToken
     pagination if present.
  2. Pick the most recent scan whose status == "Complete". If the very
     latest scan is Processing or Failed, fall back to the next most recent
     Complete one.
  3. Fetch that scan's findings, walking nextToken pagination, and run the
     same threshold gate as cicd-scanner.

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


def pick_latest_complete(scans:list) -> dict | None:
    """Given a list of scan records, return the most recent one whose
    `status` is "Complete". Recency is determined by `lastUpdateTime`,
    falling back to `startTime`. Returns None if no Complete scan exists."""
    if not isinstance(scans, list):
        return None
    completed = [
        s for s in scans
        if isinstance(s, dict) and s.get('status') == 'Complete'
    ]
    if not completed:
        return None
    completed.sort(
        key=lambda s: (s.get('lastUpdateTime') or '', s.get('startTime') or ''),
        reverse=True,
    )
    return completed[0]


def _extract_scans(body) -> list:
    """List endpoint may return either a flat list or a wrapped {"scans": [...]}.
    Try the wrapped form first, then a flat list. Anything else → []."""
    if isinstance(body, dict) and isinstance(body.get('scans'), list):
        return body['scans']
    if isinstance(body, list):
        return body
    return []


def collect_all_scans(scanner:Scanner) -> tuple[list, int]:
    """Walk GET /scans nextToken pagination and return every scan record
    seen, plus the HTTP status of the *first* page (so the caller can
    distinguish "no scans yet" from "request failed")."""
    response = scanner.scans()
    if response.status_code != 200:
        return [], response.status_code
    body = utils.safe_json(response) or {}
    scans = list(_extract_scans(body))
    next_token = body.get('nextToken') if isinstance(body, dict) else None
    page = 1
    while next_token and page < MAX_PAGINATION_PAGES:
        page += 1
        response = scanner.scans(next_token=next_token)
        if response.status_code != 200:
            print(
                f"{Colors.YELLOW}Scan-list pagination page {page} returned "
                f"HTTP {response.status_code}; stopping.{Colors.END}"
            )
            break
        body = utils.safe_json(response) or {}
        scans.extend(_extract_scans(body))
        next_token = body.get('nextToken') if isinstance(body, dict) else None
    if next_token:
        print(
            f"{Colors.YELLOW}Scan-list pagination cap of {MAX_PAGINATION_PAGES} "
            f"pages reached; some scans may be missing.{Colors.END}"
        )
    return scans, 200


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

    scans, status = collect_all_scans(scanner)
    if status != 200:
        print(f"{Colors.RED}Failed to list scans: HTTP {status}.{Colors.END}")
        sys.exit(1)
    if not scans:
        print(f"{Colors.RED}No scans found for this application/instance.{Colors.END}")
        sys.exit(1)

    selected = pick_latest_complete(scans)
    if not selected:
        print(
            f"{Colors.RED}No Completed scan available. The most recent scans "
            f"may be Processing or Failed.{Colors.END}"
        )
        sys.exit(1)

    scan_id = selected.get('scanId')
    if not scan_id:
        print(f"{Colors.RED}Latest Complete scan has no scanId.{Colors.END}")
        sys.exit(1)

    print(f"Using latest Complete scan: {scan_id}")

    detail_response = scanner.scan(scan_id)
    if detail_response.status_code != 200:
        print(
            f"{Colors.RED}Failed to fetch scan details for {scan_id}: "
            f"HTTP {detail_response.status_code}.{Colors.END}"
        )
        sys.exit(1)

    first_body = utils.safe_json(detail_response) or {}
    full_results = collect_all_findings(scanner, scan_id, first_body)
    evaluate_scan(scanconfig, full_results)


def main():
    scanconfig = ScanConfig.from_harness_execution_environment()
    run(scanconfig)


if __name__ == "__main__":
    load_dotenv()
    main()
