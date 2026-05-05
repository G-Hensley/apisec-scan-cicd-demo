#!/usr/bin/env python3
import argparse
import time
from math import trunc

import utils
from colors import Colors
from dotenv import load_dotenv
from models import ScanConfig
from scanner import Scanner


"""By default, this test will run the 'auto' option, which will create a scan, and then poll for the results"""
"""Output in the form of a printed summary or printed full table is configured by env variables INPUT_PRINT_SUMMARY and INPUT_PRINT_FULL"""
"""Will load env variables from '.env'"""
def main():
    parser = argparse.ArgumentParser("APIsec Scanner")
    parser.add_argument("--command", help="One of [init, scans, scan (with id), auto]", type=str, default="auto")
    parser.add_argument("--scan_id", help="Needed if command is [scan]", type=str)
    args = parser.parse_args()

    scanconfig = ScanConfig.from_harness_execution_environment()
    scanner = Scanner(scanconfig)
    match args.command:
        case 'init':
            response = scanner.init()
            utils.print_response(response)
        case 'scans':
            response = scanner.scans()
            utils.print_response(response)
        case 'scan':
            response = scanner.scan(args.scan_id)
            print(f"{Colors.YELLOW}HTTP {response.status_code}{Colors.END}")
            json = utils.safe_json(response) or {}
            if utils.check_complete(json, args.scan_id):
                utils.print_scan_report(json, scanconfig.print_summary, scanconfig.print_full)
        case 'auto':
            response = scanner.init()
            utils.print_response(response)
            init_body = utils.safe_json(response) or {}
            scan_id = init_body.get('scanId')
            if not scan_id:
                print(f"{Colors.RED}init response did not include scanId. Aborting.{Colors.END}")
                exit(1)
            scan_complete = False
            start = time.time()
            timeout = start + (60 * 60) # one hour
            try:
                while not scan_complete and time.time() < timeout:
                    response = scanner.scan(scan_id)
                    if 400 <= response.status_code < 500:
                        print(f"\n{Colors.RED}Scan poll returned HTTP {response.status_code}: {response.reason}. Aborting.{Colors.END}")
                        exit(1)
                    if response.status_code >= 500:
                        print(f"\n{Colors.RED}Scan poll exhausted retries (HTTP {response.status_code}). Aborting.{Colors.END}")
                        exit(1)
                    json = utils.safe_json(response) or {}
                    waiting = " " + str(trunc(time.time() - start)) + " secs"
                    scan_complete = utils.check_complete(json, scan_id, waiting)
                    if not scan_complete:
                        status = json.get('status')
                        if status not in ('Processing', 'Complete', None, 'Unknown'):
                            print(f"\n{Colors.RED}Scan ended in terminal state: {status}. Aborting.{Colors.END}")
                            exit(1)
                    time.sleep(5)
                print(f"Polling ended. Scan complete: {scan_complete}")
                if scan_complete:
                    full_results = collect_all_findings(scanner, scan_id, json)
                    evaluate_scan(scanconfig, full_results)
                else:
                    print(f"{Colors.RED}Scan did not complete within the polling window.{Colors.END}")
                    exit(1)
            except KeyboardInterrupt:
                print(f"Polling interrupted. Scan complete: {scan_complete}")
                exit(1)

MAX_PAGINATION_PAGES = 100


def collect_all_findings(scanner:Scanner, scan_id:str, first_body:dict) -> dict:
    """Walk the scan response's nextToken pagination and merge every page's
    `vulnerabilities` into a single dict. Returns a copy of `first_body` with
    the combined vulnerabilities list and `nextToken` stripped.

    Hard-capped at MAX_PAGINATION_PAGES to defend against a misbehaving server
    that echoes a token forever.
    """
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
                f"{Colors.YELLOW}Pagination page {page} returned "
                f"HTTP {response.status_code}; stopping.{Colors.END}"
            )
            break
        body = utils.safe_json(response) or {}
        merged_vulns.extend(body.get('vulnerabilities') or [])
        next_token = body.get('nextToken')
    if next_token:
        print(
            f"{Colors.YELLOW}Pagination cap of {MAX_PAGINATION_PAGES} pages reached; "
            f"some findings may be missing.{Colors.END}"
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
            print(f"{Colors.YELLOW}Skipping non-numeric CVSS score in counts: {score_key!r}{Colors.END}")
    print(f"Total Errors at Severity {threshold} or higher: {error_count}")
    if(error_count > scanconfig.fail_on_vulnerability_threshold):
        print(f"{Colors.RED}API scan failed! Number of ERRORS: {error_count} (Exceeded threshold of {scanconfig.fail_on_vulnerability_threshold}){Colors.END}")
        exit(1)
    else:
        print(f"{Colors.GREEN}API scan passed! Number of ERRORS: {error_count} (Within threshold of {scanconfig.fail_on_vulnerability_threshold}){Colors.END}")
        exit(0)

# Entry point of the script
if __name__ == "__main__":
    # https://stackoverflow.com/questions/70690682/import-dotenv-could-not-be-resolved
    load_dotenv()
    main()
