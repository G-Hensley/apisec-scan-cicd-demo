import json
import sys

import requests
from colors import Colors
from table import Table


def safe_json(response:requests.Response):
    try:
        return response.json()
    except (ValueError, json.JSONDecodeError):
        snippet = (response.text or "")[:200].replace("\n", " ")
        print(f"{Colors.RED}Non-JSON response (HTTP {response.status_code}): {snippet}{Colors.END}")
        return None

def print_response(response:requests.Response):
    print(f"{Colors.YELLOW}HTTP {response.status_code}{Colors.END}")
    if response.status_code == 200:
        body = safe_json(response)
        if body is None:
            exit(1)
        print(f"{Colors.GREEN}{json.dumps(body, indent=4)}{Colors.END}")
    else:
        print(f"{Colors.RED}{response.reason}{Colors.END}")
        exit(1)

def check_complete(json:dict, scan_id:str, extra = ""):
    if not isinstance(json, dict):
        json = {}
    status_value = json.get('status', 'Unknown')
    response_scan_id = json.get('scanId', '')
    complete = status_value == "Complete" and scan_id == response_scan_id
    if complete:
        color = Colors.GREEN
    elif status_value == "Processing":
        color = Colors.YELLOW
    else:
        color = Colors.RED
    status = f"\r{color}Scan ID: {response_scan_id or scan_id} {status_value} {extra}{Colors.END}     "
    sys.stdout.write(status)
    sys.stdout.flush()
    return complete

titles = ["Method", "Endpoint", "Category", "Test Type", "CVSS4 Score", "CVSS Rating", "Description"]

def print_scan_report(json:dict,
                      print_summary: bool = True,
                      print_full: bool = False):
    table = Table()
    for v in (json.get('vulnerabilities') or []):
        table.add_vulnerability(v)
    data = table.get_data()

    print("\t")
    if print_summary:
        print("Vulnerability Counts")
        print("--------------------")
        for qual in table.QUALS:
            if qual in table.qual_counts:
                print(summary_row([qual, table.qual_counts[qual]], [10,10]))
        print("--------------------")
        print("\t")
        print("Score Counts")
        print("------------")
        for score in sorted(table.score_counts, reverse=True):
            print(summary_row([score, table.score_counts[score]], [6,6]))
        print("------------")
        print("\t")
    if print_full:
        for i, d in enumerate(data):
            if d[5] == table.QUALS[0] or d[5] == table.QUALS[1]:
                color = Colors.RED
            elif d[5] == table.QUALS[2]:
                color = Colors.YELLOW
            else:
                color = Colors.GREEN
            print(f"{color}{row(d, table.widths)}{Colors.END}")
            if i == 0:
                print(header_line(table.widths))
        print("\t")
    return table

def row(row:list, widths:list):
    return f'{truncate(widths[0],str(row[0])).ljust(widths[0])}|{"|".join(truncate(widths[row.index(x)],str(x)).ljust(widths[row.index(x)]) for x in row if row.index(x) > 0)}'

def summary_row(row:list, widths:list):
    return f'{truncate(widths[0],str(row[0])).ljust(widths[0])}{"|".join(truncate(widths[row.index(x)],str(x)).rjust(widths[row.index(x)]) for x in row if row.index(x) > 0)}'

def header_line(widths:list):
    return f'{"-" * widths[0]}+{"+".join(str("-" * w) for w in widths if widths.index(w) > 0)}'

def truncate(max:int, text:str):
    return text[:max] if len(text) > max else text