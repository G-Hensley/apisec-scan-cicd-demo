import json
import sys

import requests
from colors import Colors
from table import Table

ACTIVE_STATUS = "ACTIVE"


def safe_json(response: requests.Response):
    try:
        return response.json()
    except (ValueError, json.JSONDecodeError):
        snippet = (response.text or "")[:200].replace("\n", " ")
        print(f"{Colors.RED}Non-JSON response (HTTP {response.status_code}): {snippet}{Colors.END}")
        return None


def print_response(response: requests.Response):
    print(f"{Colors.YELLOW}HTTP {response.status_code}{Colors.END}")
    if response.status_code == 200:
        body = safe_json(response)
        if body is None:
            sys.exit(1)
        print(f"{Colors.GREEN}{json.dumps(body, indent=4)}{Colors.END}")
    else:
        print(f"{Colors.RED}{response.reason}{Colors.END}")
        body = safe_json(response)
        if body is not None:
            print(f"{Colors.RED}{json.dumps(body, indent=4)}{Colors.END}")
        else:
            snippet = (response.text or "")[:500]
            if snippet:
                print(f"{Colors.RED}{snippet}{Colors.END}")
        sys.exit(1)


def print_detection_report(body: dict,
                           print_summary: bool = True,
                           print_full: bool = False):
    """Walk the /detections envelope and build a Table of ACTIVE findings only.

    Non-active statuses (DISMISSED / RISK_ACCEPTED / RESOLVED) are skipped —
    they exist in the response but do not count toward the gate.
    """
    table = Table()
    if not isinstance(body, dict):
        body = {}
    for group in (body.get('detections') or []):
        if not isinstance(group, dict):
            continue
        category_name = (group.get('category') or {}).get('name', '')
        test_name = (group.get('test') or {}).get('name', '')
        data = group.get('data') or {}
        for det in (data.get('vulnerabilities') or []):
            if not isinstance(det, dict):
                continue
            if det.get('status') != ACTIVE_STATUS:
                continue
            table.add_detection(det, category_name, test_name)

    data = table.get_data()

    print("\t")
    if print_summary:
        print("Vulnerability Counts")
        print("--------------------")
        for qual in table.QUALS:
            if qual in table.qual_counts:
                print(summary_row([qual, table.qual_counts[qual]], [10, 10]))
        print("--------------------")
        print("\t")
        print("Score Counts")
        print("------------")
        for score in sorted(table.score_counts, reverse=True):
            print(summary_row([score, table.score_counts[score]], [6, 6]))
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


def row(row: list, widths: list):
    head = truncate(widths[0], str(row[0])).ljust(widths[0])
    tail = "|".join(
        truncate(w, str(c)).ljust(w) for c, w in zip(row[1:], widths[1:], strict=False)
    )
    return f'{head}|{tail}'


def summary_row(row: list, widths: list):
    head = truncate(widths[0], str(row[0])).ljust(widths[0])
    tail = "|".join(
        truncate(w, str(c)).rjust(w) for c, w in zip(row[1:], widths[1:], strict=False)
    )
    return f'{head}{tail}'


def header_line(widths: list):
    return f'{"-" * widths[0]}+{"+".join("-" * w for w in widths[1:])}'


def truncate(max: int, text: str):
    return text[:max] if len(text) > max else text
