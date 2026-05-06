# cicd-latest-fetch — Changelog

## 0.2.1 — defensive pagination + truncation warning

The /detections endpoint is not documented as paginated, but a tenant
with enough findings to trip a server-side cap shouldn't silently get a
partial gate. This release adds two safety nets:

- **`nextToken` walk.** If the response ever includes a top-level
  `nextToken`, `Scanner.get_detections(next_token=...)` is called to
  fetch the next page. `MAX_PAGINATION_PAGES = 100` caps the loop. If
  no `nextToken` ever appears (current observed behaviour), this
  is a no-op.
- **Completeness check.** After all pages are merged,
  `metadata.totalActiveVulnerabilities` is compared to the count of
  ACTIVE findings actually received. If the API reports more than we
  got, a yellow warning is printed naming both numbers — the gate
  still runs against what was received, but the discrepancy is loud
  enough to spot in CI logs.

Tests cover both: a `detections-truncated` scenario where metadata
claims 5 active vulns but only 1 is in the body (warning fires), and a
`detections-paginated` scenario that walks two pages and counts both
findings before evaluating.

## 0.2.0 — pivot to /detections

Replaced the application-metadata + scan-detail flow with a single
`GET /v1/applications/{appId}/instances/{instanceId}/detections` call. The
former approach assumed `latestScanStats.scanId` existed in the application
response; per the Postman collection (v1.3, April 14 2026) it does not —
`latestScanStats` only carries `scanDate`, `percentEndpointsVulnerable`, and
severity-bucket counters. There is no documented endpoint to discover the
latest scan id after the fact, so the gate now reads the *current detection
state* instead.

### Behaviour

1. `GET /v1/applications/{appId}/instances/{instanceId}/detections?include=metadata&slim=true`
   returns every detection on the instance, grouped by `category` / `test`,
   with per-finding `status` and `testResult.cvssScore`.
2. Findings are filtered to `status == "ACTIVE"`. DISMISSED, RISK_ACCEPTED,
   and RESOLVED detections appear in the response but are **not counted**
   toward the gate — they're explicit "do not gate on this" markers.
3. The remaining ACTIVE findings run through the same CVSS-floor /
   error-count threshold gate as `cicd-scanner`.

### Trade-off vs. scan-id discovery

This image used to refuse to gate when the latest scan was `Processing` or
`Failed`. The detections endpoint has no scan-state concept — it returns
whatever the most recent completed scan produced, plus any persistent state
from prior scans (resolutions, risk-accepted markers, dismissals). If a
fresh scan is currently in flight, the gate runs against the previous
scan's state. That matches the demo intent: "gate PRs against the latest
known findings," not "gate PRs against an in-progress scan."

If no scan has ever completed for the instance, the API returns
`detections: []` and the gate passes. There is no way to distinguish
"clean" from "never scanned" with this endpoint alone — operators are
expected to ensure at least one scan has run before relying on the gate.

### Inputs (env vars)

Identical to before.

| Variable | Required | Default |
|---|---|---|
| `INPUT_APPLICATION_ID` | yes | — |
| `INPUT_INSTANCE_ID` | yes | — |
| `INPUT_ACCESS_TOKEN` | yes | — |
| `INPUT_APISEC_BASE_URL` | no | `https://api.apisecapps.com` (https-only, validated) |
| `INPUT_FAIL_ON_SEVERITY_THRESHOLD` | no | `sys.maxsize` (effectively never fail) |
| `INPUT_FAIL_ON_ERROR_THRESHOLD` | no | `sys.maxsize` |
| `INPUT_PRINT_SUMMARY` | no | `false` |
| `INPUT_PRINT_FULL` | no | `false` |

### Exit codes

| Exit | Reason |
|---|---|
| 0 | No ACTIVE findings exceed the gate |
| 1 | Gate failed, OR `GET /detections` returned non-2xx (auth, 404, 5xx exhausted) |

### Tests

`tests/test_robustness.py` runs in-process against an HTTP mock. 17
assertions covering:

- Shared utilities (`safe_json`, `Table.add_detection` drift)
- Scanner session headers, retries, 404 pass-through
- `Scanner.get_detections()` round-trip
- `run()` integration:
    - 1 ACTIVE Critical → exit 1
    - empty `detections: []` → exit 0
    - all RESOLVED → exit 0
    - mixed statuses (ACTIVE / RISK_ACCEPTED / DISMISSED) — only ACTIVE counts
    - 3 ACTIVE Highs above error threshold → exit 1
    - 3 ACTIVE Highs within error threshold → exit 0
    - 403 from detections endpoint → exit 1
    - 404 from detections endpoint → exit 1

Run inside the image:

```bash
docker build -t apisec-cicd-latest-fetch:test cicd-latest-fetch/
docker run --rm \
  -v "$PWD/cicd-latest-fetch/tests:/test:ro" \
  --workdir /apisec --entrypoint sh \
  apisec-cicd-latest-fetch:test \
  -c 'python3 /test/test_robustness.py'
```

### Sharing with cicd-scanner

`colors.py`, `table.py`, `utils.py` were intentionally duplicated from
`cicd-scanner/`. With this pivot the two diverge — `cicd-latest-fetch`
operates on the `/detections` envelope shape (`detections[].data.vulnerabilities[]`),
while `cicd-scanner` still operates on the scan-body shape
(`vulnerabilities[].scanFindings[]`). The duplication is no longer just
copy-paste — they're independently maintained.

## 0.1.0 — initial release (superseded)

Sibling tool to `cicd-scanner` for reading the latest scan without
triggering a new one. Original implementation walked
`GET /v1/applications/{id}` → `latestScanStats.scanId` →
`GET /v1/applications/{id}/instances/{id}/scans/{scanId}` with `nextToken`
pagination. Replaced in 0.2.0 — see above.
