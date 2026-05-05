# cicd-latest-fetch — Changelog

## 0.1.0 — initial release

A sibling tool to `cicd-scanner`. Whereas `cicd-scanner` triggers a scan and
polls until it completes, **`cicd-latest-fetch` reads the latest scan
recorded against an application/instance** and applies the same CVSS /
error-count threshold gate without triggering a new scan.

### Use case

CI pipelines that should not pay the 10–30 minute cost of a fresh scan on
every PR. Run scans on a schedule (e.g. nightly), and have PRs gate against
the latest results.

### How "latest" is discovered

The CI access token used by this image **cannot list scans** — the
`GET /v1/applications/{appId}/instances/{instanceId}/scans` endpoint returns
403 for the standard CI token scope. Instead the latest scan id is read off
the application metadata:

1. `GET /v1/applications/{applicationId}` returns the app + each instance
   with a `latestScanStats` object whose `scanId` is the most recent run.
2. The configured `INPUT_INSTANCE_ID` is matched against `instances[]` and
   `latestScanStats.scanId` is extracted.
3. `GET /v1/applications/{appId}/instances/{instanceId}/scans/{scanId}` is
   called with `nextToken` pagination to collect every page of findings.
4. The combined findings are run through the same CVSS-floor / error-count
   gate as `cicd-scanner`.

### Trade-off vs. a list endpoint

Without a list endpoint, this tool can only see whatever the API tells it
is "latest." If the most recent scan is `Processing` or `Failed`, the gate
exits 1 with a clear message — there is no fallback to the next-most-recent
Completed scan. The customer's scheduled-scan cadence must therefore avoid
overlapping with PR runs, or accept that PRs may briefly be blocked while a
scheduled scan is in progress.

### Inputs (env vars)

Identical to `cicd-scanner` minus `INPUT_AUTHENTICATION_ID` (no scans are
triggered, so no auth profile is needed).

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
| 0 | Latest scan is Complete and passes the gate |
| 1 | Gate failed, OR `GET /applications/{id}` returned non-2xx (auth, 404, 5xx exhausted), OR configured instance not found, OR `latestScanStats` is null, OR latest scan is not yet `Complete`, OR the detail fetch returned non-2xx |

### Pagination

Scan-detail findings follow `nextToken` pagination. Hard cap:

- `MAX_PAGINATION_PAGES = 100`. If hit, a yellow warning is printed and the
  gate proceeds with what was collected (we'd rather flag a partial result
  than fail closed when the API misbehaves).

### Tests

`tests/test_robustness.py` runs in-process against an HTTP mock. 20
assertions covering:

- Shared utility behaviour (`safe_json`, `Table.add_vulnerability` drift)
- Scanner session headers, retries, 404 pass-through
- `Scanner.get_application()` round-trip
- `Scanner.scan(next_token=...)` pagination
- `find_instance` — match, miss, missing `instances` key
- `collect_all_findings` walks detail pagination
- `run()` integration:
    - Happy path: latestScanStats → Complete with Critical → exit 1
    - Paginated findings → exit 1 across pages
    - `latestScanStats: null` → exit 1
    - Configured instance not in app → exit 1
    - Latest scan is `Processing` → exit 1 with state name
    - 403 from application endpoint → exit 1 with HTTP code

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

`colors.py`, `table.py`, `utils.py` are intentionally duplicated from
`cicd-scanner/`. The two images publish on independent cadences and
duplicating four small files is cheaper than introducing a shared package.
If a bug fix needs to land in both, propagate manually.
