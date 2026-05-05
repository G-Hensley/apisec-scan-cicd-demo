# cicd-latest-fetch — Changelog

## 0.1.0 — initial release

A sibling tool to `cicd-scanner`. Whereas `cicd-scanner` triggers a scan and
polls until it completes, **`cicd-latest-fetch` reads the most recent
Completed scan that already exists** for a given application/instance, then
applies the same CVSS / error-count threshold gate.

### Use case

CI pipelines that should not pay the 10–30 minute cost of a fresh scan on
every PR. Run scans on a schedule (e.g. nightly), and have PRs gate against
the latest results.

### Behaviour

1. `GET /v1/applications/{app}/instances/{inst}/scans` — lists scans.
   Walks `nextToken` pagination if present. Hard-capped at 100 pages.
2. Picks the most recent scan whose `status == "Complete"`. If the very
   latest scan is `Processing` or `Failed`, falls back to the next most
   recent Completed one. Recency is determined by `lastUpdateTime`,
   falling back to `startTime`.
3. `GET /scans/{scanId}` for the chosen scan, walking `nextToken` for the
   findings list.
4. Counts findings ≥ `INPUT_FAIL_ON_SEVERITY_THRESHOLD` and exits 1 if the
   count exceeds `INPUT_FAIL_ON_ERROR_THRESHOLD`.

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
| 0 | Latest Complete scan passes the gate |
| 1 | Gate failed, OR no scans exist, OR no Completed scans available, OR API returned non-2xx |

### Pagination

Both the list endpoint and the scan-detail endpoint follow `nextToken`
pagination. Caps:

- `MAX_PAGINATION_PAGES = 100` for both. If the cap is hit, a yellow warning
  is printed and the gate proceeds with what was collected (intentional —
  we'd rather flag a partial result than fail closed when the API misbehaves).

### Tests

`tests/test_robustness.py` runs in-process against an HTTP mock. 21
assertions covering:

- Shared utility behaviour (`safe_json`, `Table.add_vulnerability` drift)
- Scanner session headers, retries, 404 pass-through
- `Scanner.scans(next_token=...)` and `Scanner.scan(next_token=...)`
- `pick_latest_complete` — empty, none-Complete, latest-is-Processing,
  multiple-Completes
- `collect_all_scans` walks list pagination
- `collect_all_findings` walks detail pagination
- `run()` integration: happy path, no scans, no Completed scan, list
  pagination winner

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
