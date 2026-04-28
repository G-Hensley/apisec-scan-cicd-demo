# APIsec CI/CD Scanner — Patch Series

Patches applied on top of upstream `daveapisec/cicd:5.1.2.1`. Validated against
the live APIsec API (both populated and 0-vulnerability scan responses) plus a
19-test offline suite.

Source under `cicd-scanner/`. Tests under `cicd-scanner/tests/`. Original image
contents extracted from `daveapisec/cicd:5.1.2.1` via `docker create`.

---

## ⚠️ Breaking change for customer configs

`evaluate_scan` now compares with `>` instead of `>=`. The change is required to
make `INPUT_FAIL_ON_ERROR_THRESHOLD=0` work as customers expect ("fail on any
error"). Side effect: existing customers with `threshold=N` get slightly looser
gating — the value now means "max acceptable findings" rather than "fail at this
exact count."

| Customer's threshold | Old behavior (`>=`) | New behavior (`>`) |
|---|---|---|
| `0` | always fail (latent bug — `0` was silently rewritten to `sys.maxsize`, so the gate **never** triggered) | fail when any vuln exceeds severity floor |
| `1` | fail at 1+ findings | fail at 2+ findings |
| `5` | fail at 5+ findings | fail at 6+ findings |

**Migration note for customer release notes:** *"If you currently use
`INPUT_FAIL_ON_ERROR_THRESHOLD=N` (where N > 0) and want to preserve the exact
old failure behavior, set it to `N-1`. If you use `0`, no action needed — it
now works as documented."*

---

## Other input parsing changes

**`INPUT_APISEC_BASE_URL`** — now validated:
- `https://` required (rejects `http://` with exit 1)
- Trailing `/` stripped
- Empty string rejected

**`INPUT_PRINT_SUMMARY` / `INPUT_PRINT_FULL`** — now parses standard truthy/falsy
values:
- True: `true`, `1`, `yes`, `y`, `on` (case-insensitive)
- False: `false`, `0`, `no`, `n`, `off`, empty string

Previously only the literal `"false"` was treated as False; everything else
(including `0`, `no`, `off`) was True. Customers using non-standard values may
see different behavior — most will see this as a fix, not a regression.

**`INPUT_FAIL_ON_ERROR_THRESHOLD` / `INPUT_FAIL_ON_SEVERITY_THRESHOLD`** —
`0` is now accepted (previously rewrote to `sys.maxsize` with a warning).

---

## Bug fixes (correctness)

| # | Where | What |
|---|---|---|
| 1 | `models.py:_convert_to_integer` | `0` no longer silently disables the gate |
| 2 | `main.py` polling loop | Exits with code 1 on terminal `Failed`/`Cancelled` status (was: looped 1 hour, then silently exited 0) |
| 3 | `models.py:_convert_to_bool` | Standard truthy/falsy parsing |
| 4 | `models.py:_validate_base_url` | Enforces `https://`, strips trailing `/` |
| 5 | `main.py:evaluate_scan` | Skips non-numeric CVSS keys (was: `ValueError` on null `cvssScore`) |
| 6 | `utils.py:row/summary_row/header_line` | Uses `zip()` for column mapping (was: `list.index()`, broken on duplicates) |
| 7 | `table.py:color()` | Default branch returns `Colors.END` (was: `None` → embedded literal "None" in ANSI) |
| 8 | `table.py:add_vulnerability` | Defensive `.get()` for all nested fields |
| 9 | `utils.py:print_scan_report` | `.get('vulnerabilities') or []` |
| 10 | `table.py:width` | Returns `len(title)` for empty columns (was: `ValueError: max() arg is empty` on 0-vuln scans — the original known bug) |

## Robustness (HTTP / response handling)

| # | Where | What |
|---|---|---|
| 11 | `scanner.py` | `(connect=10s, read=60s)` timeout on every request (was: unbounded — could hang to GH job-level timeout) |
| 12 | `scanner.py` | `urllib3.Retry`: 5 attempts with exp backoff on 502/503/504, honors `Retry-After` |
| 13 | `scanner.py` | Shared `requests.Session` with auth + UA + Accept set once |
| 14 | `utils.py:safe_json` | Non-JSON responses return `None` and log a snippet (was: `JSONDecodeError` traceback) |
| 15 | `utils.py:check_complete` | Defensive `.get()` on `status` and `scanId` |
| 16 | `main.py` polling loop | Aborts on 4xx (clear HTTP code) or exhausted 5xx retries |
| 17 | `main.py` auto path | `init` body shape guarded — missing `scanId` exits with clear error |

## Diagnostics

| # | Where | What |
|---|---|---|
| 18 | `utils.py:print_response` | Prints response body on non-200 (was: just `response.reason` — "Bad Request" alone with no detail) |

## Security / privacy

| # | Where | What |
|---|---|---|
| 19 | `scanner.py:init()` | Removed `print(request_url)` — no longer logs the URL with embedded `application_id`/`instance_id` |
| 20 | `scanner.py` | Sets `User-Agent: apisec-cicd/<version>` (was: default `python-requests/X`) |

---

## Test coverage

All under `cicd-scanner/tests/`:

**Unit (`test_robustness.py` — 11 assertions, in-process mock):**
- `safe_json` on non-JSON 200
- `check_complete` on missing `status`, empty dict
- `add_vulnerability` survives null `cvssScore`, missing `testStatus`/`testDetails`
- `evaluate_scan` skips non-numeric score keys, exits 1 on real critical
- `Scanner` retries 502 → 200, returns 404 unretried
- `Session` headers (Authorization, User-Agent) set
- `init()` no longer prints request URL
- Connect timeout: unreachable host errors out within 180s

**E2E (`run_e2e.sh` + HTTPS sidecar `mock_server.py` — 8 scenarios):**
- `happy-1-critical-fail` → exit 1
- `happy-1-critical-pass` → exit 0 (high threshold)
- `zero-vulns` → exit 0
- `failed-status` → exit 1 with "terminal state: Failed"
- `init-no-scanid` → exit 1 with clear message
- `poll-404` → exit 1 with "HTTP 404"
- `flaky-502-recovers` → retries succeed, exit 1 on findings
- `http-base-url-rejected` → exit 1 with "must use https://"

**Real-API (validated in this repo's GitHub Actions):**
- 6-finding scan against full app → polls 138s, prints summary, exit 1 (matches upstream behavior on identical data)
- 0-finding scan with minimal OAS → polls 116s, prints empty headers/dividers, exit 0 (the original known bug fixed end-to-end)
- 400 from APIsec on unreachable instance → prints body with actionable error message

---

## How to run the tests

```bash
# Unit
docker build -t apisec-cicd:test cicd-scanner/
docker run --rm -v "$PWD/cicd-scanner/tests:/test:ro" \
  --workdir /apisec --entrypoint sh apisec-cicd:test \
  -c 'python3 /test/test_robustness.py'

# E2E
IMAGE=apisec-cicd:test bash cicd-scanner/tests/run_e2e.sh
```

CI also runs both via `.github/workflows/scanner-tests.yml` on any change to
`cicd-scanner/**`.

---

## File diff vs upstream `daveapisec/cicd:5.1.2.1`

Modified: `main.py`, `models.py`, `scanner.py`, `table.py`, `utils.py`.
Unchanged: `colors.py`, `__init__.py`.
Lockfile: `poetry.lock` regenerated by Poetry during build (no manual changes).

The upstream image's structure is preserved — same `WORKDIR /apisec`, same
`CMD ["./main.py"]`, same Python 3.13 + Poetry layering.

---

## Recommended versioning

**`5.2.0`** — minor bump signals the threshold operator change as breaking-ish.
Customers should be notified in release notes. If conservative framing is
preferred, `5.1.3` works but the threshold change still needs explicit
communication.

## Recommended rollout

1. Tag image as `daveapisec/cicd:5.2.0`.
2. Notify customers about the threshold operator change (migration note above).
3. Optionally keep `5.1.2.1` available for bug-for-bug compatibility while
   customers migrate.
4. Customers update their workflow YAML's image tag at their own pace.

## Deferred (worth doing in a follow-up)

- **Image hygiene:** switch base to `python:3.13.13-slim` (1.84 GB → ~300 MB),
  multi-stage build to drop Poetry from runtime, add OCI labels, lock
  `pyyaml`/`python-dotenv` in `pyproject.toml`, run as non-root, pin base by
  digest. Cuts CVE surface significantly.
- **Smoke test job:** schedule a real-API run against a known-clean APIsec
  sandbox application to catch contract drift at the scanner level.
- **Type accuracy:** `models.py:authentication_id` should be `Optional[str]`
  (Copilot review caught — minor, non-functional).
- **Reproducibility nits:** pin `curlimages/curl` in `tests/run_e2e.sh`,
  pin `pip`/`setuptools`/`wheel` versions in Dockerfile.
