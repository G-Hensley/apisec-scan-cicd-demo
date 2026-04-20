# APIsec CI/CD Demo — FastAPI on Railway

A demo FastAPI target deployed to Railway. A GitHub Actions workflow runs an APIsec security scan against the live URL on every push to `main`, every PR, weekly on a schedule, and on-demand via the Actions tab. Findings upload as SARIF and appear in the GitHub **Security** tab.

---

## Prerequisites

- [Railway](https://railway.com/) account
- GitHub repo with Actions enabled
- APIsec account — login email + password, and a **Project** configured (see Step 2)

---

## 1. Deploy to Railway

Easiest path — **web UI** (no CLI required):

1. Push this repo to GitHub (Step 3).
2. Go to https://railway.com/new → **Deploy from GitHub repo** → authorize + pick the repo.
3. Railway auto-detects the `Dockerfile` and deploys.
4. In the service → **Settings → Networking → Generate Domain**.
5. Verify:
   ```bash
   curl https://<your-railway-domain>/healthz
   # Expected: {"status":"ok"}
   ```

> Railway injects the `PORT` environment variable automatically. The Dockerfile honors it via `$PORT`.

**CLI alternative** (once Railway CLI is installed):
```bash
railway login
railway init
railway up
railway domain
```

---

## 2. Register the Project in APIsec

1. Log in to `https://[your-tenant].apisecapps.com`.
2. Create a **Project** — give it a descriptive name (e.g., `run-scan-test`). **Remember this name** — you'll enter it as a GitHub variable in Step 3.
3. Set the Target URL to your Railway public domain:
   ```
   https://<your-railway-domain>
   ```
4. Upload the OpenAPI spec:
   ```bash
   curl https://<your-railway-domain>/openapi.json -o openapi.json
   ```
   Upload `openapi.json` via the Project configuration UI.
5. Confirm you can log in with the same email + password you'll use in CI — the GitHub Action authenticates as that user.

---

## 3. Configure GitHub

Push the repo to GitHub if you haven't already:

```bash
git init
git add .
git commit -m "feat: initial APIsec scan demo"
git remote add origin https://github.com/<your-org>/<your-repo>.git
git branch -M main
git push -u origin main
```

Then add credentials:

**Settings → Secrets and variables → Actions**

Add 2 **Secrets** (sensitive):

| Secret name | Value |
|---|---|
| `APISEC_USERNAME` | Your APIsec login email |
| `APISEC_PASSWORD` | Your APIsec login password |

Add 1 **Variable** (non-sensitive):

| Variable name | Value |
|---|---|
| `APISEC_PROJECT` | Project name from Step 2 (e.g., `run-scan-test`) |

> If `APISEC_PROJECT` is unset the workflow falls back to `run-scan-test`.

---

## 4. Trigger the Scan

**Automatically:** Push any commit to `main` or open a PR targeting `main`. A weekly scheduled scan also runs Thursdays at 19:21 UTC.

**Manually (demo mode):** **Actions → APIsec → Run workflow**. No code change required.

---

## 5. Read the Results

Three places to look:

1. **Actions tab** — expand the `Trigger_APIsec_scan` job to see scan progress and the APIsec scan summary.
2. **Security tab → Code scanning** — SARIF-uploaded findings appear here, grouped by rule, with affected files highlighted. This is the best customer-facing view.
3. **APIsec dashboard** — click through to your Project for the full scan record with remediation guidance:
   ```
   https://[your-tenant].apisecapps.com
   ```

The workflow fails (red) if the scan surfaces findings that breach your APIsec project's configured thresholds. Otherwise it passes (green) and the next pipeline step continues.

---

## 6. Troubleshooting

**APIsec can't reach the target URL**
- Confirm the Railway domain is public and returns `{"status":"ok"}` on `/healthz`
- Test from your machine: `curl https://<your-railway-domain>/healthz`

**`401 Unauthorized` during scan start**
- `APISEC_USERNAME` or `APISEC_PASSWORD` secret is wrong or expired
- Log in to the APIsec UI with those credentials to confirm they work, then update the GitHub secret

**Project not found**
- `APISEC_PROJECT` variable must exactly match the Project name in the APIsec dashboard (case-sensitive, no trailing spaces)

**Scan starts but no endpoints scanned**
- The Project in APIsec is missing its OpenAPI spec — re-upload from `https://<your-railway-domain>/openapi.json`
- The Target URL on the Project doesn't match the live Railway domain

**SARIF upload step fails on private repo**
- Add `actions: read` to the job-level `permissions` block (already set in the provided workflow)

---

## What's in this repo

| Path | Purpose |
|---|---|
| `app/` | FastAPI source (auth, users, products, orders, health) |
| `tests/` | pytest suite hitting `TestClient` |
| `pyproject.toml` / `uv.lock` | `uv`-managed deps, locked for reproducible builds |
| `Dockerfile` | Production image, runs `uvicorn` on `$PORT` |
| `railway.json` | Railway builder + healthcheck config |
| `.github/workflows/apisec-scan.yml` | GitHub Action — runs `apisec-inc/apisec-run-scan@v1.0.7`, uploads SARIF |
