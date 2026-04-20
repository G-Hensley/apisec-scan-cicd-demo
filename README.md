# APIsec CI/CD Demo — FastAPI on Railway

A demo FastAPI target deployed to Railway. A GitHub Actions workflow runs an APIsec security scan against the live URL on every push to `main`, every PR, and on-demand via the Actions tab.

---

## Prerequisites

- [Railway account](https://railway.app/) with a project
- [Railway CLI](https://docs.railway.app/guides/cli): `npm install -g @railway/cli`
- GitHub repo with Actions enabled
- APIsec account with at least one Application and a generated API token

---

## 1. Deploy to Railway

```bash
# Authenticate
railway login

# Initialize project (run from repo root — select "Empty Project" if prompted)
railway init

# Deploy the app
railway up

# Generate a public domain
railway domain
```

Verify the deployment is live:

```bash
curl https://<your-railway-domain>/healthz
# Expected: {"status":"ok"}
```

> Railway injects the `PORT` environment variable automatically. The Dockerfile and app honor it via `$PORT`.

---

## 2. Register the App in APIsec

1. Log in to `https://[your-tenant].apisecapps.com`
2. Create an **Application** — give it a descriptive name (e.g., `demo-fastapi`)
3. Under that Application, create an **Instance** — set the Target URL to your Railway public domain:
   ```
   https://<your-railway-domain>
   ```
4. Upload the OpenAPI spec to the Instance:
   ```bash
   curl https://<your-railway-domain>/openapi.json -o openapi.json
   ```
   Then upload `openapi.json` via the Instance configuration UI.
5. Grab your IDs from the dashboard URL — navigate to your Instance and look at the URL:
   ```
   https://[your-tenant].apisecapps.com/application/[APP_ID]/instance/[INSTANCE_ID]
   ```
6. Grab your **Access Token**: APIsec dashboard → top-right menu → **API Token**

---

## 3. Configure GitHub

Push the repo to GitHub if you haven't already:

```bash
git remote add origin https://github.com/<your-org>/<your-repo>.git
git push -u origin main
```

Then add secrets and variables:

**Settings → Secrets and variables → Actions**

Add 3 secrets (sensitive — use the "Secrets" tab):

| Secret name | Value |
|---|---|
| `APISEC_APPLICATION_ID` | `[APP_ID]` from the dashboard URL |
| `APISEC_INSTANCE_ID` | `[INSTANCE_ID]` from the dashboard URL |
| `APISEC_ACCESS_TOKEN` | Token from the APIsec API Token menu |

Add 2 variables (optional — use the "Variables" tab, these have safe defaults):

| Variable name | Default | Description |
|---|---|---|
| `APISEC_SEVERITY_THRESHOLD` | `8` | Min CVSS score that counts toward failure |
| `APISEC_ERROR_THRESHOLD` | `0` | Max qualifying findings before build fails |

---

## 4. Trigger the Scan

**Automatically:** Push any commit to `main` or open a PR targeting `main`.

**Manually (demo mode):** Go to **Actions → APIsec API Security Scan → Run workflow** and click **Run workflow**. No code change needed.

---

## 5. Read the Results

Open the workflow run in the **Actions** tab and expand the **Run APIsec CI/CD Security Scan** step.

You will see two sections in the log:

- **Summary table** — one row per finding: endpoint, method, vulnerability category, CVSS score, severity
- **Full report** (`INPUT_PRINT_FULL=true`) — detailed finding descriptions for each issue

The step exits `0` (green) if findings are within thresholds, `1` (red) if they exceed thresholds.

For the full scan result with remediation guidance, click through to the APIsec dashboard:

```
https://[your-tenant].apisecapps.com/application/[APP_ID]/instance/[INSTANCE_ID]
```

---

## 6. Troubleshooting

**APIsec can't reach the target URL**
- Confirm `railway domain` output shows a public `*.up.railway.app` URL (not a private internal hostname)
- Test manually: `curl https://<your-railway-domain>/healthz` from your machine

**401 from APIsec / scan won't start**
- The `APISEC_ACCESS_TOKEN` secret may be expired or rotated
- Generate a new token: APIsec dashboard → API Token menu → regenerate
- Update the GitHub secret: Settings → Secrets and variables → Actions → `APISEC_ACCESS_TOKEN` → Update

**Scan starts but never completes**
- Check that the Instance target URL in APIsec exactly matches your Railway domain (no trailing slash, correct protocol)
- Verify the OpenAPI spec was uploaded to the Instance — without it, APIsec has no endpoints to scan
- Check the Instance configuration in the APIsec dashboard for validation errors

**Workflow fails immediately (Docker pull error)**
- Transient DockerHub rate limit — re-run the workflow from the Actions tab
