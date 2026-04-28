"""APIsec scan target — STUBBED to /healthz only.

Temporary minimal version used to verify the patched scanner's 0-vuln
output path against the live APIsec API. The original full app is
preserved in git history; revert this commit to restore.
"""

from fastapi import FastAPI

app = FastAPI(
    title="APIsec Scan Target (stub)",
    description="Minimal scan target with a single liveness endpoint.",
    version="0.1.0-stub",
)


@app.get("/healthz", tags=["health"])
def healthz() -> dict[str, str]:
    return {"status": "ok"}
