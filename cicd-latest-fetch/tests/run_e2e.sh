#!/usr/bin/env bash
# E2E test runner. Spins up an HTTPS mock APIsec, then runs the scanner
# image against each scenario and asserts exit code + stdout pattern.
#
# Usage: IMAGE=apisec-cicd:5.1.2.1-fix3 ./tests/run_e2e.sh
set -uo pipefail

IMAGE="${IMAGE:-apisec-cicd:5.1.2.1-fix3}"
NETWORK="apisec-test-$$"
MOCK_NAME="apisec-mock-$$"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CERT_DIR="${SCRIPT_DIR}/certs"

cleanup() {
  docker rm -f "$MOCK_NAME" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# 1. Self-signed cert (CN=mock, SAN includes mock + localhost)
mkdir -p "$CERT_DIR"
if [[ ! -f "$CERT_DIR/cert.pem" ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
    -days 1 -subj "/CN=mock" \
    -addext "subjectAltName=DNS:mock,DNS:localhost,IP:127.0.0.1" \
    >/dev/null 2>&1
  echo "Generated self-signed cert: $CERT_DIR/cert.pem"
fi

# 2. Network + mock sidecar (uses python:3.13-slim, stdlib only)
docker network create "$NETWORK" >/dev/null
docker run -d --rm --name "$MOCK_NAME" \
  --network "$NETWORK" --network-alias mock \
  -v "$SCRIPT_DIR:/work:ro" -v "$CERT_DIR:/certs:ro" \
  -w /work \
  python:3.13-slim python /work/mock_server.py >/dev/null

# Wait for mock readiness (max ~10s)
for i in $(seq 1 50); do
  if docker run --rm --network "$NETWORK" \
    -v "$CERT_DIR:/certs:ro" \
    --entrypoint sh curlimages/curl:latest \
    -c "curl -sf --cacert /certs/cert.pem https://mock:8443/v1/applications/x/instances/x/scan -X POST -d '{}' -H 'Content-Type: application/json' >/dev/null" 2>/dev/null; then
    break
  fi
  sleep 0.2
done

# 3. Run a scenario. $1=name, $2=expected exit, $3=stdout pattern, $@=extra env vars
PASS=0
FAIL=0
run_scenario() {
  local name="$1" expected_exit="$2" pattern="$3"; shift 3
  local extra_env=("$@")

  local out
  out=$(docker run --rm --network "$NETWORK" \
    -v "$CERT_DIR:/certs:ro" \
    -e REQUESTS_CA_BUNDLE=/certs/cert.pem \
    -e INPUT_APPLICATION_ID="$name" \
    -e INPUT_INSTANCE_ID="inst" \
    -e INPUT_ACCESS_TOKEN="dummy-token" \
    -e INPUT_APISEC_BASE_URL="https://mock:8443" \
    -e INPUT_FAIL_ON_SEVERITY_THRESHOLD=8 \
    "${extra_env[@]}" \
    "$IMAGE" 2>&1)
  local actual_exit=$?

  local exit_ok="ok"; [[ "$actual_exit" -ne "$expected_exit" ]] && exit_ok="MISMATCH"
  local pattern_ok="ok";
  if [[ -n "$pattern" ]] && ! grep -qE "$pattern" <<< "$out"; then
    pattern_ok="MISSING"
  fi

  if [[ "$exit_ok" == "ok" && "$pattern_ok" == "ok" ]]; then
    PASS=$((PASS+1))
    printf "  ✓ %-32s exit=%d\n" "$name" "$actual_exit"
  else
    FAIL=$((FAIL+1))
    printf "  ✗ %-32s exit=%d (want %d, %s) pattern=%s\n" \
      "$name" "$actual_exit" "$expected_exit" "$exit_ok" "$pattern_ok"
    echo "----- output -----"
    echo "$out" | sed 's/^/    /'
    echo "------------------"
  fi
}

echo
echo "Running E2E scenarios against $IMAGE"

# threshold=0 means "fail on any" with the > comparator
run_scenario "happy-1-critical-fail"   1 "API scan failed" \
  -e INPUT_FAIL_ON_ERROR_THRESHOLD=0
run_scenario "happy-1-critical-pass"   0 "API scan passed" \
  -e INPUT_FAIL_ON_ERROR_THRESHOLD=10
run_scenario "zero-vulns"              0 "API scan passed" \
  -e INPUT_FAIL_ON_ERROR_THRESHOLD=0
run_scenario "failed-status"           1 "terminal state: Failed" \
  -e INPUT_FAIL_ON_ERROR_THRESHOLD=0
run_scenario "init-no-scanid"          1 "did not include scanId" \
  -e INPUT_FAIL_ON_ERROR_THRESHOLD=0
run_scenario "poll-404"                1 "HTTP 404" \
  -e INPUT_FAIL_ON_ERROR_THRESHOLD=0
run_scenario "flaky-502-recovers"      1 "API scan failed" \
  -e INPUT_FAIL_ON_ERROR_THRESHOLD=0

# This one doesn't need the mock — validation rejects http:// scheme before any request.
echo
echo "Running validation-only scenarios"
out=$(docker run --rm \
  -e INPUT_APPLICATION_ID=x -e INPUT_INSTANCE_ID=x -e INPUT_ACCESS_TOKEN=t \
  -e INPUT_APISEC_BASE_URL="http://attacker.example" \
  "$IMAGE" 2>&1)
actual_exit=$?
if [[ "$actual_exit" -eq 1 ]] && grep -q "must use https://" <<< "$out"; then
  PASS=$((PASS+1)); echo "  ✓ http-base-url-rejected             exit=1"
else
  FAIL=$((FAIL+1)); echo "  ✗ http-base-url-rejected exit=$actual_exit"
  echo "$out" | sed 's/^/    /'
fi

echo
echo "E2E results: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
