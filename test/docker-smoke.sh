#!/usr/bin/env bash
# End-to-end smoke test for the steampipe-mcp Docker image (Task 9).
#
# Builds the image, runs it alongside a plain postgres:16 container on a
# user-defined network, and exercises it the way a real client would: over
# HTTP, through the published port, with no access to source or test code.
#
#   1. builds the image
#   2. starts postgres:16 and the image on a docker network, AUTH_MODE=token
#   3. waits for the image's HEALTHCHECK to report healthy
#   4. POSTs initialize then tools/list with the bearer token, asserts 5 tools
#   5. asserts the same POST without the token gets 401
#   6. asserts AUTH_MODE unset exits non-zero, message names ALLOW_INSECURE_REMOTE
#   7. times `docker stop` on the running container (graceful-shutdown check)
#   8. cleans up containers/network in a trap
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

RUN_ID="$$"
IMAGE_TAG="steampipe-mcp:smoke-test"
NETWORK="steampipe-mcp-smoke-net-${RUN_ID}"
PG_CONTAINER="steampipe-mcp-smoke-pg-${RUN_ID}"
MCP_CONTAINER="steampipe-mcp-smoke-mcp-${RUN_ID}"
NOAUTH_CONTAINER="steampipe-mcp-smoke-noauth-${RUN_ID}"
HOST_PORT=27199
# Exactly 40 hex characters (20 random bytes), as required by AUTH_TOKEN >= 32 chars.
TOKEN="$(head -c 20 /dev/urandom | od -An -tx1 | tr -d ' \n')"

PASS=0
FAIL=0

log() { echo "--- $* ---"; }

ok() {
  echo "PASS: $*"
  PASS=$((PASS + 1))
}

bad() {
  echo "FAIL: $*"
  FAIL=$((FAIL + 1))
}

cleanup() {
  log "cleanup"
  docker rm -f "$MCP_CONTAINER" "$NOAUTH_CONTAINER" "$PG_CONTAINER" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT

log "building image"
docker build -t "$IMAGE_TAG" "$REPO_ROOT"

log "creating network"
docker network create "$NETWORK" >/dev/null

log "starting postgres:16"
docker run -d --name "$PG_CONTAINER" --network "$NETWORK" \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=postgres \
  postgres:16 >/dev/null

log "waiting for postgres to accept connections"
pg_ready=false
for _ in $(seq 1 30); do
  if docker exec "$PG_CONTAINER" pg_isready -U postgres >/dev/null 2>&1; then
    pg_ready=true
    break
  fi
  sleep 1
done
if [ "$pg_ready" != "true" ]; then
  bad "postgres never became ready"
  exit 1
fi
ok "postgres is ready"

log "starting mcp image (AUTH_MODE=token)"
# A plain postgres:16 container on a docker network has no TLS, and the mcp
# image's target host ("$PG_CONTAINER") is not loopback, so the connection
# string must opt out of certificate verification with sslmode=disable.
docker run -d --name "$MCP_CONTAINER" --network "$NETWORK" -p "${HOST_PORT}:27123" \
  -e STEAMPIPE_MCP_AUTH_MODE=token \
  -e STEAMPIPE_MCP_AUTH_TOKEN="$TOKEN" \
  -e STEAMPIPE_MCP_WORKSPACE_DATABASE="postgresql://postgres:postgres@${PG_CONTAINER}:5432/postgres?sslmode=disable" \
  "$IMAGE_TAG" >/dev/null

log "waiting for the container HEALTHCHECK to report healthy"
healthy=false
for _ in $(seq 1 30); do
  status="$(docker inspect --format='{{.State.Health.Status}}' "$MCP_CONTAINER" 2>/dev/null || echo "")"
  if [ "$status" = "healthy" ]; then
    healthy=true
    break
  fi
  sleep 1
done
if [ "$healthy" != "true" ]; then
  bad "mcp container never became healthy (last status: ${status:-unknown})"
  docker logs "$MCP_CONTAINER" || true
  exit 1
fi
ok "mcp container is healthy"

MCP_URL="http://127.0.0.1:${HOST_PORT}/mcp"
INIT_BODY='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"docker-smoke-test","version":"1.0.0"}}}'
TOOLS_LIST_BODY='{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

log "initialize with bearer token"
init_response="$(curl -sS -w '\n%{http_code}' "$MCP_URL" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H "Authorization: Bearer ${TOKEN}" \
  -d "$INIT_BODY")"
init_status="$(echo "$init_response" | tail -n1)"
if [ "$init_status" = "200" ]; then
  ok "initialize returned 200"
else
  bad "initialize returned ${init_status}, expected 200"
fi

log "tools/list with bearer token"
list_response="$(curl -sS -w '\n%{http_code}' "$MCP_URL" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H "Authorization: Bearer ${TOKEN}" \
  -d "$TOOLS_LIST_BODY")"
list_status="$(echo "$list_response" | tail -n1)"
list_body="$(echo "$list_response" | sed '$d')"
if [ "$list_status" = "200" ]; then
  ok "tools/list returned 200"
else
  bad "tools/list returned ${list_status}, expected 200"
fi
tool_count="$(echo "$list_body" | jq '.result.tools | length' 2>/dev/null || echo "0")"
if [ "$tool_count" = "5" ]; then
  ok "tools/list returned 5 tools"
else
  bad "tools/list returned ${tool_count} tools, expected 5 (body: ${list_body})"
fi

log "tools/list without a token must be 401"
noauth_status="$(curl -sS -o /dev/null -w '%{http_code}' "$MCP_URL" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d "$TOOLS_LIST_BODY")"
if [ "$noauth_status" = "401" ]; then
  ok "request without a token returned 401"
else
  bad "request without a token returned ${noauth_status}, expected 401"
fi

log "docker stop timing (graceful shutdown)"
# -t 15: the forced-close shutdown timeout in src/shutdown.ts is itself 10s,
# so a 10s grace period (docker's default) would SIGKILL at roughly the same
# moment that timeout fires. `docker stop`'s own exit code is 0 even when it
# had to SIGKILL, so the real signal is the *container's* exit code: 0 means
# the process's own SIGTERM handler ran gracefulShutdown() to completion
# (process.exit(0)); a SIGKILL shows up as 137.
stop_start=$(date +%s)
docker stop -t 15 "$MCP_CONTAINER" >/dev/null
stop_end=$(date +%s)
stop_duration=$((stop_end - stop_start))
container_exit_code="$(docker inspect --format='{{.State.ExitCode}}' "$MCP_CONTAINER")"
echo "docker stop took ${stop_duration}s, container exit code ${container_exit_code}"
if [ "$container_exit_code" = "0" ] && [ "$stop_duration" -lt 15 ]; then
  ok "container exited 0 (graceful) in ${stop_duration}s (<15s)"
else
  bad "container exit code ${container_exit_code} after ${stop_duration}s (expected 0, graceful)"
fi

log "starting mcp image with AUTH_MODE unset (expect non-zero exit)"
set +e
noauth_output="$(docker run --rm --name "$NOAUTH_CONTAINER" --network "$NETWORK" "$IMAGE_TAG" 2>&1)"
noauth_exit=$?
set -e
echo "$noauth_output"
if [ "$noauth_exit" -ne 0 ]; then
  ok "image exited non-zero (${noauth_exit}) with AUTH_MODE unset"
else
  bad "image exited 0 with AUTH_MODE unset, expected non-zero"
fi
if echo "$noauth_output" | grep -q "ALLOW_INSECURE_REMOTE"; then
  ok "exit message names STEAMPIPE_MCP_ALLOW_INSECURE_REMOTE"
else
  bad "exit message did not mention ALLOW_INSECURE_REMOTE: ${noauth_output}"
fi

echo
echo "=== docker-smoke.sh: ${PASS} passed, ${FAIL} failed ==="
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi
