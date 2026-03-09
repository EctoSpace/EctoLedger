#!/usr/bin/env bash
# Run the EctoLedger integration test suite against an ephemeral PostgreSQL container.
#
# Usage:
#   ./scripts/test-integration.sh [extra cargo test args...]
#
# Requirements: Docker (or Podman with compose), cargo
#
# What this does:
#   1. Brings up docker-compose.test.yml (ephemeral Postgres on port 5433).
#   2. Waits for the database healthcheck to pass.
#   3. Exports DATABASE_URL and runs `cargo test --features integration`.
#   4. Tears the container down on exit regardless of test result.

set -euo pipefail

# Check for Docker or Podman before attempting to use docker compose
DOCKER_CMD="docker"
if ! command -v docker >/dev/null 2>&1; then
    if command -v podman >/dev/null 2>&1; then
        DOCKER_CMD="podman"
    else
        echo "ERROR: Neither Docker nor Podman found. Install Docker Desktop or Podman to run integration tests." >&2
        echo "  macOS: brew install --cask docker" >&2
        echo "  Linux: https://docs.docker.com/engine/install/" >&2
        exit 1
    fi
fi
if ! $DOCKER_CMD compose version &>/dev/null 2>&1; then
  echo "ERROR: '$DOCKER_CMD compose' (V2) is required. Install the compose plugin or Docker Desktop." >&2
  exit 1
fi

COMPOSE_FILE="$(cd "$(dirname "$0")/.." && pwd)/docker-compose.test.yml"
DB_URL="postgres://ectoledger:ectoledger@localhost:5433/ectoledger_test"

cleanup() {
    echo ""
    echo "Tearing down test containers..."
    $DOCKER_CMD compose -f "$COMPOSE_FILE" down --remove-orphans --volumes 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "Starting test database..."
$DOCKER_CMD compose -f "$COMPOSE_FILE" up -d --wait

echo "Waiting for Postgres to be ready..."
RETRIES=30
until $DOCKER_CMD compose -f "$COMPOSE_FILE" exec -T postgres \
    pg_isready -U ectoledger -d ectoledger_test -q 2>/dev/null; do
    RETRIES=$((RETRIES - 1))
    if [ "$RETRIES" -le 0 ]; then
        echo "ERROR: Postgres did not become ready in time." >&2
        exit 1
    fi
    sleep 1
done
echo "Postgres is ready."

export DATABASE_URL="$DB_URL"
echo "DATABASE_URL=$DATABASE_URL"

echo "Running integration tests..."
cargo test --features integration "$@"
