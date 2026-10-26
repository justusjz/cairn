#!/usr/bin/env bash
#
# db-test.sh — runs the unit tests together with the tests that need a database
# (the end-to-end tests of the packer and the GC), against a throwaway Postgres
# in a Podman container. Plain `cargo test` skips the latter.
#
# Usage:  ./db-test.sh [cargo test args...]
# e.g.    ./db-test.sh packer::e2e
#
PG_IMAGE="docker.io/library/postgres:18"
PG_CONTAINER="cairn-db-test-pg"
PG_PORT=15433                    # not test.sh's, so both can run at once
PG_USER="s3test"
PG_PASS="s3test"
STARTUP_TIMEOUT=60

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cleanup() { podman rm -f "$PG_CONTAINER" >/dev/null 2>&1; }
trap cleanup EXIT
trap 'exit 130' INT TERM

podman rm -f "$PG_CONTAINER" >/dev/null 2>&1
podman run -d --rm --name "$PG_CONTAINER" \
    -e POSTGRES_USER="$PG_USER" \
    -e POSTGRES_PASSWORD="$PG_PASS" \
    -p "127.0.0.1:${PG_PORT}:5432" \
    "$PG_IMAGE" >/dev/null || { echo "could not start Postgres container" >&2; exit 1; }

elapsed=0
# pg_isready can succeed while the entrypoint's temporary server is still up,
# so wait for a real query over TCP.
until podman exec "$PG_CONTAINER" psql -h 127.0.0.1 -U "$PG_USER" -d postgres -c 'SELECT 1' >/dev/null 2>&1; do
    sleep 1
    elapsed=$((elapsed + 1))
    if [ "$elapsed" -ge "$STARTUP_TIMEOUT" ]; then
        echo "Postgres did not become ready in ${STARTUP_TIMEOUT}s" >&2
        exit 1
    fi
done

cd "$SCRIPT_DIR" &&
    CAIRN_TEST_DATABASE="postgres://$PG_USER:$PG_PASS@127.0.0.1:${PG_PORT}/postgres" \
    cargo test "$@"
