#!/usr/bin/env bash
#
# db-test.sh — runs the unit tests together with the tests that need a database
# (the end-to-end tests of the packer and the GC), against a throwaway Postgres
# in a Podman container, and those of SSE-KMS against a throwaway OpenBao dev
# server. Plain `cargo test` skips the latter.
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
BAO_IMAGE="quay.io/openbao/openbao:2.7.2"
BAO_CONTAINER="cairn-db-test-bao"
BAO_PORT=18201

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cleanup() { podman rm -f "$PG_CONTAINER" "$BAO_CONTAINER" >/dev/null 2>&1; }
trap cleanup EXIT
trap 'exit 130' INT TERM

podman rm -f "$PG_CONTAINER" "$BAO_CONTAINER" >/dev/null 2>&1
podman run -d --rm --name "$BAO_CONTAINER" \
    -e BAO_DEV_ROOT_TOKEN_ID=root \
    -p "127.0.0.1:${BAO_PORT}:8200" \
    "$BAO_IMAGE" server -dev -dev-listen-address=0.0.0.0:8200 >/dev/null \
    || { echo "could not start OpenBao container" >&2; exit 1; }
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

# OpenBao: keys in two Transit mounts, and the JWT auth mount Cairn logs in
# to as its roles (see `kms`), trusting a throwaway key. The tests grant
# their roles keys themselves, as root.
bao() { podman exec -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN=root "$BAO_CONTAINER" bao "$@"; }
elapsed=0
until bao status >/dev/null 2>&1; do
    sleep 1
    elapsed=$((elapsed + 1))
    if [ "$elapsed" -ge "$STARTUP_TIMEOUT" ]; then
        echo "OpenBao did not become ready in ${STARTUP_TIMEOUT}s" >&2
        exit 1
    fi
done
KEY_DIR="$(mktemp -d /tmp/cairn-db-test-kms.XXXXXX)"
trap 'cleanup; rm -rf "$KEY_DIR"' EXIT
{
    openssl genpkey -algorithm ed25519 -out "$KEY_DIR/jwt.pem" &&
    openssl pkey -in "$KEY_DIR/jwt.pem" -pubout -out "$KEY_DIR/jwt.pub" &&
    podman cp "$KEY_DIR/jwt.pub" "$BAO_CONTAINER:/tmp/cairn-jwt.pub" &&
    bao secrets enable transit &&
    bao write -f transit/keys/cairn-test &&
    bao write -f transit/keys/cairn-other &&
    bao secrets enable -path=team-transit transit &&
    bao write -f team-transit/keys/invoices &&
    bao auth enable -path=cairn jwt &&
    bao write auth/cairn/config jwt_validation_pubkeys=@/tmp/cairn-jwt.pub &&
    bao write auth/cairn/role/s3 role_type=jwt user_claim=sub bound_audiences=cairn \
        token_type=batch token_ttl=5m
} >/dev/null 2>&1 || { echo "could not set up OpenBao" >&2; exit 1; }

cd "$SCRIPT_DIR" &&
    CAIRN_TEST_DATABASE="postgres://$PG_USER:$PG_PASS@127.0.0.1:${PG_PORT}/postgres" \
    CAIRN_TEST_OPENBAO="http://127.0.0.1:${BAO_PORT}" \
    CAIRN_TEST_OPENBAO_JWT_KEY="$KEY_DIR/jwt.pem" \
    cargo test "$@"
