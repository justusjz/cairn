#!/usr/bin/env bash
#
# s3-smoke-test.sh — self-contained smoke test for a Postgres-backed S3 server.
#
# What it does:
#   1. Starts a throwaway Postgres in a Podman container
#   2. Builds and runs your server in the background via `cargo run`
#   3. Exercises basic S3 operations with s3cmd
#   4. Prints a pass/fail progress report and tears everything down
#
# Usage:  ./s3-smoke-test.sh
# Exit code is 0 only if every test passes.
#
# ─── Configuration — adjust these to match your server ──────────────────────
PG_IMAGE="docker.io/library/postgres:18"
PG_CONTAINER="s3test-pg"
PG_PORT=15432                    # host port, picked to avoid a local postgres
PG_USER="s3test"
PG_PASS="s3test"
PG_DB="cairn"

SERVER_HOST="127.0.0.1"
SERVER_PORT=9000                 # the port your server listens on
ACCESS_KEY="testkey"             # credentials your server accepts
SECRET_KEY="testsecret"
USE_SIGV2=false                  # set to true if you haven't implemented SigV4 yet


CARGO_ARGS=(-- --database postgres://$PG_USER:$PG_PASS@127.0.0.1:${PG_PORT}/$PG_DB --listen-client $SERVER_HOST:${SERVER_PORT})
STARTUP_TIMEOUT=60               # seconds to wait for postgres / server
# ─────────────────────────────────────────────────────────────────────────────

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(mktemp -d /tmp/s3-smoke.XXXXXX)"
CARGO_ARGS+=(--data-dir "$WORK_DIR/data")   # required; per-run blob dir
SERVER_LOG="$WORK_DIR/server.log"
SERVER_PID=""
BUCKET="smoke-$(date +%s)"

# ─── Pretty output ───────────────────────────────────────────────────────────
if [ -t 1 ]; then
    GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
else
    GREEN=""; RED=""; YELLOW=""; BOLD=""; DIM=""; RESET=""
fi

TOTAL=16
STEP=0
PASS=0
FAIL=0
FAILED_TESTS=()

info()  { printf '%s\n' "${DIM}$*${RESET}"; }
fatal() { printf '%s\n' "${RED}${BOLD}FATAL:${RESET} $*" >&2; exit 1; }

# run_test "description" cmd args...
# Runs cmd, prints [n/N] progress with OK/FAIL, captures output for diagnostics.
run_test() {
    local desc="$1"; shift
    STEP=$((STEP + 1))
    printf '%s' "${BOLD}[${STEP}/${TOTAL}]${RESET} ${desc} ... "
    local out
    if out="$("$@" 2>&1)"; then
        printf '%s\n' "${GREEN}OK${RESET}"
        PASS=$((PASS + 1))
        return 0
    else
        printf '%s\n' "${RED}FAIL${RESET}"
        printf '%s\n' "${DIM}      cmd: $*${RESET}"
        # indent the captured output for readability
        printf '%s\n' "$out" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILED_TESTS+=("$desc")
        return 1
    fi
}

# expect_fail "description" cmd args...  — passes when the command FAILS
expect_fail() {
    local desc="$1"; shift
    STEP=$((STEP + 1))
    printf '%s' "${BOLD}[${STEP}/${TOTAL}]${RESET} ${desc} ... "
    local out
    if out="$("$@" 2>&1)"; then
        printf '%s\n' "${RED}FAIL (command unexpectedly succeeded)${RESET}"
        printf '%s\n' "$out" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILED_TESTS+=("$desc")
        return 1
    else
        printf '%s\n' "${GREEN}OK${RESET}"
        PASS=$((PASS + 1))
        return 0
    fi
}

# ─── Cleanup ─────────────────────────────────────────────────────────────────
cleanup() {
    info ""
    info "Cleaning up..."
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null
    fi
    podman rm -f "$PG_CONTAINER" >/dev/null 2>&1
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

# ─── Preflight ───────────────────────────────────────────────────────────────
for tool in podman cargo s3cmd; do
    command -v "$tool" >/dev/null 2>&1 || fatal "'$tool' not found in PATH"
done

# ─── 1. Postgres ─────────────────────────────────────────────────────────────
info "Starting Postgres ($PG_IMAGE) on port $PG_PORT..."
podman rm -f "$PG_CONTAINER" >/dev/null 2>&1
podman run -d --rm --name "$PG_CONTAINER" \
    -e POSTGRES_USER="$PG_USER" \
    -e POSTGRES_PASSWORD="$PG_PASS" \
    -e POSTGRES_DB="$PG_DB" \
    -p "127.0.0.1:${PG_PORT}:5432" \
    "$PG_IMAGE" >/dev/null || fatal "could not start Postgres container"

sleep 2
elapsed=0
until podman exec "$PG_CONTAINER" pg_isready -U "$PG_USER" -d "$PG_DB" >/dev/null 2>&1; do
    sleep 1
    elapsed=$((elapsed + 1))
    [ "$elapsed" -ge "$STARTUP_TIMEOUT" ] && fatal "Postgres did not become ready in ${STARTUP_TIMEOUT}s"
done
info "Postgres is ready."

# ─── 2. Build & run the server ───────────────────────────────────────────────
#info "Building (cargo build)..."
#(cd "$SCRIPT_DIR" && cargo build ${CARGO_ARGS[@]+"${CARGO_ARGS[@]}"} >"$WORK_DIR/build.log" 2>&1) \
#    || { tail -n 30 "$WORK_DIR/build.log" >&2; fatal "cargo build failed (full log: $WORK_DIR/build.log)"; }

info "Starting server (cargo run) on ${SERVER_HOST}:${SERVER_PORT}..."
(cd "$SCRIPT_DIR" && exec cargo run ${CARGO_ARGS[@]+"${CARGO_ARGS[@]}"} >"$SERVER_LOG" 2>&1) &
SERVER_PID=$!

elapsed=0
until (exec 3<>"/dev/tcp/${SERVER_HOST}/${SERVER_PORT}") 2>/dev/null; do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        tail -n 30 "$SERVER_LOG" >&2
        fatal "server process exited during startup (see above)"
    fi
    sleep 1
    elapsed=$((elapsed + 1))
    [ "$elapsed" -ge "$STARTUP_TIMEOUT" ] && fatal "server did not open port ${SERVER_PORT} in ${STARTUP_TIMEOUT}s"
done
exec 3>&- 3<&- 2>/dev/null
info "Server is up."

# ─── 3. s3cmd configuration ──────────────────────────────────────────────────
S3CFG="$WORK_DIR/s3cfg"
cat >"$S3CFG" <<EOF
[default]
access_key = ${ACCESS_KEY}
secret_key = ${SECRET_KEY}
host_base = ${SERVER_HOST}:${SERVER_PORT}
host_bucket = ${SERVER_HOST}:${SERVER_PORT}
use_https = False
signature_v2 = $( [ "$USE_SIGV2" = true ] && echo True || echo False )
signurl_use_https = False
EOF
s3() { s3cmd --config "$S3CFG" "$@"; }

# ─── 4. Test fixtures ────────────────────────────────────────────────────────
SMALL="$WORK_DIR/small.txt"
BIG="$WORK_DIR/big.bin"
NESTED="$WORK_DIR/nested.txt"
MULTIPART="$WORK_DIR/multi.bin"
printf 'hello from the smoke test\n' >"$SMALL"
dd if=/dev/urandom of="$BIG" bs=1M count=4 status=none    # 4 MiB, below multipart thresholds
printf 'nested object content\n' >"$NESTED"
dd if=/dev/urandom of="$MULTIPART" bs=1M count=16 status=none   # 16 MiB → 4 parts at 5 MiB chunks

check_roundtrip() {  # check_roundtrip <local> <s3uri>
    local src="$1" uri="$2" dst="$WORK_DIR/dl.$RANDOM"
    s3 get "$uri" "$dst" >/dev/null 2>&1 || return 1
    cmp -s "$src" "$dst"
}

list_contains() {    # list_contains <s3 ls target> <needle>
    s3 ls "$1" 2>/dev/null | grep -qF "$2"
}

echo ""
echo "${BOLD}Running tests against s3://${BUCKET}${RESET}"
echo ""

# ─── 5. The tests ────────────────────────────────────────────────────────────
run_test "Create bucket"                       s3 mb "s3://${BUCKET}"
run_test "Bucket appears in bucket list"       list_contains "" "s3://${BUCKET}"
run_test "Upload small text object"            s3 put "$SMALL" "s3://${BUCKET}/small.txt"
run_test "Object appears in bucket listing"    list_contains "s3://${BUCKET}" "small.txt"
run_test "Download matches upload (small)"     check_roundtrip "$SMALL" "s3://${BUCKET}/small.txt"
run_test "Upload 4 MiB binary object"          s3 put "$BIG" "s3://${BUCKET}/big.bin"
run_test "Download matches upload (binary)"    check_roundtrip "$BIG" "s3://${BUCKET}/big.bin"
run_test "Upload object under a prefix"        s3 put "$NESTED" "s3://${BUCKET}/dir/sub/nested.txt"
run_test "Listing with prefix finds object"    list_contains "s3://${BUCKET}/dir/sub/" "nested.txt"
run_test "Upload 16 MiB object via multipart"  s3 put --multipart-chunk-size-mb=5 "$MULTIPART" "s3://${BUCKET}/multi.bin"
run_test "Download multipart object matches"   check_roundtrip "$MULTIPART" "s3://${BUCKET}/multi.bin"
run_test "Overwrite object, new content wins"  bash -c "
    printf 'overwritten content\n' > '$WORK_DIR/over.txt' &&
    s3cmd --config '$S3CFG' put '$WORK_DIR/over.txt' 's3://${BUCKET}/small.txt' >/dev/null &&
    s3cmd --config '$S3CFG' get 's3://${BUCKET}/small.txt' '$WORK_DIR/over.dl' >/dev/null &&
    cmp -s '$WORK_DIR/over.txt' '$WORK_DIR/over.dl'"
run_test "Delete object"                       s3 del "s3://${BUCKET}/small.txt"
expect_fail "Deleted object is gone (GET 404s)" s3 get "s3://${BUCKET}/small.txt" "$WORK_DIR/gone"
run_test "Delete remaining objects + bucket"   bash -c "
    s3cmd --config '$S3CFG' del 's3://${BUCKET}/big.bin' >/dev/null &&
    s3cmd --config '$S3CFG' del 's3://${BUCKET}/dir/sub/nested.txt' >/dev/null &&
    s3cmd --config '$S3CFG' del 's3://${BUCKET}/multi.bin' >/dev/null &&
    s3cmd --config '$S3CFG' rb 's3://${BUCKET}' >/dev/null"
expect_fail "Removed bucket is gone (ls fails)" s3 ls "s3://${BUCKET}"

# ─── 6. Summary ──────────────────────────────────────────────────────────────
echo ""
if [ "$FAIL" -eq 0 ]; then
    echo "${GREEN}${BOLD}All ${PASS}/${TOTAL} tests passed.${RESET}"
else
    echo "${RED}${BOLD}${FAIL} of ${TOTAL} tests failed:${RESET}"
    for t in "${FAILED_TESTS[@]}"; do echo "  ${RED}✗${RESET} $t"; done
    echo ""
    echo "${YELLOW}Last 40 lines of server output:${RESET}"
    tail -n 40 "$SERVER_LOG" | sed 's/^/  /'
fi

exit "$FAIL"
