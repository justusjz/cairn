#!/usr/bin/env bash
#
# cairn-ha-test.sh — high-availability test for cairn (Postgres-backed S3 server).
#
# What it does:
#   1. Starts a throwaway Postgres in a Podman container
#   2. Builds cairn once, then starts THREE instances with --replication-factor 2
#      (client ports 9000/9002/9004, peer ports one higher: 9001/9003/9005)
#   3. Phase A: verifies basic ops work, including cross-instance reads
#      (upload via one node, download via another)
#   4. Phase B: hard-kills one instance, verifies reads of old objects AND
#      uploads of new objects still work through the two survivors
#   5. Phase C: kills a second instance, verifies uploads now FAIL
#      (replication factor 2 cannot be satisfied with one node)
#   6. Phase D: restarts a killed instance, verifies uploads work again
#
# Usage:  ./cairn-ha-test.sh
# Exit code is 0 only if every test passes.
#
# ─── Configuration — adjust these to match your server ──────────────────────
PG_IMAGE="docker.io/library/postgres:18"
PG_CONTAINER="cairn-ha-pg"
PG_PORT=15432
PG_USER="s3test"
PG_PASS="s3test"
PG_DB="cairn"

BIN_NAME="cairn"                 # binary name produced by cargo build
SERVER_HOST="127.0.0.1"
BASE_PORT=9000                   # instance i uses client port BASE+2(i-1), peer port one higher
INSTANCES=3
REPLICATION_FACTOR=2
ACCESS_KEY="testkey"
SECRET_KEY="testsecret"
USE_SIGV2=false

# If each instance needs its own blob directory, set the flag name here and the
# script will pass "<flag> $WORK_DIR/data<i>" per instance. Leave empty to skip.
# Running three instances against the SAME directory would silently defeat the
# replication test, so set this if your storage path is cwd-relative!
DATA_DIR_FLAG="--data-dir"

EXTRA_SERVER_ARGS=()             # appended to every instance's command line
STARTUP_TIMEOUT=60               # seconds to wait for postgres / each server
FAILURE_DETECT_WAIT=3            # seconds to let survivors notice a dead peer
# ─────────────────────────────────────────────────────────────────────────────

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(mktemp -d /tmp/cairn-ha.XXXXXX)"
BUCKET="ha-$(date +%s)"
declare -a PIDS=()               # PIDS[i] = pid of instance i (empty if down)

client_port() { echo $((BASE_PORT + 2 * ($1 - 1))); }
peer_port()   { echo $((BASE_PORT + 2 * ($1 - 1) + 1)); }

# ─── Pretty output ───────────────────────────────────────────────────────────
if [ -t 1 ]; then
    GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
else
    GREEN=""; RED=""; YELLOW=""; BOLD=""; DIM=""; RESET=""
fi

TOTAL=15
STEP=0
PASS=0
FAIL=0
FAILED_TESTS=()

info()    { printf '%s\n' "${DIM}$*${RESET}"; }
phase()   { printf '\n%s\n' "${YELLOW}${BOLD}── $* ──${RESET}"; }
fatal()   { printf '%s\n' "${RED}${BOLD}FATAL:${RESET} $*" >&2; exit 1; }

run_test() {
    local desc="$1"; shift
    STEP=$((STEP + 1))
    printf '%s' "${BOLD}[${STEP}/${TOTAL}]${RESET} ${desc} ... "
    local out
    if out="$("$@" 2>&1)"; then
        printf '%s\n' "${GREEN}OK${RESET}"
        PASS=$((PASS + 1)); return 0
    else
        printf '%s\n' "${RED}FAIL${RESET}"
        printf '%s\n' "${DIM}      cmd: $*${RESET}"
        printf '%s\n' "$out" | sed 's/^/      /'
        FAIL=$((FAIL + 1)); FAILED_TESTS+=("$desc"); return 1
    fi
}

expect_fail() {
    local desc="$1"; shift
    STEP=$((STEP + 1))
    printf '%s' "${BOLD}[${STEP}/${TOTAL}]${RESET} ${desc} ... "
    local out
    if out="$("$@" 2>&1)"; then
        printf '%s\n' "${RED}FAIL (command unexpectedly succeeded)${RESET}"
        printf '%s\n' "$out" | sed 's/^/      /'
        FAIL=$((FAIL + 1)); FAILED_TESTS+=("$desc"); return 1
    else
        printf '%s\n' "${GREEN}OK${RESET}"
        PASS=$((PASS + 1)); return 0
    fi
}

# ─── Cleanup ─────────────────────────────────────────────────────────────────
cleanup() {
    info ""
    info "Cleaning up..."
    local pid
    for pid in ${PIDS[@]+"${PIDS[@]}"}; do
        [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
    done
    wait 2>/dev/null
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

elapsed=0
until podman exec "$PG_CONTAINER" pg_isready -U "$PG_USER" -d "$PG_DB" >/dev/null 2>&1; do
    sleep 1; elapsed=$((elapsed + 1))
    [ "$elapsed" -ge "$STARTUP_TIMEOUT" ] && fatal "Postgres did not become ready in ${STARTUP_TIMEOUT}s"
done
info "Postgres is ready."

# ─── 2. Build once, run the binary directly ──────────────────────────────────
# We run the compiled binary instead of `cargo run` because cargo spawns the
# server as a child process: killing cargo's PID would NOT reliably kill the
# server, which matters when we simulate crashes below.
info "Building (cargo build)..."
(cd "$SCRIPT_DIR" && cargo build >"$WORK_DIR/build.log" 2>&1) \
    || { tail -n 30 "$WORK_DIR/build.log" >&2; fatal "cargo build failed (full log: $WORK_DIR/build.log)"; }

BIN="$SCRIPT_DIR/target/debug/$BIN_NAME"
[ -x "$BIN" ] || fatal "binary not found at $BIN — adjust BIN_NAME at the top of this script"

start_instance() {  # start_instance <n>
    local n="$1" cport pport
    cport="$(client_port "$n")"; pport="$(peer_port "$n")"
    local args=(
        --database "postgres://${PG_USER}:${PG_PASS}@127.0.0.1:${PG_PORT}/${PG_DB}"
        --listen-client "${SERVER_HOST}:${cport}"
        --listen-peer   "${SERVER_HOST}:${pport}"
        --replication-factor "$REPLICATION_FACTOR"
    )
    if [ -n "$DATA_DIR_FLAG" ]; then
        mkdir -p "$WORK_DIR/data$n"
        args+=("$DATA_DIR_FLAG" "$WORK_DIR/data$n")
    fi
    args+=(${EXTRA_SERVER_ARGS[@]+"${EXTRA_SERVER_ARGS[@]}"})

    info "Starting instance $n (client :${cport}, peer :${pport})..."
    "$BIN" serve "${args[@]}" >>"$WORK_DIR/server$n.log" 2>&1 &
    PIDS[$n]=$!

    local elapsed=0
    until (exec 3<>"/dev/tcp/${SERVER_HOST}/${cport}") 2>/dev/null; do
        if ! kill -0 "${PIDS[$n]}" 2>/dev/null; then
            tail -n 30 "$WORK_DIR/server$n.log" >&2
            fatal "instance $n exited during startup (see above)"
        fi
        sleep 1; elapsed=$((elapsed + 1))
        [ "$elapsed" -ge "$STARTUP_TIMEOUT" ] && fatal "instance $n did not open port ${cport} in ${STARTUP_TIMEOUT}s"
    done
    exec 3>&- 3<&- 2>/dev/null
}

kill_instance() {  # kill_instance <n> — SIGKILL to simulate a crash, not a clean shutdown
    local n="$1"
    info "Killing instance $n (SIGKILL, simulating a crash)..."
    kill -9 "${PIDS[$n]}" 2>/dev/null
    wait "${PIDS[$n]}" 2>/dev/null
    PIDS[$n]=""
    sleep "$FAILURE_DETECT_WAIT"
}

for i in $(seq 1 "$INSTANCES"); do
    PIDS[$i]=""
    start_instance "$i"
done
info "All $INSTANCES instances are up."

# ─── 3. One s3cmd config per instance ────────────────────────────────────────
for i in $(seq 1 "$INSTANCES"); do
    cat >"$WORK_DIR/s3cfg.$i" <<EOF
[default]
access_key = ${ACCESS_KEY}
secret_key = ${SECRET_KEY}
host_base = ${SERVER_HOST}:$(client_port "$i")
host_bucket = ${SERVER_HOST}:$(client_port "$i")
use_https = False
signature_v2 = $( [ "$USE_SIGV2" = true ] && echo True || echo False )
signurl_use_https = False
EOF
done
s3i() { local n="$1"; shift; s3cmd --config "$WORK_DIR/s3cfg.$n" "$@"; }

# ─── 4. Fixtures & helpers ───────────────────────────────────────────────────
FILE_A="$WORK_DIR/a.txt";  printf 'object A: uploaded while all nodes were up\n' >"$FILE_A"
FILE_B="$WORK_DIR/b.bin";  dd if=/dev/urandom of="$FILE_B" bs=1M count=4 status=none
FILE_C="$WORK_DIR/c.txt";  printf 'object C: uploaded with one node down\n' >"$FILE_C"
FILE_D="$WORK_DIR/d.txt";  printf 'object D: uploaded after recovery\n' >"$FILE_D"

roundtrip_via() {  # roundtrip_via <instance> <localfile> <s3uri>
    local n="$1" src="$2" uri="$3" dst="$WORK_DIR/dl.$RANDOM"
    s3i "$n" get "$uri" "$dst" >/dev/null 2>&1 || return 1
    cmp -s "$src" "$dst"
}

list_contains_via() {  # list_contains_via <instance> <s3 ls target> <needle>
    s3i "$1" ls "$2" 2>/dev/null | grep -qF "$3"
}

echo ""
echo "${BOLD}Running HA tests against s3://${BUCKET} (${INSTANCES} nodes, RF=${REPLICATION_FACTOR})${RESET}"

# ─── 5. Phase A: all nodes up ────────────────────────────────────────────────
phase "Phase A: all ${INSTANCES} nodes up"
run_test "Create bucket via node 1"                 s3i 1 mb "s3://${BUCKET}"
run_test "Upload A via node 1"                      s3i 1 put "$FILE_A" "s3://${BUCKET}/a.txt"
run_test "Download A via node 2 matches"            roundtrip_via 2 "$FILE_A" "s3://${BUCKET}/a.txt"
run_test "Download A via node 3 matches"            roundtrip_via 3 "$FILE_A" "s3://${BUCKET}/a.txt"
run_test "Listing via node 2 shows A"               list_contains_via 2 "s3://${BUCKET}" "a.txt"
run_test "Upload 4 MiB binary B via node 2"         s3i 2 put "$FILE_B" "s3://${BUCKET}/b.bin"
run_test "Download B via node 1 matches"            roundtrip_via 1 "$FILE_B" "s3://${BUCKET}/b.bin"

# ─── 6. Phase B: one node down (within tolerance) ────────────────────────────
phase "Phase B: node 3 crashed — cluster must keep working"
kill_instance 3
run_test "Download A via node 1 still matches"      roundtrip_via 1 "$FILE_A" "s3://${BUCKET}/a.txt"
run_test "Download B via node 2 still matches"      roundtrip_via 2 "$FILE_B" "s3://${BUCKET}/b.bin"
run_test "Upload C via node 2 still works"          s3i 2 put "$FILE_C" "s3://${BUCKET}/c.txt"
run_test "Download C via node 1 matches"            roundtrip_via 1 "$FILE_C" "s3://${BUCKET}/c.txt"

# ─── 7. Phase C: two nodes down (beyond tolerance for writes) ────────────────
phase "Phase C: node 2 also crashed — writes must now FAIL (RF=${REPLICATION_FACTOR} > 1 live node)"
kill_instance 2
expect_fail "Upload D via node 1 is rejected"       s3i 1 put "$FILE_D" "s3://${BUCKET}/d.txt"
run_test "Listing via node 1 still works (metadata is in Postgres)" \
                                                    list_contains_via 1 "s3://${BUCKET}" "c.txt"

# ─── 8. Phase D: recovery ────────────────────────────────────────────────────
phase "Phase D: node 3 restarts — writes must work again"
start_instance 3
run_test "Upload D via node 3 succeeds"             s3i 3 put "$FILE_D" "s3://${BUCKET}/d.txt"
run_test "Download D via node 1 matches"            roundtrip_via 1 "$FILE_D" "s3://${BUCKET}/d.txt"

# ─── 9. Summary ──────────────────────────────────────────────────────────────
echo ""
if [ "$FAIL" -eq 0 ]; then
    echo "${GREEN}${BOLD}All ${PASS}/${TOTAL} tests passed.${RESET}"
else
    echo "${RED}${BOLD}${FAIL} of ${TOTAL} tests failed:${RESET}"
    for t in "${FAILED_TESTS[@]}"; do echo "  ${RED}✗${RESET} $t"; done
    for i in $(seq 1 "$INSTANCES"); do
        if [ -f "$WORK_DIR/server$i.log" ]; then
            echo ""
            echo "${YELLOW}Last 25 lines of instance $i output:${RESET}"
            tail -n 25 "$WORK_DIR/server$i.log" | sed 's/^/  /'
        fi
    done
fi

exit "$FAIL"
