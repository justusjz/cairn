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


CARGO_ARGS=(-- serve --database postgres://$PG_USER:$PG_PASS@127.0.0.1:${PG_PORT}/$PG_DB --listen-client $SERVER_HOST:${SERVER_PORT})
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

TOTAL=32
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
for tool in podman cargo s3cmd curl openssl python3; do
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

# s3cmd can't issue ranged GETs, so the Range tests hit the server directly with
# curl (the server doesn't verify request signatures).
range_matches() {    # range_matches <bucket/key> <start> <end> <localfile>
    local path="$1" start="$2" end="$3" src="$4" got="$WORK_DIR/range.$RANDOM"
    curl -fsS -H "Range: bytes=${start}-${end}" \
        "http://${SERVER_HOST}:${SERVER_PORT}/${path}" -o "$got" || return 1
    cmp -s "$got" <(tail -c "+$((start + 1))" "$src" | head -c "$((end - start + 1))")
}

status_is() {        # status_is <expected-code> <bucket/key> <range>
    [ "$(curl -s -o /dev/null -w '%{http_code}' -H "Range: bytes=$3" \
        "http://${SERVER_HOST}:${SERVER_PORT}/$2")" = "$1" ]
}

head_status() {      # head_status <expected-code> <path>
    [ "$(curl -s -o /dev/null -w '%{http_code}' -I \
        "http://${SERVER_HOST}:${SERVER_PORT}/$2")" = "$1" ]
}

# Uploads <localfile> wrapped in `aws-chunked` framing (the streaming-signature
# encoding Mimir uses), then downloads it and confirms the server stored the
# DECODED object, not the chunk framing. Signatures aren't verified, so a dummy
# one is fine.
aws_chunked_roundtrip() {  # aws_chunked_roundtrip <bucket/key> <localfile>
    local path="$1" src="$2" body="$WORK_DIR/chunked.$RANDOM" dst="$WORK_DIR/chunked.dl.$RANDOM"
    local size hexsize
    size=$(wc -c < "$src")
    hexsize=$(printf '%x' "$size")
    {
        printf '%s;chunk-signature=%064x\r\n' "$hexsize" 0
        cat "$src"
        printf '\r\n0;chunk-signature=%064x\r\n\r\n' 0
    } >"$body"
    curl -fsS -X PUT --data-binary "@$body" \
        -H "Content-Encoding: aws-chunked" \
        -H "x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD" \
        -H "x-amz-decoded-content-length: ${size}" \
        "http://${SERVER_HOST}:${SERVER_PORT}/${path}" >/dev/null || return 1
    curl -fsS "http://${SERVER_HOST}:${SERVER_PORT}/${path}" -o "$dst" || return 1
    cmp -s "$src" "$dst"
}

# PUTs <localfile> as a mode-3 aws-chunked body (STREAMING-UNSIGNED-PAYLOAD-TRAILER)
# with a CRC32 trailer, printing the HTTP status. Pass "bad" to corrupt the trailer.
streaming_trailer_put() {  # streaming_trailer_put <bucket/key> <localfile> <good|bad>
    local path="$1" src="$2" mode="$3" size hexsize crc body
    size=$(wc -c <"$src")
    hexsize=$(printf '%x' "$size")
    crc=$(python3 -c "import zlib,base64,sys;print(base64.b64encode(zlib.crc32(open(sys.argv[1],'rb').read()).to_bytes(4,'big')).decode())" "$src")
    [ "$mode" = bad ] && crc="AAAAAA=="
    body="$WORK_DIR/st.$RANDOM"
    {
        printf '%s\r\n' "$hexsize"
        cat "$src"
        printf '\r\n0\r\nx-amz-checksum-crc32:%s\r\n\r\n' "$crc"
    } >"$body"
    curl -s -o /dev/null -w '%{http_code}' -X PUT --data-binary "@$body" \
        -H "Content-Encoding: aws-chunked" \
        -H "x-amz-content-sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER" \
        -H "x-amz-trailer: x-amz-checksum-crc32" \
        -H "x-amz-decoded-content-length: ${size}" \
        "http://${SERVER_HOST}:${SERVER_PORT}/${path}"
}

# A correct trailer checksum is accepted (and the decoded object stored); a wrong
# one is rejected with 400.
streaming_trailer_ok() {
    local b="$BUCKET"
    [ "$(streaming_trailer_put "$b/st-good.txt" "$NESTED" good)" = 200 ] || return 1
    check_roundtrip "$NESTED" "s3://$b/st-good.txt" || return 1
    [ "$(streaming_trailer_put "$b/st-bad.txt" "$NESTED" bad)" = 400 ] || return 1
    delete_objects_via_api "$b" st-good.txt >/dev/null
}

# ─── Pagination helpers (curl, so we control max-keys/tokens precisely) ──────
# Each lister walks every page with a small max-keys, following the cursor, and
# prints what it collected — so the tests can assert "no dupes, nothing dropped".
PBUCKET="page-$(date +%s)"   # dedicated bucket, torn down within the page tests

# Page through ListObjectsV2, printing every <Key> across all pages.
list_v2_keys() {  # list_v2_keys <prefix> <max-keys>
    local prefix="$1" mk="$2" token="" url resp
    while :; do
        url="http://${SERVER_HOST}:${SERVER_PORT}/${PBUCKET}?list-type=2&max-keys=${mk}&prefix=${prefix}"
        [ -n "$token" ] && url="${url}&continuation-token=${token}"
        resp="$(curl -fsS "$url")" || return 1
        printf '%s' "$resp" | grep -oP '(?<=<Key>).*?(?=</Key>)'
        printf '%s' "$resp" | grep -q '<IsTruncated>true</IsTruncated>' || break
        token="$(printf '%s' "$resp" | grep -oP '(?<=<NextContinuationToken>).*?(?=</NextContinuationToken>)')"
        [ -n "$token" ] || return 1   # truncated but no token = bug
    done
}

# Page through ListObjects (v1), printing every <Key> across all pages.
list_v1_keys() {  # list_v1_keys <prefix> <max-keys>
    local prefix="$1" mk="$2" marker="" url resp
    while :; do
        url="http://${SERVER_HOST}:${SERVER_PORT}/${PBUCKET}?max-keys=${mk}&prefix=${prefix}"
        [ -n "$marker" ] && url="${url}&marker=${marker}"
        resp="$(curl -fsS "$url")" || return 1
        printf '%s' "$resp" | grep -oP '(?<=<Key>).*?(?=</Key>)'
        printf '%s' "$resp" | grep -q '<IsTruncated>true</IsTruncated>' || break
        marker="$(printf '%s' "$resp" | grep -oP '(?<=<NextMarker>).*?(?=</NextMarker>)')"
        [ -n "$marker" ] || return 1
    done
}

# Page through ListObjectsV2 with a delimiter, printing every CommonPrefixes
# entry. \K drops the literal prefix so we don't also match the top-level <Prefix>.
list_v2_common_prefixes() {  # list_v2_common_prefixes <prefix> <max-keys>
    local prefix="$1" mk="$2" token="" url resp
    while :; do
        url="http://${SERVER_HOST}:${SERVER_PORT}/${PBUCKET}?list-type=2&max-keys=${mk}&prefix=${prefix}&delimiter=/"
        [ -n "$token" ] && url="${url}&continuation-token=${token}"
        resp="$(curl -fsS "$url")" || return 1
        printf '%s' "$resp" | grep -oP '<CommonPrefixes><Prefix>\K.*?(?=</Prefix>)'
        printf '%s' "$resp" | grep -q '<IsTruncated>true</IsTruncated>' || break
        token="$(printf '%s' "$resp" | grep -oP '(?<=<NextContinuationToken>).*?(?=</NextContinuationToken>)')"
        [ -n "$token" ] || return 1
    done
}

setup_pagination() {
    s3 mb "s3://${PBUCKET}" >/dev/null 2>&1 || return 1
    local k
    # 5 leaf objects under flat/, plus two folders under tree/ (d1 has two keys,
    # so its resume cursor must be the *greater* of them to skip the whole folder).
    for k in flat/obj0 flat/obj1 flat/obj2 flat/obj3 flat/obj4 \
             tree/d1/x tree/d1/y tree/d2/x; do
        printf 'content of %s\n' "$k" >"$WORK_DIR/pf"
        s3 put "$WORK_DIR/pf" "s3://${PBUCKET}/${k}" >/dev/null 2>&1 || return 1
    done
}

teardown_pagination() {
    s3 del --recursive "s3://${PBUCKET}/" >/dev/null 2>&1
    s3 rb "s3://${PBUCKET}" >/dev/null 2>&1
}

v2_leaves_ok() {
    [ "$(list_v2_keys flat/ 2 | sort)" = "$(printf 'flat/obj0\nflat/obj1\nflat/obj2\nflat/obj3\nflat/obj4')" ]
}
v1_leaves_ok() {
    [ "$(list_v1_keys flat/ 2 | sort)" = "$(printf 'flat/obj0\nflat/obj1\nflat/obj2\nflat/obj3\nflat/obj4')" ]
}
v2_prefixes_ok() {
    [ "$(list_v2_common_prefixes tree/ 1 | sort)" = "$(printf 'tree/d1/\ntree/d2/')" ]
}

# `?acl` GET (object and bucket) returns the stubbed AccessControlPolicy, and
# `s3cmd info` — which issues that ACL query — completes instead of choking.
acl_stub_ok() {
    local base="http://${SERVER_HOST}:${SERVER_PORT}" r
    r="$(curl -fsS "$base/${BUCKET}/big.bin?acl")" || return 1
    printf '%s' "$r" | grep -q '<AccessControlPolicy' || return 1
    printf '%s' "$r" | grep -q '<ID>cairn</ID>' || return 1
    r="$(curl -fsS "$base/${BUCKET}?acl")" || return 1
    printf '%s' "$r" | grep -q 'FULL_CONTROL' || return 1
    # the actual client that broke: s3cmd info must now succeed
    s3 info "s3://${BUCKET}/big.bin" >/dev/null 2>&1
}

# POST /{bucket}?delete with a <Delete> body — the batch-delete API. Sends the
# Content-MD5 the endpoint requires (base64 of the body's MD5).
delete_objects_via_api() {  # delete_objects_via_api <bucket> <key>...
    local bucket="$1"; shift
    local body='<Delete>' k md5
    for k in "$@"; do body="${body}<Object><Key>${k}</Key></Object>"; done
    body="${body}</Delete>"
    md5="$(printf '%s' "$body" | openssl dgst -md5 -binary | base64)"
    curl -fsS -X POST --data "$body" -H "Content-MD5: ${md5}" \
        "http://${SERVER_HOST}:${SERVER_PORT}/${bucket}?delete"
}

# Verifies the integrity/existence guards: missing or wrong Content-MD5 → 400,
# and a well-formed request against a missing bucket → 404 NoSuchBucket.
batch_delete_guards_ok() {
    local base="http://${SERVER_HOST}:${SERVER_PORT}" code
    local body='<Delete><Object><Key>whatever.txt</Key></Object></Delete>' md5
    md5="$(printf '%s' "$body" | openssl dgst -md5 -binary | base64)"
    # missing Content-MD5
    code="$(curl -s -o /dev/null -w '%{http_code}' -X POST --data "$body" "$base/${BUCKET}?delete")"
    [ "$code" = 400 ] || return 1
    # wrong Content-MD5
    code="$(curl -s -o /dev/null -w '%{http_code}' -X POST --data "$body" \
        -H 'Content-MD5: AAAAAAAAAAAAAAAAAAAAAA==' "$base/${BUCKET}?delete")"
    [ "$code" = 400 ] || return 1
    # correct request, missing bucket
    code="$(curl -s -o /dev/null -w '%{http_code}' -X POST --data "$body" \
        -H "Content-MD5: ${md5}" "$base/no-such-bucket-xyz?delete")"
    [ "$code" = 404 ]
}

# Exercises DeleteObjects: reporting, idempotency for absent keys, that only the
# named keys are removed, and that the result is well-formed.
batch_delete_ok() {
    local b="$BUCKET" base="http://${SERVER_HOST}:${SERVER_PORT}" k resp
    printf 'batch delete fixture\n' >"$WORK_DIR/bd"
    for k in bd1.txt bd2.txt bd3.txt; do
        s3 put "$WORK_DIR/bd" "s3://$b/$k" >/dev/null 2>&1 || return 1
    done
    resp="$(delete_objects_via_api "$b" bd1.txt bd2.txt nope.txt)" || return 1
    # both real keys and the absent one are acknowledged (delete is idempotent)
    for k in bd1.txt bd2.txt nope.txt; do
        printf '%s' "$resp" | grep -q "<Deleted><Key>${k}</Key></Deleted>" || return 1
    done
    # bd1/bd2 gone, bd3 untouched
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$base/$b/bd1.txt")" = 404 ] || return 1
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$base/$b/bd2.txt")" = 404 ] || return 1
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$base/$b/bd3.txt")" = 200 ] || return 1
    # remove the survivor too, so the bucket teardown stays simple
    delete_objects_via_api "$b" bd3.txt >/dev/null || return 1
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$base/$b/bd3.txt")" = 404 ]
}

echo ""
echo "${BOLD}Running tests against s3://${BUCKET}${RESET}"
echo ""

# ─── 5. The tests ────────────────────────────────────────────────────────────
run_test "Create bucket"                       s3 mb "s3://${BUCKET}"
run_test "Bucket appears in bucket list"       list_contains "" "s3://${BUCKET}"
run_test "HEAD existing bucket returns 200"    head_status 200 "${BUCKET}"
run_test "HEAD missing bucket returns 404"     head_status 404 "${BUCKET}-nope"
run_test "Upload small text object"            s3 put "$SMALL" "s3://${BUCKET}/small.txt"
run_test "Object appears in bucket listing"    list_contains "s3://${BUCKET}" "small.txt"
run_test "Download matches upload (small)"     check_roundtrip "$SMALL" "s3://${BUCKET}/small.txt"
run_test "Upload 4 MiB binary object"          s3 put "$BIG" "s3://${BUCKET}/big.bin"
run_test "Download matches upload (binary)"    check_roundtrip "$BIG" "s3://${BUCKET}/big.bin"
run_test "Upload object under a prefix"        s3 put "$NESTED" "s3://${BUCKET}/dir/sub/nested.txt"
run_test "Listing with prefix finds object"    list_contains "s3://${BUCKET}/dir/sub/" "nested.txt"
run_test "Upload 16 MiB object via multipart"  s3 put --multipart-chunk-size-mb=5 "$MULTIPART" "s3://${BUCKET}/multi.bin"
run_test "Download multipart object matches"   check_roundtrip "$MULTIPART" "s3://${BUCKET}/multi.bin"
run_test "Ranged GET (single part) matches"    range_matches "${BUCKET}/big.bin" 1000000 1000099 "$BIG"
run_test "Ranged GET across multipart boundary" \
                                               range_matches "${BUCKET}/multi.bin" 5242875 5242884 "$MULTIPART"
run_test "Ranged GET responds 206"             status_is 206 "${BUCKET}/big.bin" "0-99"
run_test "Unsatisfiable range responds 416"    status_is 416 "${BUCKET}/big.bin" "99999999-100000000"
run_test "aws-chunked upload is decoded"       aws_chunked_roundtrip "${BUCKET}/chunked.txt" "$NESTED"
run_test "aws-chunked trailer checksum (CRC32)" streaming_trailer_ok
run_test "Set up pagination fixtures"          setup_pagination
run_test "ListObjectsV2 paginates leaves"      v2_leaves_ok
run_test "ListObjects (v1) paginates leaves"   v1_leaves_ok
run_test "ListObjectsV2 paginates prefixes"    v2_prefixes_ok
run_test "Tear down pagination bucket"         teardown_pagination
run_test "Batch delete (DeleteObjects)"        batch_delete_ok
run_test "Batch delete guards (MD5 / bucket)"  batch_delete_guards_ok
run_test "Stubbed ACL (s3cmd info works)"      acl_stub_ok
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
    s3cmd --config '$S3CFG' del 's3://${BUCKET}/chunked.txt' >/dev/null &&
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
