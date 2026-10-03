#!/usr/bin/env bash
#
# s3-smoke-test.sh — self-contained smoke test for a Postgres-backed S3 server.
#
# What it does:
#   1. Starts a throwaway Postgres in a Podman container
#   2. Builds and runs your server in the background via `cargo run`
#   3. Exercises S3 operations with real signing clients (s3cmd, aws-cli, mcli);
#      a small python SigV4 signer (scurl) covers crafted requests no client can
#      produce, and an unsigned curl proves authentication is enforced.
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
ACCESS_KEY="testkey"             # created below as an admin role
SECRET_KEY="cairnsecret"         # with this secret

DB_URL="postgres://$PG_USER:$PG_PASS@127.0.0.1:${PG_PORT}/$PG_DB"
CARGO_ARGS=(-- serve --database "$DB_URL" --listen-client $SERVER_HOST:${SERVER_PORT})
STARTUP_TIMEOUT=60               # seconds to wait for postgres / server
# SHA-256 of the empty string — the payload hash clients sign for bodyless requests.
EMPTY_SHA256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
# ─────────────────────────────────────────────────────────────────────────────

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(mktemp -d /tmp/s3-smoke.XXXXXX)"
CARGO_ARGS+=(--data-dir "$WORK_DIR/data")   # required; per-run blob dir
SERVER_LOG="$WORK_DIR/server.log"
SERVER_PID=""
BUCKET="smoke-$(date +%s)"
PBUCKET="page-$(date +%s)"       # pagination fixtures
NBUCKET="nonempty-$(date +%s)"   # DeleteBucket-on-non-empty test
OBUCKET="other-$(date +%s)"      # cross-bucket permission tests
VBUCKET="versioned-$(date +%s)"  # versioning tests

# ─── Pretty output ───────────────────────────────────────────────────────────
if [ -t 1 ]; then
    GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
else
    GREEN=""; RED=""; YELLOW=""; BOLD=""; DIM=""; RESET=""
fi

TOTAL=73
STEP=0
PASS=0
FAIL=0
FAILED_TESTS=()

info()  { printf '%s\n' "${DIM}$*${RESET}"; }
fatal() { printf '%s\n' "${RED}${BOLD}FATAL:${RESET} $*" >&2; exit 1; }

# run_bg cmd args... — runs a test command in the background, its output in
# $TEST_OUT, and waits for it. Background commands ignore SIGINT, so Ctrl+C
# reaches only this script, whose INT trap interrupts the `wait` and aborts the
# run. (In the foreground, clients that handle Ctrl+C themselves — s3cmd and
# aws-cli exit 130 — make bash ignore the signal, so the run would just carry on
# with the next test.)
TEST_OUT="$WORK_DIR/test.out"
TEST_PID=""
run_bg() {
    "$@" >"$TEST_OUT" 2>&1 &
    TEST_PID=$!
    wait "$TEST_PID"
    local rc=$?
    TEST_PID=""
    return "$rc"
}

# kill_tree <pid> — kills a process and all its descendants.
kill_tree() {
    local child
    for child in $(pgrep -P "$1"); do kill_tree "$child"; done
    kill "$1" 2>/dev/null
}

# run_test "description" cmd args...
run_test() {
    local desc="$1"; shift
    STEP=$((STEP + 1))
    printf '%s' "${BOLD}[${STEP}/${TOTAL}]${RESET} ${desc} ... "
    if run_bg "$@"; then
        printf '%s\n' "${GREEN}OK${RESET}"
        PASS=$((PASS + 1))
        return 0
    else
        printf '%s\n' "${RED}FAIL${RESET}"
        printf '%s\n' "${DIM}      cmd: $*${RESET}"
        sed 's/^/      /' "$TEST_OUT"
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
    if run_bg "$@"; then
        printf '%s\n' "${RED}FAIL (command unexpectedly succeeded)${RESET}"
        sed 's/^/      /' "$TEST_OUT"
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
    trap '' INT TERM   # don't let a second Ctrl+C cut the cleanup short
    info ""
    info "Cleaning up..."
    [ -n "$TEST_PID" ] && kill_tree "$TEST_PID"
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null
    fi
    podman rm -f "$PG_CONTAINER" >/dev/null 2>&1
    rm -rf "$WORK_DIR"
}
# On Ctrl+C / SIGTERM, exit (running cleanup via the EXIT trap) rather than
# continuing with the next test against a torn-down environment.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ─── Preflight ───────────────────────────────────────────────────────────────
for tool in podman cargo s3cmd curl openssl python3 mcli aws; do
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

# ─── 2. Roles ────────────────────────────────────────────────────────────────
# Roles live in Postgres and are managed with `cairn role`, so set them up before
# the server starts. testkey is an admin (bucket management); since grants need
# an existing bucket, it's granted read/write on each test bucket right after
# creating it (mb_granted). The others exercise permission checks: reader can
# only read $BUCKET, writer can only use $OBUCKET (both granted once those
# exist), and bucketadmin can manage buckets but holds no grants.
cairn_role() { (cd "$SCRIPT_DIR" && cargo run -q -- role --database "$DB_URL" "$@"); }
info "Creating roles..."
{
    cairn_role create "$ACCESS_KEY" --admin --secret "$SECRET_KEY" &&
    cairn_role create reader --secret readersecret &&
    cairn_role create writer --secret writersecret &&
    cairn_role create bucketadmin --admin --secret adminsecret
} >"$WORK_DIR/roles.log" 2>&1 || { cat "$WORK_DIR/roles.log" >&2; fatal "could not create roles"; }

# ─── 2b. Run the server ───────────────────────────────────────────────────────
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

# ─── 3. Client configuration ─────────────────────────────────────────────────
# s3cmd (SigV4)
S3CFG="$WORK_DIR/s3cfg"
cat >"$S3CFG" <<EOF
[default]
access_key = ${ACCESS_KEY}
secret_key = ${SECRET_KEY}
host_base = ${SERVER_HOST}:${SERVER_PORT}
host_bucket = ${SERVER_HOST}:${SERVER_PORT}
use_https = False
signature_v2 = False
signurl_use_https = False
EOF
s3() { s3cmd --config "$S3CFG" "$@"; }

# aws-cli (SigV4), path-style addressing against our endpoint.
AWSCFG="$WORK_DIR/awscfg"
cat >"$AWSCFG" <<EOF
[default]
region = us-east-1
s3 =
    addressing_style = path
EOF
# as_role <access-key> <secret> <aws args...> — aws-cli under a given role.
as_role() {
    local key="$1" secret="$2"; shift 2
    AWS_ACCESS_KEY_ID="$key" AWS_SECRET_ACCESS_KEY="$secret" \
    AWS_DEFAULT_REGION=us-east-1 AWS_EC2_METADATA_DISABLED=true AWS_CONFIG_FILE="$AWSCFG" \
    aws --endpoint-url "http://${SERVER_HOST}:${SERVER_PORT}" "$@"
}
awss3() { as_role "$ACCESS_KEY" "$SECRET_KEY" "$@"; }

# mcli (minio-go, what Mimir uses)
MCFG="$WORK_DIR/mc"

# A python SigV4 signer for the few requests no real client can produce: mode-3
# trailer bodies, deliberately-malformed integrity claims, and precise pagination
# control. It signs whatever headers it's handed so the server's verification has
# something valid to check.
SIGNER="$WORK_DIR/sign.py"
cat >"$SIGNER" <<'PYEOF'
import os, sys, hashlib, hmac
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

method, url, payload_hash = sys.argv[1], sys.argv[2], sys.argv[3]
extra = sys.argv[4:]
secret, region, service, akid = "cairnsecret", "us-east-1", "s3", "testkey"

u = urlsplit(url)
host, path, query = u.netloc, (u.path or "/"), u.query
# SIGN_SKEW_SECS shifts the signing time, to test the server's clock-skew check.
now = datetime.now(timezone.utc) + timedelta(seconds=int(os.environ.get("SIGN_SKEW_SECS", "0")))
amzdate, datestamp = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")

headers = {"host": host, "x-amz-content-sha256": payload_hash, "x-amz-date": amzdate}
for e in extra:
    n, _, v = e.partition(":")
    headers[n.strip().lower()] = v.strip()

signed_headers = ";".join(sorted(headers))
canonical_headers = "".join(f"{k}:{headers[k]}\n" for k in sorted(headers))

pairs = []
for p in query.split("&") if query else []:
    k, _, v = p.partition("=")
    pairs.append((k, v))
pairs.sort()
cq = "&".join(f"{k}={v}" for k, v in pairs)

canonical_request = f"{method}\n{path}\n{cq}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

def mac(k, m): return hmac.new(k, m.encode(), hashlib.sha256).digest()
k = mac(("AWS4" + secret).encode(), datestamp)
k = mac(k, region); k = mac(k, service); k = mac(k, "aws4_request")
scope = f"{datestamp}/{region}/{service}/aws4_request"
sts = f"AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}"
sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()

print(f"x-amz-date: {amzdate}")
print(f"x-amz-content-sha256: {payload_hash}")
print(f"Authorization: AWS4-HMAC-SHA256 Credential={akid}/{scope}, SignedHeaders={signed_headers}, Signature={sig}")
for e in extra:
    print(e)
PYEOF

# scurl <method> <pathquery> <payload-hash> <bodyfile|-> [extra "Header: val"...]
# Signs the request and runs curl, printing the HTTP status code.
scurl() {
    local method="$1" pathquery="$2" phash="$3" body="$4"; shift 4
    local url="http://${SERVER_HOST}:${SERVER_PORT}${pathquery}" args=() line
    while IFS= read -r line; do args+=(-H "$line"); done \
        < <(python3 "$SIGNER" "$method" "$url" "$phash" "$@")
    if [ "$body" = "-" ]; then
        curl -s -o /dev/null -w '%{http_code}' -X "$method" "${args[@]}" "$url"
    else
        curl -s -o /dev/null -w '%{http_code}' -X "$method" --data-binary "@$body" "${args[@]}" "$url"
    fi
}

# scurl_get <pathquery> [extra...] — signed GET, prints the response body.
scurl_get() {
    local pathquery="$1"; shift
    local url="http://${SERVER_HOST}:${SERVER_PORT}${pathquery}" args=() line
    while IFS= read -r line; do args+=(-H "$line"); done \
        < <(python3 "$SIGNER" GET "$url" "$EMPTY_SHA256" "$@")
    curl -fsS "${args[@]}" "$url"
}

# mb_granted <bucket> — creates a bucket as testkey, then grants testkey
# read/write on it: admin alone allows no object access.
mb_granted() {
    s3 mb "s3://$1" >/dev/null 2>&1 || return 1
    cairn_role grant "$ACCESS_KEY" "$1" read write
}

# ─── 4. Test fixtures ────────────────────────────────────────────────────────
SMALL="$WORK_DIR/small.txt"
BIG="$WORK_DIR/big.bin"
NESTED="$WORK_DIR/nested.txt"
MULTIPART="$WORK_DIR/multi.bin"
printf 'hello from the smoke test\n' >"$SMALL"
dd if=/dev/urandom of="$BIG" bs=1M count=4 status=none
printf 'nested object content\n' >"$NESTED"
dd if=/dev/urandom of="$MULTIPART" bs=1M count=16 status=none

check_roundtrip() {  # check_roundtrip <local> <s3uri>
    local src="$1" uri="$2" dst="$WORK_DIR/dl.$RANDOM"
    s3 get "$uri" "$dst" >/dev/null 2>&1 || return 1
    cmp -s "$src" "$dst"
}

list_contains() {    # list_contains <s3 ls target> <needle>
    s3 ls "$1" 2>/dev/null | grep -qF "$2"
}

unsigned_rejected() {  # an unsigned request must be refused
    [ "$(curl -s -o /dev/null -w '%{http_code}' \
        "http://${SERVER_HOST}:${SERVER_PORT}/${BUCKET}/small.txt")" = 403 ]
}

# A correctly signed request whose x-amz-date is outside the 15-minute skew
# window (either way) is refused, so a captured request can't be replayed later;
# one just inside the window is accepted.
stale_request_rejected() {
    [ "$(SIGN_SKEW_SECS=-1200 scurl GET "/${BUCKET}/small.txt" "$EMPTY_SHA256" -)" = 403 ] || return 1
    [ "$(SIGN_SKEW_SECS=1200 scurl GET "/${BUCKET}/small.txt" "$EMPTY_SHA256" -)" = 403 ] || return 1
    [ "$(SIGN_SKEW_SECS=-600 scurl GET "/${BUCKET}/small.txt" "$EMPTY_SHA256" -)" = 200 ]
}

# Ranged GET via aws-cli, content compared to the expected slice.
range_ok() {  # range_ok <key> <start> <end> <localfile>
    local key="$1" start="$2" end="$3" src="$4" out="$WORK_DIR/r.$RANDOM"
    awss3 s3api get-object --bucket "$BUCKET" --key "$key" \
        --range "bytes=${start}-${end}" "$out" >/dev/null 2>&1 || return 1
    cmp -s "$out" <(tail -c "+$((start + 1))" "$src" | head -c "$((end - start + 1))")
}

# ─── CopyObject / UploadPartCopy (server-side copy) ──────────────────────────
# Each helper removes the object(s) it creates; as elsewhere, that final delete
# is the test's success condition (after the `|| return 1` guards).

# CopyObject: a server-side copy of a small object matches the source.
copy_small_ok() {
    awss3 s3api copy-object --bucket "$BUCKET" --key copy/small.txt \
        --copy-source "${BUCKET}/small.txt" >/dev/null 2>&1 || return 1
    check_roundtrip "$SMALL" "s3://${BUCKET}/copy/small.txt" || return 1
    awss3 s3api delete-object --bucket "$BUCKET" --key copy/small.txt >/dev/null 2>&1
}

# CopyObject of a multipart-uploaded source produces a *normal* object: the
# content matches and the ETag is a plain 32-hex MD5 (no multipart "-N" suffix).
copy_multipart_source_normal_ok() {
    awss3 s3api copy-object --bucket "$BUCKET" --key copy/multi.bin \
        --copy-source "${BUCKET}/multi.bin" >/dev/null 2>&1 || return 1
    check_roundtrip "$MULTIPART" "s3://${BUCKET}/copy/multi.bin" || return 1
    local etag
    etag=$(awss3 s3api head-object --bucket "$BUCKET" --key copy/multi.bin \
        --query ETag --output text 2>/dev/null) || return 1
    etag=${etag//\"/}
    [[ "$etag" =~ ^[0-9a-f]{32}$ ]] || return 1
    awss3 s3api delete-object --bucket "$BUCKET" --key copy/multi.bin >/dev/null 2>&1
}

# CopyObject with metadata-directive REPLACE overrides the content-type.
copy_replace_content_type_ok() {
    awss3 s3api copy-object --bucket "$BUCKET" --key copy/typed.txt \
        --copy-source "${BUCKET}/small.txt" \
        --metadata-directive REPLACE --content-type text/x-cairn >/dev/null 2>&1 || return 1
    awss3 s3api head-object --bucket "$BUCKET" --key copy/typed.txt \
        --query ContentType --output text 2>/dev/null | grep -qx text/x-cairn || return 1
    awss3 s3api delete-object --bucket "$BUCKET" --key copy/typed.txt >/dev/null 2>&1
}

# UploadPartCopy: assemble a destination by copying the whole source as a single
# part through a multipart upload; the result matches the source.
upload_part_copy_whole_ok() {
    local dest="upc/whole.bin" uid etag
    uid=$(awss3 s3api create-multipart-upload --bucket "$BUCKET" --key "$dest" \
        --query UploadId --output text 2>/dev/null) || return 1
    etag=$(awss3 s3api upload-part-copy --bucket "$BUCKET" --key "$dest" \
        --part-number 1 --upload-id "$uid" --copy-source "${BUCKET}/big.bin" \
        --query 'CopyPartResult.ETag' --output text 2>/dev/null) || return 1
    etag=${etag//\"/}
    awss3 s3api complete-multipart-upload --bucket "$BUCKET" --key "$dest" \
        --upload-id "$uid" \
        --multipart-upload "{\"Parts\":[{\"PartNumber\":1,\"ETag\":\"${etag}\"}]}" >/dev/null 2>&1 || return 1
    check_roundtrip "$BIG" "s3://${BUCKET}/${dest}" || return 1
    awss3 s3api delete-object --bucket "$BUCKET" --key "$dest" >/dev/null 2>&1
}

# UploadPartCopy with copy-source-range: build a destination from two byte ranges
# of a multipart source (the split crosses its internal part boundaries), then
# complete. The reassembled object matches the whole source.
upload_part_copy_ranged_ok() {
    local dest="upc/ranged.bin" uid e1 e2 size half
    size=$(wc -c <"$MULTIPART"); half=$((size / 2))
    uid=$(awss3 s3api create-multipart-upload --bucket "$BUCKET" --key "$dest" \
        --query UploadId --output text 2>/dev/null) || return 1
    e1=$(awss3 s3api upload-part-copy --bucket "$BUCKET" --key "$dest" \
        --part-number 1 --upload-id "$uid" --copy-source "${BUCKET}/multi.bin" \
        --copy-source-range "bytes=0-$((half - 1))" \
        --query 'CopyPartResult.ETag' --output text 2>/dev/null) || return 1
    e2=$(awss3 s3api upload-part-copy --bucket "$BUCKET" --key "$dest" \
        --part-number 2 --upload-id "$uid" --copy-source "${BUCKET}/multi.bin" \
        --copy-source-range "bytes=${half}-$((size - 1))" \
        --query 'CopyPartResult.ETag' --output text 2>/dev/null) || return 1
    e1=${e1//\"/}; e2=${e2//\"/}
    awss3 s3api complete-multipart-upload --bucket "$BUCKET" --key "$dest" \
        --upload-id "$uid" \
        --multipart-upload "{\"Parts\":[{\"PartNumber\":1,\"ETag\":\"${e1}\"},{\"PartNumber\":2,\"ETag\":\"${e2}\"}]}" >/dev/null 2>&1 || return 1
    check_roundtrip "$MULTIPART" "s3://${BUCKET}/${dest}" || return 1
    awss3 s3api delete-object --bucket "$BUCKET" --key "$dest" >/dev/null 2>&1
}

# ─── Conditional requests (RFC 7232 if-* headers) ────────────────────────────
# Signed with scurl so we can assert exact status codes (304 / 412 / 200).

# Conditional GET on ETag: If-None-Match hit → 304, miss → 200; If-Match hit →
# 200, miss → 412.
conditional_get_etag_ok() {
    local etag zero='"00000000000000000000000000000000"'
    etag=$(awss3 s3api head-object --bucket "$BUCKET" --key small.txt \
        --query ETag --output text 2>/dev/null) || return 1
    etag=${etag//\"/}
    [ "$(scurl GET "/${BUCKET}/small.txt" "$EMPTY_SHA256" - "If-None-Match: \"$etag\"")" = 304 ] || return 1
    [ "$(scurl GET "/${BUCKET}/small.txt" "$EMPTY_SHA256" - "If-None-Match: $zero")" = 200 ] || return 1
    [ "$(scurl GET "/${BUCKET}/small.txt" "$EMPTY_SHA256" - "If-Match: \"$etag\"")" = 200 ] || return 1
    [ "$(scurl GET "/${BUCKET}/small.txt" "$EMPTY_SHA256" - "If-Match: $zero")" = 412 ]
}

# Conditional GET on dates: not-modified-since a future date → 304; modified
# since 1970 → 200; unmodified-since 1970 → 412; unmodified-since future → 200.
conditional_get_date_ok() {
    local past="Thu, 01 Jan 1970 00:00:00 GMT" future="Sat, 01 Jan 2050 00:00:00 GMT"
    [ "$(scurl GET "/${BUCKET}/small.txt" "$EMPTY_SHA256" - "If-Modified-Since: $future")" = 304 ] || return 1
    [ "$(scurl GET "/${BUCKET}/small.txt" "$EMPTY_SHA256" - "If-Modified-Since: $past")" = 200 ] || return 1
    [ "$(scurl GET "/${BUCKET}/small.txt" "$EMPTY_SHA256" - "If-Unmodified-Since: $past")" = 412 ] || return 1
    [ "$(scurl GET "/${BUCKET}/small.txt" "$EMPTY_SHA256" - "If-Unmodified-Since: $future")" = 200 ]
}

# Conditional copy: x-amz-copy-source-if-match against the source ETag — a wrong
# tag blocks the copy (412 → aws errors), the right tag lets it through.
conditional_copy_ok() {
    local etag
    etag=$(awss3 s3api head-object --bucket "$BUCKET" --key small.txt \
        --query ETag --output text 2>/dev/null) || return 1
    etag=${etag//\"/}
    ! awss3 s3api copy-object --bucket "$BUCKET" --key copy/cond.txt \
        --copy-source "${BUCKET}/small.txt" \
        --copy-source-if-match 00000000000000000000000000000000 >/dev/null 2>&1 || return 1
    awss3 s3api copy-object --bucket "$BUCKET" --key copy/cond.txt \
        --copy-source "${BUCKET}/small.txt" \
        --copy-source-if-match "$etag" >/dev/null 2>&1 || return 1
    check_roundtrip "$SMALL" "s3://${BUCKET}/copy/cond.txt" || return 1
    awss3 s3api delete-object --bucket "$BUCKET" --key copy/cond.txt >/dev/null 2>&1
}

# Conditional PUT (crafted with scurl for exact codes): If-None-Match:* is
# create-if-absent (200 then 412); If-Match is compare-and-swap (200 on the
# current tag, 412 on a wrong one).
conditional_put_ok() {
    local key="cput-$RANDOM" etag zero='"00000000000000000000000000000000"'
    [ "$(scurl PUT "/${BUCKET}/${key}" UNSIGNED-PAYLOAD "$SMALL" "If-None-Match: *")" = 200 ] || return 1
    [ "$(scurl PUT "/${BUCKET}/${key}" UNSIGNED-PAYLOAD "$SMALL" "If-None-Match: *")" = 412 ] || return 1
    etag=$(awss3 s3api head-object --bucket "$BUCKET" --key "$key" \
        --query ETag --output text 2>/dev/null) || return 1
    etag=${etag//\"/}
    [ "$(scurl PUT "/${BUCKET}/${key}" UNSIGNED-PAYLOAD "$SMALL" "If-Match: \"$etag\"")" = 200 ] || return 1
    [ "$(scurl PUT "/${BUCKET}/${key}" UNSIGNED-PAYLOAD "$SMALL" "If-Match: $zero")" = 412 ] || return 1
    awss3 s3api delete-object --bucket "$BUCKET" --key "$key" >/dev/null 2>&1
}

# Conditional CompleteMultipartUpload: If-None-Match:* is create-if-absent — the
# first completion creates the object (200), a second one to the same key is
# rejected (412). Uses scurl for the complete POST to assert exact codes.
conditional_complete_ok() {
    local key="cmu-$RANDOM" uid etag xml="$WORK_DIR/cmu.xml"
    complete_once() {  # complete_once <expected-code>; echoes nothing, returns status
        uid=$(awss3 s3api create-multipart-upload --bucket "$BUCKET" --key "$key" \
            --query UploadId --output text 2>/dev/null) || return 1
        etag=$(awss3 s3api upload-part --bucket "$BUCKET" --key "$key" \
            --part-number 1 --upload-id "$uid" --body "$SMALL" \
            --query ETag --output text 2>/dev/null) || return 1
        etag=${etag//\"/}
        printf '<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"%s"</ETag></Part></CompleteMultipartUpload>' \
            "$etag" >"$xml"
        [ "$(scurl POST "/${BUCKET}/${key}?uploadId=${uid}" UNSIGNED-PAYLOAD "$xml" "If-None-Match: *")" = "$1" ]
    }
    complete_once 200 || return 1
    # Second upload to the now-existing key: its conditional completion is refused,
    # leaving the upload staged — abort it as cleanup.
    complete_once 412 || { awss3 s3api abort-multipart-upload --bucket "$BUCKET" --key "$key" --upload-id "$uid" >/dev/null 2>&1; return 1; }
    awss3 s3api abort-multipart-upload --bucket "$BUCKET" --key "$key" --upload-id "$uid" >/dev/null 2>&1
    awss3 s3api delete-object --bucket "$BUCKET" --key "$key" >/dev/null 2>&1
}

# Mode 2: whole-body SHA-256. Correct hash accepted + round-trips; wrong → 400.
content_sha256_ok() {
    local sha
    sha=$(openssl dgst -sha256 "$NESTED" | awk '{print $NF}')
    [ "$(scurl PUT "/${BUCKET}/cs-good.txt" "$sha" "$NESTED")" = 200 ] || return 1
    check_roundtrip "$NESTED" "s3://${BUCKET}/cs-good.txt" || return 1
    local wrong="0000000000000000000000000000000000000000000000000000000000000000"
    [ "$(scurl PUT "/${BUCKET}/cs-bad.txt" "$wrong" "$NESTED")" = 400 ] || return 1
    awss3 s3api delete-object --bucket "$BUCKET" --key cs-good.txt >/dev/null 2>&1
}

# Mode 3: STREAMING-UNSIGNED-PAYLOAD-TRAILER with a CRC32 trailer. Correct CRC
# accepted + round-trips; wrong CRC → 400. No real client emits mode 3, so the
# body is crafted and signed with scurl.
streaming_trailer_ok() {
    local body="$WORK_DIR/st.body" size hexsize crc
    size=$(wc -c <"$NESTED"); hexsize=$(printf '%x' "$size")
    crc=$(python3 -c "import zlib,base64,sys;print(base64.b64encode(zlib.crc32(open(sys.argv[1],'rb').read()).to_bytes(4,'big')).decode())" "$NESTED")
    local h=(STREAMING-UNSIGNED-PAYLOAD-TRAILER "$body"
        "Content-Encoding: aws-chunked" "x-amz-trailer: x-amz-checksum-crc32"
        "x-amz-decoded-content-length: ${size}")
    { printf '%s\r\n' "$hexsize"; cat "$NESTED"; printf '\r\n0\r\nx-amz-checksum-crc32:%s\r\n\r\n' "$crc"; } >"$body"
    [ "$(scurl PUT "/${BUCKET}/st-good.txt" "${h[@]}")" = 200 ] || return 1
    check_roundtrip "$NESTED" "s3://${BUCKET}/st-good.txt" || return 1
    { printf '%s\r\n' "$hexsize"; cat "$NESTED"; printf '\r\n0\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n'; } >"$body"
    [ "$(scurl PUT "/${BUCKET}/st-bad.txt" "${h[@]}")" = 400 ] || return 1
    awss3 s3api delete-object --bucket "$BUCKET" --key st-good.txt >/dev/null 2>&1
}

# Mode 4 via mcli — minio-go, the exact client Mimir uses. The good-secret cp
# streams STREAMING-AWS4-HMAC-SHA256-PAYLOAD with per-chunk signatures, exercising
# both the seed signature and the chunk chain end-to-end. The wrong secret is
# rejected (mcli validates credentials with a signed request on `alias set`).
mc_streaming_ok() {
    local host="http://${SERVER_HOST}:${SERVER_PORT}"
    mcli --config-dir "$MCFG" alias set good "$host" "$ACCESS_KEY" cairnsecret >/dev/null 2>&1 || return 1
    mcli --config-dir "$MCFG" cp "$NESTED" "good/${BUCKET}/mc-good.txt" >/dev/null 2>&1 || return 1
    check_roundtrip "$NESTED" "s3://${BUCKET}/mc-good.txt" || return 1
    ! mcli --config-dir "$MCFG" alias set bad "$host" "$ACCESS_KEY" wrongsecret123 >/dev/null 2>&1 || return 1
    mcli --config-dir "$MCFG" rm "good/${BUCKET}/mc-good.txt" >/dev/null 2>&1
}

# ─── Pagination: signed GETs (scurl) so we control max-keys/tokens precisely ──

list_v2_keys() {  # list_v2_keys <prefix> <max-keys>
    local prefix="$1" mk="$2" token="" q resp
    while :; do
        q="/${PBUCKET}?list-type=2&max-keys=${mk}&prefix=${prefix}"
        [ -n "$token" ] && q="${q}&continuation-token=${token}"
        resp="$(scurl_get "$q")" || return 1
        printf '%s' "$resp" | grep -oP '(?<=<Key>).*?(?=</Key>)'
        printf '%s' "$resp" | grep -q '<IsTruncated>true</IsTruncated>' || break
        token="$(printf '%s' "$resp" | grep -oP '(?<=<NextContinuationToken>).*?(?=</NextContinuationToken>)')"
        [ -n "$token" ] || return 1
    done
}

list_v1_keys() {  # list_v1_keys <prefix> <max-keys>
    local prefix="$1" mk="$2" marker="" q resp
    while :; do
        q="/${PBUCKET}?max-keys=${mk}&prefix=${prefix}"
        [ -n "$marker" ] && q="${q}&marker=${marker}"
        resp="$(scurl_get "$q")" || return 1
        printf '%s' "$resp" | grep -oP '(?<=<Key>).*?(?=</Key>)'
        printf '%s' "$resp" | grep -q '<IsTruncated>true</IsTruncated>' || break
        marker="$(printf '%s' "$resp" | grep -oP '(?<=<NextMarker>).*?(?=</NextMarker>)')"
        [ -n "$marker" ] || return 1
    done
}

list_v2_common_prefixes() {  # list_v2_common_prefixes <prefix> <max-keys>
    local prefix="$1" mk="$2" token="" q resp
    while :; do
        q="/${PBUCKET}?list-type=2&max-keys=${mk}&prefix=${prefix}&delimiter=/"
        [ -n "$token" ] && q="${q}&continuation-token=${token}"
        resp="$(scurl_get "$q")" || return 1
        printf '%s' "$resp" | grep -oP '<CommonPrefixes><Prefix>\K.*?(?=</Prefix>)'
        printf '%s' "$resp" | grep -q '<IsTruncated>true</IsTruncated>' || break
        token="$(printf '%s' "$resp" | grep -oP '(?<=<NextContinuationToken>).*?(?=</NextContinuationToken>)')"
        [ -n "$token" ] || return 1
    done
}

setup_pagination() {
    mb_granted "$PBUCKET" >/dev/null 2>&1 || return 1
    local k
    for k in flat/obj0 flat/obj1 flat/obj2 flat/obj3 flat/obj4 \
             tree/d1/x tree/d1/y tree/d2/x; do
        printf 'content of %s\n' "$k" >"$WORK_DIR/pf"
        s3 put "$WORK_DIR/pf" "s3://${PBUCKET}/${k}" >/dev/null 2>&1 || return 1
    done
}

teardown_pagination() {
    # --force: s3cmd refuses a recursive bucket wipe without it (and does nothing).
    # rb then requires the bucket to be empty (DeleteBucket returns BucketNotEmpty
    # otherwise), so the recursive delete must actually succeed first.
    s3 del --recursive --force "s3://${PBUCKET}/" >/dev/null 2>&1
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

# ACL stub: get-object-acl reports owner cairn, and s3cmd info (which queries the
# ACL) completes instead of choking on object bytes.
acl_ok() {
    awss3 s3api get-object-acl --bucket "$BUCKET" --key big.bin 2>/dev/null | grep -q cairn || return 1
    s3 info "s3://${BUCKET}/big.bin" >/dev/null 2>&1
}

# Bucket sub-resource stubs: location/versioning succeed (200, empty config);
# policy/cors/tagging/lifecycle are "not configured" (the client errors on 404).
subresource_stubs_ok() {
    awss3 s3api get-bucket-location --bucket "$BUCKET" >/dev/null 2>&1 || return 1
    awss3 s3api get-bucket-versioning --bucket "$BUCKET" >/dev/null 2>&1 || return 1
    ! awss3 s3api get-bucket-policy --bucket "$BUCKET" >/dev/null 2>&1 || return 1
    ! awss3 s3api get-bucket-cors --bucket "$BUCKET" >/dev/null 2>&1 || return 1
    ! awss3 s3api get-bucket-tagging --bucket "$BUCKET" >/dev/null 2>&1 || return 1
    ! awss3 s3api get-bucket-lifecycle-configuration --bucket "$BUCKET" >/dev/null 2>&1 || return 1
}

# DeleteObjects via aws-cli — which sends an x-amz-checksum-crc32 (not Content-MD5).
# Removes the named keys (incl. an absent one — idempotent), leaving others alone.
batch_delete_ok() {
    local k
    printf 'batch delete fixture\n' >"$WORK_DIR/bd"
    for k in bd1.txt bd2.txt bd3.txt; do
        s3 put "$WORK_DIR/bd" "s3://${BUCKET}/$k" >/dev/null 2>&1 || return 1
    done
    awss3 s3api delete-objects --bucket "$BUCKET" \
        --delete '{"Objects":[{"Key":"bd1.txt"},{"Key":"bd2.txt"},{"Key":"nope.txt"}]}' >/dev/null 2>&1 || return 1
    ! awss3 s3api head-object --bucket "$BUCKET" --key bd1.txt >/dev/null 2>&1 || return 1
    ! awss3 s3api head-object --bucket "$BUCKET" --key bd2.txt >/dev/null 2>&1 || return 1
    awss3 s3api head-object --bucket "$BUCKET" --key bd3.txt >/dev/null 2>&1 || return 1
    awss3 s3api delete-object --bucket "$BUCKET" --key bd3.txt >/dev/null 2>&1
}

# DeleteBucket refuses a non-empty bucket. S3 returns 409 BucketNotEmpty; without
# the emptiness guard the buckets->objects ON DELETE CASCADE would silently wipe
# every object. Assert the exact codes with scurl, confirm the object survives the
# rejected delete, then empty the bucket and delete it cleanly (204). Self-contained
# throwaway bucket so it's independent of the main fixtures.
delete_nonempty_bucket_rejected() {
    local nb="$NBUCKET"
    mb_granted "$nb" >/dev/null 2>&1 || return 1
    s3 put "$SMALL" "s3://${nb}/keep.txt" >/dev/null 2>&1 || return 1
    [ "$(scurl DELETE "/${nb}" "$EMPTY_SHA256" -)" = 409 ] || return 1
    check_roundtrip "$SMALL" "s3://${nb}/keep.txt" || return 1
    s3 del "s3://${nb}/keep.txt" >/dev/null 2>&1 || return 1
    [ "$(scurl DELETE "/${nb}" "$EMPTY_SHA256" -)" = 204 ]
}

# DeleteObjects integrity/existence guards (crafted, signed with scurl): no
# integrity header → 400, a wrong CRC32 → 400, a valid Content-MD5 (minio-go's
# path) → 200, and a well-formed request against a missing bucket → 403: no role
# can hold a grant on a missing bucket, so it can't tell whether it exists.
batch_delete_guards_ok() {
    local body="$WORK_DIR/del.xml" md5
    printf '<Delete><Object><Key>whatever.txt</Key></Object></Delete>' >"$body"
    md5="$(openssl dgst -md5 -binary "$body" | base64)"
    [ "$(scurl POST "/${BUCKET}?delete" UNSIGNED-PAYLOAD "$body")" = 400 ] || return 1
    [ "$(scurl POST "/${BUCKET}?delete" UNSIGNED-PAYLOAD "$body" "x-amz-checksum-crc32: AAAAAA==")" = 400 ] || return 1
    [ "$(scurl POST "/${BUCKET}?delete" UNSIGNED-PAYLOAD "$body" "Content-MD5: ${md5}")" = 200 ] || return 1
    [ "$(scurl POST "/no-such-bucket-xyz?delete" UNSIGNED-PAYLOAD "$body" "Content-MD5: ${md5}")" = 403 ] || return 1
}

# Immediate part reaping: after deleting objects, their on-disk part files should
# disappear WITHOUT running prune (the happy-path optimization). We can't map keys
# to part files, so we check the data-dir file count returns to its pre-upload
# baseline (single node, RF=1, so the coordinator reaps its own files). Polls,
# since the reap runs in the background.
immediate_reap_ok() {
    local datadir="$WORK_DIR/data" before after k i
    before=$(find "$datadir" -type f | wc -l)
    for k in r1 r2 r3; do s3 put "$NESTED" "s3://${BUCKET}/reap/$k" >/dev/null 2>&1 || return 1; done
    for k in r1 r2 r3; do s3 del "s3://${BUCKET}/reap/$k" >/dev/null 2>&1 || return 1; done
    for i in $(seq 1 20); do
        after=$(find "$datadir" -type f | wc -l)
        [ "$after" -le "$before" ] && return 0
        sleep 0.5
    done
    return 1
}

# Multipart cleanup reaps too: an aborted upload's staged parts, and the staged
# parts a completion leaves out, are deleted from disk without a prune. Stages two
# parts, aborts; stages two more, completes with only the first, deletes the
# result; then waits for the part-file count to return to its starting point.
multipart_reap_ok() {
    local datadir="$WORK_DIR/data" before after uid e1 i
    before=$(find "$datadir" -type f | wc -l)
    uid=$(awss3 s3api create-multipart-upload --bucket "$BUCKET" --key reap/mpu \
        --query UploadId --output text 2>/dev/null) || return 1
    for i in 1 2; do
        awss3 s3api upload-part --bucket "$BUCKET" --key reap/mpu --upload-id "$uid" \
            --part-number $i --body "$NESTED" >/dev/null 2>&1 || return 1
    done
    awss3 s3api abort-multipart-upload --bucket "$BUCKET" --key reap/mpu \
        --upload-id "$uid" >/dev/null 2>&1 || return 1
    uid=$(awss3 s3api create-multipart-upload --bucket "$BUCKET" --key reap/mpu \
        --query UploadId --output text 2>/dev/null) || return 1
    e1=$(awss3 s3api upload-part --bucket "$BUCKET" --key reap/mpu --upload-id "$uid" \
        --part-number 1 --body "$NESTED" --query ETag --output text 2>/dev/null) || return 1
    awss3 s3api upload-part --bucket "$BUCKET" --key reap/mpu --upload-id "$uid" \
        --part-number 2 --body "$NESTED" >/dev/null 2>&1 || return 1
    e1=${e1//\"/}
    awss3 s3api complete-multipart-upload --bucket "$BUCKET" --key reap/mpu \
        --upload-id "$uid" \
        --multipart-upload "{\"Parts\":[{\"PartNumber\":1,\"ETag\":\"${e1}\"}]}" >/dev/null 2>&1 || return 1
    s3 del "s3://${BUCKET}/reap/mpu" >/dev/null 2>&1 || return 1
    for i in $(seq 1 20); do
        after=$(find "$datadir" -type f | wc -l)
        [ "$after" -le "$before" ] && return 0
        sleep 0.5
    done
    return 1
}

# ─── Versioning helpers ───
# vput <key> <file> — PUT into $VBUCKET, printing the reported VersionId.
vput() {
    awss3 s3api put-object --bucket "$VBUCKET" --key "$1" --body "$2" \
        --query VersionId --output text 2>/dev/null
}
# vget_is <key> <expected-file> [version] — the (given version of the) key reads
# back as exactly <expected-file>.
vget_is() {
    awss3 s3api get-object --bucket "$VBUCKET" --key "$1" ${3:+--version-id "$3"} \
        "$WORK_DIR/vget.out" >/dev/null 2>&1 && cmp -s "$2" "$WORK_DIR/vget.out"
}
# vdel <key> [version] — DELETE, printing "<DeleteMarker>\t<VersionId>".
vdel() {
    awss3 s3api delete-object --bucket "$VBUCKET" --key "$1" ${2:+--version-id "$2"} \
        --query '[DeleteMarker,VersionId]' --output text 2>/dev/null
}

# A new bucket reports no versioning state. Changing it is bucket management
# (admin-only), so writer, holding read/write, can't; the admin enables it and
# it reads back. testkey also gets delete-version here, for the tests below.
versioning_enable_ok() {
    mb_granted "$VBUCKET" || return 1
    cairn_role grant "$ACCESS_KEY" "$VBUCKET" delete-version >/dev/null 2>&1 || return 1
    cairn_role grant writer "$VBUCKET" read write >/dev/null 2>&1 || return 1
    [ "$(awss3 s3api get-bucket-versioning --bucket "$VBUCKET" \
        --query Status --output text 2>/dev/null)" = "None" ] || return 1
    ! as_role writer writersecret s3api put-bucket-versioning --bucket "$VBUCKET" \
        --versioning-configuration Status=Enabled >/dev/null 2>&1 || return 1
    awss3 s3api put-bucket-versioning --bucket "$VBUCKET" \
        --versioning-configuration Status=Enabled >/dev/null 2>&1 || return 1
    [ "$(awss3 s3api get-bucket-versioning --bucket "$VBUCKET" \
        --query Status --output text 2>/dev/null)" = "Enabled" ]
}

# An overwrite in an enabled bucket keeps the old version: each PUT reports a
# fresh VersionId, a plain GET reads the newest, and the old one stays readable
# by its ID (HEAD reports it back too).
versioned_overwrite_ok() {
    local v1 v2
    v1=$(vput ow "$SMALL") && v2=$(vput ow "$NESTED") || return 1
    [ -n "$v1" ] && [ "$v1" != "None" ] && [ "$v1" != "null" ] && [ "$v1" != "$v2" ] || return 1
    vget_is ow "$NESTED" || return 1
    vget_is ow "$SMALL" "$v1" || return 1
    [ "$(awss3 s3api head-object --bucket "$VBUCKET" --key ow --version-id "$v1" \
        --query VersionId --output text 2>/dev/null)" = "$v1" ]
}

# A plain DELETE adds a delete marker: the key reads as gone (404) and drops out
# of listings, but its data stays readable by version ID. Reading the marker
# itself by ID is a 405, as in S3.
delete_marker_ok() {
    local v1 out marker
    v1=$(vput dm "$SMALL") || return 1
    out=$(vdel dm) || return 1
    [ "${out%%$'\t'*}" = "True" ] || return 1
    marker=${out#*$'\t'}
    [ -n "$marker" ] && [ "$marker" != "$v1" ] || return 1
    awss3 s3api get-object --bucket "$VBUCKET" --key dm "$WORK_DIR/dm" 2>&1 | grep -q NoSuchKey || return 1
    [ "$(awss3 s3api list-objects-v2 --bucket "$VBUCKET" --prefix dm \
        --query 'length(Contents || `[]`)' --output text 2>/dev/null)" = "0" ] || return 1
    vget_is dm "$SMALL" "$v1" || return 1
    awss3 s3api head-object --bucket "$VBUCKET" --key dm --version-id "$marker" 2>&1 | grep -q 405
}

# DELETE with a versionId removes that version for good; removing the current
# one promotes the next-newest. Peel a marker and two versions off one by one.
delete_version_promotes_ok() {
    local v1 v2 marker
    v1=$(vput pr "$SMALL") && v2=$(vput pr "$NESTED") || return 1
    marker=$(vdel pr) || return 1
    marker=${marker#*$'\t'}
    [ "$(vdel pr "$marker")" = "True"$'\t'"$marker" ] || return 1
    vget_is pr "$NESTED" || return 1
    vdel pr "$v2" >/dev/null || return 1
    vget_is pr "$SMALL" || return 1
    ! vget_is pr "$SMALL" "$v2" || return 1
    vdel pr "$v1" >/dev/null || return 1
    ! vget_is pr "$SMALL"
}

# Multipart uploads and copies create versions too, and report them.
versioned_multipart_copy_ok() {
    local v cv
    awss3 s3 cp "$MULTIPART" "s3://${VBUCKET}/mp" >/dev/null 2>&1 || return 1
    v=$(awss3 s3api head-object --bucket "$VBUCKET" --key mp \
        --query VersionId --output text 2>/dev/null) || return 1
    [ -n "$v" ] && [ "$v" != "None" ] && [ "$v" != "null" ] || return 1
    cv=$(awss3 s3api copy-object --bucket "$VBUCKET" --key mp-copy --copy-source "${VBUCKET}/mp" \
        --query VersionId --output text 2>/dev/null) || return 1
    [ -n "$cv" ] && [ "$cv" != "None" ] && [ "$cv" != "$v" ] || return 1
    vget_is mp-copy "$MULTIPART" "$cv"
}

# Suspending keeps existing versions but lands new writes on the single `null`
# version (an overwrite replaces it), and a DELETE swaps the null version for a
# null delete marker. Re-enables versioning afterwards.
versioning_suspended_ok() {
    local v1 out
    v1=$(vput su "$SMALL") || return 1
    awss3 s3api put-bucket-versioning --bucket "$VBUCKET" \
        --versioning-configuration Status=Suspended >/dev/null 2>&1 || return 1
    [ "$(awss3 s3api get-bucket-versioning --bucket "$VBUCKET" \
        --query Status --output text 2>/dev/null)" = "Suspended" ] || return 1
    [ "$(vput su "$NESTED")" = "null" ] || return 1
    [ "$(vput su "$BIG")" = "null" ] || return 1
    vget_is su "$BIG" || return 1
    vget_is su "$BIG" null || return 1
    vget_is su "$SMALL" "$v1" || return 1
    out=$(vdel su) || return 1
    [ "$out" = "True"$'\t'"null" ] || return 1
    ! vget_is su "$BIG" null || return 1
    vget_is su "$SMALL" "$v1" || return 1
    awss3 s3api put-bucket-versioning --bucket "$VBUCKET" \
        --versioning-configuration Status=Enabled >/dev/null 2>&1
}

# Removing a version for good needs the delete-version grant, so a role with
# only read/write (like a backup client) can't destroy history: writer may add a
# delete marker but not delete a version, by DeleteObject or DeleteObjects
# (where the entry fails with AccessDenied). testkey, holding the grant, can.
delete_version_needs_grant_ok() {
    local w=(as_role writer writersecret) v req
    v=$("${w[@]}" s3api put-object --bucket "$VBUCKET" --key perm --body "$SMALL" \
        --query VersionId --output text 2>/dev/null) || return 1
    ! "${w[@]}" s3api delete-object --bucket "$VBUCKET" --key perm --version-id "$v" >/dev/null 2>&1 || return 1
    req="{\"Objects\":[{\"Key\":\"perm\",\"VersionId\":\"$v\"}]}"
    [ "$("${w[@]}" s3api delete-objects --bucket "$VBUCKET" --delete "$req" \
        --query 'Errors[0].Code' --output text 2>/dev/null)" = "AccessDenied" ] || return 1
    vget_is perm "$SMALL" "$v" || return 1
    [ "$("${w[@]}" s3api delete-object --bucket "$VBUCKET" --key perm \
        --query DeleteMarker --output text 2>/dev/null)" = "True" ] || return 1
    vget_is perm "$SMALL" "$v" || return 1
    [ "$(awss3 s3api delete-objects --bucket "$VBUCKET" --delete "$req" \
        --query 'Deleted[0].VersionId' --output text 2>/dev/null)" = "$v" ] || return 1
    ! vget_is perm "$SMALL" "$v"
}

# ListObjectVersions lists every version and delete marker, keys ascending and
# each key's versions newest first, with the current one flagged IsLatest.
list_versions_ok() {
    local v1 v2 out
    v1=$(vput lv/a "$SMALL") && v2=$(vput lv/a "$NESTED") || return 1
    vdel lv/a >/dev/null || return 1
    vput lv/b "$SMALL" >/dev/null && vput lv/dir/c "$SMALL" >/dev/null || return 1
    out=$(awss3 s3api list-object-versions --bucket "$VBUCKET" --prefix lv/ \
        --query '[Versions[].[Key,VersionId,IsLatest], DeleteMarkers[].[Key,IsLatest]]' \
        --output text 2>/dev/null) || return 1
    [ "$out" = "lv/a	$v2	False
lv/a	$v1	False
lv/b	$(awss3 s3api head-object --bucket "$VBUCKET" --key lv/b --query VersionId --output text)	True
lv/dir/c	$(awss3 s3api head-object --bucket "$VBUCKET" --key lv/dir/c --query VersionId --output text)	True
lv/a	True" ] || { echo "$out"; return 1; }
    # A delimiter rolls lv/dir/ up into one common prefix.
    [ "$(awss3 s3api list-object-versions --bucket "$VBUCKET" --prefix lv/ --delimiter / \
        --query 'CommonPrefixes[].Prefix' --output text 2>/dev/null)" = "lv/dir/" ]
}

# Paging through ListObjectVersions with key-marker / version-id-marker (aws-cli
# follows NextKeyMarker / NextVersionIdMarker) yields exactly the full listing,
# for any page size, with and without a delimiter.
list_versions_paginates_ok() {
    local q='[Versions[].[Key,VersionId], DeleteMarkers[].[Key,VersionId], CommonPrefixes[].Prefix]'
    local full paged d n
    for d in "" "/"; do
        full=$(awss3 s3api list-object-versions --bucket "$VBUCKET" ${d:+--delimiter "$d"} \
            --query "$q" --output json 2>/dev/null) || return 1
        for n in 1 2 3; do
            paged=$(awss3 s3api list-object-versions --bucket "$VBUCKET" ${d:+--delimiter "$d"} \
                --page-size "$n" --query "$q" --output json 2>/dev/null) || return 1
            [ "$paged" = "$full" ] || { echo "page size $n, delimiter '$d' differs"; return 1; }
        done
    done
    # The pages above really were pages: one entry per request is truncated, and
    # hands back both markers.
    [ "$(awss3 s3api list-object-versions --bucket "$VBUCKET" --max-keys 1 --no-paginate \
        --query '[IsTruncated, NextKeyMarker != null, NextVersionIdMarker != null]' \
        --output text 2>/dev/null)" = "True	True	True" ] || return 1
    # A version-id-marker needs a key-marker.
    ! awss3 s3api list-object-versions --bucket "$VBUCKET" --version-id-marker x \
        --no-paginate >/dev/null 2>&1
}

# Copying a named source version: CopyObject onto the same key restores an old
# version as the new current one (reporting both version IDs), UploadPartCopy
# reads the named version too, and naming a delete marker as the source fails.
copy_source_version_ok() {
    local v1 v2 out cv marker uid etag
    v1=$(vput cs "$SMALL") && v2=$(vput cs "$NESTED") || return 1
    out=$(awss3 s3api copy-object --bucket "$VBUCKET" --key cs \
        --copy-source "${VBUCKET}/cs?versionId=${v1}" \
        --query '[CopySourceVersionId,VersionId]' --output text 2>/dev/null) || return 1
    [ "${out%%$'\t'*}" = "$v1" ] || return 1
    cv=${out#*$'\t'}
    [ "$cv" != "$v1" ] && [ "$cv" != "$v2" ] || return 1
    vget_is cs "$SMALL" || return 1
    vget_is cs "$NESTED" "$v2" || return 1
    uid=$(awss3 s3api create-multipart-upload --bucket "$VBUCKET" --key cs-mpu \
        --query UploadId --output text 2>/dev/null) || return 1
    out=$(awss3 s3api upload-part-copy --bucket "$VBUCKET" --key cs-mpu --upload-id "$uid" \
        --part-number 1 --copy-source "${VBUCKET}/cs?versionId=${v2}" \
        --query '[CopySourceVersionId,CopyPartResult.ETag]' --output text 2>/dev/null) || return 1
    [ "${out%%$'\t'*}" = "$v2" ] || return 1
    etag=${out#*$'\t'}; etag=${etag//\"/}
    awss3 s3api complete-multipart-upload --bucket "$VBUCKET" --key cs-mpu --upload-id "$uid" \
        --multipart-upload "{\"Parts\":[{\"PartNumber\":1,\"ETag\":\"${etag}\"}]}" >/dev/null 2>&1 || return 1
    vget_is cs-mpu "$NESTED" || return 1
    marker=$(vdel cs) || return 1
    marker=${marker#*$'\t'}
    awss3 s3api copy-object --bucket "$VBUCKET" --key cs2 \
        --copy-source "${VBUCKET}/cs?versionId=${marker}" 2>&1 | grep -q InvalidRequest || return 1
    awss3 s3api copy-object --bucket "$VBUCKET" --key cs2 \
        --copy-source "${VBUCKET}/cs" 2>&1 | grep -q NoSuchKey || return 1
    awss3 s3api copy-object --bucket "$VBUCKET" --key cs2 \
        --copy-source "${VBUCKET}/cs?versionId=nosuchversion" 2>&1 | grep -q NoSuchVersion
}

# An unversioned bucket lists its objects as `null` versions, all current.
list_versions_unversioned_ok() {
    local out
    awss3 s3api put-object --bucket "$BUCKET" --key unv-list.txt --body "$SMALL" >/dev/null 2>&1 || return 1
    out=$(awss3 s3api list-object-versions --bucket "$BUCKET" --prefix unv-list \
        --query 'Versions[].[Key,VersionId,IsLatest]' --output text 2>/dev/null) || return 1
    [ "$out" = "unv-list.txt	null	True" ] || return 1
    awss3 s3api delete-object --bucket "$BUCKET" --key unv-list.txt >/dev/null 2>&1
}

# Listing versions is a read: a role holding only `write` on the bucket can't.
# (The grant is revoked again, as later tests expect writer to have none here.)
list_versions_needs_read_ok() {
    cairn_role grant writer "$BUCKET" write >/dev/null 2>&1 || return 1
    ! as_role writer writersecret s3api list-object-versions --bucket "$BUCKET" >/dev/null 2>&1
    local rc=$?
    cairn_role revoke writer "$BUCKET" >/dev/null 2>&1 || return 1
    return "$rc"
}

# A bucket that has never been versioned reports no version IDs at all.
unversioned_no_version_id_ok() {
    [ "$(awss3 s3api put-object --bucket "$BUCKET" --key unv.txt --body "$SMALL" \
        --query VersionId --output text 2>/dev/null)" = "None" ] || return 1
    [ "$(awss3 s3api head-object --bucket "$BUCKET" --key unv.txt \
        --query VersionId --output text 2>/dev/null)" = "None" ] || return 1
    awss3 s3api delete-object --bucket "$BUCKET" --key unv.txt >/dev/null 2>&1
}

# Old versions and delete markers count as content: a bucket holding nothing
# but a delete marker can't be deleted until the marker is removed too.
versioned_bucket_not_empty_ok() {
    local b="dmonly-$(date +%s)" v marker
    mb_granted "$b" || return 1
    cairn_role grant "$ACCESS_KEY" "$b" delete-version >/dev/null 2>&1 || return 1
    awss3 s3api put-bucket-versioning --bucket "$b" \
        --versioning-configuration Status=Enabled >/dev/null 2>&1 || return 1
    v=$(awss3 s3api put-object --bucket "$b" --key k --body "$SMALL" \
        --query VersionId --output text 2>/dev/null) || return 1
    marker=$(awss3 s3api delete-object --bucket "$b" --key k \
        --query VersionId --output text 2>/dev/null) || return 1
    awss3 s3api delete-object --bucket "$b" --key k --version-id "$v" >/dev/null 2>&1 || return 1
    awss3 s3api delete-bucket --bucket "$b" 2>&1 | grep -q BucketNotEmpty || return 1
    awss3 s3api delete-object --bucket "$b" --key k --version-id "$marker" >/dev/null 2>&1 || return 1
    awss3 s3api delete-bucket --bucket "$b" >/dev/null 2>&1
}

# Prune rmdir's empty shard directories. Upload then delete a batch of objects
# (emptying their shard dirs), then run `prune --apply` against the peer endpoint
# and confirm the directory count dropped. Live objects' shards stay (non-empty).
prune_empty_dirs_ok() {
    local datadir="$WORK_DIR/data" before after k
    for k in $(seq 1 8); do s3 put "$NESTED" "s3://${BUCKET}/dirs/o$k" >/dev/null 2>&1 || return 1; done
    for k in $(seq 1 8); do s3 del "s3://${BUCKET}/dirs/o$k" >/dev/null 2>&1 || return 1; done
    before=$(find "$datadir" -type d | wc -l)
    # The peer endpoint (unauthenticated) defaults to :9431. curl blocks until the
    # streamed prune report ends, i.e. until the prune has finished.
    curl -fsS "http://${SERVER_HOST}:9431/prune?apply=true" >/dev/null 2>&1 || return 1
    after=$(find "$datadir" -type d | wc -l)
    [ "$after" -lt "$before" ]
}

echo ""
echo "${BOLD}Running tests against s3://${BUCKET}${RESET}"
echo ""

# ─── Roles and permissions ───────────────────────────────────────────────────

# reader holds only `read` on $BUCKET: it can fetch and list, but not write,
# delete, create buckets, or see into a bucket it has no grant on.
reader_permissions_ok() {
    local r=(as_role reader readersecret)
    "${r[@]}" s3api get-object --bucket "$BUCKET" --key big.bin "$WORK_DIR/rd.bin" >/dev/null 2>&1 || return 1
    cmp -s "$BIG" "$WORK_DIR/rd.bin" || return 1
    "${r[@]}" s3api list-objects-v2 --bucket "$BUCKET" >/dev/null 2>&1 || return 1
    ! "${r[@]}" s3api put-object --bucket "$BUCKET" --key rd.txt --body "$SMALL" >/dev/null 2>&1 || return 1
    ! "${r[@]}" s3api delete-object --bucket "$BUCKET" --key big.bin >/dev/null 2>&1 || return 1
    ! "${r[@]}" s3api create-bucket --bucket "rd-$(date +%s)" >/dev/null 2>&1 || return 1
    ! "${r[@]}" s3api list-objects-v2 --bucket "$OBUCKET" >/dev/null 2>&1
}

# ListBuckets shows a non-admin only the buckets it holds a grant on; an admin
# sees them all.
list_buckets_filtered_ok() {
    local names
    names=$(as_role reader readersecret s3api list-buckets \
        --query 'Buckets[].Name' --output text 2>/dev/null) || return 1
    [ "$names" = "$BUCKET" ] || return 1
    awss3 s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null \
        | tr '\t' '\n' | grep -qx "$OBUCKET"
}

# Admin is bucket management only: bucketadmin can create, HEAD, and delete a
# bucket, but can't touch objects without a grant.
admin_scope_ok() {
    local a=(as_role bucketadmin adminsecret) b="adm-$(date +%s)"
    "${a[@]}" s3api create-bucket --bucket "$b" >/dev/null 2>&1 || return 1
    "${a[@]}" s3api head-bucket --bucket "$b" >/dev/null 2>&1 || return 1
    ! "${a[@]}" s3api put-object --bucket "$b" --key x.txt --body "$SMALL" >/dev/null 2>&1 || return 1
    ! "${a[@]}" s3api get-object --bucket "$BUCKET" --key big.bin "$WORK_DIR/adm.bin" >/dev/null 2>&1 || return 1
    "${a[@]}" s3api delete-bucket --bucket "$b" >/dev/null 2>&1
}

# writer holds read/write on $OBUCKET only. It can use its own bucket, but can't
# copy out of $BUCKET (no read on the source), nor reach an upload in $BUCKET by
# its ID through its own bucket's URL.
cross_bucket_denied_ok() {
    local w=(as_role writer writersecret) uid
    "${w[@]}" s3api put-object --bucket "$OBUCKET" --key mine.txt --body "$SMALL" >/dev/null 2>&1 || return 1
    "${w[@]}" s3api delete-object --bucket "$OBUCKET" --key mine.txt >/dev/null 2>&1 || return 1
    ! "${w[@]}" s3api copy-object --bucket "$OBUCKET" --key stolen.bin \
        --copy-source "${BUCKET}/big.bin" >/dev/null 2>&1 || return 1
    uid=$(awss3 s3api create-multipart-upload --bucket "$BUCKET" --key xb.bin \
        --query UploadId --output text 2>/dev/null) || return 1
    ! "${w[@]}" s3api abort-multipart-upload --bucket "$OBUCKET" --key xb.bin \
        --upload-id "$uid" >/dev/null 2>&1 || return 1
    # The upload survived the foreign abort; its owner can still abort it.
    awss3 s3api abort-multipart-upload --bucket "$BUCKET" --key xb.bin \
        --upload-id "$uid" >/dev/null 2>&1
}

# Second bucket for the cross-bucket tests, and the grants for reader/writer.
setup_role_buckets() {
    mb_granted "$OBUCKET" || return 1
    cairn_role grant writer "$OBUCKET" read write || return 1
    cairn_role grant reader "$BUCKET" read
}

# Grants follow the bucket's lifecycle: granting on a missing bucket fails, and
# deleting a bucket drops its grants, so re-creating it doesn't revive them.
grants_follow_bucket_ok() {
    local a=(as_role bucketadmin adminsecret) b="life-$(date +%s)"
    ! cairn_role grant writer "$b" read >/dev/null 2>&1 || return 1
    "${a[@]}" s3api create-bucket --bucket "$b" >/dev/null 2>&1 || return 1
    cairn_role grant writer "$b" read >/dev/null 2>&1 || return 1
    as_role writer writersecret s3api list-objects-v2 --bucket "$b" >/dev/null 2>&1 || return 1
    "${a[@]}" s3api delete-bucket --bucket "$b" >/dev/null 2>&1 || return 1
    "${a[@]}" s3api create-bucket --bucket "$b" >/dev/null 2>&1 || return 1
    ! as_role writer writersecret s3api list-objects-v2 --bucket "$b" >/dev/null 2>&1 || return 1
    "${a[@]}" s3api delete-bucket --bucket "$b" >/dev/null 2>&1
}

# A revoked grant takes effect on the very next request (no caching).
revoke_takes_effect_ok() {
    cairn_role revoke reader "$BUCKET" >/dev/null 2>&1 || return 1
    ! as_role reader readersecret s3api head-object --bucket "$BUCKET" --key big.bin >/dev/null 2>&1
}

# ─── 5. The tests ────────────────────────────────────────────────────────────
run_test    "Create bucket"                         mb_granted "$BUCKET"
run_test    "Bucket appears in bucket list"         list_contains "" "s3://${BUCKET}"
run_test    "HEAD existing bucket"                  awss3 s3api head-bucket --bucket "${BUCKET}"
expect_fail "HEAD missing bucket fails"             awss3 s3api head-bucket --bucket "${BUCKET}-nope"
run_test    "Unsigned request is rejected (403)"    unsigned_rejected
expect_fail "Unknown access key is rejected"        as_role nosuchrole nosuchsecret s3api list-buckets
run_test    "Upload small text object"              s3 put "$SMALL" "s3://${BUCKET}/small.txt"
run_test    "Stale/future-dated request rejected"   stale_request_rejected
run_test    "Object appears in bucket listing"      list_contains "s3://${BUCKET}" "small.txt"
run_test    "Download matches upload (small)"       check_roundtrip "$SMALL" "s3://${BUCKET}/small.txt"
run_test    "Upload 4 MiB binary object"            s3 put "$BIG" "s3://${BUCKET}/big.bin"
run_test    "Download matches upload (binary)"      check_roundtrip "$BIG" "s3://${BUCKET}/big.bin"
run_test    "Upload object under a prefix"          s3 put "$NESTED" "s3://${BUCKET}/dir/sub/nested.txt"
run_test    "Listing with prefix finds object"      list_contains "s3://${BUCKET}/dir/sub/" "nested.txt"
run_test    "Upload 16 MiB object via multipart"    s3 put --multipart-chunk-size-mb=5 "$MULTIPART" "s3://${BUCKET}/multi.bin"
run_test    "Download multipart object matches"     check_roundtrip "$MULTIPART" "s3://${BUCKET}/multi.bin"
run_test    "Ranged GET (single part) matches"      range_ok big.bin 1000000 1000099 "$BIG"
run_test    "Ranged GET across multipart boundary"  range_ok multi.bin 5242875 5242884 "$MULTIPART"
expect_fail "Unsatisfiable range is rejected"       awss3 s3api get-object --bucket "${BUCKET}" --key big.bin --range "bytes=99999999-100000000" "$WORK_DIR/x416"
run_test    "CopyObject (small object)"             copy_small_ok
run_test    "CopyObject of multipart src is normal" copy_multipart_source_normal_ok
run_test    "CopyObject REPLACE sets content-type"  copy_replace_content_type_ok
expect_fail "Self-copy without REPLACE rejected"    awss3 s3api copy-object --bucket "$BUCKET" --key big.bin --copy-source "${BUCKET}/big.bin"
expect_fail "Copy from missing source fails"        awss3 s3api copy-object --bucket "$BUCKET" --key copy/none.txt --copy-source "${BUCKET}/does-not-exist.txt"
run_test    "UploadPartCopy (whole object)"         upload_part_copy_whole_ok
run_test    "UploadPartCopy (ranged, multipart src)" upload_part_copy_ranged_ok
run_test    "Conditional GET (ETag: 304/412/200)"   conditional_get_etag_ok
run_test    "Conditional GET (dates: 304/412/200)"  conditional_get_date_ok
run_test    "Conditional copy (copy-source-if-match)" conditional_copy_ok
run_test    "Conditional PUT (If-None-Match / If-Match)" conditional_put_ok
run_test    "Conditional CompleteMultipartUpload"     conditional_complete_ok
run_test    "Body SHA-256 verified (good/bad)"      content_sha256_ok
run_test    "aws-chunked trailer checksum (CRC32)"  streaming_trailer_ok
run_test    "Signed streaming upload via mcli (mode 4)" mc_streaming_ok
run_test    "Set up pagination fixtures"            setup_pagination
run_test    "ListObjectsV2 paginates leaves"        v2_leaves_ok
run_test    "ListObjects (v1) paginates leaves"     v1_leaves_ok
run_test    "ListObjectsV2 paginates prefixes"      v2_prefixes_ok
run_test    "Tear down pagination bucket"           teardown_pagination
run_test    "Batch delete (DeleteObjects)"          batch_delete_ok
run_test    "Batch delete guards (MD5 / bucket)"    batch_delete_guards_ok
run_test    "DeleteBucket on non-empty bucket rejected" delete_nonempty_bucket_rejected
run_test    "Deleted parts reaped without prune"    immediate_reap_ok
run_test    "Multipart leftovers reaped without prune" multipart_reap_ok
run_test    "Enable versioning (admin-only)"         versioning_enable_ok
run_test    "Versioned overwrite keeps old version"  versioned_overwrite_ok
run_test    "Delete adds a delete marker"            delete_marker_ok
run_test    "Deleting versions promotes the next"    delete_version_promotes_ok
run_test    "Multipart + copy create versions"       versioned_multipart_copy_ok
run_test    "Suspended versioning uses null version" versioning_suspended_ok
run_test    "Deleting a version needs the grant"     delete_version_needs_grant_ok
run_test    "Unversioned bucket reports no versions" unversioned_no_version_id_ok
run_test    "ListObjectVersions lists versions"      list_versions_ok
run_test    "ListObjectVersions paginates"           list_versions_paginates_ok
run_test    "Copy from a named source version"       copy_source_version_ok
run_test    "Unversioned bucket lists null versions" list_versions_unversioned_ok
run_test    "Listing versions needs read"            list_versions_needs_read_ok
run_test    "Delete markers keep a bucket non-empty" versioned_bucket_not_empty_ok
run_test    "Prune removes empty shard dirs"         prune_empty_dirs_ok
run_test    "Stubbed ACL (s3cmd info works)"        acl_ok
run_test    "Bucket sub-resource stubs"             subresource_stubs_ok
run_test    "Create second bucket, grant roles"     setup_role_buckets
run_test    "Read-only role can read, not write"    reader_permissions_ok
run_test    "ListBuckets filtered by grants"        list_buckets_filtered_ok
run_test    "Admin manages buckets, not objects"    admin_scope_ok
run_test    "No cross-bucket copy / upload access"  cross_bucket_denied_ok
run_test    "Grants follow bucket lifecycle"        grants_follow_bucket_ok
run_test    "Revoked grant takes effect"            revoke_takes_effect_ok
run_test    "Overwrite object, new content wins"    bash -c "
    printf 'overwritten content\n' > '$WORK_DIR/over.txt' &&
    s3cmd --config '$S3CFG' put '$WORK_DIR/over.txt' 's3://${BUCKET}/small.txt' >/dev/null &&
    s3cmd --config '$S3CFG' get 's3://${BUCKET}/small.txt' '$WORK_DIR/over.dl' >/dev/null &&
    cmp -s '$WORK_DIR/over.txt' '$WORK_DIR/over.dl'"
run_test    "Delete object"                         s3 del "s3://${BUCKET}/small.txt"
expect_fail "Deleted object is gone (GET 404s)"     s3 get "s3://${BUCKET}/small.txt" "$WORK_DIR/gone"
run_test    "Delete remaining objects + bucket"     bash -c "
    s3cmd --config '$S3CFG' del 's3://${BUCKET}/big.bin' >/dev/null &&
    s3cmd --config '$S3CFG' del 's3://${BUCKET}/dir/sub/nested.txt' >/dev/null &&
    s3cmd --config '$S3CFG' del 's3://${BUCKET}/multi.bin' >/dev/null &&
    s3cmd --config '$S3CFG' rb 's3://${BUCKET}' >/dev/null &&
    s3cmd --config '$S3CFG' rb 's3://${OBUCKET}' >/dev/null"
expect_fail "Removed bucket is gone (ls fails)"     s3 ls "s3://${BUCKET}"

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
