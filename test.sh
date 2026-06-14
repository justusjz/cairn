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
ACCESS_KEY="testkey"             # any access key id is accepted
SECRET_KEY="cairnsecret"         # must match the server's hardcoded secret

CARGO_ARGS=(-- serve --database postgres://$PG_USER:$PG_PASS@127.0.0.1:${PG_PORT}/$PG_DB --listen-client $SERVER_HOST:${SERVER_PORT})
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

# ─── Pretty output ───────────────────────────────────────────────────────────
if [ -t 1 ]; then
    GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
else
    GREEN=""; RED=""; YELLOW=""; BOLD=""; DIM=""; RESET=""
fi

TOTAL=36
STEP=0
PASS=0
FAIL=0
FAILED_TESTS=()

info()  { printf '%s\n' "${DIM}$*${RESET}"; }
fatal() { printf '%s\n' "${RED}${BOLD}FATAL:${RESET} $*" >&2; exit 1; }

# run_test "description" cmd args...
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

# ─── 2. Run the server ───────────────────────────────────────────────────────
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
awss3() {
    AWS_ACCESS_KEY_ID="$ACCESS_KEY" AWS_SECRET_ACCESS_KEY="$SECRET_KEY" \
    AWS_DEFAULT_REGION=us-east-1 AWS_EC2_METADATA_DISABLED=true AWS_CONFIG_FILE="$AWSCFG" \
    aws --endpoint-url "http://${SERVER_HOST}:${SERVER_PORT}" "$@"
}

# mcli (minio-go, what Mimir uses)
MCFG="$WORK_DIR/mc"

# A python SigV4 signer for the few requests no real client can produce: mode-3
# trailer bodies, deliberately-malformed integrity claims, and precise pagination
# control. It signs whatever headers it's handed so the server's verification has
# something valid to check.
SIGNER="$WORK_DIR/sign.py"
cat >"$SIGNER" <<'PYEOF'
import sys, hashlib, hmac
from datetime import datetime, timezone
from urllib.parse import urlsplit

method, url, payload_hash = sys.argv[1], sys.argv[2], sys.argv[3]
extra = sys.argv[4:]
secret, region, service, akid = "cairnsecret", "us-east-1", "s3", "testkey"

u = urlsplit(url)
host, path, query = u.netloc, (u.path or "/"), u.query
now = datetime.now(timezone.utc)
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

# Ranged GET via aws-cli, content compared to the expected slice.
range_ok() {  # range_ok <key> <start> <end> <localfile>
    local key="$1" start="$2" end="$3" src="$4" out="$WORK_DIR/r.$RANDOM"
    awss3 s3api get-object --bucket "$BUCKET" --key "$key" \
        --range "bytes=${start}-${end}" "$out" >/dev/null 2>&1 || return 1
    cmp -s "$out" <(tail -c "+$((start + 1))" "$src" | head -c "$((end - start + 1))")
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
PBUCKET="page-$(date +%s)"

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
    s3 mb "s3://${PBUCKET}" >/dev/null 2>&1 || return 1
    local k
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

# DeleteObjects integrity/existence guards (crafted, signed with scurl): no
# integrity header → 400, a wrong CRC32 → 400, a valid Content-MD5 (minio-go's
# path) → 200, and a well-formed request against a missing bucket → 404.
batch_delete_guards_ok() {
    local body="$WORK_DIR/del.xml" md5
    printf '<Delete><Object><Key>whatever.txt</Key></Object></Delete>' >"$body"
    md5="$(openssl dgst -md5 -binary "$body" | base64)"
    [ "$(scurl POST "/${BUCKET}?delete" UNSIGNED-PAYLOAD "$body")" = 400 ] || return 1
    [ "$(scurl POST "/${BUCKET}?delete" UNSIGNED-PAYLOAD "$body" "x-amz-checksum-crc32: AAAAAA==")" = 400 ] || return 1
    [ "$(scurl POST "/${BUCKET}?delete" UNSIGNED-PAYLOAD "$body" "Content-MD5: ${md5}")" = 200 ] || return 1
    [ "$(scurl POST "/no-such-bucket-xyz?delete" UNSIGNED-PAYLOAD "$body" "Content-MD5: ${md5}")" = 404 ] || return 1
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

# ─── 5. The tests ────────────────────────────────────────────────────────────
run_test    "Create bucket"                         s3 mb "s3://${BUCKET}"
run_test    "Bucket appears in bucket list"         list_contains "" "s3://${BUCKET}"
run_test    "HEAD existing bucket"                  awss3 s3api head-bucket --bucket "${BUCKET}"
expect_fail "HEAD missing bucket fails"             awss3 s3api head-bucket --bucket "${BUCKET}-nope"
run_test    "Unsigned request is rejected (403)"    unsigned_rejected
run_test    "Upload small text object"              s3 put "$SMALL" "s3://${BUCKET}/small.txt"
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
run_test    "Deleted parts reaped without prune"    immediate_reap_ok
run_test    "Prune removes empty shard dirs"         prune_empty_dirs_ok
run_test    "Stubbed ACL (s3cmd info works)"        acl_ok
run_test    "Bucket sub-resource stubs"             subresource_stubs_ok
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
    s3cmd --config '$S3CFG' rb 's3://${BUCKET}' >/dev/null"
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
