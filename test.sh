#!/usr/bin/env bash
#
# test.sh — self-contained smoke test for a Postgres-backed S3 server.
#
# What it does:
#   1. Starts a throwaway Postgres in a Podman container
#   2. Builds and runs your server in the background via `cargo run`
#   3. Exercises S3 operations with real signing clients (s3cmd, aws-cli, mcli);
#      a small python SigV4 signer (scurl) covers crafted requests no client can
#      produce, and an unsigned curl proves authentication is enforced.
#   4. Prints a pass/fail progress report and tears everything down
#
# Usage:  ./test.sh
# Exit code is 0 only if every test passes.
#
# ─── Configuration — adjust these to match your server ──────────────────────
BAO_IMAGE="quay.io/openbao/openbao:2.7.2"   # the KMS for SSE-KMS
BAO_CONTAINER="s3test-bao"
BAO_PORT=18202
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
# No TLS proxy here, so SSE-C keys come over plain HTTP.
CARGO_ARGS+=(--allow-sse-c-over-http)
# Virtual-hosted-style requests to bucket.localhost, which resolves to this
# host without any DNS.
CARGO_ARGS+=(--domain localhost)
# SSE-KMS, with keys in OpenBao's Transit engine, used as each role (see
# `kms`), logged in to with a throwaway key.
CARGO_ARGS+=(--kms-address "http://127.0.0.1:${BAO_PORT}" --kms-jwt-key "$WORK_DIR/kms-jwt.pem"
             --kms-sse-s3-key sse-s3)
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

TOTAL=112
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
    podman rm -f -v "$PG_CONTAINER" "$BAO_CONTAINER" >/dev/null 2>&1
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
podman rm -f -v "$PG_CONTAINER" >/dev/null 2>&1
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

# ─── 1b. OpenBao ─────────────────────────────────────────────────────────────
info "Starting OpenBao ($BAO_IMAGE) on port $BAO_PORT..."
podman rm -f -v "$BAO_CONTAINER" >/dev/null 2>&1
podman run -d --rm --name "$BAO_CONTAINER" -e BAO_DEV_ROOT_TOKEN_ID=root \
    -p "127.0.0.1:${BAO_PORT}:8200" "$BAO_IMAGE" server -dev -dev-listen-address=0.0.0.0:8200 \
    >/dev/null || fatal "could not start OpenBao container"
bao() { podman exec -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN=root "$BAO_CONTAINER" bao "$@"; }
elapsed=0
until bao status >/dev/null 2>&1; do
    sleep 1
    elapsed=$((elapsed + 1))
    [ "$elapsed" -ge "$STARTUP_TIMEOUT" ] && fatal "OpenBao did not become ready in ${STARTUP_TIMEOUT}s"
done
# Two keys, and the JWT auth mount Cairn logs in to as its roles, trusting
# its key; testkey may use both keys (see 2a), the other roles neither.
{
    openssl genpkey -algorithm ed25519 -out "$WORK_DIR/kms-jwt.pem" &&
    openssl pkey -in "$WORK_DIR/kms-jwt.pem" -pubout -out "$WORK_DIR/kms-jwt.pub" &&
    podman cp "$WORK_DIR/kms-jwt.pub" "$BAO_CONTAINER:/tmp/cairn-jwt.pub" &&
    bao secrets enable transit &&
    bao write -f transit/keys/cairn-test &&
    bao write -f transit/keys/cairn-other &&
    bao write -f transit/keys/sse-s3 &&
    bao auth enable -path=cairn jwt &&
    bao write auth/cairn/config jwt_validation_pubkeys=@/tmp/cairn-jwt.pub &&
    bao write auth/cairn/role/s3 role_type=jwt user_claim=sub bound_audiences=cairn \
        token_type=batch token_ttl=5m &&
    podman exec -i -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN=root "$BAO_CONTAINER" \
        bao policy write cairn-test-keys - <<'POLICY'
path "transit/datakey/plaintext/cairn-*" { capabilities = ["update"] }
path "transit/decrypt/cairn-*" { capabilities = ["update"] }
POLICY
    podman exec -i -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN=root "$BAO_CONTAINER" \
        bao policy write cairn-sse-s3 - <<'POLICY'
path "transit/datakey/plaintext/sse-s3" { capabilities = ["update"] }
path "transit/decrypt/sse-s3" { capabilities = ["update"] }
POLICY
} >/dev/null 2>&1 || fatal "could not set up OpenBao"
info "OpenBao is ready."

# ─── 2. Roles ────────────────────────────────────────────────────────────────
# Roles live in Postgres and are managed with `cairn role`, so set them up before
# the server starts. testkey is an admin (AdministratorAccess); since grants need
# an existing bucket, it's granted read/write on each test bucket right after
# creating it (mb_granted). The others exercise permission checks: reader can
# only read $BUCKET, writer can only use $OBUCKET (both granted once those
# exist), and bucketadmin is an admin that holds no grants.
cairn_role() { (cd "$SCRIPT_DIR" && cargo run -q -- role --database "$DB_URL" "$@"); }
info "Creating roles..."
{
    cairn_role create "$ACCESS_KEY" --admin --secret "$SECRET_KEY" &&
    cairn_role create reader --secret readersecret &&
    cairn_role create writer --secret writersecret &&
    cairn_role create bucketadmin --admin --secret adminsecret
} >"$WORK_DIR/roles.log" 2>&1 || { cat "$WORK_DIR/roles.log" >&2; fatal "could not create roles"; }

# ─── 2a. testkey's and Cairn's identities in OpenBao ─────────────────────────
# Made beforehand, as an OpenBao admin can, so that they may use their keys
# from the first request: entities, and their aliases on Cairn's mount: the
# role's ID, and `cairn` for Cairn itself (for SSE-S3). (Cairn would make them
# when it starts; the other roles get theirs that way.)
{
    role_id=$(podman exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -tAc \
        "SELECT id FROM roles WHERE name = '$ACCESS_KEY'") &&
    accessor=$(bao read -field=accessor sys/auth/cairn) &&
    entity=$(bao write -field=id identity/entity name=cairn-testkey policies=cairn-test-keys) &&
    bao write identity/entity-alias name="$role_id" canonical_id="$entity" mount_accessor="$accessor" &&
    entity=$(bao write -field=id identity/entity name=cairn-itself policies=cairn-sse-s3) &&
    bao write identity/entity-alias name=cairn canonical_id="$entity" mount_accessor="$accessor"
} >"$WORK_DIR/kms-identity.log" 2>&1 || { cat "$WORK_DIR/kms-identity.log" >&2; fatal "could not set up testkey in OpenBao"; }

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
    signature_version = s3v4
EOF
# as_role <access-key> <secret> <aws args...> — aws-cli under a given role.
as_role() {
    local key="$1" secret="$2"; shift 2
    AWS_ACCESS_KEY_ID="$key" AWS_SECRET_ACCESS_KEY="$secret" \
    AWS_DEFAULT_REGION=us-east-1 AWS_EC2_METADATA_DISABLED=true AWS_CONFIG_FILE="$AWSCFG" \
    aws --endpoint-url "http://${SERVER_HOST}:${SERVER_PORT}" "$@"
}
awss3() { as_role "$ACCESS_KEY" "$SECRET_KEY" "$@"; }
# aws-cli with virtual-hosted-style addressing: bucket.localhost:port/key.
AWSCFG_VHOST="$WORK_DIR/awscfg-vhost"
sed 's/addressing_style = path/addressing_style = virtual/' "$AWSCFG" >"$AWSCFG_VHOST"
awsvhost() {
    AWS_ACCESS_KEY_ID="$ACCESS_KEY" AWS_SECRET_ACCESS_KEY="$SECRET_KEY" \
    AWS_DEFAULT_REGION=us-east-1 AWS_EC2_METADATA_DISABLED=true AWS_CONFIG_FILE="$AWSCFG_VHOST" \
    aws --endpoint-url "http://localhost:${SERVER_PORT}" "$@"
}

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

# A presigner (SigV4 in the query string), from the standard library only:
# presign.py <method> <url> <expires> [extra query params, already encoded]
PRESIGNER="$WORK_DIR/presign.py"
cat >"$PRESIGNER" <<'PYEOF'
import sys, hashlib, hmac
from datetime import datetime, timezone
from urllib.parse import urlsplit, quote

method, url, expires = sys.argv[1], sys.argv[2], sys.argv[3]
extra = sys.argv[4] if len(sys.argv) > 4 else ""
secret, region, akid = "cairnsecret", "us-east-1", "testkey"
u = urlsplit(url)
now = datetime.now(timezone.utc)
amzdate, datestamp = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
scope = f"{datestamp}/{region}/s3/aws4_request"
params = {
    "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
    "X-Amz-Credential": quote(f"{akid}/{scope}", safe=""),
    "X-Amz-Date": amzdate,
    "X-Amz-Expires": expires,
    "X-Amz-SignedHeaders": "host",
}
for p in extra.split("&") if extra else []:
    k, _, v = p.partition("=")
    params[k] = v
query = "&".join(f"{k}={params[k]}" for k in sorted(params))
canonical = f"{method}\n{u.path}\n{query}\nhost:{u.netloc}\n\nhost\nUNSIGNED-PAYLOAD"
def mac(k, m): return hmac.new(k, m.encode(), hashlib.sha256).digest()
k = mac(("AWS4" + secret).encode(), datestamp)
k = mac(mac(mac(k, region), "s3"), "aws4_request")
sts = f"AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n{hashlib.sha256(canonical.encode()).hexdigest()}"
print(f"{u.scheme}://{u.netloc}{u.path}?{query}&X-Amz-Signature={hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()}")
PYEOF

# POST Object: signs a form's policy as botocore's generate_presigned_post
# does, and prints its fields, one `name=value` a line: post-sign.py <bucket>
# <key> <max-size> [name=value...], each extra field covered by an eq condition.
POST_SIGNER="$WORK_DIR/post-sign.py"
cat >"$POST_SIGNER" <<'PYEOF'
import sys, hashlib, hmac, json, base64
from datetime import datetime, timedelta, timezone

bucket, key, max_size = sys.argv[1], sys.argv[2], int(sys.argv[3])
extra = [a.split("=", 1) for a in sys.argv[4:]]
secret, region, akid = "cairnsecret", "us-east-1", "testkey"
now = datetime.now(timezone.utc)
amzdate, datestamp = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
credential = f"{akid}/{datestamp}/{region}/s3/aws4_request"
conditions = [{"bucket": bucket}, ["content-length-range", 0, max_size]]
conditions += [{k: v} for k, v in extra]
conditions.append(["starts-with", "$key", key[:-len("${filename}")]] if key.endswith("${filename}") else {"key": key})
conditions += [{"x-amz-algorithm": "AWS4-HMAC-SHA256"}, {"x-amz-credential": credential}, {"x-amz-date": amzdate}]
expiration = (now + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
policy = base64.b64encode(json.dumps({"expiration": expiration, "conditions": conditions}).encode()).decode()
def mac(k, m): return hmac.new(k, m.encode(), hashlib.sha256).digest()
k = mac(mac(mac(mac(("AWS4" + secret).encode(), datestamp), region), "s3"), "aws4_request")
fields = [("key", key)] + extra + [("x-amz-algorithm", "AWS4-HMAC-SHA256"), ("x-amz-credential", credential),
          ("x-amz-date", amzdate), ("policy", policy), ("x-amz-signature", hmac.new(k, policy.encode(), hashlib.sha256).hexdigest())]
for name, value in fields:
    print(f"{name}={value}")
PYEOF

# scurl <method> <pathquery> <payload-hash> <bodyfile|-> [extra "Header: val"...]
# Signs the request and runs curl, printing the HTTP status code. With
# SCURL_UNSIGNED="Header: val", that header is added after signing, so the
# signature doesn't cover it. With SCURL_DROP=<header name>, that signed header
# isn't sent.
scurl() {
    local method="$1" pathquery="$2" phash="$3" body="$4"; shift 4
    local url="http://${SERVER_HOST}:${SERVER_PORT}${pathquery}" args=() line
    while IFS= read -r line; do
        [ -n "${SCURL_DROP:-}" ] && [ "${line%%:*}" = "$SCURL_DROP" ] && continue
        args+=(-H "$line")
    done < <(python3 "$SIGNER" "$method" "$url" "$phash" "$@")
    [ -n "${SCURL_UNSIGNED:-}" ] && args+=(-H "$SCURL_UNSIGNED")
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

# As in S3, the signature must cover every x-amz-* header: one added after
# signing is refused (403), and so is a request without x-amz-content-sha256
# (400), which declares what the signature covers the body with.
unsigned_headers_rejected() {
    local path="/${BUCKET}/small.txt"
    [ "$(SCURL_UNSIGNED="x-amz-meta-added: 1" scurl GET "$path" "$EMPTY_SHA256" -)" = 403 ] || return 1
    [ "$(SCURL_DROP=x-amz-content-sha256 scurl GET "$path" "$EMPTY_SHA256" -)" = 400 ] || return 1
    [ "$(scurl GET "$path" "$EMPTY_SHA256" -)" = 200 ]
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

# Virtual-hosted-style requests (`--domain localhost`), in buckets with and
# without dots: a bucket made, filled, listed, copied out of, read and
# emptied through its host. Taken as path-style, creating the bucket (PUT /)
# would fail, and listing it (GET /) would list the buckets instead. Both
# styles reach the same bucket.
vhost_ok() {
    local b
    for b in vhost-test vhost.dotted-test; do
        awsvhost --debug s3api create-bucket --bucket "$b" 2>&1 \
            | grep -q "https\?://${b}\.localhost:${SERVER_PORT}/" || return 1
        cairn_role grant "$ACCESS_KEY" "$b" read write >/dev/null 2>&1 || return 1
        awsvhost s3api head-bucket --bucket "$b" >/dev/null 2>&1 || return 1
        awsvhost s3api put-object --bucket "$b" --key dir/small.txt --body "$SMALL" >/dev/null 2>&1 || return 1
        awsvhost s3api copy-object --bucket "$b" --key copy.txt \
            --copy-source "${BUCKET}/small.txt" >/dev/null 2>&1 || return 1
        [ "$(awsvhost s3api list-objects-v2 --bucket "$b" --query 'Contents[].Key' --output text 2>/dev/null)" \
            = "copy.txt	dir/small.txt" ] || return 1
        awsvhost s3api get-object --bucket "$b" --key dir/small.txt "$WORK_DIR/vhost.out" >/dev/null 2>&1 || return 1
        cmp -s "$SMALL" "$WORK_DIR/vhost.out" || return 1
        check_roundtrip "$SMALL" "s3://${b}/copy.txt" || return 1
        awsvhost s3api delete-object --bucket "$b" --key dir/small.txt >/dev/null 2>&1 || return 1
        awsvhost s3api delete-object --bucket "$b" --key copy.txt >/dev/null 2>&1 || return 1
        awsvhost s3api delete-bucket --bucket "$b" >/dev/null 2>&1 || return 1
    done
}

# CopyObject only copies metadata: the copy shares the source's data, so no
# file is written, and it reads back intact after the source is gone.
copy_shares_data_ok() {
    local before
    s3 put "$BIG" "s3://${BUCKET}/copy/shared-src" >/dev/null 2>&1 || return 1
    before=$(find "$WORK_DIR/data" -type f | wc -l)
    awss3 s3api copy-object --bucket "$BUCKET" --key copy/shared \
        --copy-source "${BUCKET}/copy/shared-src" >/dev/null 2>&1 || return 1
    [ "$(find "$WORK_DIR/data" -type f | wc -l)" -eq "$before" ] || return 1
    s3 del "s3://${BUCKET}/copy/shared-src" >/dev/null 2>&1 || return 1
    check_roundtrip "$BIG" "s3://${BUCKET}/copy/shared" || return 1
    awss3 s3api delete-object --bucket "$BUCKET" --key copy/shared >/dev/null 2>&1
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

# Metadata: aws-cli's user metadata and stored headers come back on HEAD; a
# COPY copy keeps them, a REPLACE copy takes its own; more than 2 KB of user
# metadata is refused.
metadata_ok() {
    local key="meta/m.txt" got big
    awss3 s3api put-object --bucket "$BUCKET" --key "$key" --body "$SMALL" \
        --metadata color=blue,shape=round --cache-control max-age=60 \
        --content-disposition attachment >/dev/null 2>&1 || return 1
    got=$(awss3 s3api head-object --bucket "$BUCKET" --key "$key" \
        --query '[Metadata.color, Metadata.shape, CacheControl, ContentDisposition]' --output text 2>/dev/null)
    [ "$got" = "$(printf 'blue\tround\tmax-age=60\tattachment')" ] || return 1
    awss3 s3api copy-object --bucket "$BUCKET" --key meta/kept.txt \
        --copy-source "${BUCKET}/$key" >/dev/null 2>&1 || return 1
    got=$(awss3 s3api head-object --bucket "$BUCKET" --key meta/kept.txt \
        --query '[Metadata.color, CacheControl]' --output text 2>/dev/null)
    [ "$got" = "$(printf 'blue\tmax-age=60')" ] || return 1
    awss3 s3api copy-object --bucket "$BUCKET" --key meta/replaced.txt \
        --copy-source "${BUCKET}/$key" --metadata-directive REPLACE --metadata size=big >/dev/null 2>&1 || return 1
    got=$(awss3 s3api head-object --bucket "$BUCKET" --key meta/replaced.txt \
        --query 'Metadata' --output json 2>/dev/null | tr -d ' \n')
    [ "$got" = '{"size":"big"}' ] || return 1
    big=$(head -c 2100 /dev/zero | tr '\0' x)
    ! awss3 s3api put-object --bucket "$BUCKET" --key meta/big.txt --body "$SMALL" \
        --metadata "big=$big" >/dev/null 2>&1 || return 1
    for key in "$key" meta/kept.txt meta/replaced.txt; do
        awss3 s3api delete-object --bucket "$BUCKET" --key "$key" >/dev/null 2>&1 || return 1
    done
}

# SSE-C: objects written with a client's key read back with it (whole and in a
# range), and not without it or with another.
sse_c_ok() {
    local k1="$WORK_DIR/sse-key1" k2="$WORK_DIR/sse-key2" out="$WORK_DIR/sse-out" key
    head -c 32 /dev/urandom >"$k1"
    head -c 32 /dev/urandom >"$k2"
    for key in small.txt big.bin; do
        local src="$SMALL"; [ "$key" = big.bin ] && src="$BIG"
        awss3 s3api put-object --bucket "$BUCKET" --key "sse/$key" --body "$src" \
            --sse-customer-algorithm AES256 --sse-customer-key "fileb://$k1" >/dev/null 2>&1 || return 1
        awss3 s3api get-object --bucket "$BUCKET" --key "sse/$key" "$out" \
            --sse-customer-algorithm AES256 --sse-customer-key "fileb://$k1" >/dev/null 2>&1 || return 1
        cmp -s "$src" "$out" || return 1
        ! awss3 s3api get-object --bucket "$BUCKET" --key "sse/$key" "$out" >/dev/null 2>&1 || return 1
        ! awss3 s3api get-object --bucket "$BUCKET" --key "sse/$key" "$out" \
            --sse-customer-algorithm AES256 --sse-customer-key "fileb://$k2" >/dev/null 2>&1 || return 1
    done
    awss3 s3api get-object --bucket "$BUCKET" --key sse/big.bin --range bytes=100000-299999 "$out" \
        --sse-customer-algorithm AES256 --sse-customer-key "fileb://$k1" >/dev/null 2>&1 || return 1
    cmp -s <(tail -c +100001 "$BIG" | head -c 200000) "$out" || return 1
    [ "$(awss3 s3api head-object --bucket "$BUCKET" --key sse/big.bin --query ContentLength --output text \
        --sse-customer-algorithm AES256 --sse-customer-key "fileb://$k1" 2>/dev/null)" = "$(stat -c %s "$BIG")" ] || return 1
    # Multipart (16 MiB in 8 MiB parts), and downloaded in parallel ranges.
    awss3 s3 cp "$MULTIPART" "s3://${BUCKET}/sse/multi.bin" --sse-c AES256 --sse-c-key "fileb://$k1" \
        >/dev/null 2>&1 || return 1
    awss3 s3 cp "s3://${BUCKET}/sse/multi.bin" "$out" --sse-c AES256 --sse-c-key "fileb://$k1" \
        >/dev/null 2>&1 || return 1
    cmp -s "$MULTIPART" "$out" || return 1
    ! awss3 s3 cp "s3://${BUCKET}/sse/multi.bin" "$out" --sse-c AES256 --sse-c-key "fileb://$k2" \
        >/dev/null 2>&1 || return 1
    awss3 s3api delete-object --bucket "$BUCKET" --key sse/multi.bin >/dev/null 2>&1 || return 1
    # Copies: to another key (in place, which rotates it), and decrypted.
    awss3 s3api copy-object --bucket "$BUCKET" --key sse/big.bin --copy-source "${BUCKET}/sse/big.bin" \
        --copy-source-sse-customer-algorithm AES256 --copy-source-sse-customer-key "fileb://$k1" \
        --sse-customer-algorithm AES256 --sse-customer-key "fileb://$k2" >/dev/null 2>&1 || return 1
    awss3 s3api get-object --bucket "$BUCKET" --key sse/big.bin "$out" \
        --sse-customer-algorithm AES256 --sse-customer-key "fileb://$k2" >/dev/null 2>&1 || return 1
    cmp -s "$BIG" "$out" || return 1
    awss3 s3api copy-object --bucket "$BUCKET" --key sse/clear.bin --copy-source "${BUCKET}/sse/big.bin" \
        --copy-source-sse-customer-algorithm AES256 --copy-source-sse-customer-key "fileb://$k2" \
        >/dev/null 2>&1 || return 1
    awss3 s3api get-object --bucket "$BUCKET" --key sse/clear.bin "$out" >/dev/null 2>&1 || return 1
    cmp -s "$BIG" "$out" || return 1
    for key in small.txt big.bin clear.bin; do
        awss3 s3api delete-object --bucket "$BUCKET" --key "sse/$key" >/dev/null 2>&1 || return 1
    done
}

# S3's checksums: a PUT's, the client's, told by a HEAD with checksum mode
# and checked by the client as it downloads; a multipart upload's of an
# algorithm, COMPOSITE, of its parts, and a FULL_OBJECT one's, whose parts
# needn't carry theirs; a copy's of the algorithm it asks for, FULL_OBJECT.
checksums_ok() {
    local out="$WORK_DIR/ck-out" url="http://${SERVER_HOST}:${SERVER_PORT}/${BUCKET}" sha crc told id etag
    crc32() { python3 -I -c 'import sys, zlib, base64
print(base64.b64encode(zlib.crc32(open(sys.argv[1], "rb").read()).to_bytes(4, "big")).decode())' "$1"; }
    sha=$(openssl dgst -sha256 -binary "$BIG" | base64)
    awss3 s3api put-object --bucket "$BUCKET" --key ck/sha.bin --body "$BIG" --checksum-algorithm SHA256 \
        >/dev/null 2>&1 || return 1
    told=$(awss3 s3api head-object --bucket "$BUCKET" --key ck/sha.bin --checksum-mode ENABLED \
        --query '[ChecksumType, ChecksumSHA256]' --output text 2>/dev/null)
    [ "$told" = "FULL_OBJECT	$sha" ] || return 1
    awss3 s3api get-object --bucket "$BUCKET" --key ck/sha.bin --checksum-mode ENABLED "$out" \
        >/dev/null 2>&1 || return 1
    cmp -s "$BIG" "$out" || return 1
    crc=$(crc32 "$BIG")
    awss3 s3api put-object --bucket "$BUCKET" --key ck/crc.bin --body "$BIG" --checksum-algorithm CRC32 \
        >/dev/null 2>&1 || return 1
    [ "$(awss3 s3api head-object --bucket "$BUCKET" --key ck/crc.bin --checksum-mode ENABLED \
        --query ChecksumCRC32 --output text 2>/dev/null)" = "$crc" ] || return 1
    # Multipart (16 MiB in 8 MiB parts).
    awss3 s3 cp "$MULTIPART" "s3://${BUCKET}/ck/multi.bin" --checksum-algorithm SHA256 >/dev/null 2>&1 || return 1
    told=$(awss3 s3api head-object --bucket "$BUCKET" --key ck/multi.bin --checksum-mode ENABLED \
        --query '[ChecksumType, ChecksumSHA256]' --output text 2>/dev/null)
    case "$told" in "COMPOSITE	"*-2) ;; *) return 1 ;; esac
    awss3 s3api copy-object --bucket "$BUCKET" --key ck/copy.bin --copy-source "${BUCKET}/ck/multi.bin" \
        --checksum-algorithm CRC32 >/dev/null 2>&1 || return 1
    told=$(awss3 s3api head-object --bucket "$BUCKET" --key ck/copy.bin --checksum-mode ENABLED \
        --query '[ChecksumType, ChecksumCRC32]' --output text 2>/dev/null)
    [ "$told" = "FULL_OBJECT	$(crc32 "$MULTIPART")" ] || return 1
    # A FULL_OBJECT upload's part may come without its checksum, which it's
    # then told, and be listed without it.
    id=$(awss3 s3api create-multipart-upload --bucket "$BUCKET" --key ck/full.bin --checksum-algorithm CRC32 \
        --checksum-type FULL_OBJECT --query UploadId --output text 2>/dev/null) || return 1
    told=$(curl -s -D - -o /dev/null -X PUT -T "$BIG" --aws-sigv4 "aws:amz:us-east-1:s3" \
        --user "$ACCESS_KEY:$SECRET_KEY" "$url/ck/full.bin?partNumber=1&uploadId=$id" | tr -d '\r')
    echo "$told" | grep -qx "x-amz-checksum-crc32: $crc" || return 1
    etag=$(echo "$told" | sed -n 's/^etag: //Ip')
    awss3 s3api complete-multipart-upload --bucket "$BUCKET" --key ck/full.bin --upload-id "$id" \
        --multipart-upload "{\"Parts\": [{\"PartNumber\": 1, \"ETag\": $(printf '%s' "$etag" | python3 -I -c 'import json, sys; print(json.dumps(sys.stdin.read()))')}]}" \
        >/dev/null 2>&1 || return 1
    told=$(awss3 s3api head-object --bucket "$BUCKET" --key ck/full.bin --checksum-mode ENABLED \
        --query '[ChecksumType, ChecksumCRC32]' --output text 2>/dev/null)
    [ "$told" = "FULL_OBJECT	$crc" ] || return 1
    for key in sha.bin crc.bin multi.bin copy.bin full.bin; do
        awss3 s3api delete-object --bucket "$BUCKET" --key "ck/$key" >/dev/null 2>&1 || return 1
    done
}

# SSE-KMS: objects written under a KMS key (the default one, or another, with a
# context) read back without any key, whole, in ranges and multipart, and tell
# their key; copies change it, or decrypt. A key the role may not use is
# refused, as is a read by a role that may read the bucket but not use the
# key, and SSE-KMS headers on a read.
sse_kms_ok() {
    local out="$WORK_DIR/kms-out" context
    context=$(printf '{"team":"storage"}' | base64)
    awss3 s3api put-object --bucket "$BUCKET" --key kms/default.bin --body "$BIG" \
        --server-side-encryption aws:kms --ssekms-key-id cairn-test >/dev/null 2>&1 || return 1
    # There's no default key.
    ! awss3 s3api put-object --bucket "$BUCKET" --key kms/x.bin --body "$SMALL" \
        --server-side-encryption aws:kms >/dev/null 2>&1 || return 1
    awss3 s3api put-object --bucket "$BUCKET" --key kms/other.bin --body "$BIG" \
        --server-side-encryption aws:kms --ssekms-key-id cairn-other \
        --ssekms-encryption-context "$context" >/dev/null 2>&1 || return 1
    for key in default other; do
        awss3 s3api get-object --bucket "$BUCKET" --key "kms/$key.bin" "$out" >/dev/null 2>&1 || return 1
        cmp -s "$BIG" "$out" || return 1
    done
    [ "$(awss3 s3api head-object --bucket "$BUCKET" --key kms/default.bin \
        --query '[ServerSideEncryption,SSEKMSKeyId]' --output text 2>/dev/null)" \
        = "$(printf 'aws:kms\tarn:aws:kms:transit/cairn-test')" ] || return 1
    [ "$(awss3 s3api get-object --bucket "$BUCKET" --key kms/other.bin "$out" \
        --query SSEKMSKeyId --output text 2>/dev/null)" = "arn:aws:kms:transit/cairn-other" ] || return 1
    awss3 s3api get-object --bucket "$BUCKET" --key kms/other.bin --range bytes=100000-299999 "$out" \
        >/dev/null 2>&1 || return 1
    cmp -s <(tail -c +100001 "$BIG" | head -c 200000) "$out" || return 1
    # Multipart (16 MiB in 8 MiB parts), and downloaded in parallel ranges.
    awss3 s3 cp "$MULTIPART" "s3://${BUCKET}/kms/multi.bin" --sse aws:kms --sse-kms-key-id cairn-other \
        >/dev/null 2>&1 || return 1
    awss3 s3 cp "s3://${BUCKET}/kms/multi.bin" "$out" >/dev/null 2>&1 || return 1
    cmp -s "$MULTIPART" "$out" || return 1
    # Copies: to another KMS key (sharing the data), and decrypted.
    awss3 s3api copy-object --bucket "$BUCKET" --key kms/copy.bin --copy-source "${BUCKET}/kms/other.bin" \
        --server-side-encryption aws:kms --ssekms-key-id cairn-test >/dev/null 2>&1 || return 1
    [ "$(awss3 s3api get-object --bucket "$BUCKET" --key kms/copy.bin "$out" \
        --query SSEKMSKeyId --output text 2>/dev/null)" = "arn:aws:kms:transit/cairn-test" ] || return 1
    cmp -s "$BIG" "$out" || return 1
    awss3 s3api copy-object --bucket "$BUCKET" --key kms/clear.bin --copy-source "${BUCKET}/kms/copy.bin" \
        >/dev/null 2>&1 || return 1
    [ "$(awss3 s3api get-object --bucket "$BUCKET" --key kms/clear.bin "$out" \
        --query ServerSideEncryption --output text 2>/dev/null)" = None ] || return 1
    cmp -s "$BIG" "$out" || return 1
    ! awss3 s3api put-object --bucket "$BUCKET" --key kms/x.bin --body "$SMALL" \
        --server-side-encryption aws:kms --ssekms-key-id no-such-key >/dev/null 2>&1 || return 1
    [ "$(scurl GET "/${BUCKET}/kms/copy.bin" "$EMPTY_SHA256" - "x-amz-server-side-encryption: aws:kms")" = 400 ] \
        || return 1
    # A role that may read the bucket, but not use the key, can't read it
    # (but a plain object).
    cairn_role grant reader "$BUCKET" read >/dev/null 2>&1 || return 1
    ! as_role reader readersecret s3api get-object --bucket "$BUCKET" --key kms/copy.bin "$out" \
        >/dev/null 2>&1 || return 1
    as_role reader readersecret s3api get-object --bucket "$BUCKET" --key kms/clear.bin "$out" \
        >/dev/null 2>&1 || return 1
    cairn_role revoke reader "$BUCKET" read >/dev/null 2>&1 || return 1
    for key in default other multi copy clear; do
        awss3 s3api delete-object --bucket "$BUCKET" --key "kms/$key.bin" >/dev/null 2>&1 || return 1
    done
}

# SSE-S3: objects under Cairn's own key read back for any role that may read
# them (reader has no KMS keys), whole and multipart, and tell that they're
# AES256; copies to SSE-KMS and back keep the data.
sse_s3_ok() {
    local out="$WORK_DIR/s3-out" key
    awss3 s3api put-object --bucket "$BUCKET" --key s3/big.bin --body "$BIG" \
        --server-side-encryption AES256 >/dev/null 2>&1 || return 1
    [ "$(awss3 s3api head-object --bucket "$BUCKET" --key s3/big.bin --query ServerSideEncryption \
        --output text 2>/dev/null)" = AES256 ] || return 1
    awss3 s3 cp "$MULTIPART" "s3://${BUCKET}/s3/multi.bin" --sse AES256 >/dev/null 2>&1 || return 1
    cairn_role grant reader "$BUCKET" read >/dev/null 2>&1 || return 1
    for key in big multi; do
        local src="$BIG"; [ "$key" = multi ] && src="$MULTIPART"
        as_role reader readersecret s3api get-object --bucket "$BUCKET" --key "s3/$key.bin" "$out" \
            >/dev/null 2>&1 || return 1
        cmp -s "$src" "$out" || return 1
    done
    cairn_role revoke reader "$BUCKET" read >/dev/null 2>&1 || return 1
    # The ETag is the MD5, as in S3, which s3cmd checks after an upload.
    local log="$WORK_DIR/s3cmd-sse-s3.log"
    s3 put "$BIG" "s3://${BUCKET}/s3/s3cmd.bin" --server-side-encryption >"$log" 2>&1 || return 1
    ! grep -q "MD5" "$log" || return 1
    s3 get --force "s3://${BUCKET}/s3/s3cmd.bin" "$out" >/dev/null 2>&1 || return 1
    cmp -s "$BIG" "$out" || return 1
    [ "$(awss3 s3api head-object --bucket "$BUCKET" --key s3/s3cmd.bin --query ETag --output text \
        2>/dev/null)" = "\"$(md5sum "$BIG" | cut -d' ' -f1)\"" ] || return 1
    awss3 s3api copy-object --bucket "$BUCKET" --key s3/kms.bin --copy-source "${BUCKET}/s3/big.bin" \
        --server-side-encryption aws:kms --ssekms-key-id cairn-test >/dev/null 2>&1 || return 1
    awss3 s3api copy-object --bucket "$BUCKET" --key s3/back.bin --copy-source "${BUCKET}/s3/kms.bin" \
        --server-side-encryption AES256 >/dev/null 2>&1 || return 1
    [ "$(awss3 s3api get-object --bucket "$BUCKET" --key s3/back.bin "$out" --query ServerSideEncryption \
        --output text 2>/dev/null)" = AES256 ] || return 1
    cmp -s "$BIG" "$out" || return 1
    for key in big multi s3cmd kms back; do
        awss3 s3api delete-object --bucket "$BUCKET" --key "s3/$key.bin" >/dev/null 2>&1 || return 1
    done
}

# Default encryption: a bucket's default (SSE-KMS under a key) is set by an
# admin only, read back, and applied to writes that ask for no encryption of
# their own; one that asks for SSE-C gets that. SSE-S3 is one too. Removing
# it leaves new writes plain.
bucket_encryption_ok() {
    local out="$WORK_DIR/enc-out" k1="$WORK_DIR/enc-key"
    local kms='{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"cairn-test"}}]}'
    local aes='{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
    head -c 32 /dev/urandom >"$k1"
    ! awss3 s3api get-bucket-encryption --bucket "$BUCKET" >/dev/null 2>&1 || return 1
    awss3 s3api put-bucket-encryption --bucket "$BUCKET" \
        --server-side-encryption-configuration "$aes" >/dev/null 2>&1 || return 1
    awss3 s3api put-object --bucket "$BUCKET" --key enc/s3.txt --body "$SMALL" >/dev/null 2>&1 || return 1
    [ "$(awss3 s3api head-object --bucket "$BUCKET" --key enc/s3.txt --query ServerSideEncryption \
        --output text 2>/dev/null)" = AES256 ] || return 1
    ! as_role writer writersecret s3api put-bucket-encryption --bucket "$BUCKET" \
        --server-side-encryption-configuration "$kms" >/dev/null 2>&1 || return 1
    awss3 s3api put-bucket-encryption --bucket "$BUCKET" \
        --server-side-encryption-configuration "$kms" >/dev/null 2>&1 || return 1
    [ "$(awss3 s3api get-bucket-encryption --bucket "$BUCKET" --output text \
        --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyID' \
        2>/dev/null)" = "arn:aws:kms:transit/cairn-test" ] || return 1
    awss3 s3api put-object --bucket "$BUCKET" --key enc/default.txt --body "$SMALL" >/dev/null 2>&1 || return 1
    [ "$(awss3 s3api head-object --bucket "$BUCKET" --key enc/default.txt \
        --query '[ServerSideEncryption,SSEKMSKeyId]' --output text 2>/dev/null)" \
        = "$(printf 'aws:kms\tarn:aws:kms:transit/cairn-test')" ] || return 1
    awss3 s3api get-object --bucket "$BUCKET" --key enc/default.txt "$out" >/dev/null 2>&1 || return 1
    cmp -s "$SMALL" "$out" || return 1
    awss3 s3api put-object --bucket "$BUCKET" --key enc/sse-c.txt --body "$SMALL" \
        --sse-customer-algorithm AES256 --sse-customer-key "fileb://$k1" >/dev/null 2>&1 || return 1
    [ "$(awss3 s3api head-object --bucket "$BUCKET" --key enc/sse-c.txt --query SSECustomerAlgorithm \
        --output text --sse-customer-algorithm AES256 --sse-customer-key "fileb://$k1" 2>/dev/null)" = AES256 ] \
        || return 1
    awss3 s3api delete-bucket-encryption --bucket "$BUCKET" >/dev/null 2>&1 || return 1
    ! awss3 s3api get-bucket-encryption --bucket "$BUCKET" >/dev/null 2>&1 || return 1
    awss3 s3api put-object --bucket "$BUCKET" --key enc/plain.txt --body "$SMALL" >/dev/null 2>&1 || return 1
    [ "$(awss3 s3api head-object --bucket "$BUCKET" --key enc/plain.txt --query ServerSideEncryption \
        --output text 2>/dev/null)" = None ] || return 1
    for key in s3 default sse-c plain; do
        awss3 s3api delete-object --bucket "$BUCKET" --key "enc/$key.txt" >/dev/null 2>&1 || return 1
    done
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

# A body must match the SHA-256 its request signs, whatever else is claimed. A
# signed PUT replayed with someone else's aws-chunked body (and Content-Encoding,
# which isn't signed) is refused, and so is a DeleteObjects whose key list was
# swapped for another with its own Content-MD5: the object it names survives.
replayed_body_rejected() {
    local sha body="$WORK_DIR/swap.body" list="$WORK_DIR/swap.xml" md5
    sha=$(openssl dgst -sha256 "$NESTED" | awk '{print $NF}')
    printf '4\r\nevil\r\n0\r\n\r\n' >"$body"
    [ "$(SCURL_UNSIGNED="Content-Encoding: aws-chunked" \
        scurl PUT "/${BUCKET}/swap.txt" "$sha" "$body")" = 400 ] || return 1
    s3 put "$SMALL" "s3://${BUCKET}/swap-keep.txt" >/dev/null 2>&1 || return 1
    printf '<Delete><Object><Key>swap-keep.txt</Key></Object></Delete>' >"$list"
    md5=$(openssl dgst -md5 -binary "$list" | base64)
    [ "$(scurl POST "/${BUCKET}?delete" "$sha" "$list" "Content-MD5: ${md5}")" = 400 ] || return 1
    check_roundtrip "$SMALL" "s3://${BUCKET}/swap-keep.txt" || return 1
    awss3 s3api delete-object --bucket "$BUCKET" --key swap-keep.txt >/dev/null 2>&1
}

# A version ID that can't be one is refused (400 InvalidArgument) wherever it's
# given, as S3 does; one with a newline used to crash the request. In the
# versioned bucket, where testkey may delete versions.
malformed_version_id_rejected() {
    local path="/${VBUCKET}/cs"
    [ "$(scurl DELETE "${path}?versionId=%0A" "$EMPTY_SHA256" -)" = 400 ] || return 1
    [ "$(scurl GET "${path}?versionId=nope" "$EMPTY_SHA256" -)" = 400 ] || return 1
    [ "$(scurl GET "/${VBUCKET}?versions&version-id-marker=nope" "$EMPTY_SHA256" -)" = 400 ] || return 1
    [ "$(scurl PUT "/${VBUCKET}/copied.txt" "$EMPTY_SHA256" - \
        "x-amz-copy-source: ${path}?versionId=nope")" = 400 ] || return 1
    # A well-formed one that names no version is a 404, as before.
    [ "$(scurl GET "${path}?versionId=$(printf 'x%.0s' {1..32})" "$EMPTY_SHA256" -)" = 404 ]
}

# A body that's read whole (here PutBucketVersioning's) is refused once it's
# larger than 8 MiB (400), rather than kept in memory, whether it declares its
# length or arrives in HTTP chunks. The document is valid, and names no bucket,
# so the same one, read, gets a 404.
oversized_body_rejected() {
    local doc="$WORK_DIR/versioning.xml" big="$WORK_DIR/huge.xml" path="/no-such-bucket-cap?versioning"
    printf '<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>' >"$doc"
    { cat "$doc"; head -c $((9 * 1024 * 1024)) /dev/zero | tr '\0' ' '; } >"$big"
    [ "$(scurl PUT "$path" UNSIGNED-PAYLOAD "$doc")" = 404 ] || return 1
    [ "$(scurl PUT "$path" UNSIGNED-PAYLOAD "$big")" = 400 ] || return 1
    [ "$(scurl PUT "$path" UNSIGNED-PAYLOAD "$big" "Transfer-Encoding: chunked")" = 400 ]
}

# Content-MD5 and x-amz-checksum-* headers are checked against an upload's
# data: a right one is accepted, a wrong one refused (400 BadDigest). aws-cli
# computes a SHA-1 checksum itself.
upload_checksums_ok() {
    local md5 key="sums.txt"
    md5=$(openssl dgst -md5 -binary "$NESTED" | base64)
    [ "$(scurl PUT "/${BUCKET}/${key}" UNSIGNED-PAYLOAD "$NESTED" "Content-MD5: ${md5}")" = 200 ] || return 1
    [ "$(scurl PUT "/${BUCKET}/${key}" UNSIGNED-PAYLOAD "$NESTED" \
        "Content-MD5: 1B2M2Y8AsgTpgAmY7PhCfg==")" = 400 ] || return 1
    [ "$(scurl PUT "/${BUCKET}/${key}" UNSIGNED-PAYLOAD "$NESTED" \
        "x-amz-checksum-crc32: AAAAAA==")" = 400 ] || return 1
    awss3 s3api put-object --bucket "$BUCKET" --key "$key" --body "$BIG" \
        --checksum-algorithm SHA1 >/dev/null 2>&1 || return 1
    check_roundtrip "$BIG" "s3://${BUCKET}/${key}" || return 1
    awss3 s3api delete-object --bucket "$BUCKET" --key "$key" >/dev/null 2>&1
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

# Signed streaming with a trailing checksum, whose signature covers it
# (STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER), via mcli, in each of S3's
# checksum algorithms.
mc_trailer_ok() {
    local host="http://${SERVER_HOST}:${SERVER_PORT}" algorithm
    mcli --config-dir "$MCFG" alias set good "$host" "$ACCESS_KEY" cairnsecret >/dev/null 2>&1 || return 1
    for algorithm in CRC32 CRC32C CRC64NVME SHA1 SHA256; do
        mcli --config-dir "$MCFG" cp --checksum "$algorithm" "$BIG" "good/${BUCKET}/mc-trailer.bin" \
            >/dev/null 2>&1 || return 1
        check_roundtrip "$BIG" "s3://${BUCKET}/mc-trailer.bin" || return 1
    done
    mcli --config-dir "$MCFG" rm "good/${BUCKET}/mc-trailer.bin" >/dev/null 2>&1
}

# A key must be valid UTF-8 without NUL (as in MinIO; invalid UTF-8 used to
# be stored mangled, and NUL failed with a 500), and at most 1024 bytes long, as
# in S3.
malformed_keys_rejected() {
    local long1024 long1025
    long1024=$(printf 'k%.0s' {1..1024}); long1025="${long1024}k"
    [ "$(scurl PUT "/${BUCKET}/bad%FFkey" UNSIGNED-PAYLOAD "$SMALL")" = 400 ] || return 1
    [ "$(scurl PUT "/${BUCKET}/bad%00key" UNSIGNED-PAYLOAD "$SMALL")" = 400 ] || return 1
    [ "$(scurl GET "/${BUCKET}?list-type=2&prefix=%FF" "$EMPTY_SHA256" -)" = 400 ] || return 1
    [ "$(scurl PUT "/${BUCKET}/${long1025}" UNSIGNED-PAYLOAD "$SMALL")" = 400 ] || return 1
    [ "$(scurl PUT "/${BUCKET}/${long1024}" UNSIGNED-PAYLOAD "$SMALL")" = 200 ] || return 1
    awss3 s3api delete-object --bucket "$BUCKET" --key "$long1024" >/dev/null 2>&1
}

# Keys are listed in UTF-8 byte order, as S3 lists them, not by the database's
# locale (which would put "a" before "B", and "a b" after "a1").
byte_order_listing_ok() {
    local k got
    for k in "ord/a" "ord/B" "ord/_x" "ord/a b" "ord/a1" "ord/é"; do
        s3 put "$SMALL" "s3://${BUCKET}/${k}" >/dev/null 2>&1 || return 1
    done
    got=$(awss3 s3api list-objects-v2 --bucket "$BUCKET" --prefix ord/ \
        --query 'Contents[].Key' --output text 2>/dev/null | tr '\t' '|')
    for k in "ord/a" "ord/B" "ord/_x" "ord/a b" "ord/a1" "ord/é"; do
        awss3 s3api delete-object --bucket "$BUCKET" --key "$k" >/dev/null 2>&1
    done
    [ "$got" = "ord/B|ord/_x|ord/a|ord/a b|ord/a1|ord/é" ]
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

# Tags: an object's from its PUT (sorted, as S3 hands them back), counted on
# HEAD; replaced in place by PutObjectTagging (no new version, the same ETag),
# per version; kept or replaced by a copy (a lowercase directive is refused,
# as in S3); given by an upload, but refused on its parts; a bucket's; and
# S3's errors for tags it doesn't take.
tagging_ok() {
    local tags etag version newer out="$WORK_DIR/tag-out"
    tags_of() { awss3 s3api get-object-tagging --bucket "$1" --key "$2" ${3:+--version-id "$3"} \
        --query 'TagSet[].[Key,Value]' --output text 2>/dev/null; }
    awss3 s3api put-object --bucket "$BUCKET" --key tag/a.bin --body "$SMALL" --tagging 'z=1&a=b%20c' \
        >/dev/null 2>&1 || return 1
    [ "$(tags_of "$BUCKET" tag/a.bin)" = "$(printf 'a\tb c\nz\t1')" ] || return 1
    [ "$(awss3 s3api head-object --bucket "$BUCKET" --key tag/a.bin --query TagCount --output text 2>/dev/null)" \
        = 2 ] || return 1
    etag=$(awss3 s3api head-object --bucket "$BUCKET" --key tag/a.bin --query ETag --output text 2>/dev/null)
    awss3 s3api put-object-tagging --bucket "$BUCKET" --key tag/a.bin \
        --tagging 'TagSet=[{Key=k,Value=v}]' >/dev/null 2>&1 || return 1
    [ "$(tags_of "$BUCKET" tag/a.bin)" = "$(printf 'k\tv')" ] || return 1
    [ "$(awss3 s3api head-object --bucket "$BUCKET" --key tag/a.bin --query ETag --output text 2>/dev/null)" \
        = "$etag" ] || return 1
    # Copies keep the source's, or take the request's.
    awss3 s3api copy-object --bucket "$BUCKET" --key tag/kept.bin --copy-source "${BUCKET}/tag/a.bin" \
        --tagging 'ignored=1' >/dev/null 2>&1 || return 1
    [ "$(tags_of "$BUCKET" tag/kept.bin)" = "$(printf 'k\tv')" ] || return 1
    awss3 s3api copy-object --bucket "$BUCKET" --key tag/new.bin --copy-source "${BUCKET}/tag/a.bin" \
        --tagging-directive REPLACE --tagging 'n=1' >/dev/null 2>&1 || return 1
    [ "$(tags_of "$BUCKET" tag/new.bin)" = "$(printf 'n\t1')" ] || return 1
    ! awss3 s3api copy-object --bucket "$BUCKET" --key tag/x.bin --copy-source "${BUCKET}/tag/a.bin" \
        --tagging-directive replace --tagging 'n=1' >"$out" 2>&1 || return 1
    grep -q "Unknown tagging directive" "$out" || return 1
    awss3 s3api delete-object-tagging --bucket "$BUCKET" --key tag/a.bin >/dev/null 2>&1 || return 1
    [ -z "$(tags_of "$BUCKET" tag/a.bin)" ] || return 1
    [ "$(awss3 s3api head-object --bucket "$BUCKET" --key tag/a.bin --query TagCount --output text 2>/dev/null)" \
        = None ] || return 1
    # S3's errors.
    ! awss3 s3api put-object --bucket "$BUCKET" --key tag/bad.bin --body "$SMALL" --tagging 'a=1&a=2' \
        >"$out" 2>&1 || return 1
    grep -q "InvalidArgument" "$out" || return 1
    ! awss3 s3api put-object-tagging --bucket "$BUCKET" --key tag/a.bin \
        --tagging 'TagSet=[{Key=aws:x,Value=v}]' >"$out" 2>&1 || return 1
    grep -q "InvalidTag" "$out" || return 1
    # An upload's, from its creation (the parts can't have any).
    local uid; uid=$(awss3 s3api create-multipart-upload --bucket "$BUCKET" --key tag/up.bin --tagging 'u=1' \
        --query UploadId --output text 2>/dev/null) || return 1
    etag=$(awss3 s3api upload-part --bucket "$BUCKET" --key tag/up.bin --upload-id "$uid" --part-number 1 \
        --body "$SMALL" --query ETag --output text 2>/dev/null) || return 1
    awss3 s3api complete-multipart-upload --bucket "$BUCKET" --key tag/up.bin --upload-id "$uid" \
        --multipart-upload "{\"Parts\":[{\"PartNumber\":1,\"ETag\":$etag}]}" >/dev/null 2>&1 || return 1
    [ "$(tags_of "$BUCKET" tag/up.bin)" = "$(printf 'u\t1')" ] || return 1
    # Each version its own, in a versioned bucket.
    version=$(awss3 s3api put-object --bucket "$VBUCKET" --key tag/v.bin --body "$SMALL" --tagging 'v=1' \
        --query VersionId --output text 2>/dev/null) || return 1
    newer=$(awss3 s3api put-object --bucket "$VBUCKET" --key tag/v.bin --body "$SMALL" --tagging 'v=2' \
        --query VersionId --output text 2>/dev/null) || return 1
    awss3 s3api put-object-tagging --bucket "$VBUCKET" --key tag/v.bin --version-id "$version" \
        --tagging 'TagSet=[{Key=v,Value=old}]' >/dev/null 2>&1 || return 1
    [ "$(tags_of "$VBUCKET" tag/v.bin "$version")" = "$(printf 'v\told')" ] || return 1
    [ "$(tags_of "$VBUCKET" tag/v.bin)" = "$(printf 'v\t2')" ] || return 1
    for v in "$version" "$newer"; do
        awss3 s3api delete-object --bucket "$VBUCKET" --key tag/v.bin --version-id "$v" >/dev/null 2>&1 || return 1
    done
    # A bucket's.
    ! awss3 s3api get-bucket-tagging --bucket "$BUCKET" >/dev/null 2>&1 || return 1
    awss3 s3api put-bucket-tagging --bucket "$BUCKET" --tagging 'TagSet=[{Key=team,Value=storage}]' \
        >/dev/null 2>&1 || return 1
    [ "$(awss3 s3api get-bucket-tagging --bucket "$BUCKET" --query 'TagSet[].[Key,Value]' --output text \
        2>/dev/null)" = "$(printf 'team\tstorage')" ] || return 1
    awss3 s3api delete-bucket-tagging --bucket "$BUCKET" >/dev/null 2>&1 || return 1
    ! awss3 s3api get-bucket-tagging --bucket "$BUCKET" >/dev/null 2>&1 || return 1
    for key in a.bin kept.bin new.bin up.bin; do
        awss3 s3api delete-object --bucket "$BUCKET" --key "tag/$key" >/dev/null 2>&1 || return 1
    done
}

# Changing an object's tags is a write: reader (`read`) may read them, not
# change them; writer (`write`, not `delete-version`) may change a version's.
tagging_roles_ok() {
    local r=(as_role reader readersecret) w=(as_role writer writersecret)
    awss3 s3api put-object --bucket "$BUCKET" --key tag/r.bin --body "$SMALL" --tagging 'r=1' \
        >/dev/null 2>&1 || return 1
    [ "$("${r[@]}" s3api get-object-tagging --bucket "$BUCKET" --key tag/r.bin \
        --query 'TagSet[0].Value' --output text 2>/dev/null)" = 1 ] || return 1
    ! "${r[@]}" s3api put-object-tagging --bucket "$BUCKET" --key tag/r.bin \
        --tagging 'TagSet=[{Key=r,Value=2}]' >/dev/null 2>&1 || return 1
    ! "${r[@]}" s3api delete-object-tagging --bucket "$BUCKET" --key tag/r.bin >/dev/null 2>&1 || return 1
    ! "${r[@]}" s3api put-bucket-tagging --bucket "$BUCKET" --tagging 'TagSet=[{Key=a,Value=b}]' \
        >/dev/null 2>&1 || return 1
    awss3 s3api delete-object --bucket "$BUCKET" --key tag/r.bin >/dev/null 2>&1 || return 1
    "${w[@]}" s3api put-object --bucket "$OBUCKET" --key tag/w.bin --body "$SMALL" >/dev/null 2>&1 || return 1
    "${w[@]}" s3api put-object-tagging --bucket "$OBUCKET" --key tag/w.bin --version-id null \
        --tagging 'TagSet=[{Key=w,Value=1}]' >/dev/null 2>&1 || return 1
    "${w[@]}" s3api delete-object-tagging --bucket "$OBUCKET" --key tag/w.bin --version-id null \
        >/dev/null 2>&1 || return 1
    "${w[@]}" s3api delete-object --bucket "$OBUCKET" --key tag/w.bin >/dev/null 2>&1
}

# Bucket sub-resource stubs: location/versioning/accelerate/request payment/
# logging/notification succeed (200, empty or default config);
# website/replication are "not configured" (the client errors on 404),
# and so are CORS, tags and lifecycle, until they're set. The policy holds
# the bucket's grants (see `grants`), and nothing else.
subresource_stubs_ok() {
    awss3 s3api get-bucket-location --bucket "$BUCKET" >/dev/null 2>&1 || return 1
    awss3 s3api get-bucket-versioning --bucket "$BUCKET" >/dev/null 2>&1 || return 1
    [ "$(awss3 s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text 2>/dev/null \
        | python3 -c 'import json,sys; print(all(s["Sid"].startswith("CairnGrant") for s in json.load(sys.stdin)["Statement"]))')" \
        = True ] || return 1
    ! awss3 s3api get-bucket-cors --bucket "$BUCKET" >/dev/null 2>&1 || return 1
    ! awss3 s3api get-bucket-tagging --bucket "$BUCKET" >/dev/null 2>&1 || return 1
    ! awss3 s3api get-bucket-lifecycle-configuration --bucket "$BUCKET" >/dev/null 2>&1 || return 1
    ! awss3 s3api get-bucket-website --bucket "$BUCKET" >/dev/null 2>&1 || return 1
    ! awss3 s3api get-bucket-replication --bucket "$BUCKET" >/dev/null 2>&1 || return 1
    awss3 s3api get-bucket-accelerate-configuration --bucket "$BUCKET" >/dev/null 2>&1 || return 1
    [ "$(awss3 s3api get-bucket-request-payment --bucket "$BUCKET" --query Payer --output text 2>/dev/null)" \
        = BucketOwner ] || return 1
    awss3 s3api get-bucket-logging --bucket "$BUCKET" >/dev/null 2>&1 || return 1
    awss3 s3api get-bucket-notification-configuration --bucket "$BUCKET" >/dev/null 2>&1 || return 1
}

# CORS: a configuration is bucket management (admin-only), reads back, and
# answers browsers' preflights (unsigned) and the requests they allow, with
# CORS headers even on errors; a request from another origin gets none.
cors_ok() {
    local url="http://${SERVER_HOST}:${SERVER_PORT}/${BUCKET}" doc="$WORK_DIR/cors.json" out pre
    printf '%s' '{"CORSRules":[{"ID":"app","AllowedOrigins":["https://*.example.com"],
        "AllowedMethods":["GET","PUT"],"AllowedHeaders":["content-type","x-amz-*"],
        "ExposeHeaders":["ETag"],"MaxAgeSeconds":600}]}' > "$doc"
    # No configuration yet: a preflight is refused.
    [ "$(curl -s -o /dev/null -w '%{http_code}' -X OPTIONS -H 'Origin: https://app.example.com' \
        -H 'Access-Control-Request-Method: GET' "$url/small.txt")" = 403 ] || return 1
    ! as_role writer writersecret s3api put-bucket-cors --bucket "$BUCKET" \
        --cors-configuration "file://$doc" >/dev/null 2>&1 || return 1
    awss3 s3api put-bucket-cors --bucket "$BUCKET" --cors-configuration "file://$doc" >/dev/null 2>&1 || return 1
    [ "$(awss3 s3api get-bucket-cors --bucket "$BUCKET" \
        --query 'CORSRules[0].[ID,AllowedOrigins[0],MaxAgeSeconds]' --output text 2>/dev/null)" \
        = "$(printf 'app\thttps://*.example.com\t600')" ] || return 1
    # The preflight of a presigned PUT a page would make.
    out=$(curl -s -D - -o /dev/null -X OPTIONS -H 'Origin: https://app.example.com' \
        -H 'Access-Control-Request-Method: PUT' -H 'Access-Control-Request-Headers: content-type' \
        "$url/cors/up.txt" | tr -d '\r')
    echo "$out" | grep -q '^HTTP/1.1 200' || return 1
    echo "$out" | grep -qi '^access-control-allow-origin: https://app.example.com$' || return 1
    echo "$out" | grep -qi '^access-control-allow-methods: GET, PUT$' || return 1
    echo "$out" | grep -qi '^access-control-allow-headers: content-type$' || return 1
    echo "$out" | grep -qi '^access-control-max-age: 600$' || return 1
    [ "$(curl -s -o /dev/null -w '%{http_code}' -X OPTIONS -H 'Origin: https://app.example.com' \
        -H 'Access-Control-Request-Method: DELETE' "$url/cors/up.txt")" = 403 ] || return 1
    [ "$(curl -s -o /dev/null -w '%{http_code}' -X OPTIONS -H 'Origin: https://app.example.org' \
        -H 'Access-Control-Request-Method: PUT' "$url/cors/up.txt")" = 403 ] || return 1
    # The PUT itself, and a GET of what it wrote, presigned.
    pre=$(python3 "$PRESIGNER" PUT "$url/cors/up.txt" 60) || return 1
    out=$(curl -s -D - -o /dev/null -T "$SMALL" -H 'Origin: https://app.example.com' "$pre" | tr -d '\r')
    echo "$out" | grep -q '^HTTP/1.1 200' || return 1
    echo "$out" | grep -qi '^access-control-allow-origin: https://app.example.com$' || return 1
    echo "$out" | grep -qi '^access-control-expose-headers: ETag$' || return 1
    pre=$(python3 "$PRESIGNER" GET "$url/cors/up.txt" 60) || return 1
    curl -s -D - -o /dev/null -H 'Origin: https://app.example.com' "$pre" \
        | grep -qi '^access-control-allow-origin: https://app.example.com' || return 1
    curl -s -D - -o /dev/null -H 'Origin: https://app.example.org' "$pre" \
        | grep -qi '^access-control-allow-origin' && return 1
    # An error (here, an unsigned request) can be read by the page too.
    out=$(curl -s -D - -o /dev/null -H 'Origin: https://app.example.com' "$url/cors/up.txt" | tr -d '\r')
    echo "$out" | grep -q '^HTTP/1.1 403' || return 1
    echo "$out" | grep -qi '^access-control-allow-origin: https://app.example.com$' || return 1
    awss3 s3api delete-bucket-cors --bucket "$BUCKET" >/dev/null 2>&1 || return 1
    ! awss3 s3api get-bucket-cors --bucket "$BUCKET" >/dev/null 2>&1 || return 1
    s3 del "s3://${BUCKET}/cors/up.txt" >/dev/null 2>&1
}

# A lifecycle configuration is bucket management (admin-only): writer can't
# set one; the admin can, and it reads back, rule ID and tag filters and all.
# Transitions are
# refused (501), and the configuration can be deleted again.
lifecycle_config_ok() {
    local doc="$WORK_DIR/lifecycle.json" glacier="$WORK_DIR/lifecycle-glacier.json"
    printf '%s' '{"Rules":[{"ID":"expire-logs","Filter":{"Prefix":"logs/"},"Status":"Enabled",
        "Expiration":{"Days":30},"NoncurrentVersionExpiration":{"NoncurrentDays":7}},
        {"ID":"tmp","Filter":{"And":{"Prefix":"x/","Tags":[{"Key":"tmp","Value":"yes"},{"Key":"k","Value":""}]}},
        "Status":"Enabled","Expiration":{"Days":1}}]}' > "$doc"
    printf '%s' '{"Rules":[{"ID":"cold","Filter":{},"Status":"Enabled",
        "Transitions":[{"Days":30,"StorageClass":"GLACIER"}]}]}' > "$glacier"
    ! as_role writer writersecret s3api put-bucket-lifecycle-configuration --bucket "$VBUCKET" \
        --lifecycle-configuration "file://$doc" >/dev/null 2>&1 || return 1
    ! awss3 s3api put-bucket-lifecycle-configuration --bucket "$VBUCKET" \
        --lifecycle-configuration "file://$glacier" >/dev/null 2>&1 || return 1
    awss3 s3api put-bucket-lifecycle-configuration --bucket "$VBUCKET" \
        --lifecycle-configuration "file://$doc" >/dev/null 2>&1 || return 1
    [ "$(awss3 s3api get-bucket-lifecycle-configuration --bucket "$VBUCKET" \
        --query 'Rules[0].[ID,Filter.Prefix,Expiration.Days,NoncurrentVersionExpiration.NoncurrentDays]' \
        --output text 2>/dev/null)" = "$(printf 'expire-logs\tlogs/\t30\t7')" ] || return 1
    # A rule filtering on tags, as written (S3 sorts nothing here).
    [ "$(awss3 s3api get-bucket-lifecycle-configuration --bucket "$VBUCKET" \
        --query 'Rules[1].Filter.And.[Prefix, Tags[0].Key, Tags[0].Value, Tags[1].Key]' \
        --output text 2>/dev/null)" = "$(printf 'x/\ttmp\tyes\tk')" ] || return 1
    awss3 s3api delete-bucket-lifecycle --bucket "$VBUCKET" >/dev/null 2>&1 || return 1
    ! awss3 s3api get-bucket-lifecycle-configuration --bucket "$VBUCKET" >/dev/null 2>&1
}

# ListMultipartUploads: aws-cli lists an incomplete upload under its prefix,
# and no longer once it's aborted.
list_uploads_ok() {
    local key="lmu/pending.bin" uid listed
    uid=$(awss3 s3api create-multipart-upload --bucket "$BUCKET" --key "$key" \
        --query UploadId --output text 2>/dev/null) || return 1
    listed=$(awss3 s3api list-multipart-uploads --bucket "$BUCKET" --prefix lmu/ \
        --query 'Uploads[].[Key,UploadId]' --output text 2>/dev/null)
    awss3 s3api abort-multipart-upload --bucket "$BUCKET" --key "$key" --upload-id "$uid" >/dev/null 2>&1 || return 1
    [ "$listed" = "$(printf '%s\t%s' "$key" "$uid")" ] || return 1
    listed=$(awss3 s3api list-multipart-uploads --bucket "$BUCKET" --prefix lmu/ \
        --query 'length(Uploads || `[]`)' --output text 2>/dev/null)
    [ "$listed" = 0 ]
}

# A PUT declaring more than 5 GiB is refused (400 EntityTooLarge) before its
# body is read: here, it never comes.
too_large_refused() {
    [ "$(scurl PUT "/${BUCKET}/too-large" UNSIGNED-PAYLOAD "$SMALL" "Content-Length: 5368709121")" = 400 ]
}

# ACLs, as with S3's default "bucket owner enforced": a write may ask for the
# owner's ACL only (or none), setting it is a no-op, anything else is refused;
# reading ACLs and ownership controls shows the owner in control.
acls_disabled_ok() {
    local nb="acl-$(date +%s)"
    ! awss3 s3api put-object --bucket "$BUCKET" --key acl/x.txt --body "$SMALL" --acl public-read \
        >/dev/null 2>&1 || return 1
    awss3 s3api put-object --bucket "$BUCKET" --key acl/x.txt --body "$SMALL" \
        --acl bucket-owner-full-control >/dev/null 2>&1 || return 1
    awss3 s3api put-object-acl --bucket "$BUCKET" --key acl/x.txt --acl bucket-owner-full-control \
        >/dev/null 2>&1 || return 1
    awss3 s3api put-object-acl --bucket "$BUCKET" --key acl/x.txt --acl public-read 2>&1 \
        | grep -q AccessControlListNotSupported || return 1
    awss3 s3api put-object-acl --bucket "$BUCKET" --key acl/missing --acl bucket-owner-full-control 2>&1 \
        | grep -q NoSuchKey || return 1
    awss3 s3api create-bucket --bucket "$nb" --acl public-read 2>&1 \
        | grep -q InvalidBucketAclWithObjectOwnership || return 1
    awss3 s3api create-bucket --bucket "$nb" --acl private >/dev/null 2>&1 || return 1
    [ "$(awss3 s3api get-bucket-ownership-controls --bucket "$nb" \
        --query 'OwnershipControls.Rules[0].ObjectOwnership' --output text 2>/dev/null)" = BucketOwnerEnforced ] || return 1
    awss3 s3api delete-bucket --bucket "$nb" >/dev/null 2>&1 || return 1
    awss3 s3api delete-object --bucket "$BUCKET" --key acl/x.txt >/dev/null 2>&1
}

# Listing parameters as S3 takes them: url-encoded keys, an empty delimiter
# that isn't one, a page size that's no number refused; and ListBuckets in
# pages.
listing_parameters_ok() {
    local listed tok
    s3 put "$SMALL" "s3://${BUCKET}/enc/a+b c" >/dev/null 2>&1 || return 1
    listed=$(scurl_get "/${BUCKET}?list-type=2&prefix=enc%2F&encoding-type=url&delimiter=") || return 1
    echo "$listed" | grep -q '<Key>enc/a%2Bb%20c</Key>' || return 1
    echo "$listed" | grep -q '<EncodingType>url</EncodingType>' || return 1
    ! echo "$listed" | grep -q '<Delimiter>' || return 1
    [ "$(scurl GET "/${BUCKET}?max-keys=blah" "$EMPTY_SHA256" -)" = 400 ] || return 1
    tok=$(awss3 s3api list-buckets --max-buckets 1 --query ContinuationToken --output text 2>/dev/null) || return 1
    [ -n "$tok" ] && [ "$tok" != None ] || return 1
    [ "$(awss3 s3api list-buckets --max-buckets 1 --continuation-token "$tok" \
        --query 'length(Buckets)' --output text 2>/dev/null)" = 1 ] || return 1
    s3 del "s3://${BUCKET}/enc/a+b c" >/dev/null 2>&1
}

# Smaller things S3 does: If-Match on a key without an object is a 404, an
# upload in chunked transfer encoding is fine, a copy range out of the source
# a 416 (and a malformed one a 400), and a bucket name like an IP address a 400.
s3_details_ok() {
    local hash uid code
    hash=$(sha256sum "$SMALL" | cut -d' ' -f1)
    [ "$(scurl PUT "/${BUCKET}/no-such-key" "$hash" "$SMALL" "If-Match: *")" = 404 ] || return 1
    [ "$(scurl PUT "/${BUCKET}/chunked" UNSIGNED-PAYLOAD "$SMALL" "Transfer-Encoding: chunked")" = 200 ] || return 1
    check_roundtrip "$SMALL" "s3://${BUCKET}/chunked" || return 1
    s3 del "s3://${BUCKET}/chunked" >/dev/null 2>&1
    uid=$(awss3 s3api create-multipart-upload --bucket "$BUCKET" --key range-copy \
        --query UploadId --output text 2>/dev/null) || return 1
    code=$(scurl PUT "/${BUCKET}/range-copy?partNumber=1&uploadId=${uid}" "$EMPTY_SHA256" - \
        "x-amz-copy-source: /${BUCKET}/small.txt" "x-amz-copy-source-range: bytes=0-99999")
    [ "$code" = 416 ] || return 1
    code=$(scurl PUT "/${BUCKET}/range-copy?partNumber=1&uploadId=${uid}" "$EMPTY_SHA256" - \
        "x-amz-copy-source: /${BUCKET}/small.txt" "x-amz-copy-source-range: 0-2")
    [ "$code" = 400 ] || return 1
    awss3 s3api abort-multipart-upload --bucket "$BUCKET" --key range-copy --upload-id "$uid" \
        >/dev/null 2>&1 || return 1
    awss3 s3api create-bucket --bucket 10.0.0.1 2>&1 | grep -q InvalidBucketName
}

# Every response has an x-amz-request-id, and an error document names it too.
request_id_ok() {
    local url="http://${SERVER_HOST}:${SERVER_PORT}/${BUCKET}" args=() line out id
    while IFS= read -r line; do args+=(-H "$line"); done \
        < <(python3 "$SIGNER" GET "$url/no-such-key" "$EMPTY_SHA256")
    out=$(curl -s -D - "${args[@]}" "$url/no-such-key")
    id=$(echo "$out" | tr -d '\r' | sed -n 's/^x-amz-request-id: //Ip')
    [ "${#id}" = 16 ] || return 1
    echo "$out" | grep -q "<RequestId>$id</RequestId>" || return 1
    args=()
    while IFS= read -r line; do args+=(-H "$line"); done \
        < <(python3 "$SIGNER" GET "$url/small.txt" "$EMPTY_SHA256")
    curl -s -D - -o /dev/null "${args[@]}" "$url/small.txt" | grep -qi '^x-amz-request-id: '
}

# Presigned URLs: a GET (aws-cli's) and a PUT (ours) work with nothing but
# curl, and a GET can set the response's Content-Disposition; changing the URL
# or letting it expire breaks it.
presigned_ok() {
    local base="http://${SERVER_HOST}:${SERVER_PORT}/${BUCKET}" url code
    url=$(awss3 s3 presign "s3://${BUCKET}/small.txt" --expires-in 60 2>/dev/null) || return 1
    curl -sf "$url" -o "$WORK_DIR/pre.get" && cmp -s "$SMALL" "$WORK_DIR/pre.get" || return 1
    url=$(python3 "$PRESIGNER" PUT "$base/pre/up.txt" 60) || return 1
    curl -sf -T "$SMALL" "$url" -o /dev/null || return 1
    check_roundtrip "$SMALL" "s3://${BUCKET}/pre/up.txt" || return 1
    url=$(python3 "$PRESIGNER" GET "$base/pre/up.txt" 60 \
        "response-content-disposition=attachment%3B%20filename%3D%22saved.txt%22") || return 1
    curl -sf -D - -o /dev/null "$url" | grep -qi '^content-disposition: attachment; filename="saved.txt"' || return 1
    code=$(curl -s -o /dev/null -w '%{http_code}' "${url/pre\/up.txt/small.txt}")
    [ "$code" = 403 ] || return 1
    url=$(python3 "$PRESIGNER" GET "$base/pre/up.txt" 1) || return 1
    sleep 2
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$url")" = 403 ] || return 1
    s3 del "s3://${BUCKET}/pre/up.txt" >/dev/null 2>&1
}

# POST Object: a form signed with a policy uploads with nothing but curl,
# under its key prefix (the file's name for ${filename}), with the response
# it asks for; a file over the policy's size is refused, and so is a form
# signed with another secret.
post_object_ok() {
    local url="http://${SERVER_HOST}:${SERVER_PORT}/${BUCKET}" args=() line out="$WORK_DIR/post.out" code
    while IFS= read -r line; do args+=(--form-string "$line"); done \
        < <(python3 "$POST_SIGNER" "$BUCKET" 'post/${filename}' 100000 success_action_status=201 Content-Type=text/plain)
    [ "${#args[@]}" -gt 0 ] || return 1
    code=$(curl -s -o "$out" -w '%{http_code}' "${args[@]}" -F "file=@$SMALL;filename=small.txt" "$url")
    [ "$code" = 201 ] && grep -q "<Key>post/small.txt</Key>" "$out" || return 1
    check_roundtrip "$SMALL" "s3://${BUCKET}/post/small.txt" || return 1
    code=$(curl -s -o "$out" -w '%{http_code}' "${args[@]}" -F "file=@$BIG;filename=big.bin" "$url")
    [ "$code" = 400 ] && grep -q "<Code>EntityTooLarge</Code>" "$out" || return 1
    args=("${args[@]/x-amz-signature=/x-amz-signature=0}")
    code=$(curl -s -o "$out" -w '%{http_code}' "${args[@]}" -F "file=@$SMALL;filename=other.txt" "$url")
    [ "$code" = 403 ] && grep -q "<Code>SignatureDoesNotMatch</Code>" "$out" || return 1
    s3 del "s3://${BUCKET}/post/small.txt" >/dev/null 2>&1
}

# Operations Cairn doesn't implement are refused (501), not run as the plain
# PUT/DELETE/GET they'd otherwise route to: the object and the bucket survive.
unsupported_subresources_refused() {
    local path="/${BUCKET}/small.txt" xml="$WORK_DIR/legal-hold.xml"
    printf '<LegalHold><Status>ON</Status></LegalHold>' >"$xml"
    local hash; hash=$(sha256sum "$xml" | cut -d' ' -f1)
    [ "$(scurl PUT "$path?legal-hold" "$hash" "$xml")" = 501 ] || return 1
    [ "$(scurl PUT "$path?retention" "$EMPTY_SHA256" -)" = 501 ] || return 1
    [ "$(scurl DELETE "$path?retention" "$EMPTY_SHA256" -)" = 501 ] || return 1
    [ "$(scurl GET "$path?legal-hold" "$EMPTY_SHA256" -)" = 501 ] || return 1
    [ "$(scurl DELETE "/${BUCKET}?website" "$EMPTY_SHA256" -)" = 501 ] || return 1
    check_roundtrip "$SMALL" "s3://${BUCKET}/small.txt"
}

# A multipart object, read part by part (GetObject and HeadObject with
# --part-number), its attributes (GetObjectAttributes), and a Complete that
# says what size it expects (--mpu-object-size): refused if it's wrong.
parts_and_attributes_ok() {
    local key=parts/mp.bin p1="$WORK_DIR/part1.bin" p2="$WORK_DIR/part2.bin" out="$WORK_DIR/part.out" uid e1 e2 err
    head -c 8388608 "$MULTIPART" >"$p1"
    tail -c +8388609 "$MULTIPART" >"$p2"
    uid=$(awss3 s3api create-multipart-upload --bucket "$BUCKET" --key "$key" \
        --query UploadId --output text 2>/dev/null) || return 1
    e1=$(awss3 s3api upload-part --bucket "$BUCKET" --key "$key" --upload-id "$uid" --part-number 1 \
        --body "$p1" --query ETag --output text 2>/dev/null) || return 1
    e2=$(awss3 s3api upload-part --bucket "$BUCKET" --key "$key" --upload-id "$uid" --part-number 2 \
        --body "$p2" --query ETag --output text 2>/dev/null) || return 1
    local parts="{\"Parts\":[{\"PartNumber\":1,\"ETag\":${e1}},{\"PartNumber\":2,\"ETag\":${e2}}]}"
    err=$(awss3 s3api complete-multipart-upload --bucket "$BUCKET" --key "$key" --upload-id "$uid" \
        --multipart-upload "$parts" --mpu-object-size 1 2>&1) && return 1
    echo "$err" | grep -q "does not match what was computed: 16777216" || return 1
    awss3 s3api complete-multipart-upload --bucket "$BUCKET" --key "$key" --upload-id "$uid" \
        --multipart-upload "$parts" --mpu-object-size 16777216 >/dev/null 2>&1 || return 1
    [ "$(awss3 s3api get-object --bucket "$BUCKET" --key "$key" --part-number 2 "$out" \
        --query PartsCount --output text 2>/dev/null)" = 2 ] || return 1
    cmp -s "$out" "$p2" || return 1
    [ "$(awss3 s3api head-object --bucket "$BUCKET" --key "$key" --part-number 1 \
        --query ContentLength --output text 2>/dev/null)" = 8388608 ] || return 1
    ! awss3 s3api head-object --bucket "$BUCKET" --key "$key" --part-number 3 >/dev/null 2>&1 || return 1
    [ "$(awss3 s3api get-object-attributes --bucket "$BUCKET" --key "$key" \
        --object-attributes ObjectParts ObjectSize --query '[ObjectParts.TotalPartsCount, ObjectSize]' \
        --output text 2>/dev/null)" = "$(printf '2\t16777216')" ] || return 1
    s3 del "s3://${BUCKET}/${key}" >/dev/null 2>&1
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
# path) → 200, and a well-formed request against a missing bucket → 404, as in S3.
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
# disappear WITHOUT waiting for the GC (the happy-path optimization). We can't map keys
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
# parts a completion leaves out, are deleted from disk without the GC. Stages two
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
    awss3 s3api get-object --bucket "$VBUCKET" --key "$1" ${3:+--version-id="$3"} \
        "$WORK_DIR/vget.out" >/dev/null 2>&1 && cmp -s "$2" "$WORK_DIR/vget.out"
}
# vdel <key> [version] — DELETE, printing "<DeleteMarker>\t<VersionId>".
vdel() {
    awss3 s3api delete-object --bucket "$VBUCKET" --key "$1" ${2:+--version-id="$2"} \
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
    [ "$(awss3 s3api head-object --bucket "$VBUCKET" --key ow --version-id="$v1" \
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
    awss3 s3api head-object --bucket "$VBUCKET" --key dm --version-id="$marker" 2>&1 | grep -q 405
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
# version (an overwrite replaces it; as in S3, a write reports no version ID
# for it), and a DELETE swaps the null version for a null delete marker.
# Re-enables versioning afterwards.
versioning_suspended_ok() {
    local v1 out
    v1=$(vput su "$SMALL") || return 1
    awss3 s3api put-bucket-versioning --bucket "$VBUCKET" \
        --versioning-configuration Status=Suspended >/dev/null 2>&1 || return 1
    [ "$(awss3 s3api get-bucket-versioning --bucket "$VBUCKET" \
        --query Status --output text 2>/dev/null)" = "Suspended" ] || return 1
    [ "$(vput su "$NESTED")" = "None" ] || return 1
    [ "$(vput su "$BIG")" = "None" ] || return 1
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
    ! "${w[@]}" s3api delete-object --bucket "$VBUCKET" --key perm --version-id="$v" >/dev/null 2>&1 || return 1
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
    # A version ID that can't be one is malformed; a well-formed one names no
    # version.
    awss3 s3api copy-object --bucket "$VBUCKET" --key cs2 \
        --copy-source "${VBUCKET}/cs?versionId=nosuchversion" 2>&1 | grep -q InvalidArgument || return 1
    awss3 s3api copy-object --bucket "$VBUCKET" --key cs2 \
        --copy-source "${VBUCKET}/cs?versionId=$(printf 'x%.0s' {1..32})" 2>&1 | grep -q NoSuchVersion
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
    awss3 s3api delete-object --bucket "$b" --key k --version-id="$v" >/dev/null 2>&1 || return 1
    awss3 s3api delete-bucket --bucket "$b" 2>&1 | grep -q BucketNotEmpty || return 1
    awss3 s3api delete-object --bucket "$b" --key k --version-id="$marker" >/dev/null 2>&1 || return 1
    awss3 s3api delete-bucket --bucket "$b" >/dev/null 2>&1
}

# maintain_now — runs a maintenance pass (GC, then packing) on the server now,
# as the background one (every minute) would, but sweeping all of the data dir.
# The peer endpoint answers once the pass is done. The background pass may get
# to the work first, so the tests check what was done, not which pass did it.
maintain_now() { curl -fsS -X POST "http://${SERVER_HOST}:9431/maintain" >/dev/null 2>&1; }

# The GC removes empty shard directories. Upload then delete a batch of objects
# (emptying their shard dirs), run a maintenance pass, and confirm the
# directory count dropped. Live objects' shards stay (non-empty).
gc_empty_dirs_ok() {
    local datadir="$WORK_DIR/data" before after k
    for k in $(seq 1 8); do s3 put "$NESTED" "s3://${BUCKET}/dirs/o$k" >/dev/null 2>&1 || return 1; done
    for k in $(seq 1 8); do s3 del "s3://${BUCKET}/dirs/o$k" >/dev/null 2>&1 || return 1; done
    before=$(find "$datadir" -type d | wc -l)
    maintain_now || return 1
    after=$(find "$datadir" -type d | wc -l)
    [ "$after" -lt "$before" ]
}

# The GC deletes a file the catalog doesn't know (as a crash mid-upload leaves
# behind), in a shard directory of its own.
gc_orphan_ok() {
    local id=0199aaaa-0000-7000-8000-00000000beef
    mkdir -p "$WORK_DIR/data/be/ef"
    printf 'orphan' >"$WORK_DIR/data/be/ef/$id"
    maintain_now || return 1
    [ ! -e "$WORK_DIR/data/be/ef/$id" ] && [ ! -e "$WORK_DIR/data/be/ef" ]
}

# ─── Packing ───
pack_now() { maintain_now; }

# packed_until <cmd...> — runs packing passes until <cmd> holds (for up to two
# minutes, while a background pass may still be busy with the work).
packed_until() {
    local i
    for i in $(seq 1 60); do
        pack_now
        "$@" && return 0
        sleep 2
    done
    return 1
}

# sql <query> — runs a query against the catalog, printing the bare result.
sql() { podman exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -tAc "$1"; }

# Blobs small enough to be packed (up to 64 MiB).
SMALL_BLOBS="FROM blobs WHERE state = 'committed' AND size <= 67108864"
small_waiting() { sql "SELECT coalesce(sum(size), 0) $SMALL_BLOBS"; }
no_small_blobs() { [ "$(sql "SELECT count(*) $SMALL_BLOBS")" = 0 ]; }
# The packed blobs.
large_blobs() { sql "SELECT string_agg(blob_id::text, ',' ORDER BY blob_id) FROM blobs WHERE size > 67108864"; }

# accounting_ok — every byte of every referenced blob is either live (some
# part's; copies share bytes, so each counts once) or counted as garbage. Right
# after a pass, which folds the garbage log.
accounting_ok() {
    [ "$(sql "SELECT (SELECT coalesce(sum(b.size - b.dead_size), 0) FROM blobs b
                      WHERE b.state = 'committed'
                        AND EXISTS (SELECT 1 FROM parts p WHERE p.blob_id = b.blob_id))
                   = (SELECT coalesce(sum(upper(r) - lower(r)), 0)
                      FROM (SELECT unnest(range_agg(int8range(blob_offset, blob_offset + size))) AS r
                            FROM parts GROUP BY blob_id) AS ranges)")" = t ]
}

# bytes_at_most <n> — the data dir holds at most <n> bytes.
bytes_at_most() { [ "$(du -sb "$WORK_DIR/data" | cut -f1)" -le "$1" ]; }

PACK_DIR="$WORK_DIR/pack"
PACK_VBUCKET="packver-$(date +%s)"

# Uploads 120 small objects of different sizes, two versions of an object in a
# versioned bucket and two staged parts of a multipart upload, then objects of
# 63 MiB until the small blobs waiting (these, and the others stored so far, like
# the parts of multi.bin) fill a 256 MiB blob. Packing can't start before the
# last of them lands, so all of them are consolidated, into two blobs.
# Everything reads back intact: whole, ranged, the old version, and the upload
# once it's completed.
pack_consolidates_ok() {
    local dir="$PACK_DIR" i v1 v2 uid e1 e2 fills=0
    mkdir -p "$dir/up"
    for i in $(seq 1 120); do head -c $((i * 1024)) /dev/urandom >"$dir/up/o$i"; done
    for i in v1 v2 p2; do head -c 3000 /dev/urandom >"$dir/$i"; done
    # A part that isn't the last is at least 5 MiB.
    head -c $((5 * 1024 * 1024)) /dev/urandom >"$dir/p1"
    awss3 s3 cp --recursive "$dir/up" "s3://${BUCKET}/pack/" >/dev/null 2>&1 || return 1
    mb_granted "$PACK_VBUCKET" >/dev/null 2>&1 || return 1
    cairn_role grant "$ACCESS_KEY" "$PACK_VBUCKET" delete-version >/dev/null 2>&1 || return 1
    awss3 s3api put-bucket-versioning --bucket "$PACK_VBUCKET" \
        --versioning-configuration Status=Enabled >/dev/null 2>&1 || return 1
    v1=$(awss3 s3api put-object --bucket "$PACK_VBUCKET" --key k --body "$dir/v1" \
        --query VersionId --output text 2>/dev/null) || return 1
    v2=$(awss3 s3api put-object --bucket "$PACK_VBUCKET" --key k --body "$dir/v2" \
        --query VersionId --output text 2>/dev/null) || return 1
    uid=$(awss3 s3api create-multipart-upload --bucket "$BUCKET" --key pack-mpu \
        --query UploadId --output text 2>/dev/null) || return 1
    e1=$(awss3 s3api upload-part --bucket "$BUCKET" --key pack-mpu --upload-id "$uid" \
        --part-number 1 --body "$dir/p1" --query ETag --output text 2>/dev/null) || return 1
    e2=$(awss3 s3api upload-part --bucket "$BUCKET" --key pack-mpu --upload-id "$uid" \
        --part-number 2 --body "$dir/p2" --query ETag --output text 2>/dev/null) || return 1
    # One at a time, and each in a single PUT, so the blob only fills once the
    # last one is complete.
    while [ "$(small_waiting)" -lt 268435456 ]; do
        fills=$((fills + 1))
        [ "$fills" -le 6 ] || return 1
        head -c $((63 * 1024 * 1024)) /dev/urandom >"$dir/up/fill$fills"
        awss3 s3api put-object --bucket "$BUCKET" --key "pack/fill$fills" \
            --body "$dir/up/fill$fills" >/dev/null 2>&1 || return 1
    done

    packed_until no_small_blobs || return 1
    [ "$(sql "SELECT count(*) FROM blobs WHERE state = 'committed'")" = 2 ] || return 1
    accounting_ok || return 1

    awss3 s3 cp --recursive "s3://${BUCKET}/pack/" "$dir/down" >/dev/null 2>&1 || return 1
    diff -r "$dir/up" "$dir/down" >/dev/null || return 1
    range_ok pack/o100 1000 1999 "$dir/up/o100" || return 1
    check_roundtrip "$MULTIPART" "s3://${BUCKET}/multi.bin" || return 1
    for i in v1 v2; do
        awss3 s3api get-object --bucket "$PACK_VBUCKET" --key k --version-id="${!i}" \
            "$dir/$i.dl" >/dev/null 2>&1 || return 1
        cmp -s "$dir/$i" "$dir/$i.dl" || return 1
    done
    awss3 s3api complete-multipart-upload --bucket "$BUCKET" --key pack-mpu --upload-id "$uid" \
        --multipart-upload "{\"Parts\":[{\"PartNumber\":1,\"ETag\":${e1}},{\"PartNumber\":2,\"ETag\":${e2}}]}" \
        >/dev/null 2>&1 || return 1
    cat "$dir/p1" "$dir/p2" >"$dir/mpu"
    check_roundtrip "$dir/mpu" "s3://${BUCKET}/pack-mpu" || return 1

    for i in "$v1" "$v2"; do
        awss3 s3api delete-object --bucket "$PACK_VBUCKET" --key k --version-id="$i" \
            >/dev/null 2>&1 || return 1
    done
    awss3 s3api delete-bucket --bucket "$PACK_VBUCKET" >/dev/null 2>&1 || return 1
    s3 del "s3://${BUCKET}/pack-mpu" >/dev/null 2>&1
}

# Small blobs that don't fill a blob aren't worth packing yet, and a packed
# blob with a little garbage isn't worth rewriting: packing leaves both alone.
pack_below_thresholds_ok() {
    local dir="$PACK_DIR" i packed
    mkdir -p "$dir/few"
    for i in $(seq 1 50); do head -c 1000 /dev/urandom >"$dir/few/f$i"; done
    awss3 s3 cp --recursive "$dir/few" "s3://${BUCKET}/pack-few/" >/dev/null 2>&1 || return 1
    # o1-o5 are the smallest packed objects: well under a quarter of a blob.
    for i in 1 2 3 4 5; do
        s3 del "s3://${BUCKET}/pack/o$i" >/dev/null 2>&1 || return 1
        rm "$dir/up/o$i"
    done
    packed=$(large_blobs)
    pack_now || return 1
    [ "$(sql "SELECT count(*) $SMALL_BLOBS")" = 50 ] || return 1
    [ "$(large_blobs)" = "$packed" ] || return 1
    accounting_ok || return 1
    awss3 s3 rm --recursive "s3://${BUCKET}/pack-few/" >/dev/null 2>&1
}

# no_sparse_blobs — no blob is a quarter garbage or more. Right after a pass.
no_sparse_blobs() {
    [ "$(sql "SELECT count(*) FROM blobs WHERE dead_size > 0 AND dead_size >= size / 4")" = 0 ]
}

# disk_matches_catalog — the data dir holds no more than the blobs in the
# catalog (plus their checksum tables, and the directories): the files of
# dropped blobs are gone.
disk_matches_catalog() {
    local blobs dirs
    blobs=$(sql "SELECT coalesce(sum(size), 0) FROM blobs")
    dirs=$(find "$WORK_DIR/data" -type d | wc -l)
    bytes_at_most $((blobs + blobs / 1000 + dirs * 4096 + 1048576))
}

# Deletes the large objects and the larger half of the small ones, so most of
# the packed blobs is garbage: they're compacted until none is a quarter
# garbage anymore, and the space is freed. What's left still reads back intact,
# and the deleted objects stay gone.
pack_compacts_ok() {
    local dir="$PACK_DIR" i keys packed before fills
    # Tests run in subshells, so count the 63 MiB objects the packing test made.
    fills=$(find "$dir/up" -name 'fill*' | wc -l)
    keys=$(for i in $(seq 61 120); do printf '{"Key":"pack/o%s"},' "$i"; done
           for i in $(seq 1 "$fills"); do printf '{"Key":"pack/fill%s"},' "$i"; done)
    packed=$(large_blobs)
    before=$(sql "SELECT sum(size) FROM blobs")
    awss3 s3api delete-objects --bucket "$BUCKET" \
        --delete "{\"Objects\":[${keys%,}]}" >/dev/null 2>&1 || return 1
    # Deleting objects from packed blobs frees nothing until they're compacted.
    packed_until eval '[ "$(large_blobs)" != "$packed" ] && no_sparse_blobs' || {
        echo "not compacted: $(sql "SELECT blob_id, size, dead_size FROM blobs WHERE size > 67108864")"
        return 1
    }
    [ "$(sql "SELECT sum(size) FROM blobs")" -le $((before - fills * 63 * 1024 * 1024)) ] || {
        echo "blobs shrank from $before to $(sql "SELECT sum(size) FROM blobs") bytes only"
        return 1
    }
    packed_until disk_matches_catalog || {
        echo "data dir: $(du -sb "$WORK_DIR/data" | cut -f1) bytes, blobs: $(sql "SELECT sum(size) FROM blobs")"
        return 1
    }
    accounting_ok || return 1
    for i in $(seq 61 120); do rm "$dir/up/o$i"; done
    rm "$dir"/up/fill*
    rm -rf "$dir/down"
    awss3 s3 cp --recursive "s3://${BUCKET}/pack/" "$dir/down" >/dev/null 2>&1 || return 1
    diff -r "$dir/up" "$dir/down" >/dev/null || return 1
    check_roundtrip "$MULTIPART" "s3://${BUCKET}/multi.bin" || return 1
    awss3 s3 rm --recursive "s3://${BUCKET}/pack/" >/dev/null 2>&1
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

cairn_user() { (cd "$SCRIPT_DIR" && cargo run -q -- user --database "$DB_URL" "$@"); }
cairn_bucket_policy() { (cd "$SCRIPT_DIR" && cargo run -q -- bucket-policy --database "$DB_URL" "$@"); }

# Bucket policies: only an admin sets one; it reads back as S3 keeps it, and
# decides requests as S3's does: anonymous ones (a public prefix, and nothing
# else: a missing key there is a 403, as the policy doesn't allow listing),
# and a user's (allowed what it has no grant for, denied what its grant would
# allow, with S3's messages). One that denies everyone, its admins too, the
# superadmin can still remove.
bucket_policy_ok() {
    local b="pol-$(date +%s)" doc="$WORK_DIR/policy.json" deny="$WORK_DIR/deny-all.json" out arn account url
    url="http://${SERVER_HOST}:${SERVER_PORT}/$b"
    arn=$(cairn_user list | sed -n 's|^  \(arn:aws:iam::[0-9]*:user/writer\)$|\1|p')
    account=$(echo "$arn" | cut -d: -f5)
    [ -n "$account" ] || return 1
    awss3 s3api create-bucket --bucket "$b" >/dev/null 2>&1 || return 1
    cairn_role grant "$ACCESS_KEY" "$b" read write >/dev/null 2>&1 || return 1
    cairn_role grant writer "$b" write >/dev/null 2>&1 || return 1
    printf 'public' > "$WORK_DIR/pub.txt"
    for key in pub/a.txt private.txt; do
        awss3 s3api put-object --bucket "$b" --key "$key" --body "$WORK_DIR/pub.txt" >/dev/null 2>&1 || return 1
    done
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$url/pub/a.txt")" = 403 ] || return 1
    # The grants are the bucket's policy, so far.
    awss3 s3api get-bucket-policy --bucket "$b" --query Policy --output text 2>/dev/null \
        | grep -q '"Sid":"CairnGrantWrite"' || return 1
    printf '%s' '{"Version":"2012-10-17","Statement":[
 {"Sid":"PublicRead","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::'"$b"'/pub/*"},
 {"Sid":"Drop","Effect":"Allow","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::'"$b"'/drop/*"},
 {"Effect":"Allow","Principal":{"AWS":"'"$arn"'"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::'"$b"'/private.txt"},
 {"Effect":"Deny","Principal":{"AWS":"'"$account"'"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::'"$b"'/locked/*"}]}' \
        > "$doc"
    ! as_role writer writersecret s3api put-bucket-policy --bucket "$b" --policy "file://$doc" >/dev/null 2>&1 || return 1
    # A new bucket blocks public access, as in S3: the public policy is
    # refused until its block is off.
    [ "$(awss3 s3api get-public-access-block --bucket "$b" \
        --query 'PublicAccessBlockConfiguration.[BlockPublicAcls,IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets]' \
        --output text 2>/dev/null)" = "$(printf 'True\tTrue\tTrue\tTrue')" ] || return 1
    out=$(awss3 s3api put-bucket-policy --bucket "$b" --policy "file://$doc" 2>&1) && return 1
    echo "$out" | grep -q BlockPublicPolicy || return 1
    awss3 s3api delete-public-access-block --bucket "$b" >/dev/null 2>&1 || return 1
    ! awss3 s3api get-public-access-block --bucket "$b" >/dev/null 2>&1 || return 1
    awss3 s3api put-bucket-policy --bucket "$b" --policy "file://$doc" >/dev/null 2>&1 || return 1
    # Grants are statements of the bucket's policy, which that replaced.
    cairn_role grant writer "$b" write >/dev/null 2>&1 || return 1
    awss3 s3api get-bucket-policy --bucket "$b" --query Policy --output text 2>/dev/null \
        | grep -qF "\"Principal\":{\"AWS\":\"arn:aws:iam::$account:root\"}" || return 1
    [ "$(awss3 s3api get-bucket-policy-status --bucket "$b" --query PolicyStatus.IsPublic --output text 2>/dev/null)" = True ] \
        || return 1
    # Anonymous.
    [ "$(curl -s "$url/pub/a.txt")" = public ] || return 1
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$url/private.txt")" = 403 ] || return 1
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$url/pub/missing.txt")" = 403 ] || return 1
    [ "$(curl -s -o /dev/null -w '%{http_code}' -T "$WORK_DIR/pub.txt" "$url/pub/new.txt")" = 403 ] || return 1
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$url?list-type=2")" = 403 ] || return 1
    # RestrictPublicBuckets: the public policy allows anonymous requests
    # nothing, while it's on.
    awss3 s3api put-public-access-block --bucket "$b" \
        --public-access-block-configuration RestrictPublicBuckets=true >/dev/null 2>&1 || return 1
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$url/pub/a.txt")" = 403 ] || return 1
    awss3 s3api delete-public-access-block --bucket "$b" >/dev/null 2>&1 || return 1
    [ "$(curl -s "$url/pub/a.txt")" = public ] || return 1
    # An unsigned form, where the policy allows anyone to upload, and not
    # elsewhere.
    [ "$(curl -s -o /dev/null -w '%{http_code}' -F key=drop/form.txt -F "file=@$WORK_DIR/pub.txt" "$url")" = 204 ] \
        || return 1
    [ "$(curl -s -o /dev/null -w '%{http_code}' -F key=pub/form.txt -F "file=@$WORK_DIR/pub.txt" "$url")" = 403 ] \
        || return 1
    # The writer: a read its grant doesn't give, and a write the policy takes.
    as_role writer writersecret s3api get-object --bucket "$b" --key private.txt "$WORK_DIR/pol.out" >/dev/null 2>&1 \
        || return 1
    as_role writer writersecret s3api put-object --bucket "$b" --key open/x.txt --body "$WORK_DIR/pub.txt" \
        >/dev/null 2>&1 || return 1
    out=$(as_role writer writersecret s3api put-object --bucket "$b" --key locked/x.txt --body "$WORK_DIR/pub.txt" 2>&1) \
        && return 1
    echo "$out" | grep -q 'with an explicit deny in a resource-based policy' || return 1
    # A request naming two subresources is handled as what it was authorized
    # as: the writer reads the tags it may read, not the policy; the admin's
    # DeleteBucketCors deletes no policy.
    out=$(curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user "writer:writersecret" "$url?tagging&policy")
    echo "$out" | grep -q NoSuchTagSet || return 1
    [ "$(curl -s -o /dev/null -w '%{http_code}' -X DELETE --aws-sigv4 "aws:amz:us-east-1:s3" \
        --user "$ACCESS_KEY:$SECRET_KEY" "$url?cors&policy")" = 204 ] || return 1
    awss3 s3api get-bucket-policy --bucket "$b" >/dev/null 2>&1 || return 1
    # Refused as S3 refuses it.
    out=$(awss3 s3api put-bucket-policy --bucket "$b" --policy \
        '{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::'"$account"':user/nobody"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::'"$b"'/*"}]}' 2>&1) \
        && return 1
    echo "$out" | grep -q 'Invalid principal in policy' || return 1
    # Everyone denied everything: the admin can't even read or remove it.
    printf '%s' '{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::'"$b"'","arn:aws:s3:::'"$b"'/*"]}]}' \
        > "$deny"
    awss3 s3api put-bucket-policy --bucket "$b" --policy "file://$deny" >/dev/null 2>&1 || return 1
    ! awss3 s3api delete-bucket-policy --bucket "$b" >/dev/null 2>&1 || return 1
    ! awss3 s3api get-object --bucket "$b" --key pub/a.txt "$WORK_DIR/pol.out" >/dev/null 2>&1 || return 1
    cairn_bucket_policy delete "$b" >/dev/null 2>&1 || return 1
    awss3 s3api get-object --bucket "$b" --key pub/a.txt "$WORK_DIR/pol.out" >/dev/null 2>&1 || return 1
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$url/pub/a.txt")" = 403 ] || return 1
    for key in pub/a.txt private.txt open/x.txt drop/form.txt; do
        awss3 s3api delete-object --bucket "$b" --key "$key" >/dev/null 2>&1
    done
    awss3 s3api delete-bucket --bucket "$b" >/dev/null 2>&1
}

# A user's access keys: a second one signs as the user until it's
# deactivated; and an inline policy denies what a grant allows.
user_keys_and_policies_ok() {
    local b="keys-$(date +%s)" out id secret
    awss3 s3api create-bucket --bucket "$b" >/dev/null 2>&1 || return 1
    cairn_user grant reader "$b" read >/dev/null 2>&1 || return 1
    out=$(cairn_user key create reader) || return 1
    id=$(echo "$out" | sed -n 's/^access key: //p')
    secret=$(echo "$out" | sed -n 's/^secret key: //p')
    as_role "$id" "$secret" s3api list-objects-v2 --bucket "$b" >/dev/null 2>&1 || return 1
    cairn_user key deactivate "$id" >/dev/null 2>&1 || return 1
    ! as_role "$id" "$secret" s3api list-objects-v2 --bucket "$b" >/dev/null 2>&1 || return 1
    cairn_user key delete "$id" >/dev/null 2>&1 || return 1
    printf '%s' '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:ListBucket","Resource":"arn:aws:s3:::'"$b"'"}]}' \
        > "$WORK_DIR/nolist.json"
    cairn_user policy put reader nolist "$WORK_DIR/nolist.json" >/dev/null 2>&1 || return 1
    out=$(as_role reader readersecret s3api list-objects-v2 --bucket "$b" 2>&1) && return 1
    echo "$out" | grep -q 'with an explicit deny in an identity-based policy' || return 1
    cairn_user policy delete reader nolist >/dev/null 2>&1 || return 1
    as_role reader readersecret s3api list-objects-v2 --bucket "$b" >/dev/null 2>&1 || return 1
    awss3 s3api delete-bucket --bucket "$b" >/dev/null 2>&1
}

# An admin has AdministratorAccess, as AWS's: bucketadmin, without a single
# grant, creates, HEADs and deletes buckets, and reads and writes objects in
# any bucket of its account (here: its own, and lists $BUCKET).
admin_scope_ok() {
    local a=(as_role bucketadmin adminsecret) b="adm-$(date +%s)"
    "${a[@]}" s3api create-bucket --bucket "$b" >/dev/null 2>&1 || return 1
    "${a[@]}" s3api get-bucket-location --bucket "$b" >/dev/null 2>&1 || return 1
    "${a[@]}" s3api head-bucket --bucket "$b" >/dev/null 2>&1 || return 1
    "${a[@]}" s3api put-object --bucket "$b" --key x.txt --body "$SMALL" >/dev/null 2>&1 || return 1
    "${a[@]}" s3api get-object --bucket "$b" --key x.txt "$WORK_DIR/adm.bin" >/dev/null 2>&1 || return 1
    "${a[@]}" s3api list-objects-v2 --bucket "$BUCKET" >/dev/null 2>&1 || return 1
    "${a[@]}" s3api delete-object --bucket "$b" --key x.txt >/dev/null 2>&1 || return 1
    "${a[@]}" s3api delete-bucket --bucket "$b" >/dev/null 2>&1
}

# The IAM API, on the same endpoint (requests signed for `iam`), as the AWS
# CLI calls it: an admin makes a user, its access key and an inline policy,
# which the new key then signs S3 requests under; reader may do none of it;
# a user with something attached can't be deleted until it's gone, as in IAM.
iam_api_ok() {
    local u="iam-$(date +%s)" b="iamb-$(date +%s)" doc="$WORK_DIR/iam-policy.json" key id secret out
    awss3 iam create-user --user-name "$u" >/dev/null 2>&1 || return 1
    key=$(awss3 iam create-access-key --user-name "$u" \
        --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text 2>/dev/null) || return 1
    id=$(echo "$key" | cut -f1); secret=$(echo "$key" | cut -f2)
    [ "$(as_role "$id" "$secret" sts get-caller-identity --query Arn --output text 2>/dev/null)" \
        = "$(awss3 iam get-user --user-name "$u" --query User.Arn --output text 2>/dev/null)" ] || return 1
    awss3 s3api create-bucket --bucket "$b" >/dev/null 2>&1 || return 1
    ! as_role "$id" "$secret" s3api list-objects-v2 --bucket "$b" >/dev/null 2>&1 || return 1
    printf '%s' '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::'"$b"'"}]}' \
        > "$doc"
    awss3 iam put-user-policy --user-name "$u" --policy-name list --policy-document "file://$doc" >/dev/null 2>&1 || return 1
    as_role "$id" "$secret" s3api list-objects-v2 --bucket "$b" >/dev/null 2>&1 || return 1
    awss3 iam get-user-policy --user-name "$u" --policy-name list --query PolicyDocument.Statement[0].Action \
        --output text 2>/dev/null | grep -qx s3:ListBucket || return 1
    out=$(as_role reader readersecret iam list-users 2>&1) && return 1
    echo "$out" | grep -q 'not authorized to perform: iam:ListUsers' || return 1
    out=$(awss3 iam delete-user --user-name "$u" 2>&1) && return 1
    echo "$out" | grep -q DeleteConflict || return 1
    awss3 iam delete-access-key --user-name "$u" --access-key-id "$id" >/dev/null 2>&1 || return 1
    awss3 iam delete-user-policy --user-name "$u" --policy-name list >/dev/null 2>&1 || return 1
    awss3 iam delete-user --user-name "$u" >/dev/null 2>&1 || return 1
    ! awss3 iam get-user --user-name "$u" >/dev/null 2>&1 || return 1
    awss3 s3api delete-bucket --bucket "$b" >/dev/null 2>&1
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

# Resuming an upload with write alone: the role finds its upload
# (ListMultipartUploads), the parts uploaded so far and their ETags
# (ListParts), and completes it with them.
resume_upload_ok() {
    local w=(as_role writer writersecret) key="resume.bin" uid listed
    cairn_role revoke writer "$OBUCKET" read >/dev/null 2>&1 || return 1
    uid=$("${w[@]}" s3api create-multipart-upload --bucket "$OBUCKET" --key "$key" \
        --query UploadId --output text 2>/dev/null) || return 1
    "${w[@]}" s3api upload-part --bucket "$OBUCKET" --key "$key" --upload-id "$uid" \
        --part-number 1 --body "$SMALL" >/dev/null 2>&1 || return 1
    [ "$("${w[@]}" s3api list-multipart-uploads --bucket "$OBUCKET" --query 'Uploads[0].UploadId' \
        --output text 2>/dev/null)" = "$uid" ] || return 1
    listed=$("${w[@]}" s3api list-parts --bucket "$OBUCKET" --key "$key" --upload-id "$uid" \
        --query '{Parts: Parts[].{PartNumber: PartNumber, ETag: ETag}}' --output json 2>/dev/null) || return 1
    "${w[@]}" s3api complete-multipart-upload --bucket "$OBUCKET" --key "$key" --upload-id "$uid" \
        --multipart-upload "$listed" >/dev/null 2>&1 || return 1
    cairn_role grant writer "$OBUCKET" read >/dev/null 2>&1 || return 1
    check_roundtrip "$SMALL" "s3://${OBUCKET}/$key" || return 1
    "${w[@]}" s3api delete-object --bucket "$OBUCKET" --key "$key" >/dev/null 2>&1
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

# As in S3, a missing bucket is a 404 to any role, and one without a grant on
# an existing bucket gets a 403; CreateBucket without admin is a 403 too.
missing_bucket_404_ok() {
    local r=(as_role reader readersecret)
    "${r[@]}" s3api list-objects-v2 --bucket "$OBUCKET" 2>&1 | grep -q AccessDenied || return 1
    "${r[@]}" s3api list-objects-v2 --bucket "no-such-bucket-$(date +%s)" 2>&1 | grep -q NoSuchBucket || return 1
    "${r[@]}" s3api get-object --bucket "no-such-bucket-$(date +%s)" --key k "$WORK_DIR/x404" 2>&1 \
        | grep -q NoSuchBucket || return 1
    "${r[@]}" s3api create-bucket --bucket "no-such-bucket-$(date +%s)" 2>&1 | grep -q AccessDenied
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
run_test    "Headers outside the signature rejected" unsigned_headers_rejected
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
run_test    "Virtual-hosted-style requests"         vhost_ok
run_test    "CopyObject shares the source's data"   copy_shares_data_ok
run_test    "CopyObject of multipart src is normal" copy_multipart_source_normal_ok
run_test    "CopyObject REPLACE sets content-type"  copy_replace_content_type_ok
run_test    "Metadata stored, copied, replaced"     metadata_ok
run_test    "Checksums stored, told, copied"         checksums_ok
run_test    "SSE-C put/multipart/copy/get, wrong key" sse_c_ok
run_test    "SSE-KMS put/multipart/copy/get, keys"   sse_kms_ok
run_test    "SSE-S3 put/multipart/copy/get"          sse_s3_ok
run_test    "Bucket default encryption"              bucket_encryption_ok
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
run_test    "Signed trailer checksums via mcli"     mc_trailer_ok
run_test    "Replayed request with another body refused" replayed_body_rejected
run_test    "Upload Content-MD5/checksum headers checked" upload_checksums_ok
run_test    "Oversized XML body refused"            oversized_body_rejected
run_test    "Keys listed in byte order"             byte_order_listing_ok
run_test    "Malformed and over-long keys refused"  malformed_keys_rejected
run_test    "Set up pagination fixtures"            setup_pagination
run_test    "ListObjectsV2 paginates leaves"        v2_leaves_ok
run_test    "ListObjects (v1) paginates leaves"     v1_leaves_ok
run_test    "ListObjectsV2 paginates prefixes"      v2_prefixes_ok
run_test    "Tear down pagination bucket"           teardown_pagination
run_test    "Batch delete (DeleteObjects)"          batch_delete_ok
run_test    "Batch delete guards (MD5 / bucket)"    batch_delete_guards_ok
run_test    "DeleteBucket on non-empty bucket rejected" delete_nonempty_bucket_rejected
run_test    "Deleted parts reaped without the GC"   immediate_reap_ok
run_test    "Multipart leftovers reaped without GC" multipart_reap_ok
run_test    "Enable versioning (admin-only)"         versioning_enable_ok
run_test    "Lifecycle configuration (admin-only)"   lifecycle_config_ok
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
run_test    "Malformed version IDs refused"          malformed_version_id_rejected
run_test    "Unversioned bucket lists null versions" list_versions_unversioned_ok
run_test    "Listing versions needs read"            list_versions_needs_read_ok
run_test    "Delete markers keep a bucket non-empty" versioned_bucket_not_empty_ok
run_test    "GC removes empty shard dirs"            gc_empty_dirs_ok
run_test    "GC deletes orphaned files"              gc_orphan_ok
run_test    "Packer consolidates small blobs"        pack_consolidates_ok
run_test    "Packer leaves too little alone"         pack_below_thresholds_ok
run_test    "Packer compacts mostly-dead blobs"      pack_compacts_ok
run_test    "Stubbed ACL (s3cmd info works)"        acl_ok
run_test    "Bucket sub-resource stubs"             subresource_stubs_ok
run_test    "CORS configuration and preflights"     cors_ok
run_test    "Object and bucket tags"                tagging_ok
run_test    "Unimplemented operations refused (501)" unsupported_subresources_refused
run_test    "Parts, attributes and expected sizes"   parts_and_attributes_ok
run_test    "ACLs disabled, as in modern S3"        acls_disabled_ok
run_test    "Presigned GET/PUT, response headers"   presigned_ok
run_test    "POST Object with a signed policy"      post_object_ok
run_test    "Listing parameters as in S3"           listing_parameters_ok
run_test    "Request IDs in headers and errors"     request_id_ok
run_test    "If-Match 404, chunked, ranges, names"  s3_details_ok
run_test    "A PUT over 5 GiB is refused"           too_large_refused
run_test    "ListMultipartUploads (aws-cli)"         list_uploads_ok
run_test    "Create second bucket, grant roles"     setup_role_buckets
run_test    "Read-only role can read, not write"    reader_permissions_ok
run_test    "Tags: read with read, changed with write" tagging_roles_ok
run_test    "ListBuckets filtered by grants"        list_buckets_filtered_ok
run_test    "Admin has AdministratorAccess"          admin_scope_ok
run_test    "IAM API: users, keys, inline policies"  iam_api_ok
run_test    "No cross-bucket copy / upload access"  cross_bucket_denied_ok
run_test    "Resume an upload with write alone"     resume_upload_ok
run_test    "Grants follow bucket lifecycle"        grants_follow_bucket_ok
run_test    "Missing bucket 404, no grant 403"      missing_bucket_404_ok
run_test    "Revoked grant takes effect"            revoke_takes_effect_ok
run_test    "Bucket policies, anonymous and signed" bucket_policy_ok
run_test    "Users' access keys and policies"       user_keys_and_policies_ok
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
