#!/usr/bin/env bash
# Spike E3 (story 1.16): builds and checks the crate in a Debian 13 Rust container, starts the
# rustls test server in a compose project, runs every client against it once, and prints one
# `PASS <name>` or `FAIL <name>` line per check, then the per-client table. Exits non-zero on
# any failure. A client negotiating the classical group is a recorded result, not a failure,
# except where a check below expects a given group. Needs only Docker on the host.
set -uo pipefail

# rust:1-trixie (Debian 13), the same digest as docker/compose.yaml.
RUST_IMAGE="rust@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a"
TARGET_VOLUME="vilicus-hybrid-kex-target"
PROJECT="vilicus-e3-hybrid-kex"
# Update when a test function is added or removed: a run that silently lost tests must not pass.
EXPECTED_TESTS=19

SPIKE_DIR="$(cd "$(dirname "$0")" && pwd)"
# Git Bash on Windows: give Docker a Windows path and stop MSYS rewriting container paths.
if HOST_DIR="$(cd "$SPIKE_DIR" && pwd -W 2>/dev/null)"; then
  export MSYS_NO_PATHCONV=1
else
  HOST_DIR="$SPIKE_DIR"
fi
COMPOSE=(docker compose --project-name "$PROJECT" --file "$HOST_DIR/docker/compose.yaml" --profile clients)

failed=0
pass() { echo "PASS $1"; }
fail() {
  echo "FAIL $1"
  failed=1
}
cleanup() { "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1; }
trap cleanup EXIT

# --- 1. Crate checks and release build, in the Rust container ------------------------------
docker volume create "$TARGET_VOLUME" >/dev/null
docker run --rm --interactive \
  -v "$HOST_DIR:/spike:ro" \
  -v vilicus-spike-cargo-registry:/usr/local/cargo/registry \
  -v "$TARGET_VOLUME:/target" \
  -e CARGO_TARGET_DIR=/target \
  -e CARGO_TERM_COLOR=never \
  -e EXPECTED_TESTS="$EXPECTED_TESTS" \
  -w /spike \
  "$RUST_IMAGE" bash -s <<'IN_CONTAINER'
set -uo pipefail
status=0
step() {
  local name="$1"; shift
  if "$@" >/tmp/step.log 2>&1; then
    echo "PASS $name"
  else
    echo "FAIL $name"
    sed 's/^/  | /' /tmp/step.log
    status=1
  fi
}
step toolchain_components rustup component add rustfmt clippy
step fmt cargo fmt --check
step clippy cargo clippy --locked --all-targets -- -D warnings
step build_release cargo build --locked --release
cargo test --locked --no-fail-fast >/tmp/tests.log 2>&1
tests_status=$?
grep -h '^test .* \.\.\. \(ok\|FAILED\|ignored\)$' /tmp/tests.log \
  | sed -e 's/^test \(.*\) \.\.\. ok$/PASS test.\1/' \
        -e 's/^test \(.*\) \.\.\. FAILED$/FAIL test.\1/' \
        -e 's/^test \(.*\) \.\.\. ignored$/FAIL test.\1 (ignored)/'
passed=$(grep -h '^test result:' /tmp/tests.log | sed 's/.* \([0-9]*\) passed.*/\1/' | awk '{ s += $1 } END { print s + 0 }')
ignored=$(grep -h '^test result:' /tmp/tests.log | sed 's/.* \([0-9]*\) ignored.*/\1/' | awk '{ s += $1 } END { print s + 0 }')
if [ "$tests_status" -eq 0 ] && [ "$passed" -eq "$EXPECTED_TESTS" ] && [ "$ignored" -eq 0 ]; then
  echo "PASS test_count ($passed passed, $ignored ignored, $EXPECTED_TESTS expected)"
else
  echo "FAIL test_count ($passed passed, $ignored ignored, $EXPECTED_TESTS expected)"
  grep -h -A30 '^failures:' /tmp/tests.log | sed 's/^/  | /'
  status=1
fi
exit $status
IN_CONTAINER
if [ $? -ne 0 ]; then
  echo "RESULT FAIL (crate checks failed; clients not run)"
  exit 1
fi

lock_version() { grep -A1 "^name = \"$1\"$" "$SPIKE_DIR/Cargo.lock" | sed -n 's/^version = "\(.*\)"$/\1/p'; }
echo "INFO server: rustls $(lock_version rustls), aws-lc-rs $(lock_version aws-lc-rs), tokio-rustls $(lock_version tokio-rustls), tokio $(lock_version tokio), rcgen $(lock_version rcgen)"

# --- 2. Client images and server ------------------------------------------------------------
cleanup
if build_log="$("${COMPOSE[@]}" build --quiet 2>&1)"; then
  pass client_images_build
else
  fail client_images_build
  sed 's/^/  | /' <<<"$build_log"
fi
if "${COMPOSE[@]}" up --detach --wait server >/dev/null 2>&1; then
  pass server_start
else
  fail server_start
  echo "RESULT FAIL"
  exit 1
fi
server_log() { "${COMPOSE[@]}" logs --no-color --no-log-prefix server 2>/dev/null; }
server_line="$(server_log | grep -m1 '^SERVER ')"
echo "INFO $server_line"
server_groups="$(grep -o 'groups=[^ ]*' <<<"$server_line" | cut -d= -f2)"
if [ -n "$server_groups" ]; then
  pass "server_groups ($server_groups)"
else
  fail server_groups
fi

# --- 3. Clients -----------------------------------------------------------------------------
field() { grep -o " $2=[^ ]*" <<<" $1" | head -1 | cut -d= -f2-; }

# The server logs a record once the connection ends, which can trail the client's exit:
# poll for up to about 5 seconds before declaring it missing.
wait_record() {
  local name="$1" record attempt
  for attempt in $(seq 1 10); do
    record="$(server_log | grep -m1 "^HANDSHAKE client=$name ")"
    if [ -n "$record" ]; then
      echo "$record"
      return
    fi
    sleep 0.5
  done
}

# The group a client reports on its own side: `client_side_group=` (rustls probe, Go) or the
# `name` of Node's ephemeral key info.
client_side_group() {
  local output="$1" group
  group="$(grep -o 'client_side_group=[^ ]*' <<<"$output" | head -1 | cut -d= -f2)"
  if [ -z "$group" ]; then
    group="$(grep -o 'client_side_key_info={[^}]*}' <<<"$output" | grep -o '"name":"[^"]*"' | cut -d'"' -f4)"
  fi
  echo "$group"
}

# First offered group the server supports: what rustls 0.23.45 selects (client order).
first_mutual_group() {
  local offered="$1" group
  IFS=',' read -r -a offered_list <<<"$offered"
  for group in "${offered_list[@]}"; do
    if [[ ",$server_groups," == *",$group,"* ]]; then
      echo "$group"
      return
    fi
  done
  echo "none"
}

table=()
# run_client <name> <expected group|any> <expect hrr yes|no|any> <version text or @command> -- <compose run args...>
run_client() {
  local name="$1" expected="$2" expected_hrr="$3" version="$4"
  shift 5
  local service="$1" output status record group hrr hrr_inferred protocol offered shares mutual own_group
  output="$("${COMPOSE[@]}" run --rm --no-deps -T "$@" 2>&1)"
  status=$?
  record="$(wait_record "$name")"
  if [ $status -ne 0 ] || [ -z "$record" ]; then
    fail "handshake.$name (exit $status)"
    sed 's/^/  | /' <<<"$output" | tail -20
    table+=("| $name | $version | - | - | handshake failed | - |")
    return
  fi
  group="$(field "$record" group)"
  hrr="$(field "$record" hrr)"
  hrr_inferred="$(field "$record" hrr_inferred)"
  protocol="$(field "$record" protocol)"
  offered="$(field "$record" offered)"
  shares="$(field "$record" key_shares)"
  if [ "$group" = "none" ]; then
    fail "handshake.$name"
    echo "  | $record"
  else
    pass "handshake.$name ($group)"
  fi
  if [ "$expected" != "any" ]; then
    if [ "$group" = "$expected" ]; then pass "group.$name (expected $expected)"; else fail "group.$name (expected $expected, got $group)"; fi
  fi
  if [ "$expected_hrr" != "any" ]; then
    if [ "$hrr" = "$expected_hrr" ]; then pass "hrr.$name (expected $expected_hrr)"; else fail "hrr.$name (expected $expected_hrr, got $hrr)"; fi
  fi
  if [ "$protocol" = "TLSv1_3" ]; then pass "protocol.$name (TLSv1_3)"; else fail "protocol.$name (got $protocol)"; fi
  # hrr comes from rustls (handshake_kind); hrr_inferred from the captured key shares.
  if [ "$hrr" = "$hrr_inferred" ]; then
    pass "hrr_cross_check.$name ($hrr)"
  else
    fail "hrr_cross_check.$name (rustls $hrr, key shares say $hrr_inferred)"
  fi
  case "$service" in
    rustls | node | go)
      own_group="$(client_side_group "$output")"
      if [ "$own_group" = "$group" ]; then
        pass "client_side_group.$name ($own_group)"
      else
        fail "client_side_group.$name (client says '$own_group', server says $group)"
      fi
      ;;
  esac
  mutual="$(first_mutual_group "$offered")"
  if [ "$group" = "$mutual" ]; then
    pass "client_order.$name (first mutual group $mutual)"
  else
    fail "client_order.$name (first mutual group $mutual, negotiated $group)"
  fi
  if [[ "$version" == @* ]]; then
    # The user agent is already in the server log; the table keeps the version fields.
    version="$(grep -m1 "${version#@}" <<<"$output" | sed -e 's/ ua=".*"//' -e 's/|/\//g')"
    if [ -n "$version" ]; then pass "version.$name"; else fail "version.$name (no version line)"; fi
  fi
  table+=("| $name | $version | $(sed 's/GREASE,//g' <<<"$offered") | $(sed 's/GREASE,//g' <<<"$shares") | $group | $hrr |")
}

tool_version() { "${COMPOSE[@]}" run --rm --no-deps -T "$@" 2>/dev/null | head -1 | tr -d '\r'; }
deb13_curl="$(tool_version debian13 curl --version | cut -d' ' -f1-2,5)"
deb13_openssl="$(tool_version debian13 openssl version | cut -d' ' -f1-2)"
deb12_curl="$(tool_version debian12 curl --version | cut -d' ' -f1-2,5)"
deb12_openssl="$(tool_version debian12 openssl version | cut -d' ' -f1-2)"
for tool in deb13_curl deb13_openssl deb12_curl deb12_openssl; do
  if [ -n "${!tool}" ]; then pass "version.$tool (${!tool})"; else fail "version.$tool (empty)"; fi
done
rustls_version="rustls $(lock_version rustls) (aws-lc-rs $(lock_version aws-lc-rs))"
s_client_request='printf "GET /client/%s HTTP/1.1\r\nHost: server\r\nConnection: close\r\n\r\n" "$0" | openssl s_client -connect server:8443 -servername server -CAfile /pki/ca.pem -verify_return_error -verify_hostname server -ign_eof "$@" 2>&1'

run_client rustls-default X25519MLKEM768 no "$rustls_version, provider default groups" -- rustls rustls-default default
run_client rustls-classical X25519 no "$rustls_version, X25519 only" -- rustls rustls-classical classical
run_client curl-debian13 any any "$deb13_curl, Debian 13" -- debian13 curl -sS --fail --cacert /pki/ca.pem https://server:8443/client/curl-debian13
run_client curl-debian13-x25519 X25519 no "$deb13_curl, Debian 13, --curves X25519" -- debian13 curl -sS --fail --curves X25519 --cacert /pki/ca.pem https://server:8443/client/curl-debian13-x25519
run_client openssl-debian13 any any "$deb13_openssl s_client, Debian 13" -- debian13 sh -c "$s_client_request" openssl-debian13
# Hybrid listed first but a key share for X25519 only: the server must ask for the hybrid share.
run_client openssl-debian13-hrr X25519MLKEM768 yes "$deb13_openssl s_client, -groups X25519MLKEM768:*X25519" -- debian13 sh -c "$s_client_request" openssl-debian13-hrr -groups 'X25519MLKEM768:*X25519'
run_client curl-debian12 any any "$deb12_curl, Debian 12" -- debian12 curl -sS --fail --cacert /pki/ca.pem https://server:8443/client/curl-debian12
run_client openssl-debian12 any any "$deb12_openssl s_client, Debian 12" -- debian12 sh -c "$s_client_request" openssl-debian12
run_client node any any "@^NODE " -- node node
run_client go any any "@^GO " -- go go
run_client chromium any any "@^BROWSER " -- playwright chromium chromium
run_client firefox any any "@^BROWSER " -- playwright firefox firefox
run_client webkit-linux any any "@^BROWSER " -- playwright webkit webkit-linux

# --- 4. Results -----------------------------------------------------------------------------
echo
echo "| Client | Version | Offered groups (client order, GREASE removed) | Key shares | Negotiated | HRR |"
echo "|---|---|---|---|---|---|"
printf '%s\n' "${table[@]}"
echo

if [ "$failed" -ne 0 ]; then
  echo "RESULT FAIL"
  exit 1
fi
echo "RESULT PASS"
