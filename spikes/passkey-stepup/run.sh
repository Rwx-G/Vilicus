#!/usr/bin/env bash
# Spike E2 login half (story 1.5): checks and builds the crate in a Debian 13 Rust container,
# starts the relying party in a compose project, runs every browser driver once against it, and
# prints one `PASS <name>` or `FAIL <name>` line per check. Exits non-zero on any failure,
# including an ignored test. Removes its compose project on exit. Needs only Docker on the host.
set -uo pipefail

# rust:1-trixie (Debian 13), the same digest as compose.yaml.
RUST_IMAGE="rust@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a"
TARGET_VOLUME="vilicus-passkey-stepup-target"
PROJECT="vilicus-e2-passkey-stepup"
ORIGIN="https://rp.vilicus.test:8443"
# The browser prompt timeout. Short, so the expiry check waits seconds; long enough for a
# virtual authenticator.
export STEP_UP_TTL_MS=4000

SPIKE_DIR="$(cd "$(dirname "$0")" && pwd)"
# Git Bash on Windows: give Docker a Windows path and stop MSYS rewriting container paths.
if HOST_DIR="$(cd "$SPIKE_DIR" && pwd -W 2>/dev/null)"; then
  HOST_SPIKES="$(cd "$SPIKE_DIR/.." && pwd -W)"
  export MSYS_NO_PATHCONV=1
else
  HOST_DIR="$SPIKE_DIR"
  HOST_SPIKES="$(cd "$SPIKE_DIR/.." && pwd)"
fi
COMPOSE=(docker compose --project-name "$PROJECT" --file "$HOST_DIR/compose.yaml" --profile browsers)

failed=0
pass() { echo "PASS $1"; }
fail() {
  echo "FAIL $1"
  failed=1
}
cleanup() { "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1; }
trap cleanup EXIT

# --- 1. Crate checks and release build, in the Rust container ------------------------------
# The parent directory is mounted because the crate depends on ../canonical-cbor by path.
docker volume create "$TARGET_VOLUME" >/dev/null
docker run --rm --interactive \
  -v "$HOST_SPIKES:/spikes:ro" \
  -v vilicus-spike-cargo-registry:/usr/local/cargo/registry \
  -v "$TARGET_VOLUME:/target" \
  -e CARGO_TARGET_DIR=/target \
  -e CARGO_TERM_COLOR=never \
  -w /spikes/passkey-stepup \
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
# The expected count comes from the test harness's own listing, so an ignored or filtered test
# shows up as a gap between listed and passed.
listed=$(cargo test --locked -q -- --list --format terse 2>/dev/null | grep -c ': test$')
cargo test --locked --no-fail-fast >/tmp/tests.log 2>&1
tests_status=$?
grep -h '^test .* \.\.\. \(ok\|FAILED\|ignored\)$' /tmp/tests.log \
  | sed -e 's/^test \(.*\) \.\.\. ok$/PASS test.\1/' \
        -e 's/^test \(.*\) \.\.\. FAILED$/FAIL test.\1/' \
        -e 's/^test \(.*\) \.\.\. ignored$/FAIL test.\1 (ignored)/'
passed=$(grep -h '^test result:' /tmp/tests.log | sed 's/.* \([0-9]*\) passed.*/\1/' | awk '{ s += $1 } END { print s + 0 }')
ignored=$(grep -h '^test result:' /tmp/tests.log | sed 's/.* \([0-9]*\) ignored.*/\1/' | awk '{ s += $1 } END { print s + 0 }')
if [ "$tests_status" -eq 0 ] && [ "$listed" -gt 0 ] && [ "$passed" -eq "$listed" ] && [ "$ignored" -eq 0 ]; then
  echo "PASS test_count ($passed passed, $ignored ignored, $listed listed)"
else
  echo "FAIL test_count ($passed passed, $ignored ignored, $listed listed)"
  grep -h -A30 '^failures:' /tmp/tests.log | sed 's/^/  | /'
  status=1
fi
exit $status
IN_CONTAINER
if [ $? -ne 0 ]; then
  echo "RESULT FAIL (crate checks failed; browsers not run)"
  exit 1
fi

lock_version() { grep -A1 "^name = \"$1\"$" "$SPIKE_DIR/Cargo.lock" | sed -n 's/^version = "\(.*\)"$/\1/p'; }
echo "INFO server: webauthn-rs $(lock_version webauthn-rs), axum $(lock_version axum), hyper $(lock_version hyper), tokio $(lock_version tokio), rustls $(lock_version rustls), aws-lc-rs $(lock_version aws-lc-rs), rcgen $(lock_version rcgen), openssl $(lock_version openssl)"

# --- 2. Driver images and server ------------------------------------------------------------
cleanup
if build_log="$("${COMPOSE[@]}" build --quiet 2>&1)"; then
  pass driver_images_build
else
  fail driver_images_build
  sed 's/^/  | /' <<<"$build_log"
fi
if "${COMPOSE[@]}" up --detach --wait server >/dev/null 2>&1; then
  pass server_start
else
  fail server_start
  "${COMPOSE[@]}" logs --no-color server 2>&1 | sed 's/^/  | /'
  echo "RESULT FAIL"
  exit 1
fi
server_line="$("${COMPOSE[@]}" logs --no-color --no-log-prefix server 2>/dev/null | grep -m1 '^SERVER ')"
echo "INFO $server_line"
# The server's own expiry (prompt timeout plus its slack), so the driver waits past it.
SERVER_EXPIRY_MS="$(grep -o 'expiry_ms=[0-9]*' <<<"$server_line" | cut -d= -f2)"
if [ -n "$SERVER_EXPIRY_MS" ]; then pass "server_expiry ($SERVER_EXPIRY_MS ms)"; else fail server_expiry; fi

# --- 3. Browsers ----------------------------------------------------------------------------
# run_driver <service> <engine> <label>
run_driver() {
  local service="$1" engine="$2" label="$3" output status
  output="$("${COMPOSE[@]}" run --rm --no-deps -T "$service" "$engine" "$label" "$ORIGIN" /pki/ca.pem "$SERVER_EXPIRY_MS" 2>&1)"
  status=$?
  grep -E '^(PASS|FAIL|INFO|ERROR) ' <<<"$output"
  if [ $status -ne 0 ] || ! grep -q '^PASS ' <<<"$output" || grep -q '^FAIL ' <<<"$output"; then
    fail "browser.$label (exit $status)"
    grep -vE '^(PASS|FAIL|INFO|ERROR) ' <<<"$output" | tail -20 | sed 's/^/  | /'
  else
    pass "browser.$label"
  fi
}

run_driver browsers-current chromium chromium-current
run_driver browsers-current firefox firefox-current
run_driver browsers-previous chromium chromium-previous
run_driver browsers-previous firefox firefox-previous

# --- 4. Server's view -----------------------------------------------------------------------
echo
echo "INFO server outcomes (count, outcome):"
"${COMPOSE[@]}" logs --no-color --no-log-prefix server 2>/dev/null \
  | grep -E '^(REGISTER|LOGIN|STEP_UP) ' \
  | sed -e 's/ request=[0-9a-f]*//' -e 's/\(outcome=refused:[a-z_]*\).*/\1/' \
  | sort | uniq -c | sed 's/^/INFO /'
echo

if [ "$failed" -ne 0 ]; then
  echo "RESULT FAIL"
  exit 1
fi
echo "RESULT PASS"
