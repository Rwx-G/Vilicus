#!/usr/bin/env bash
# Spike E1 and E2 PRF half (story 1.17): checks and builds the probe in a Debian 13 Rust
# container, starts it in a compose project, and drives it with headless Chromium's virtual
# authenticator (CDP, hasPrf) through Playwright. Prints one `PASS <name>` or `FAIL <name>` line
# per check and exits non-zero on any failure or ignored test. Needs only Docker on the host.
#
# This proves the pipeline, not the result: the household devices run RUNBOOK.md.
set -uo pipefail

# rust:1-trixie (Debian 13), the same digest as docker/compose.yaml.
RUST_IMAGE="rust@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a"
TARGET_VOLUME="vilicus-prf-probe-target"
PROJECT="vilicus-prf-probe"
# Update when a test function is added or removed: a run that silently lost tests must not pass.
EXPECTED_TESTS=17

SPIKE_DIR="$(cd "$(dirname "$0")" && pwd)"
# Git Bash on Windows: give Docker a Windows path and stop MSYS rewriting container paths.
if HOST_DIR="$(cd "$SPIKE_DIR" && pwd -W 2>/dev/null)"; then
  export MSYS_NO_PATHCONV=1
else
  HOST_DIR="$SPIKE_DIR"
fi
COMPOSE=(docker compose --project-name "$PROJECT" --file "$HOST_DIR/docker/compose.yaml" --profile clients)

failed=0
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
    sed 's/^/  | /' /tmp/step.log | tail -n 40
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
  echo "RESULT FAIL (crate checks failed; end-to-end check not run)"
  exit 1
fi

lock_version() { grep -A1 "^name = \"$1\"$" "$SPIKE_DIR/Cargo.lock" | sed -n 's/^version = "\(.*\)"$/\1/p'; }
echo "INFO server: webauthn-rs $(lock_version webauthn-rs), rustls $(lock_version rustls), hyper $(lock_version hyper)"

# --- 2. Server and Playwright client --------------------------------------------------------
cleanup
if build_log="$("${COMPOSE[@]}" build --quiet 2>&1)"; then
  echo "PASS client_image_build"
else
  echo "FAIL client_image_build"
  sed 's/^/  | /' <<<"$build_log"
  failed=1
fi
if "${COMPOSE[@]}" up --detach --wait server >/dev/null 2>&1; then
  echo "PASS server_start"
else
  echo "FAIL server_start"
  "${COMPOSE[@]}" logs --no-color server 2>&1 | tail -20 | sed 's/^/  | /'
  echo "RESULT FAIL"
  exit 1
fi

e2e_output="$("${COMPOSE[@]}" run --rm --no-deps -T playwright 2>&1)"
e2e_status=$?
grep -E '^(PASS|FAIL|INFO) ' <<<"$e2e_output"
if [ $e2e_status -ne 0 ] || ! grep -q '^E2E_DONE ' <<<"$e2e_output"; then
  echo "FAIL e2e_exit (status $e2e_status)"
  grep -vE '^(PASS|FAIL|INFO|E2E_DONE) ' <<<"$e2e_output" | tail -20 | sed 's/^/  | /'
  failed=1
else
  echo "PASS e2e_exit ($(grep -m1 '^E2E_DONE ' <<<"$e2e_output" | cut -d' ' -f2))"
fi
if grep -q '^FAIL ' <<<"$e2e_output"; then
  failed=1
fi

# The server log names ceremonies and authenticator extension keys only, never a digest.
server_log="$("${COMPOSE[@]}" logs --no-color --no-log-prefix server 2>/dev/null)"
grep -m1 '^SERVER ' <<<"$server_log" | sed 's/^/INFO /'
if grep -Eq '[0-9a-f]{64}' <<<"$server_log"; then
  echo "FAIL server_log_holds_no_digest"
  failed=1
else
  echo "PASS server_log_holds_no_digest"
fi

if [ "$failed" -ne 0 ]; then
  echo "RESULT FAIL"
  exit 1
fi
echo "RESULT PASS"
