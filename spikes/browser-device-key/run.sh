#!/usr/bin/env bash
# Spike E22 (story 1.3): checks and builds the crate in a Debian 13 Rust container, installs the
# browser OPAQUE package, starts the HTTPS server in a compose project, runs the browser driver
# once per browser of the matrix, and prints one `PASS <name>` or `FAIL <name>` line per check,
# then `RESULT PASS` or `RESULT FAIL`. Removes its compose project and exits non-zero on any
# failure. Runs from Linux or from Git Bash on Windows; needs only Docker.
set -uo pipefail

# rust:1.99-trixie (Debian 13), the same digest as compose.yaml.
RUST_IMAGE="rust@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a"
# node:24-trixie-slim.
NODE_IMAGE="node@sha256:7f486cabe892bff8fef04c0f7da8dba84a560be3e4e2740b7a86afc57ebec315"
TARGET_VOLUME="vilicus-browser-device-key-target"
WEB_DEPS_VOLUME="vilicus-browser-device-key-web-deps"
PROJECT="vilicus-e22-browser-device-key"
# Update when a test function is added or removed: a run that silently lost tests must not pass.
EXPECTED_TESTS=27
# Checks each browser run of browser/driver.mjs must pass. Update when a check is added or
# removed: a driver that stopped early or skipped checks must not pass.
EXPECTED_CHECKS=58

# label kind executable: Chrome over CDP, stock Firefox over WebDriver BiDi.
BROWSERS=(
  "chrome-155 chromium /opt/browsers/chrome-155/chrome-linux64/chrome"
  "chrome-154 chromium /opt/browsers/chrome-154/chrome-linux64/chrome"
  "firefox-158 firefox /opt/browsers/firefox-158/firefox/firefox"
  "firefox-157 firefox /opt/browsers/firefox-157/firefox/firefox"
)

SPIKE_DIR="$(cd "$(dirname "$0")" && pwd)"
# Git Bash on Windows: give Docker a Windows path and stop MSYS rewriting container paths.
if HOST_DIR="$(cd "$SPIKE_DIR" && pwd -W 2>/dev/null)"; then
  SPIKES_HOST_DIR="$(cd "$SPIKE_DIR/.." && pwd -W)"
  export MSYS_NO_PATHCONV=1
else
  HOST_DIR="$SPIKE_DIR"
  SPIKES_HOST_DIR="$(cd "$SPIKE_DIR/.." && pwd)"
fi
COMPOSE=(docker compose --project-name "$PROJECT" --file "$HOST_DIR/compose.yaml" --profile browsers)

failed=0
cleanup() { "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1; }
trap cleanup EXIT

# --- 1. Crate checks and release build ------------------------------------------------------
# The parent `spikes/` directory is mounted because the crate depends on ../canonical-cbor.
docker volume create "$TARGET_VOLUME" >/dev/null
docker run --rm --interactive \
  -v "$SPIKES_HOST_DIR:/spikes:ro" \
  -v vilicus-spike-cargo-registry:/usr/local/cargo/registry \
  -v "$TARGET_VOLUME:/target" \
  -e CARGO_TARGET_DIR=/target \
  -e CARGO_TERM_COLOR=never \
  -e EXPECTED_TESTS="$EXPECTED_TESTS" \
  -w /spikes/browser-device-key \
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
echo "INFO $(rustc --version)"
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
  echo "RESULT FAIL (crate checks failed; browsers not run)"
  exit 1
fi

lock_version() { grep -A1 "^name = \"$1\"$" "$SPIKE_DIR/Cargo.lock" | sed -n 's/^version = "\(.*\)"$/\1/p' | head -1; }
echo "INFO server: opaque-ke $(lock_version opaque-ke), aws-lc-rs $(lock_version aws-lc-rs), dcbor $(lock_version dcbor), rustls $(lock_version rustls), hyper $(lock_version hyper), tokio $(lock_version tokio), rcgen $(lock_version rcgen)"

# --- 2. Browser OPAQUE package --------------------------------------------------------------
docker volume create "$WEB_DEPS_VOLUME" >/dev/null
if web_log="$(docker run --rm \
  -v "$HOST_DIR/web:/src:ro" \
  -v "$WEB_DEPS_VOLUME:/deps" \
  -w /deps \
  "$NODE_IMAGE" sh -c 'cp /src/package.json /src/package-lock.json /deps/ && npm ci --ignore-scripts --no-audit --no-fund && node -p "require(\"/deps/node_modules/@serenity-kit/opaque/package.json\").version"' 2>&1)"; then
  echo "PASS web_dependencies"
  echo "INFO @serenity-kit/opaque $(tail -n 1 <<<"$web_log")"
else
  echo "FAIL web_dependencies"
  sed 's/^/  | /' <<<"$web_log"
  echo "RESULT FAIL"
  exit 1
fi

# --- 3. Server and browser image ------------------------------------------------------------
cleanup
if build_log="$("${COMPOSE[@]}" build --quiet 2>&1)"; then
  echo "PASS browser_image_build"
else
  echo "FAIL browser_image_build"
  sed 's/^/  | /' <<<"$build_log"
  echo "RESULT FAIL"
  exit 1
fi
if "${COMPOSE[@]}" up --detach --wait server >/dev/null 2>&1; then
  echo "PASS server_start"
else
  echo "FAIL server_start"
  "${COMPOSE[@]}" logs --no-color server 2>&1 | sed 's/^/  | /'
  echo "RESULT FAIL"
  exit 1
fi
echo "INFO $("${COMPOSE[@]}" logs --no-color --no-log-prefix server 2>/dev/null | grep -m1 '^SERVER ')"
playwright_version="$("${COMPOSE[@]}" run --rm --no-deps --entrypoint node browsers -p 'require("/driver/node_modules/playwright-core/package.json").version' 2>/dev/null)"
echo "INFO playwright-core $playwright_version"

# --- 4. Browser matrix ------------------------------------------------------------------------
for entry in "${BROWSERS[@]}"; do
  read -r label kind executable <<<"$entry"
  version="$("${COMPOSE[@]}" run --rm --no-deps --entrypoint "$executable" browsers --version 2>/dev/null | tr -d '\r' | tail -n 1)"
  echo "INFO $label: $version"
  output="$("${COMPOSE[@]}" run --rm --no-deps browsers "$label" "$kind" "$executable" 2>&1)"
  driver_status=$?
  tr -d '\r' <<<"$output" | grep -E '^(PASS|FAIL|INFO) '
  if [ "$driver_status" -ne 0 ] || ! grep -q '^PASS ' <<<"$output" || grep -q '^FAIL ' <<<"$output"; then
    failed=1
    if ! grep -q '^FAIL ' <<<"$output"; then
      echo "FAIL $label.driver_exit ($driver_status)"
      tr -d '\r' <<<"$output" | grep -vE '^(PASS|FAIL|INFO) ' | tail -n 40 | sed 's/^/  | /'
    fi
  fi
  # A driver that stopped early or skipped checks must not pass.
  checks_passed="$(grep -c "^PASS $label\." <<<"$output")"
  if [ "$checks_passed" -eq "$EXPECTED_CHECKS" ]; then
    echo "PASS $label.check_count ($checks_passed passed, $EXPECTED_CHECKS expected)"
  else
    echo "FAIL $label.check_count ($checks_passed passed, $EXPECTED_CHECKS expected)"
    failed=1
  fi
done

echo "INFO android: Not run here (Chrome and Firefox for Android need a device or an emulator; manual procedure in the story)"

if [ "$failed" -ne 0 ]; then
  echo "RESULT FAIL"
  exit 1
fi
echo "RESULT PASS"
