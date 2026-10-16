#!/usr/bin/env bash
# E11 spike: builds and runs every check inside a Debian 13 container, prints one
# `PASS <name>` or `FAIL <name>` line per check, and exits non-zero on any failure.
# Runs from Linux or from Git Bash on Windows; needs Docker only.
set -euo pipefail

spike_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
image="vilicus-spike-sqlite-authorizer"
mount_dir="$spike_dir"
if command -v cygpath >/dev/null 2>&1; then
  mount_dir="$(cygpath -w "$spike_dir")"
fi

docker build --quiet --tag "$image" "$spike_dir" >/dev/null

# The target directory and the cargo registry live in named volumes, so nothing is built into
# the source tree and repeated runs are incremental.
MSYS_NO_PATHCONV=1 docker run --rm --interactive \
  --volume "$mount_dir:/src:ro" \
  --volume vilicus-sqlite-authorizer-target:/target \
  --volume vilicus-cargo-registry:/usr/local/cargo/registry \
  --env CARGO_TARGET_DIR=/target \
  --workdir /src \
  "$image" bash -s <<'IN_CONTAINER'
set -uo pipefail
failed=0
check() {
  local name="$1"; shift
  if "$@" >/tmp/check.log 2>&1; then
    echo "PASS $name"
  else
    echo "FAIL $name"
    sed 's/^/  | /' /tmp/check.log
    failed=1
  fi
}

echo "INFO $(rustc --version)"
echo "INFO $(grep -A1 '^name = "rusqlite"' Cargo.lock | tr '\n' ' ')"
echo "INFO $(grep -A1 '^name = "libsqlite3-sys"' Cargo.lock | tr '\n' ' ')"

check fmt cargo fmt --check
check clippy cargo clippy --locked --all-targets -- -D warnings
check build_tests cargo test --locked --no-run

# First run: the per-check lines the tests print (they can share a line with libtest's own
# "test <name> ..." prefix, hence the match anywhere on the line).
cargo test --locked --no-fail-fast -- --test-threads=1 --nocapture >/tmp/checks.log 2>&1
checks_status=$?
grep -o 'CHECK INFO .*' /tmp/checks.log | sed 's/^CHECK //' || true
grep -o 'CHECK \(PASS\|FAIL\) .*' /tmp/checks.log | sed 's/^CHECK //'
# Second run, captured: one line per test function.
cargo test --locked --no-fail-fast -- --test-threads=1 >/tmp/tests.log 2>&1
tests_status=$?
grep -h '^test .* \.\.\. \(ok\|FAILED\)$' /tmp/tests.log \
  | sed -e 's/^test \(.*\) \.\.\. ok$/PASS test.\1/' -e 's/^test \(.*\) \.\.\. FAILED$/FAIL test.\1/'
if [ "$checks_status" -ne 0 ] || [ "$tests_status" -ne 0 ] || grep -q 'CHECK FAIL' /tmp/checks.log; then
  grep -h -A20 '^failures:' /tmp/tests.log | sed 's/^/  | /' || true
  failed=1
fi

# A run that silently lost or skipped tests must not pass. Update EXPECTED_TESTS when a test
# function is added or removed.
EXPECTED_TESTS=28
passed_tests=$(grep -h '^test result:' /tmp/tests.log | sed 's/.* \([0-9]*\) passed.*/\1/' | awk '{ sum += $1 } END { print sum + 0 }')
ignored_tests=$(grep -h '^test result:' /tmp/tests.log | sed 's/.* \([0-9]*\) ignored.*/\1/' | awk '{ sum += $1 } END { print sum + 0 }')
if [ "$passed_tests" -eq "$EXPECTED_TESTS" ] && [ "$ignored_tests" -eq 0 ]; then
  echo "PASS test_count ($passed_tests passed, $ignored_tests ignored, $EXPECTED_TESTS expected)"
else
  echo "FAIL test_count ($passed_tests passed, $ignored_tests ignored, $EXPECTED_TESTS expected)"
  failed=1
fi

if [ "$failed" -ne 0 ]; then
  echo "RESULT FAIL"
  exit 1
fi
echo "RESULT PASS"
IN_CONTAINER
