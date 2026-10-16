#!/usr/bin/env bash
# Spike E10 (story 1.6): builds the spike in a Debian 13 Rust container, then runs every check
# under systemd as PID 1 in a Debian 13 container. Prints one `PASS <name>` or `FAIL <name>`
# line per check and exits non-zero on any failure, on an ignored test, or on a missing test.
# Runs from Linux or from Git Bash on Windows; needs Docker only (and network access to build
# the images). The systemd container is privileged: see the story's limits.
set -euo pipefail

spike_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mount_dir="$spike_dir"
if command -v cygpath >/dev/null 2>&1; then
  mount_dir="$(cygpath -w "$spike_dir")"
  export MSYS_NO_PATHCONV=1
fi
build_image="vilicus-spike-e10-build"
systemd_image="vilicus-spike-e10-systemd"
target_volume="vilicus-e10-target"
container="vilicus-spike-e10-$$"

# Both images are built from stdin with no context, so nothing of the tree is sent to Docker.
docker build --quiet --tag "$build_image" - <"$spike_dir/Dockerfile.build" >/dev/null
docker build --quiet --tag "$systemd_image" - <"$spike_dir/Dockerfile.systemd" >/dev/null

status=0
docker run --rm --interactive \
  --volume "$mount_dir:/src:ro" \
  --volume "$target_volume:/target" \
  --volume vilicus-cargo-registry:/usr/local/cargo/registry \
  --env CARGO_TARGET_DIR=/target \
  --env CARGO_TERM_COLOR=never \
  --workdir /src \
  "$build_image" bash -s <<'IN_BUILD' || status=1
set -uo pipefail
failed=0
step() {
  local name="$1"; shift
  if "$@" >/tmp/step.log 2>&1; then
    echo "PASS $name"
  else
    echo "FAIL $name"
    sed 's/^/  | /' /tmp/step.log
    failed=1
  fi
}
echo "INFO $(rustc --version)"
echo "INFO $(grep -A1 '^name = "libc"' Cargo.lock | tr '\n' ' ')"
step build cargo build --locked --all-targets
step fmt cargo fmt --check
step clippy cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --no-fail-fast >/tmp/tests.log 2>&1
tests_status=$?
grep -h '^test .* \.\.\. \(ok\|FAILED\|ignored\)$' /tmp/tests.log \
  | sed -e 's/^test \(.*\) \.\.\. ok$/PASS test.\1/' \
        -e 's/^test \(.*\) \.\.\. FAILED$/FAIL test.\1/' \
        -e 's/^test \(.*\) \.\.\. ignored$/FAIL test.\1 (ignored)/'
# Every #[test] in the tree must have run and passed; none may be ignored.
expected=$(grep -rh '#\[test\]' src tests | wc -l)
passed=$(grep -h '^test result:' /tmp/tests.log | sed 's/.* \([0-9]*\) passed.*/\1/' | awk '{ s += $1 } END { print s + 0 }')
ignored=$(grep -h '^test result:' /tmp/tests.log | sed 's/.* \([0-9]*\) ignored.*/\1/' | awk '{ s += $1 } END { print s + 0 }')
if [ "$tests_status" -eq 0 ] && [ "$passed" -eq "$expected" ] && [ "$ignored" -eq 0 ]; then
  echo "PASS test_count ($passed passed, $ignored ignored, $expected expected)"
else
  echo "FAIL test_count ($passed passed, $ignored ignored, $expected expected)"
  grep -h -A20 '^failures:' /tmp/tests.log | sed 's/^/  | /' || true
  failed=1
fi
exit $failed
IN_BUILD

if [ "$status" -eq 0 ]; then
  cleanup() { docker stop --time 5 "$container" >/dev/null 2>&1 || true; }
  trap cleanup EXIT
  # systemd as PID 1 needs a writable cgroup tree and mount namespaces: --privileged and a
  # private cgroup namespace. The container is removed when stopped (--rm).
  docker run --detach --rm --name "$container" \
    --privileged --cgroupns=private \
    --volume "$mount_dir:/spike:ro" \
    --volume "$target_volume:/target:ro" \
    "$systemd_image" >/dev/null
  state=$(docker exec "$container" systemctl is-system-running --wait || true)
  echo "INFO systemd state at boot: $state"
  docker exec "$container" bash /spike/checks.sh || status=1
fi

if [ "$status" -ne 0 ]; then
  echo "RUN FAIL"
  exit 1
fi
echo "RUN PASS"
