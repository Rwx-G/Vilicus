#!/usr/bin/env bash
# Spike E32 (story 1.15): builds and runs everything inside a Debian 13 Rust container
# constrained to the reference host's size (--cpus=4 --memory=8g, no swap). This is an
# emulation on a larger desktop, not the reference host: a CPU quota over many cores is not
# the same as 4 physical cores. Prints one PASS or FAIL line per check (toolchain, build,
# format, lint, tests, then every spike check) and the measured tables; exits non-zero on any
# failure or on any ignored or missing test. Needs only Docker on the host.
#
# E32_DURATION overrides the measured seconds of the gate run (default 600),
# E32_SENSITIVITY_DURATION those of the sensitivity run (default 300) and E32_PAUSE_SIZES the
# file sizes in MiB of the pause bound measurement (default 64,256,512).
set -euo pipefail

# rust:1-trixie (Debian 13, rustc 1.99.1) as pulled on 2026-10-16, pinned by digest.
IMAGE="${E32_IMAGE:-rust@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a}"
SPIKES_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_DIR="$(cd "$SPIKES_DIR/.." && pwd)"
# The source the run is built from: this crate and its path dependency on the story 1.7
# spike. Read-only git queries; the dirty count is the uncommitted paths under either one.
GIT_HEAD="$(git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_DIRTY="$(git -C "$REPO_DIR" status --porcelain -- spikes/core-execution spikes/sqlite-authorizer 2>/dev/null | wc -l | tr -d ' ')"
# Git Bash on Windows: give Docker a Windows path and stop MSYS rewriting container paths.
if HOST_DIR="$(cd "$SPIKES_DIR" && pwd -W 2>/dev/null)"; then
  export MSYS_NO_PATHCONV=1
else
  HOST_DIR="$SPIKES_DIR"
fi

# The whole spikes directory is mounted because the crate reuses ../sqlite-authorizer (story
# 1.7) as a path dependency. The build output lives in a named volume, never in the source tree.
docker run --rm \
  --cpus=4 --memory=8g --memory-swap=8g \
  -v "$HOST_DIR:/spikes" \
  -v vilicus-spike-cargo-registry:/usr/local/cargo/registry \
  -v vilicus-e32-target:/target \
  -e CARGO_TARGET_DIR=/target \
  -e CARGO_TERM_COLOR=never \
  -e E32_DURATION="${E32_DURATION:-600}" \
  -e E32_SENSITIVITY_DURATION="${E32_SENSITIVITY_DURATION:-300}" \
  -e E32_PAUSE_SIZES="${E32_PAUSE_SIZES:-64,256,512}" \
  -e GIT_HEAD="$GIT_HEAD" \
  -e GIT_DIRTY="$GIT_DIRTY" \
  -w /spikes/core-execution \
  "$IMAGE" bash -c '
    set -uo pipefail
    status=0
    step() {
      local name="$1"; shift
      if "$@" > /tmp/step.log 2>&1; then
        echo "PASS $name"
      else
        echo "FAIL $name"
        sed "s/^/  /" /tmp/step.log
        status=1
      fi
    }
    echo "INFO image $(. /etc/os-release && echo "$PRETTY_NAME"), $(rustc --version), $(nproc) CPUs visible, emulated reference host"
    echo "INFO source git HEAD $GIT_HEAD; $GIT_DIRTY uncommitted paths under spikes/core-execution and spikes/sqlite-authorizer (path dependency)"
    echo "INFO storage of the work directory /tmp: $(df -T /tmp | tail -1 | tr -s " " | cut -d" " -f1,2)"
    echo "INFO container root mount: $(grep -m1 " / " /proc/mounts | cut -d" " -f1-3)"
    for crate in rusqlite libsqlite3-sys tokio aws-lc-rs aws-lc-sys argon2; do
      echo "INFO $crate $(grep -A1 "^name = \"$crate\"$" Cargo.lock | sed -n "s/^version = \"\(.*\)\"$/\1/p")"
    done
    step toolchain_components rustup component add rustfmt clippy
    step build cargo build --locked --release --all-targets
    step fmt cargo fmt --check
    step clippy cargo clippy --locked --all-targets -- -D warnings
    cargo test --locked --release > /tmp/tests.log 2>&1
    tests_status=$?
    grep -h "^test .* \.\.\. \(ok\|FAILED\|ignored\)$" /tmp/tests.log \
      | sed -e "s/^test \(.*\) \.\.\. ok$/PASS test.\1/" \
            -e "s/^test \(.*\) \.\.\. FAILED$/FAIL test.\1/" \
            -e "s/^test \(.*\) \.\.\. ignored$/FAIL test.\1 (ignored)/"
    # A run that silently lost or skipped tests must not pass. Update EXPECTED_TESTS when a
    # test function is added or removed.
    EXPECTED_TESTS=15
    passed=$(grep -h "^test result:" /tmp/tests.log | sed "s/.* \([0-9]*\) passed.*/\1/" | awk "{ s += \$1 } END { print s + 0 }")
    ignored=$(grep -h "^test result:" /tmp/tests.log | sed "s/.* \([0-9]*\) ignored.*/\1/" | awk "{ s += \$1 } END { print s + 0 }")
    if [ "$tests_status" -eq 0 ] && [ "$passed" -eq "$EXPECTED_TESTS" ] && [ "$ignored" -eq 0 ]; then
      echo "PASS tests ($passed passed, $ignored ignored, $EXPECTED_TESTS expected)"
    else
      echo "FAIL tests ($passed passed, $ignored ignored, $EXPECTED_TESTS expected)"
      grep -h -A30 "^failures:" /tmp/tests.log | sed "s/^/  /"
      status=1
    fi
    # What one durable commit costs on this storage: the pipeline is fsync-bound.
    /target/release/core-execution fsync-bench --iterations 2000 || status=1
    # The gate run: the AD-9 model as recommended, judged on D116.
    /target/release/core-execution run --name ad9 --pool 3 --duration "$E32_DURATION" || status=1
    # Sensitivity run, not the gate: four unlock loops on a four-permit pool, so Argon2id can
    # hold all four CPUs while the backup and the household load run.
    /target/release/core-execution run --name saturated-pool4 --pool 4 --unlockers 4 \
      --duration "$E32_SENSITIVITY_DURATION" --informational || status=1
    # AD-31 pause against file size, with a WAL holding a long day of commits.
    /target/release/core-execution pause-bound --sizes "$E32_PAUSE_SIZES" --updates 20000 || status=1
    if [ "$status" -ne 0 ]; then echo "RESULT FAIL"; else echo "RESULT PASS"; fi
    exit $status
  '
