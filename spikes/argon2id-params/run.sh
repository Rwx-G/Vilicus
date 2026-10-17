#!/usr/bin/env bash
# Spike E12 (story 1.8): builds and runs the whole spike inside a Debian 13 Rust container
# constrained to the reference host's size (4 CPUs, 8 GB RAM, no swap). This is an emulation
# on a larger machine, not the reference host: CPU quota is not the same as 4 physical cores.
# E12_HOST=reference on the reference host itself removes the selection margin kept for emulation.
# Prints one PASS or FAIL line per check (build, format, lint, tests, then every spike check),
# the measured tables, and exits non-zero on any failure. Needs only Docker on the host.
set -euo pipefail

IMAGE="${E12_IMAGE:-rust:1.99-trixie}"
SPIKE_DIR="$(cd "$(dirname "$0")" && pwd)"
# Git Bash on Windows: give Docker a Windows path and stop MSYS rewriting container paths.
if HOST_DIR="$(cd "$SPIKE_DIR" && pwd -W 2>/dev/null)"; then
  export MSYS_NO_PATHCONV=1
else
  HOST_DIR="$SPIKE_DIR"
fi

# The build output lives in a named volume, never in the source tree.
docker run --rm \
  --cpus=4 --memory=8g --memory-swap=8g \
  -v "$HOST_DIR:/spike" \
  -v vilicus-spike-cargo-registry:/usr/local/cargo/registry \
  -v vilicus-e12-target:/target \
  -e CARGO_TARGET_DIR=/target \
  -e CARGO_TERM_COLOR=never   -e E12_HOST="${E12_HOST:-emulation}" \
  -w /spike \
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
        return 1
      fi
    }
    step toolchain_components rustup component add rustfmt clippy
    built=1
    step build cargo build --locked --release --all-targets || built=0
    step fmt cargo fmt --check
    step clippy cargo clippy --locked --all-targets -- -D warnings
    step tests cargo test --locked --release
    echo "INFO image=$(. /etc/os-release && echo "$PRETTY_NAME") $(rustc --version)"
    # Never run a stale binary left in the target volume by an earlier build.
    if [ "$built" = 1 ]; then
      /target/release/argon2id-params || status=1
    fi
    exit $status
  '
