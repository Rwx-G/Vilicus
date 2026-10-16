#!/usr/bin/env bash
# Spike E17 (story 1.11): builds and runs the whole spike inside a Debian 13 Rust container.
# Prints one PASS or FAIL line per check (build, format, lint, tests, then every spike check)
# and exits non-zero on any failure. Needs only Docker on the host.
set -euo pipefail

# rust:1-trixie (Debian 13, rustc 1.99.1) as pulled on 2026-10-16, pinned by digest.
IMAGE="${E17_IMAGE:-rust@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a}"
SPIKE_DIR="$(cd "$(dirname "$0")" && pwd)"
# Git Bash on Windows: give Docker a Windows path and stop MSYS rewriting container paths.
if HOST_DIR="$(cd "$SPIKE_DIR" && pwd -W 2>/dev/null)"; then
  export MSYS_NO_PATHCONV=1
else
  HOST_DIR="$SPIKE_DIR"
fi

# The build output lives in a named volume, never in the source tree.
docker run --rm \
  -v "$HOST_DIR:/spike" \
  -v vilicus-spike-cargo-registry:/usr/local/cargo/registry \
  -v vilicus-e17-target:/target \
  -e CARGO_TARGET_DIR=/target \
  -e CARGO_TERM_COLOR=never \
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
      fi
    }
    step toolchain_components rustup component add rustfmt clippy
    step build cargo build --locked --all-targets
    step fmt cargo fmt --check
    step clippy cargo clippy --locked --all-targets -- -D warnings
    step tests cargo test --locked
    cargo run --locked --quiet || status=1
    exit $status
  '
