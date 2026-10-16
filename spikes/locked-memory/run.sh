#!/usr/bin/env bash
# Spike E16 (story 1.10): builds and runs the whole spike inside Debian 13 Rust containers.
# Prints one PASS or FAIL line per step and per check (INFO lines carry measurements that are
# not pass criteria, such as the residue of the default library paths) and exits non-zero on
# any failure, on any ignored test, or if a container fails. Needs only Docker on the host.
#
# Four containers, each granted only what its checks need:
#   main      --cap-add SYS_PTRACE (the harness reads a non-dumpable subject's memory, as a
#             root attacker would), --ulimit memlock=8 MiB (the systemd default LimitMEMLOCK).
#             Build, format, lint, tests, then the memory scans and crash paths.
#   noptrace  no added capability, same memlock: same-user reading and core dumps.
#   nomemlock no added capability, --ulimit memlock=0: the refused mlock case.
#   swap      no added capability, --memory 256m --memory-swap 1g: locked pages under pressure.
set -uo pipefail

# rust:1-trixie (Debian 13, rustc 1.99.1) as pulled on 2026-10-16, pinned by digest.
IMAGE="${E16_IMAGE:-rust@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a}"
SPIKE_DIR="$(cd "$(dirname "$0")" && pwd)"
# Git Bash on Windows: give Docker a Windows path and stop MSYS rewriting container paths.
if HOST_DIR="$(cd "$SPIKE_DIR" && pwd -W 2>/dev/null)"; then
  export MSYS_NO_PATHCONV=1
else
  HOST_DIR="$SPIKE_DIR"
fi
MEMLOCK=8388608
BIN=/target/release/locked-memory

# The build output lives in a named volume, never in the source tree.
run_container() {
  docker run --rm \
    -v "$HOST_DIR:/spike:ro" \
    -v vilicus-spike-cargo-registry:/usr/local/cargo/registry \
    -v vilicus-e16-target:/target \
    -e CARGO_TARGET_DIR=/target \
    -e CARGO_TERM_COLOR=never \
    -w /spike \
    "$@"
}

failures=0
count() {
  local status=$1 output=$2
  printf '%s\n' "$output"
  if [ "$status" -ne 0 ] && ! grep -q '^FAIL ' <<<"$output"; then
    echo "FAIL container: exit status $status"
  fi
  [ "$status" -ne 0 ] && failures=$((failures + 1))
}

output="$(run_container --cap-add SYS_PTRACE --ulimit "memlock=$MEMLOCK:$MEMLOCK" "$IMAGE" bash -c '
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
    no_ignored_tests() {
      cargo test --locked 2>&1 | tee /tmp/tests.log
      local rc=${PIPESTATUS[0]}
      [ "$rc" -eq 0 ] || return "$rc"
      if grep -Eq "[1-9][0-9]* ignored" /tmp/tests.log; then
        echo "a test is ignored"
        return 1
      fi
    }
    # Usage rule U1 of spikes/hpke-review/REVIEW.md: the scans measure the build with these on.
    zeroize_features() {
      local package name
      for package in x25519-dalek@2.0.1 curve25519-dalek@4.1.3 aes@0.8.4 aes-gcm@0.10.3 ghash@0.5.1 polyval@0.6.2 argon2@0.6.0; do
        name="${package%@*}"
        if cargo tree --locked -e normal,features -i "$package" --prefix none | grep -q "^$name feature \"zeroize\""; then
          echo "$package: zeroize enabled"
        else
          echo "$package: zeroize NOT enabled"
          return 1
        fi
      done
    }
    echo "INFO environment: $(rustc --version), Debian $(cat /etc/debian_version), kernel $(uname -r), core_pattern $(cat /proc/sys/kernel/core_pattern), RLIMIT_MEMLOCK $(ulimit -l) KiB"
    step toolchain_components rustup component add rustfmt clippy
    step build cargo build --locked --release --all-targets
    step fmt cargo fmt --check
    step clippy cargo clippy --locked --all-targets -- -D warnings
    step tests no_ignored_tests
    step zeroize_features zeroize_features
    '"$BIN"' checks main || status=1
    exit $status
  ' 2>&1)"
count $? "$output"

output="$(run_container --ulimit "memlock=$MEMLOCK:$MEMLOCK" "$IMAGE" "$BIN" checks noptrace 2>&1)"
count $? "$output"

output="$(run_container --ulimit memlock=0:0 "$IMAGE" "$BIN" checks nomemlock 2>&1)"
count $? "$output"

output="$(run_container --ulimit "memlock=$MEMLOCK:$MEMLOCK" --memory 256m --memory-swap 1g "$IMAGE" "$BIN" checks swap 2>&1)"
count $? "$output"

if [ "$failures" -ne 0 ]; then
  echo "$failures container(s) reported a failure"
  exit 1
fi
echo "all checks passed"
