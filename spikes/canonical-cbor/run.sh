#!/usr/bin/env bash
# E19 spike (story 1.9): builds and runs every check inside a Debian 13 container with Rust and
# a pinned Node, prints one `PASS <name>` or `FAIL <name>` line per check, and exits non-zero on
# any failure. Runs from Linux or from Git Bash on Windows; needs Docker only.
#
# The committed vectors are replayed on both sides, then a larger fresh generation with other
# seeds is replayed the same way. The pinned Node's Unicode version must equal the one of the
# Rust NFC tables, so text normalization is compared strictly.
set -euo pipefail

spike_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
image="vilicus-spike-canonical-cbor"
mount_dir="$spike_dir"
if command -v cygpath >/dev/null 2>&1; then
  mount_dir="$(cygpath -w "$spike_dir")"
fi

docker build --quiet --tag "$image" "$spike_dir" >/dev/null

# Build outputs, the cargo registry and the npm cache live in named volumes, so nothing is
# written into the source tree and repeated runs are incremental.
MSYS_NO_PATHCONV=1 docker run --rm --interactive \
  --volume "$mount_dir:/src:ro" \
  --volume vilicus-canonical-cbor-target:/target \
  --volume vilicus-cargo-registry:/usr/local/cargo/registry \
  --volume vilicus-npm-cache:/root/.npm \
  --env CARGO_TARGET_DIR=/target \
  --workdir /src \
  "$image" bash -s <<'IN_CONTAINER'
set -uo pipefail
failed=0
logs="$(mktemp -d)"
check() {
  local name="$1"; shift
  if "$@" >"$logs/$name.log" 2>&1; then
    echo "PASS $name"
  else
    echo "FAIL $name"
    tail -n 40 "$logs/$name.log" | sed 's/^/  | /'
    failed=1
  fi
}

# Replays one vector directory on the Rust side (the committed one when the second argument is
# empty, which also checks it equals a fresh generation). A first run prints the INFO lines,
# a second, captured run gives one line per test function (with --nocapture, the INFO lines
# can share a line with libtest's "test <name> ..." prefix).
rust_vectors() {
  local label="$1" dir="$2"
  local -a env_args=() skip_args=()
  if [ -n "$dir" ]; then
    # Another generation: no committed file to compare and no hand-written set.
    env_args=(VECTORS_DIR="$dir")
    skip_args=(--skip committed_vectors_equal_a_fresh_generation --skip invalid_inputs_are_all_rejected)
  fi
  env "${env_args[@]}" cargo test --locked --test vectors -- --test-threads=1 --nocapture \
    "${skip_args[@]}" >"$logs/rust-$label-info.log" 2>&1
  env "${env_args[@]}" cargo test --locked --test vectors -- --test-threads=1 \
    "${skip_args[@]}" >"$logs/rust-$label.log" 2>&1
  local status=$?
  grep -h '^test .* \.\.\. \(ok\|FAILED\)$' "$logs/rust-$label.log" \
    | sed -e "s/^test \(.*\) \.\.\. ok$/PASS rust.$label.\1/" \
          -e "s/^test \(.*\) \.\.\. FAILED$/FAIL rust.$label.\1/"
  grep -o 'CHECK INFO .*' "$logs/rust-$label-info.log" | cut -c1-300 | sed 's/^CHECK /  /' || true
  if [ "$status" -ne 0 ]; then
    grep -h -A8 'panicked' "$logs/rust-$label.log" | sed 's/^/  | /' || true
    failed=1
  fi
}

# Replays one vector directory on the TypeScript side, same output shape.
ts_vectors() {
  local label="$1"
  (cd /work/ts && VECTORS_DIR="$2" REQUIRE_SAME_UNICODE=1 \
    node --test --test-reporter=spec test/profile.test.ts test/corpus.test.ts test/rejections.test.ts) \
    >"$logs/ts-$label.log" 2>&1
  local status=$?
  sed -n -e "s/^✔ \(.*\) ([0-9.]*ms)$/PASS ts.$label.\1/p" \
         -e "s/^✖ \(.*\) ([0-9.]*ms)$/FAIL ts.$label.\1/p" "$logs/ts-$label.log" | sort -u
  grep -o 'CHECK INFO .*' "$logs/ts-$label.log" | cut -c1-300 | sed 's/^CHECK /  /' || true
  if [ "$status" -ne 0 ]; then
    grep -v '^\s*at ' "$logs/ts-$label.log" | tail -n 30 | sed 's/^/  | /'
    failed=1
  fi
}

echo "INFO $(rustc --version), node $(node --version) (unicode $(node -p process.versions.unicode)), Debian $(cat /etc/debian_version)"
echo "INFO $(grep -A1 '^name = "dcbor"' Cargo.lock | tr '\n' ' ')"
echo "INFO $(grep -A1 '^name = "unicode-normalization"' Cargo.lock | tr '\n' ' ')"
echo "INFO cbor2 $(node -p "require('/src/ts/package-lock.json').packages['node_modules/cbor2'].version")"

check vectors-sha256sums sh -c 'cd vectors && sha256sum -c SHA256SUMS'
check fmt cargo fmt --check
check clippy cargo clippy --locked --all-targets -- -D warnings
check rust-unit-tests cargo test --locked --lib
# The TypeScript package is copied out of the read-only mount so npm can write node_modules.
mkdir -p /work/ts
cp -r /src/ts/package.json /src/ts/package-lock.json /src/ts/src /src/ts/test /work/ts/
check npm-ci sh -c 'cd /work/ts && npm ci --ignore-scripts --no-audit --no-fund'

rust_vectors committed ""
ts_vectors committed /src/vectors

fresh=/work/fresh
check fresh-generation cargo run --locked --quiet --bin gen_vectors -- "$fresh" 2026101601 4000 20000 2026101602 100000 100000
grep -h 'written to' "$logs/fresh-generation.log" | sed 's/^/  INFO /' || true
rust_vectors fresh "$fresh"
ts_vectors fresh "$fresh"

if [ "$failed" -ne 0 ]; then
  echo "RESULT FAIL"
  exit 1
fi
echo "RESULT PASS"
IN_CONTAINER
