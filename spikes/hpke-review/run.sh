#!/usr/bin/env bash
# Runs the whole HPKE spike (story 1.2) inside a Debian 13 (trixie) container with the Rust
# toolchain: vector provenance, format, lint, RFC 9180 vectors, the 10 000-case cross-test
# against each hpke-rs provider, the error paths, the sender-substitution model, the zeroize
# feature check and the dependency tree. Prints one `PASS <name>` or `FAIL <name>` line per
# check and exits non-zero if any check fails. `cargo audit` is not run here: it needs the
# network for its advisory database and is not in the image; run it on the host.
#
# Usage: bash spikes/hpke-review/run.sh       (from any directory, Docker required)
# Environment: RUST_IMAGE overrides the image (default below, Debian trixie based).
set -u

# rust:1.94-trixie, pinned by digest (recorded 2026-10-16) so the image cannot move.
RUST_IMAGE="${RUST_IMAGE:-rust:1.94-trixie@sha256:652612f07bfbbdfa3af34761c1e435094c00dde4a98036132fca28c7bb2b165c}"
# SHA-256 of test-vectors.json at github.com/cfrg/draft-irtf-cfrg-hpke, commit 5f503c5, the
# file the hpke crate ships as test-vectors-5f503c5.json.
UPSTREAM_SHA256="61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6"

if [ "${1:-}" != "--inside" ]; then
    spike_dir="$(cd "$(dirname "$0")" && (pwd -W 2>/dev/null || pwd))"
    # MSYS_NO_PATHCONV keeps Git Bash on Windows from rewriting the container paths.
    MSYS_NO_PATHCONV=1 exec docker run --rm \
        -v "${spike_dir}:/work:ro" \
        -v hpke-review-cargo-registry:/usr/local/cargo/registry \
        -v hpke-review-target:/target \
        -e CARGO_TARGET_DIR=/target \
        -e UPSTREAM_SHA256="${UPSTREAM_SHA256}" \
        -w /work \
        "${RUST_IMAGE}" bash /work/run.sh --inside
fi

failures=0
logs="$(mktemp -d)"

check() {
    local name="$1"
    shift
    if "$@" >"${logs}/${name}.log" 2>&1; then
        echo "PASS ${name}"
    else
        echo "FAIL ${name}"
        tail -n 40 "${logs}/${name}.log" | sed 's/^/    /'
        failures=$((failures + 1))
    fi
}

upstream_vectors_sha256() {
    local file
    file="$(find "${CARGO_HOME}/registry/src" -path '*/hpke-0.13.0/test-vectors-5f503c5.json' | head -n 1)"
    [ -n "${file}" ] || { echo "hpke-0.13.0 vector file not found"; return 1; }
    echo "${UPSTREAM_SHA256}  ${file}" | sha256sum -c -
}

# Proves that the `zeroize` feature is resolved on for each crate, not that memory is wiped:
# polyval's runtime-detection wrapper never drops its backend, and curve25519-dalek leaves a
# stack copy of the clamped scalar, whatever the features (REVIEW.md F1, F2).
zeroize_features() {
    local package name
    for package in x25519-dalek@2.0.1 curve25519-dalek@4.1.3 aes@0.8.4 aes-gcm@0.10.3 ghash@0.5.1 polyval@0.6.2; do
        name="${package%@*}"
        if cargo tree --locked -e normal,features -i "${package}" --prefix none | grep -q "^${name} feature \"zeroize\""; then
            echo "${package}: zeroize enabled"
        else
            echo "${package}: zeroize NOT enabled"
            return 1
        fi
    done
}

cross_test() {
    cargo test --locked --test cross_test -- --nocapture --test-threads 1 || return 1
}

dependency_tree() {
    cargo tree --locked -e normal --prefix depth
}

echo "image ${RUST_IMAGE}, $(rustc --version), Debian $(cat /etc/debian_version)"
check toolchain-components rustup component add clippy rustfmt
check vectors-subset-sha256 sh -c 'cd vectors && sha256sum -c SHA256SUMS'
check cargo-fetch cargo fetch --locked
check upstream-vectors-sha256 upstream_vectors_sha256
check fmt cargo fmt --check
check clippy cargo clippy --locked --all-targets -- -D warnings
check rfc9180-vectors cargo test --locked --test rfc9180_vectors
check cross-test-10000 cross_test
grep -o 'cross-test [[].*' "${logs}/cross-test-10000.log" | sed 's/^/    /'
check error-paths cargo test --locked --test error_paths
check sender-substitution cargo test --locked --test sender_substitution
check zeroize-features zeroize_features
check dependency-tree dependency_tree
sed 's/^/    /' "${logs}/dependency-tree.log"

if [ "${failures}" -ne 0 ]; then
    echo "${failures} check(s) failed"
    exit 1
fi
echo "all checks passed"
