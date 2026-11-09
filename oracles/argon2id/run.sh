#!/usr/bin/env bash
# The Argon2id checks of Story 4.4 that need more locked memory than a test runner allows, in a
# container of the pinned image whose RLIMIT_MEMLOCK is unlimited (D128: the Core's LimitMEMLOCK
# covers the key pool and 1 GiB of Argon2id working memory):
# - the workspace tests ignored by `cargo test` for that reason, at the floor and the version 1
#   cost (`cargo test -- --ignored`);
# - the oracle of this directory: the Core's Argon2id against phc-winner-argon2, linked from
#   Debian 13's libargon2-dev, and against OpenSSL 3.5's `openssl kdf`, on 10 000 random cases and
#   the coverage list of doc/qa/argon2-review.md (U8), the floor, version 1 and ceiling costs
#   through the Core's entry point and limiter, and a burst whose locked memory is sampled.
# Prints one `PASS <name>` or `FAIL <name>` line per check and exits non-zero if any fails. The
# network is used for the toolchain and libargon2-dev only; the crates come from vendor/.
#
# Usage: bash oracles/argon2id/run.sh           (from any directory, Docker required)
#        bash oracles/argon2id/run.sh --bench   the unlock benchmark of Story 4.4 (AC3) instead,
#        under the reference host's limits (4 CPUs, 8 GB); E12_HOST names the host profile.
set -u

IMAGE="rust:1.99-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a"
# The Debian source package libargon2-dev is built from, checked before the library is trusted
# as the reference: phc-winner-argon2 at its tag 20190702.
ARGON2_SOURCE="argon2 (0~20190702+dfsg-4)"

if [ "${1:-}" != "--inside" ] && [ "${1:-}" != "--inside-bench" ]; then
    repo="$(cd "$(dirname "$0")/../.." && (pwd -W 2>/dev/null || pwd))"
    mode="--inside"
    limits=()
    if [ "${1:-}" = "--bench" ]; then
        mode="--inside-bench"
        limits=(--cpus=4 --memory=8g --memory-swap=8g)
    fi
    # MSYS_NO_PATHCONV keeps Git Bash on Windows from rewriting the container paths.
    MSYS_NO_PATHCONV=1 exec docker run --rm \
        --ulimit memlock=-1:-1 \
        "${limits[@]}" \
        --tmpfs /target:exec \
        -e CARGO_TARGET_DIR=/target \
        -e CARGO_TERM_COLOR=never \
        -e ARGON2_SOURCE="${ARGON2_SOURCE}" \
        -e E12_HOST="${E12_HOST:-emulation}" \
        -v "${repo}:/w:ro" \
        -w /w \
        "${IMAGE}" bash /w/oracles/argon2id/run.sh "${mode}"
fi

if [ "${1:-}" = "--inside-bench" ]; then
    exec cargo run --release --frozen --config ci/cargo-vendored.toml -p vilicus-crypto \
        --features testing --example argon2id_bench
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

install_reference() {
    apt-get update -qq && apt-get install -y -qq --no-install-recommends libargon2-dev
}

reference_provenance() {
    dpkg-query -W -f='${Package} ${Version} source ${source:Package} (${source:Version})\n' libargon2-dev
    dpkg-query -W -f='${source:Package} (${source:Version})' libargon2-dev | grep -qxF "${ARGON2_SOURCE}"
    grep -E '^(Upstream-Name|Source):' /usr/share/doc/libargon2-1/copyright
    grep -qxF 'Upstream-Name: phc-winner-argon2' /usr/share/doc/libargon2-1/copyright
}

memlock_unlimited() {
    echo "RLIMIT_MEMLOCK: $(ulimit -l)"
    [ "$(ulimit -l)" = "unlimited" ]
}

ignored_tests() {
    cargo test --workspace --frozen --config ci/cargo-vendored.toml -- --ignored
}

oracle() {
    (cd oracles/argon2id && cargo run --release --frozen --config ../../ci/cargo-vendored.toml)
}

echo "image ${IMAGE}, Debian $(cat /etc/debian_version)"
check memlock-unlimited memlock_unlimited
check install-libargon2 install_reference
check libargon2-provenance reference_provenance
check toolchain rustc --version
check ignored-tests ignored_tests
check oracle oracle
grep -h -E '^(PASS|FAIL) ' "${logs}/oracle.log" | sed 's/^/  /'
grep -h -E '^test result: ok\. [1-9]|FAILED' "${logs}/ignored-tests.log" | sed 's/^/  /'
cat "${logs}/libargon2-provenance.log" | sed 's/^/  /'

if [ "${failures}" -ne 0 ]; then
    echo "${failures} check(s) failed"
    exit 1
fi
echo "all Argon2id checks passed"
