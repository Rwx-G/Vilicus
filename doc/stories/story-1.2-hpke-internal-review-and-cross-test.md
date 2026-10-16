---
title: 'HPKE internal review and cross-test'
epic: 1
story: 2
status: 'done'
author: Rwx-G
created: 2026-10-16
implements: [D61, D107, AD-18, DC-40, DC-62, R33, D28]
---

# Story 1.2: HPKE internal review and cross-test

As the owner,
I want the `hpke` crate reviewed internally and cross-tested against an independent implementation before the household key is wrapped with it,
So that the one recorded exception to the audited-libraries rule (D28) reaches the done state of D107 before FR-8 code.

**Acceptance Criteria:**

**AC1 (D61, D107, AD-18)**
**Given** the `hpke` crate in base mode with DHKEM(X25519, HKDF-SHA256) and AES-256-GCM
**When** the RFC 9180 test vectors for that suite run in a CI job of the spike package `spikes/hpke-cross-test/`
**Then** every vector passes

**AC2 (D61, D107, DC-62)**
**Given** the independent implementation named in the decision task below, used as a dev-dependency only
**When** the cross-test seals with one implementation and opens with the other, in both directions, on 10 000 random cases (keys, info, associated data and plaintext lengths)
**Then** every case agrees, and the job runs in CI on every change to the spike package

**AC3 (D61, AD-18, R33, D28)**
**Given** the crate source at the pinned version and Vilicus's intended use of it (household key wrap, backup key sealing, inbox sealing later)
**When** the internal security review is done, assisted by the most capable model available (AD-18)
**Then** a written review is committed with every finding closed or accepted
**And** neither the review nor any other document calls the crate audited

**AC4 (D107, DC-40)**
**Given** the review finds a defect
**When** the defect cannot be fixed upstream and pinned within the timebox
**Then** the fallback is recorded in `doc/decisions.md`: V0.1 exits with UJ-2 limited to the first member and FR-8 ships in V0.1.x

**Spike plan:**
- Question: does the `hpke` crate agree with RFC 9180 and an independent implementation, and does an internal review find no open defect (D61)?
- Method: RFC 9180 vectors, a 10 000-case two-way cross-test in CI, a written review of the crate and of Vilicus's use of it.
- Pass criterion: the D107 done state: vectors pass, the cross-test agrees on 10 000 random cases in CI, the review is committed with every finding closed or accepted.
- Timebox: 8 working days.
- Fallback on failure: a defect is fixed upstream and the fix pinned; failing that, V0.1 exits with UJ-2 limited to the first member and FR-8 ships in V0.1.x (D107).
- Result record: the review file, the open question of `doc/research-notes.md` section 4 on the independent implementation closed with a link to the CI run, a decision record if the fallback is taken.

**Decision tasks:**
- [ ] Decide which independent HPKE implementation the cross-test uses, before the review starts. Recommended: `hpke-rs` with its RustCrypto provider, as a dev-dependency only. Gives up: a second Rust implementation shares the language and ecosystem, so a C implementation would be more independent but costs FFI in the test harness.
- [ ] Decide where the written review is committed. Recommended: `doc/reviews/hpke-review.md`. Gives up: nothing material; the path only needs to be stable for later links.

**Dependencies:**
- None. Runs together with Story 1.1, first in the V0.1 spike order.

**References:**
- `doc/decisions.md` D28, D61, D107
- `doc/architecture-spine.md` AD-18, Deferred section
- `doc/prd.md` section 6.1, section 9 (HPKE review and cross-test), DC-40, DC-62
- `doc/research-notes.md` section 3 and section 4
- `doc/architecture.md` section 16, section 20 (R33)

## Implementation Notes

Built in `spikes/hpke-review/`, a standalone crate (empty `[workspace]`, edition 2024, Apache-2.0, `publish = false`):

- `src/lib.rs`: the AD-18 profile as Vilicus will use it: suite and base mode fixed in the types; `seal` (single-shot, refuses a non-canonical recipient key); `open_into` (single-shot, in place, into a caller-owned buffer, one `Refused` error for every failure); `derive_backup_keypair` (32 bytes of input only). The `hpke::Kem` trait is not re-exported.
- `tests/rfc9180_vectors.rs`: the suite's vector from the CFRG HPKE test-vector file referenced by RFC 9180 (mode 0, KEM 0x0020, KDF 0x0001, AEAD 0x0002; RFC 9180 Appendix A prints no vector for this suite), run through the public API of `hpke` and of `hpke-rs` with each provider, plus a test that rebuilds the stored subset from the upstream file shipped in the `hpke` package and refuses any difference.
- `tests/cross_test.rs`: the 10 000-case two-way cross-test, default seed `0x56494c4943555331` ("VILICUS1"), overridable with `HPKE_CROSS_TEST_SEED` for exploration only, run once against each `hpke-rs` provider (RustCrypto, libcrux).
- `tests/error_paths.rs`: one test per behaviour the review relies on (small-order points with bit 255 clear and set, non-canonical recipient keys, binding of key, `info` and additional data, failed-open buffer state after a flipped tag and a wrong aad, malformed lengths and output buffers one byte short and one byte long, clamping, the top bit of `enc`, `DeriveKeyPair` input length).
- `tests/sender_substitution.rs`: a disk writer substitutes a household key wrap; which confirmation refuses it (REVIEW.md F12, usage rule U10).
- `vectors/`: the subset, `SHA256SUMS`, and `SOURCE.txt` with the upstream URL, commit and SHA-256.
- `REVIEW.md`: the written review (scope, method, findings F1 to F13 with dispositions, usage rules U1 to U10 with U3b, and the record of a second-pass review).
- `run.sh`: runs the checks in a `rust:1.94-trixie` container pinned by digest (`sha256:652612f07bfbbdfa3af34761c1e435094c00dde4a98036132fca28c7bb2b165c`, Debian 13) and prints one `PASS` or `FAIL` line per check. `cargo audit` is not in it (it needs the network and is not in the image).

Dependencies:

| Crate | Version | Kind | Reason |
|---|---|---|---|
| `hpke` | =0.13.0, features `x25519`, `alloc` | normal | crate under review, as pinned by the key prototype |
| `x25519-dalek`, `aes`, `aes-gcm`, `ghash`, `polyval` | 2.0.1, 0.8.4, 0.10.3, 0.5.1, 0.6.2 | normal | no new crate: all are already in the `hpke` tree; declared only to switch on their `zeroize` features (review F1, usage rule U1) |
| `hpke-rs` | =0.8.0, features `rustcrypto`, `libcrux-no-sys-rng`, `std` | dev | the independent implementation (decision task 1) |
| `hpke-rs-rust-crypto` | =0.8.0 | dev | its RustCrypto provider |
| `hpke-rs-libcrux` | =0.8.0, no default features | dev | its libcrux provider: X25519, AES-GCM, HKDF and SHA-256 outside the dalek and RustCrypto lineage of `hpke` (REVIEW.md F11); pure Rust, builds cleanly |
| `hpke-rs-crypto` | =0.8.0 | dev | already in the `hpke-rs` tree; named to implement its provider trait with queued randomness, so the cross-test is fully deterministic and can compare sealed bytes |
| `serde_json` | 1 (1.0.154 locked) | dev | parses the official vector file as published, instead of a hand-written parser that would itself need review |
| `hkdf`, `hmac`, `sha2` | 0.12.4, 0.12.1, 0.10.9 | dev | no new crate: already in the `hpke` tree; the sender-substitution test computes the permanent MAC and the member commitment with them |

`hpke-rs` and its crates are MPL-2.0; as dev-dependencies they are never built into or distributed with Vilicus.

Decision tasks settled:

- Independent implementation: `hpke-rs` 0.8.0 with its RustCrypto provider, dev-dependency only, as recommended. It builds and supports the suite. Its HPKE layer is independent code, but its RustCrypto primitives share the dalek and RustCrypto lineage of `hpke` in other major versions, the X25519 path most of all; the cross-test therefore also runs against the libcrux provider of the same `hpke-rs`, which shares no primitive code with `hpke` (REVIEW.md F11).
- Review location: `spikes/hpke-review/REVIEW.md`, not the recommended `doc/reviews/hpke-review.md`. Reason: the review cites the spike's tests and `run.sh` by name and lives next to them; a committed spike path is as stable for links as a `doc/` path. Gives up: the review is not under `doc/`, so the reading order of `doc/README.md` does not list it; the proposed new decision record links it from the decision log instead.

Deviations:

- The package is `spikes/hpke-review/`, not `spikes/hpke-cross-test/` as AC1 names it; it holds the review as well as the cross-test. AC1's path is in the proposed updates.
- The ephemeral key of both implementations is fixed by serving them the same 32 random bytes, through `QueuedBytes`, in tests only. Both derive the ephemeral key pair as `DeriveKeyPair` over those bytes, so this exercises the production code path, not a test hook; it lets the vector test reproduce `enc` and the cross-test compare sealed output byte for byte.
- `hpke` 0.14.1 now resolves (REVIEW.md F10), contrary to the key prototype's `Cargo.toml` comment; the pin stays at 0.13.0 for V0.1, for the reasons in F10.
- The cross-test runs against two providers of `hpke-rs`, not one, after a second-pass review (REVIEW.md section 9).

## Result

Commands, from the repository root:

```sh
cargo test --manifest-path spikes/hpke-review/Cargo.toml
cargo clippy --manifest-path spikes/hpke-review/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path spikes/hpke-review/Cargo.toml --check
bash spikes/hpke-review/run.sh
```

On 2026-10-16 the first three pass on the Windows development host (rustc 1.94.0), and `run.sh` passes in the pinned `rust:1.94-trixie` image (Debian 13.4, rustc 1.94.1) with a `PASS` line for each check: `toolchain-components`, `vectors-subset-sha256`, `cargo-fetch`, `upstream-vectors-sha256`, `fmt`, `clippy`, `rfc9180-vectors`, `cross-test-10000`, `error-paths`, `sender-substitution`, `zeroize-features`, `dependency-tree`.

| Criterion | Result | Evidence |
|---|---|---|
| AC1, RFC 9180 vectors in a CI job | **Pass, except the CI job: not run here** | `tests/rfc9180_vectors.rs`, 5 tests pass: the suite's vector from the CFRG HPKE test-vector file referenced by RFC 9180 passes for `hpke` (`DeriveKeyPair`, `enc`, the 257 sealed and opened messages of the sequence, 3 exports) and for `hpke-rs` with each provider; the stored subset equals the suite's entries of the upstream file, whose SHA-256 matches. The repository has no CI yet (spine AD-33), so no CI job exists; procedure below. |
| AC2, 10 000-case two-way cross-test in CI | **Pass, except the CI job: not run here** | `tests/cross_test.rs` prints, for each provider, `cross-test [RustCrypto with queued randomness] seed 0x56494c4943555331: 10000 cases; hpke->hpke-rs 10000, hpke-rs->hpke 10000, byte-identical seals 10000, exports 20000, tampered refused 20000` and the same line for `[Libcrux]`, identical on the host and in Debian 13. Recipient keys (derived and raw), `info`, additional data and plaintext lengths (0 to 1 500 bytes, every tenth case 32 bytes) vary per case. `hpke-rs` is a dev-dependency only. |
| AC3, written review, every finding closed or accepted, never called audited | **Pass, pending owner approval of the dispositions** | `spikes/hpke-review/REVIEW.md`: 13 findings, none High. F1 (Medium) partially closed by usage rule U1, its residue accepted in F2; F12 (Medium, base mode authenticates no sender) accepted with usage rule U10 and an open design question on the first receipt of HK; F2, F3, F4 (Low) accepted with reasons; F13 (Low) closed in the profile; the others Info, closed or accepted. The review states that the crate is not audited. The dispositions become final when the owner approves the file. |
| AC4, fallback recorded if a defect cannot be fixed | **Not applicable** | No finding needs an upstream fix, so the D107 fallback is not taken and no fallback record is written. |

Not run here, CI: once the CI story of spine AD-33 lands, add a job that runs on every change under `spikes/hpke-review/`, on a Linux runner with Docker, and executes `bash spikes/hpke-review/run.sh`; the job fails when the script exits non-zero. For GitHub Actions: `push` and `pull_request` triggers with `paths: ["spikes/hpke-review/**"]`, `runs-on: ubuntu-latest`, `actions/checkout`, and one step `bash spikes/hpke-review/run.sh`. The link to its first green run closes the research-notes question (update 5 below) and the remaining part of the gate.

Not run here, `cargo audit` in the container: the image has no `cargo-audit`, and the advisory database needs the network. On the host, `cargo audit` (cargo-audit 0.22.1, RustSec database of 2026-10-16) reports no vulnerability and one unmaintained warning (RUSTSEC-2026-0173, `proc-macro-error2`, in lock entries of the dev-only `hpke-rs` chain).

## Proposed design document updates

To be made by the owner, or in a later change, once this story is approved; none is made here. "The new decision record" below is the next free record of `doc/decisions.md`, numbered when it is written.

1. `doc/decisions.md`, a new decision record:
   - Table row: `| <new record> | HPKE gate passed except its CI job: review, vectors and cross-test of the hpke crate | Accepted |`.
   - Record: "HPKE gate passed except its CI job: review, vectors and cross-test of the hpke crate. Amends D61. Context: D61 and D107 gate the household key wrap on an internal review of the `hpke` crate, the RFC 9180 test vectors and a cross-test against an independent implementation, both in CI. Decision: the gate is passed except the CI job D61 requires, which closes with the first CI story: for `hpke` 0.13.0 as built in `spikes/hpke-review/`, the RFC 9180 vectors of the AD-18 suite pass, a cross-test against `hpke-rs` 0.8.0, a dev-dependency only, with its RustCrypto and its libcrux providers agrees on 10 000 random cases in both directions for each, and the review (`spikes/hpke-review/REVIEW.md`) closes or accepts every finding; these runs are local and in a pinned Debian 13 container, not yet in CI. The exception covers `hpke` and the primitive crates it depends on, which are Core dependencies for `cargo deny` and `cargo vet`. The Core uses HPKE only under the review's usage rules U1 to U10, among them the `zeroize` features of the primitive crates, single-shot base mode only, a value unique per seal in `info`, in-place opening of wrapped keys into locked memory, and the confirmation of every opened key against an independently authenticated value. Consequences: FR-8 code may start once the owner approves the review; any change of the `hpke` version reopens the review; the CI job of the cross-test is added with the first CI story, and its first green run completes the gate; the external review before V1 stays required (D61)."
   - D61's table status "Accepted, amended by D74 and D107" becomes "Accepted, amended by D74, D107 and" the new record.
2. `doc/architecture-spine.md`, AD-18 rule: "AES-GCM and HKDF come from aws-lc-rs." becomes "AES-GCM and HKDF come from aws-lc-rs, except inside HPKE, whose crate brings its own primitive crates under the same exception." At the end of the rule, after "[ADOPTED, D107].", add: "The gate is passed for `hpke` 0.13.0, except the CI job, which closes with the first CI story, under the usage rules of `spikes/hpke-review/REVIEW.md` [ADOPTED, new decision record]."
3. `doc/key-management.md` section 2, paragraph after the table: "AES-GCM and HKDF come from aws-lc-rs; HPKE comes from the `hpke` crate under the D61 exception." becomes "AES-GCM and HKDF come from aws-lc-rs; HPKE comes from the `hpke` crate, with the primitive crates it depends on, under the D61 exception, and is used only under the usage rules of its review (new decision record)."
4. `doc/key-management.md` section 10, after "Process crashes drop keys and lock the instance.": add "Inside HPKE, copies of secrets stay in freed memory whatever the build features: HKDF states, a copy of the DH output, the ephemeral seed, copies of private keys made by serialization and comparison, the clamped scalar of each X25519 operation, and, on x86_64, the GHASH key of each AES-GCM context, which the runtime-detected `polyval` backend never wipes; the Core opens wrapped keys in place into locked memory, and the residue is of the same class as the root attacker below (new decision record)."
5. `doc/key-management.md` section 2, after step 4 of the construction: add "**Confirmation of HK at unlock.** HPKE base mode authenticates no sender, so a disk writer who holds a member public key can seal an HK' of its choice to it, and can compute the permanent MAC under HK' as well. When a member first receives HK, the Core writes a commitment to HK and its version under a key derived from the member's DEK, and at every later unlock refuses an opened HK that does not match it, with an alert. **Open**: the first receipt of HK has no such anchor; whether it is confirmed by the authorizing adult, by a value under the instance key, or accepted as a trust-on-first-unwrap point is to be decided before FR-8 code." And in `doc/research-notes.md` section 4, add the same open question.
6. `doc/research-notes.md` section 4, HPKE item: "(done state in D107; **open**: which independent implementation, to be named before the review starts)" becomes "(done state in D107; the independent implementation is `hpke-rs` 0.8.0 with its RustCrypto and libcrux providers, and the review, vectors and cross-test passed in `spikes/hpke-review/` (new decision record); **open** until the CI job exists and the link to its first green run is added)". Section 3, "The D61 review and cross-test remain open." becomes "The D61 review and cross-test passed locally (new decision record); the CI job closes the gate with the first CI story."
7. `doc/prd.md` section 9 (HPKE row) and `doc/architecture.md` section 20 (R33): no wording change; both point to D61 and D107, and the new record is reached from D61.
8. This story, AC1: "a CI job of the spike package `spikes/hpke-cross-test/`" becomes "a CI job of the spike package `spikes/hpke-review/`"; decision task 2's recommended path becomes `spikes/hpke-review/REVIEW.md`.
9. `spikes/ad36-key-prototype/Cargo.toml` (another spike's file, not edited here): the comment "hpke 0.14 needs a prerelease aes-gcm that cargo does not resolve; 0.13.0 is pinned." becomes "hpke 0.13.0 is pinned: it is the version the D61 review covers (spikes/hpke-review/REVIEW.md)."
