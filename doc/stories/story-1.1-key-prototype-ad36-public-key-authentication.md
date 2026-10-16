---
title: 'Key prototype: AD-36 public-key authentication'
type: 'feature'
created: '2026-10-16'
status: 'done'
baseline_commit: 'cc9d33baa15ac70065dc26f46a3f3af39260a2a6'
route: 'dispatch'
review_loop_iteration: 0
author: Rwx-G
epic: 1
story: 1
implements: [AD-36, DC-40, DC-72, D74, D107, D117, FR-7, FR-8, T23]
context:
  - '{project-root}/doc/key-management.md'
---

<frozen-after-approval reason="human-owned intent - do not modify unless human renegotiates">

## Intent

**Problem:** AD-36 and `doc/key-management.md` section 2 describe how a member public key is authenticated from `vilicus member add` (or first enrollment) until the household key (HK) is wrapped to it, but the exact encodings are not fixed and nothing proves that a disk-write attacker without HK is stopped (T23). FR-8 code may not start until this holds (D74, D107).

**Approach:** A standalone Rust spike crate under `spikes/ad36-key-prototype/` implements the seven steps of `doc/key-management.md` section 2 with the AD-18 primitives, fixes every label and byte layout, and proves by tests that a substituted public key is refused while a correctly enrolled one receives the HK wrap. The result is written back into the design documents.

## Boundaries & Constraints

**Always:** HKDF-SHA-256, HMAC-SHA-256 and AES-256-GCM (random 96-bit nonce) from `aws-lc-rs`; HPKE base mode DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM from the `hpke` crate; every stored value carries a format version and algorithm identifiers (key-management section 9); MAC comparison in constant time; labels exactly as in key-management section 2 (`vilicus/v1/enroll-auth/`, `vilicus/v1/hk/enroll-wrap/`, `vilicus/v1/pubkey-mac/`), plus a fixed label for the token check hash.

**Never:** home-made primitives (D28); any dependency beyond `aws-lc-rs` and `hpke` (their transitive crates included, `hpke::rand_core` used through the re-export); SQLite or serde (the prototype store is a flat binary file); joining a workspace (Epic 2 creates it); key material in logs or `Debug` output.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| First member | No HK, no member | HK created, key pairs generated, permanent MAC written at once, HK wrapped | N/A |
| Further adult, honest | `member add` by an unlocked adult, then enrollment with the token, then next adult unlock | Enrollment tag verifies, permanent MAC written, HK wrapped to the new public key | N/A |
| Public key substituted before unlock | Attacker rewrites the member or inbox public key in `wrappers.db` | No HK wrap | Refusal with a distinct error, alert event recorded |
| Tag or wrapped enrollment key tampered | Attacker edits the tag or the wrapped enrollment key | No HK wrap | Refusal |
| Permanent MAC tampered later | Public key and MAC edited after the first wrap | Later HK wrap or re-wrap refused | Refusal |
| Wrong or reused token | Token not matching the stored check hash, or second use | Enrollment refused | Refusal, nothing stored |

</frozen-after-approval>

## Code Map

- `doc/key-management.md` section 2 (construction steps 1-7, labels), sections 3 and 5 -- normative source; the spike fixes what it leaves open ("exact encodings are fixed with the key prototype").
- `doc/architecture-spine.md` AD-18 (suite), AD-36 (rule) -- do not change their rules, only cite the result.
- `doc/decisions.md` D74, D107, D117 -- the next free record is D119.
- `doc/research-notes.md` section 4 gate text on AD-36 -- status to update.
- No Rust code exists yet; `.gitignore` already ignores `/target/` only at the root, so the spike needs its own ignore of `target/`.

## Tasks & Acceptance

**Execution:**
- [x] `spikes/ad36-key-prototype/Cargo.toml`, `Cargo.lock`, `.cargo/config.toml`, `.gitignore` -- standalone crate, edition 2024, `license = "Apache-2.0"`, `aws-lc-rs` and `hpke = "=0.13.0"` (default features off, `x25519`, `alloc`); `[env] AWS_LC_SYS_PREBUILT_NASM = "1"` so it builds on the Windows dev host without NASM -- hpke 0.14 needs a prerelease `aes-gcm` that cargo will not resolve.
- [x] `spikes/ad36-key-prototype/src/` -- primitives wrapper, CSPRNG adapter (`hpke::rand_core` over `aws_lc_rs::rand::SystemRandom`), versioned wrapper and tag encodings, flat-file `wrappers.db` store, and the ceremony functions: `create_first_member`, `member_add`, `enroll`, `adult_unlock_wrap_pending`.
- [x] `spikes/ad36-key-prototype/tests/` -- one test per I/O matrix row, attacker modelled as raw byte edits of `wrappers.db` with no HK.
- [x] `spikes/ad36-key-prototype/README.md` -- question, construction as built with exact byte layouts, how to run, result.
- [x] `doc/key-management.md` section 2 -- replace "The exact encodings are fixed with the key prototype" with the fixed encodings (or a pointer to the spike README for byte layouts) and the result.
- [x] `doc/decisions.md` -- D119 records the construction as validated (Amends D74), with its row and section; `doc/research-notes.md` gate text updated; `doc/README.md` decision range.

**Acceptance Criteria:**
- Given the spike crate, when `cargo test` runs on the dev host, then every I/O matrix test passes and no key bytes appear in any test output.
- Given the result, when the design documents are read, then the construction, labels and layouts are stated in `doc/key-management.md` and D119 exists, and the AD-36 gate is marked passed for the construction (the D61 HPKE review stays Story 1.2's).

## Implementation Notes

- 25 tests across one file per I/O matrix row, plus moved or copied tags, wraps and MACs, a relabelled HK version and a token issued for another member; a `readme_layouts.rs` test keeps the README byte layouts in step with the code.
- Build on the Windows dev host: the `.cargo/config.toml` env entry only applies when cargo runs from the spike directory, so `aws-lc-rs` uses its `prebuilt-nasm` feature instead (default features off: `aws-lc-sys`, `alloc`, `prebuilt-nasm`). The `.cargo/` directory is redundant and is left for the owner to delete (`rm` is denied in this workspace).
- `hpke` pinned to 0.13.0: 0.14.1 depends on a prerelease `aes-gcm` that cargo does not resolve.
- Zeroization is best effort without a direct `zeroize` dependency; HPKE private keys are zeroized by the `hpke` crate.
- Not covered by the spike, by design: the passphrase and DEK layer, the delay and veto, token expiry, alert delivery, inbox MACs (home milestone, D107), the Gateway limit of step 7.
- A pending enrollment wrap does not survive an HK rotation between `member add` and the next adult unlock (recorded in D119).
- Design documents: `doc/key-management.md` section 2 and section 12, D119, `doc/research-notes.md`, `doc/README.md`, spine Deferred item for AD-36 (republished from the authoring copy).

## Spec Change Log

## Review Triage Log

| # | Source | Finding | Verdict | Evidence | Route |
|---|---|---|---|---|---|
| 1 | verification-gap, blind | Encodings checked only by round-trip; drift test weaker than claimed | medium | No test pins `mac_input`, `versioned_context` or HKDF bytes; `readme_layouts.rs` checks labels, alg ids and lengths only | patch |
| 2 | verification-gap | `unlock`'s permanent-MAC check never the failing check | medium | Only tamper test edits key and MAC together, HPKE open fails first | patch |
| 3 | verification-gap, edge | `Inconsistent` alert branch and moved-tag-only case untested | medium | No test reaches `InconsistentRecord`; moved-tag test moves wrap too | patch |
| 4 | verification-gap | Store refusal rules untested | medium | No test builds a malformed store | patch |
| 5 | verification-gap, edge | Unknown-member token test does not assert store unchanged | low | Sibling tests assert it, this one does not | patch |
| 6 | blind | `hk_version` binding of the permanent MAC key never exercised | medium | Relabel test stops at the version equality check | patch |
| 7 | blind | Dead `Error` variants duplicating `Refusal` | low | Defined in `error.rs`, never constructed | patch |
| 8 | blind | HK rotation with a pending enrollment raises a false tampering alert | medium | Enrollment wrap carries no `hk_version`; failure maps to `EnrollmentKeyUnwrapFailed` | patch |
| 9 | blind | HK rotation must re-MAC every member; not stated in section 5 or D119 | medium | `verify_permanent_mac` refuses other HK versions | patch |
| 10 | blind, edge | Limits missing: no whole-store authentication (deletion, rollback), no adult/child role, alerts not persisted | medium | `store.rs` claims "any edit"; rollback can restore a vetoed member's valid record | patch (docs) + defer (design fix) |
| 11 | blind | Member identifier and token text encodings unspecified | medium | Member id bound everywhere, defined as raw bytes | patch (docs) |
| 12 | blind, edge | Wording: "every value" vs raw member id; `hk_version` "at the end"; notation | low | Read in section 2 | patch |
| 13 | edge | Crypto failure after tag verification reported as `InconsistentRecord` | low | Reachable only on CSPRNG or HKDF failure; spike-only | reject |
| 14 | edge | Stale `UnlockedAdult` handle or non-active adult in `member_add` | low | Single-process spike; the Core re-reads state per request | reject |
| 15 | edge | Race in `create_first_member`, concurrent load-save, no fsync, u16 overflow | low | Spike store is a stand-in; the Core uses SQLCipher (Epic 3) | reject |
| 16 | edge, blind | Sprint status says in-progress while spec says in-review | false | Sprint sync to `review` happens at the presentation step | reject |
| 17 | blind | Code Map cites research-notes section 4 instead of 3 | low | Fix edits the spec | reject |
| 18 | blind, edge | Rewritten story dropped AC3, timebox, fallback text, references | low | Fix edits the spec; the FR-8 gate stays in Intent and D107, D117 | reject |
| 19 | blind | D119 recorded as accepted before review ends | false | Review completes in this run before any commit | reject |
| 20 | blind | `.cargo/config.toml` redundant but staged | low | `rm` denied; owner deletes it before commit | reject (owner action) |
| 21 | blind | Encodings duplicated in key-management and README | low | key-management states rules, README holds bytes; known-answer tests pin the bytes | reject |

## Design Notes

Store layout: one record per member, fields length-prefixed (u16 big-endian) in a fixed order, each wrapper prefixed by `version u8, alg_id u8`. MAC input is the canonical concatenation `member_id || member_pk || inbox_pk` with each field length-prefixed, so field boundaries cannot shift. HK wrap uses HPKE `info = "vilicus/v1/hk/wrap/" || member_id || hk_version` and `aad` = the permanent MAC tag, binding the wrap to the authenticated key.

## Verification

**Commands:**
- `cargo test --manifest-path spikes/ad36-key-prototype/Cargo.toml` -- expected: all tests pass
- `cargo clippy --manifest-path spikes/ad36-key-prototype/Cargo.toml --all-targets -- -D warnings` -- expected: clean
- `cargo fmt --manifest-path spikes/ad36-key-prototype/Cargo.toml --check` -- expected: clean
