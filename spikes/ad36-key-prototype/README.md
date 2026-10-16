---
title: 'Key prototype: AD-36 public-key authentication'
author: Rwx-G
story: doc/stories/story-1.1-key-prototype-ad36-public-key-authentication.md
---

# Key prototype: AD-36 public-key authentication

Author: Rwx-G. Standalone spike crate; it never joins the Vilicus workspace.

## Question

Spine AD-36 and `doc/key-management.md` section 2 (D74) say that a member public key in `wrappers.db` receives the household key (HK) only after a MAC under a key that an attacker who can write the disk, but does not hold HK, cannot produce (threat T23). The section left the exact encodings to this prototype. Does the construction, built with the AD-18 primitives and nothing else, refuse a substituted public key while a correctly enrolled one receives the HK wrap?

## Construction as built

Primitives: HKDF-SHA-256, HMAC-SHA-256 and AES-256-GCM with a random 96-bit nonce from `aws-lc-rs`; HPKE base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM from `hpke` 0.13.0. HPKE draws randomness from the AWS-LC system generator through an `hpke::rand_core` adapter. MACs are verified with `aws_lc_rs::hmac::verify` and the token check with `aws_lc_rs::constant_time`, both constant time.

Every HKDF call uses no salt (RFC 5869 zero salt) and 32 bytes of output. `||` is plain concatenation; `hk_version` is a `u32` big-endian. In each `info` below, the label comes first, the member identifier is the only variable-length part and, where present, `hk_version` is fixed width at the end; no label is a prefix of another, so no two contexts collide.

The member identifier bound into every `info`, MAC input and HPKE `info` is, in the product, the Core's opaque 16-byte UUIDv7 member identifier in binary, never a display name, so it is stable across a rename. The spike accepts any 1 to 255 raw bytes so its tests can use readable names. The token is 16 random bytes here; its printed text encoding is fixed by the enrollment story, not by this prototype.

| Step (key-management section 2) | Computation |
|---|---|
| 2. `member add` | `token` = 128 random bits. `check = HKDF(token, "vilicus/v1/enroll-token-check/" \|\| member_id)`. `enroll_key = HKDF(token, "vilicus/v1/enroll-auth/" \|\| member_id)`. `enroll_wrap = AES-256-GCM(HKDF(HK, "vilicus/v1/hk/enroll-wrap/" \|\| member_id \|\| hk_version), nonce, aad = format_version \|\| alg_id \|\| hk_version \|\| member_id, enroll_key)`. Stored: `check`, `enroll_wrap` with its `hk_version`. |
| 3. Enrollment | The presented token's `check` is compared in constant time; on mismatch, or when no check is stored (token already used), enrollment is refused and nothing is written. The Core generates the member and personal inbox X25519 key pairs. `enroll_tag = HMAC(enroll_key, mac_input)`. Stored: both public keys and `enroll_tag`; `check` is erased, so the token is single use. |
| 4. Next adult unlock | If `enroll_wrap` names another `hk_version` than the unlocking adult's HK, the member is reported as stale (`StaleHouseholdKeyVersion`), not as tampering, gets no wrap, and is added again. Otherwise `enroll_key` = open `enroll_wrap` under HK; failure is refusal `EnrollmentKeyUnwrapFailed`. `enroll_tag` verified over `mac_input` of the stored keys; failure is refusal `EnrollmentTagMismatch`. Only then: `pubkey_mac = HMAC(HKDF(HK, "vilicus/v1/pubkey-mac/" \|\| member_id \|\| hk_version), mac_input)` and the HK wrap. `enroll_wrap` and `enroll_tag` are erased. A refusal records an alert and wraps nothing. |
| 5. First member | HK, both key pairs, `pubkey_mac` and the HK wrap are written in one step; no token. |
| Every later HK wrap | `pubkey_mac` is verified under the unlocking adult's HK, and its `hk_version` must equal that HK's version, before any HPKE seal. |

`mac_input = len16(member_id) || member_id || len16(member_pk_field) || member_pk_field || len16(inbox_pk_field) || inbox_pk_field`, where `len16` is a `u16` big-endian length and each public key enters in its stored encoding (format version and algorithm identifier included), so neither field boundaries nor algorithm identifiers can shift under the MAC. The enrollment tag and the permanent MAC use the same input.

HK wrap: HPKE single-shot seal of the 32-byte HK to the member public key with `info = "vilicus/v1/hk/wrap/" || member_id || hk_version` and `aad = pubkey_mac` tag. The wrap therefore opens only next to the authenticated MAC it was made with. At unlock the member opens it, then checks their own `pubkey_mac` under the recovered HK.

## Byte layouts

`wrappers.db` (prototype store, flat file): `"VLCW" || format_version u8 || record_count u16 BE || records`. Trailing bytes, duplicate member identifiers, unknown format versions and unknown algorithm identifiers are refused, never repaired.

A record is the fields below in this order, each as `len u16 BE || bytes`; length 0 means absent. Every stored value starts with `format_version u8 || alg_id u8`; format version 1 is the only one accepted.

| Field | Encoded length (bytes) | Layout after `format_version \|\| alg_id` |
|---|---|---|
| `MemberId` | variable, 1 to 255 | raw identifier, no header |
| `TokenCheck` | 34 | check hash (32) |
| `EnrollKeyWrap` | 66 | hk_version u32 BE (4) \|\| nonce (12) \|\| ciphertext (32) \|\| GCM tag (16) |
| `MemberPublicKey` | 34 | X25519 public key (32) |
| `InboxPublicKey` | 34 | X25519 public key (32) |
| `EnrollTag` | 34 | HMAC tag (32) |
| `PubkeyMac` | 38 | hk_version u32 BE (4) \|\| HMAC tag (32) |
| `HkWrap` | 86 | hk_version u32 BE (4) \|\| HPKE encapsulated key (32) \|\| ciphertext (32) \|\| GCM tag (16) |

Algorithm identifiers (`alg_id`):

| `alg_id` | Meaning |
|---|---|
| `0x01` | Token check hash, HKDF-SHA-256 |
| `0x02` | Key wrap, AES-256-GCM with a random 96-bit nonce, key from HKDF-SHA-256 |
| `0x03` | MAC, HMAC-SHA-256, key from HKDF-SHA-256 |
| `0x04` | Public key of DHKEM(X25519, HKDF-SHA256) |
| `0x05` | HPKE base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM |

The record's state follows from which fields are present: awaiting enrollment (`TokenCheck`, `EnrollKeyWrap`), awaiting HK (`EnrollKeyWrap`, both public keys, `EnrollTag`), active (both public keys, `PubkeyMac`, `HkWrap`). Any other combination is inconsistent and raises an alert at the next adult unlock.

`tests/readme_layouts.rs` checks that every label, every algorithm identifier and every fixed field length in the code appears in this file; it does not check the rest of the prose. The known-answer tests in `src/known_answers.rs` pin the byte composition itself: the MAC input, the versioned contexts, one HKDF output per derivation label and the store encoding, against values computed outside the crate.

## How to run

From the repository root:

```sh
cargo test --manifest-path spikes/ad36-key-prototype/Cargo.toml
cargo clippy --manifest-path spikes/ad36-key-prototype/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path spikes/ad36-key-prototype/Cargo.toml --check
```

The `prebuilt-nasm` feature of `aws-lc-rs` lets it build on the Windows dev host without NASM.

The tests model the attacker as raw byte edits of `wrappers.db` by a process that writes the disk without HK, using a key pair from a household the attacker controls. One test file per row of the story's I/O matrix: `first_member`, `further_adult`, `substituted_public_key`, `tampered_enrollment`, `tampered_permanent_mac`, `token_refusal`; `store_refusals` covers the store parsing rules.

## Result

The construction holds on every row of the matrix. A member or inbox public key substituted before the adult unlock is refused with `EnrollmentTagMismatch`, an alert is recorded at each adult unlock and HK is not wrapped. An edited tag is refused the same way; an edited wrapped enrollment key, or one moved from another member's record, is refused with `EnrollmentKeyUnwrapFailed`. A public key and permanent MAC edited after the first wrap, a MAC copied from another member, and a MAC relabelled to another HK version are all refused before any re-wrap; an edited inbox public key of an active member makes that member's own unlock refuse. A record in no ceremony state raises an `InconsistentRecord` alert. An enrollment wrapped under another HK version is reported as stale, without a tampering alert. A wrong token, a token issued for another member and a reused token are refused with nothing written. An honest enrollment receives the HK wrap and its member unlocks with the same HK as the other adults.

## Limits and what this spike does not cover

- The passphrase, the DEK and the wrapping of private keys by the DEK are out of scope; `MemberSecrets` stands for what a member's unlock recovers.
- The delay and veto before step 4 and the 15-minute token expiry are product behaviour, not part of the construction.
- Alerts are returned in `UnlockReport`, not persisted; recording them in the audit log and delivering them to every adult belong to the Core.
- Nothing authenticates `wrappers.db` as a whole. Deleting a record raises no alert, and restoring an older `wrappers.db` (rollback) can bring back a valid record of a member since vetoed or suspended. A disk writer can also relabel a pending wrap's `hk_version` so that a tampered enrollment is reported as stale rather than as tampering; the member still gets no wrap.
- The spike has no adult or child role: every member it wraps HK to is treated as an adult.
- Step 6, inbox public key authentication under the DEK and the instance key, ships with the home milestone and is not a V0.1 gate (D107). The personal inbox public key is still covered by the enrollment tag and the permanent MAC.
- Step 7, a compromised Gateway that also writes `wrappers.db`, is a process-separation property, not something a test of this crate can show.
- Secrets are overwritten on drop with `fill(0)` and `black_box`, which is best effort; the product uses `zeroize` and locked memory (key-management section 10). The HPKE private keys are zeroized by the `hpke` crate.
- HK rotation is not implemented (PRD FR-9, after V0.1). It must verify every permanent MAC under HK n and rewrite it under HK n+1 before any wrap under n+1, since the MAC key binds the HK version; pending enrollments made under n are then reported as stale and added again.
- The D61 internal review and cross-test of the `hpke` crate are Story 1.2; this spike uses the crate, it does not review it.
