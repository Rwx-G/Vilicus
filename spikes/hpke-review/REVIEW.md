---
title: 'Internal security review of the hpke crate 0.13.0'
author: Rwx-G
story: doc/stories/story-1.2-hpke-internal-review-and-cross-test.md
date: 2026-10-16
---

# Internal security review of the `hpke` crate 0.13.0

Author: Rwx-G. Prepared with model assistance as AD-18 requires (Claude Opus 5.5, 2026-10-16). This is an internal review under the D61 exception to D28. It is not an audit, and the crate is not audited: its own README says it "has not been formally audited". Nothing in this file or elsewhere may call it audited.

## 1. What was reviewed

| Item | Value |
|---|---|
| Crate | `hpke` 0.13.0, crates.io, released 2025-02-19 (crate changelog) |
| Upstream commit | `a27764ae2ec3526f402d9500e14682637e57c95c` (github.com/rozbb/rust-hpke, from the package's `.cargo_vcs_info.json`) |
| Package checksum | `f65d16b699dd1a1fa2d851c970b0c971b388eeeb40f744252b8de48860980c8f` (`Cargo.lock`) |
| Features | `default-features = false`, `x25519`, `alloc` |
| Suite | Base mode, DHKEM(X25519, HKDF-SHA256) 0x0020, HKDF-SHA256 0x0001, AES-256-GCM 0x0002 (AD-18) |
| Source read | Every file of `src/` in the published package (about 4 300 lines, test modules included) |

Vilicus's intended uses (key management section 2, spine AD-31 and AD-37): wrapping the household key (HK) to a member public key, with `info = "vilicus/v1/hk/wrap/" || member_id || hk_version` and the permanent MAC tag as additional data; sealing the instance key, the audit key, passphrase wrappers and file names to the backup public key, whose key pair is `DeriveKeyPair` over an Argon2id output; sealing inbox rows later (home milestone). All are single-shot, base mode.

### Scope

In scope, read line by line against RFC 9180: `setup_sender` and `setup_receiver` in base mode (`setup.rs`), `single_shot_seal`, `single_shot_open` and their in-place detached forms (`single_shot.rs`), DHKEM encapsulation and decapsulation (`kem/dhkem.rs`, `kem.rs`), the X25519 group, key derivation and serialization (`dhkex/x25519.rs`), `LabeledExtract`, `LabeledExpand` and `ExtractAndExpand` (`kdf.rs`), the key schedule (`setup.rs`), nonce computation and the sequence counter, the AEAD context and the exporter (`aead.rs`, `aead/aes_gcm.rs`), suite identifiers and helpers (`util.rs`), operation modes (`op_mode.rs`), error types and the zeroization of every secret value, error paths, constant-time concerns, and the dependency tree.

Out of scope: the P-256, P-384 and P-521 KEMs, ChaCha20-Poly1305, the export-only AEAD, PSK and Auth modes (compiled but not reachable from the AD-18 profile), and the internals of the primitive crates (`x25519-dalek`, `curve25519-dalek`, `aes-gcm`, `aes`, `ghash`, `polyval`, `hkdf`, `hmac`, `sha2`, `subtle`), which were checked only at the points listed in section 4.

## 2. Method

1. Line-by-line reading of the in-scope code against the RFC 9180 pseudocode (sections 4, 4.1, 5.1, 5.2, 5.3, 6.1, 7.1.2, 7.1.3, 7.1.4), recording every place where a secret is created, copied or dropped.
2. RFC 9180 test vectors for the suite, run through the public API only, against the crate and against the independent implementation (`tests/rfc9180_vectors.rs`; provenance in `vectors/SOURCE.txt`).
3. A two-way cross-test against `hpke-rs` 0.8.0, 10 000 cases from a recorded seed, run once with its RustCrypto provider (the story's choice) and once with its libcrux provider, including byte-for-byte comparison of sealed output under the same ephemeral seed (`tests/cross_test.rs`).
4. One test per behaviour this review relies on (`tests/error_paths.rs`, `tests/sender_substitution.rs`), so that each claim below is executable rather than prose.
5. Dependency tree with resolved features (`cargo tree -e normal,features`), `cargo audit` against the RustSec database, and the advisories of each primitive crate in the tree.

`bash spikes/hpke-review/run.sh` runs items 2 to 4, the resolved-feature check of F1 and the dependency listing in a Debian 13 container pinned by digest. `cargo audit` is not in it: it needs the network for its advisory database and is not in the image, so it was run on the host (section 6).

## 3. Conformance to RFC 9180

| RFC 9180 element | Code | Result |
|---|---|---|
| `LabeledExtract`, `LabeledExpand` with `"HPKE-v1"`, `suite_id`, `I2OSP(L, 2)` (section 4) | `kdf.rs` | Matches; `L` above 65 535 or 255 x Nh is an error, not a panic |
| KEM `suite_id = "KEM" || I2OSP(kem_id, 2)`, HPKE `suite_id = "HPKE" || kem_id || kdf_id || aead_id` | `util.rs` | Matches |
| `Encap`, `Decap`: `kem_context = enc || pkRm`, `ExtractAndExpand` (section 4.1) | `kem/dhkem.rs` | Matches |
| All-zero DH output refused (section 7.1.4) | `dhkex/x25519.rs` line 142, constant-time compare | Matches; the seven small-order u-coordinates, with bit 255 clear and with it set, are refused as `DecapError` on open and `EncapError` on seal (`small_order_encapsulated_keys_are_refused_by_both`, `sealing_to_a_small_order_public_key_is_refused`) |
| `KeySchedule` with mode 0, empty `psk` and `psk_id` (section 5.1) | `setup.rs`, `op_mode.rs` | Matches |
| `ComputeNonce`: `base_nonce` XOR `I2OSP(seq, Nn)` (section 5.2) | `aead.rs` `mix_nonce` | Matches; see F7 on the counter width |
| `Export` with label `"sec"` (section 5.3) | `aead.rs` | Matches |
| `DeriveKeyPair` for X25519 (section 7.1.3) | `dhkex/x25519.rs` | Matches; outputs equal the vector's `skRm`, `pkRm`, `skEm`, `pkEm` |
| `SerializePrivateKey` and `DeriveKeyPair` clamp (section 7.1.2) | `dhkex/x25519.rs` | Deviates, see F3 |

The vector test drives the whole published transcript: `enc`, the 257 ciphertexts of the sequence (sender and receiver), and the three exported values all match.

## 4. Findings

Severity: **High** breaks confidentiality or integrity of a Vilicus use; **Medium** weakens a property the design documents state; **Low** defense in depth; **Info** no security effect, recorded for the record. Dispositions are the reviewer's; the owner's approval of this file makes them final.

### F1. Medium. Private keys, DH outputs and AES-GCM key schedules are not zeroized on drop

`hpke` declares `x25519-dalek = { version = "2", default-features = false, features = ["static_secrets"] }` (`Cargo.toml.orig` line 51), which leaves out x25519-dalek's `zeroize` feature, so neither `StaticSecret` (the member, backup and ephemeral private keys) nor `SharedSecret` (the DH output) is wiped on drop, and `curve25519-dalek` is built without `zeroize` too. The crate's comments say the opposite ("The underlying type is zeroize-on-drop", `dhkex/x25519.rs` lines 17 and 36). Likewise `aes-gcm`, `aes`, `ghash` and `polyval` are built without their `zeroize` features, so the AES-256 round keys and the GHASH key of every HPKE context stay in freed memory. Key management section 10 states that derived keys are zeroized on drop.

Disposition: **partially closed** by usage rule U1. The features are switched on by Cargo feature unification, without adding a crate (`Cargo.toml` of this spike); `run.sh` check `zeroize-features` proves that the feature is resolved on for each crate it names, not that memory is wiped. With the features on, `StaticSecret`, `SharedSecret`, the AES round keys (the `aes` runtime-detection wrapper drops its active backend, `aes` 0.8.4 `src/autodetect.rs` lines 183 to 189) and the GHASH key copy in `aes-gcm` are wiped. Two copies stay, whatever the features, and are part of F2's accepted residue: on x86_64, `polyval` 0.6.2 selects its backend at run time and keeps it in a union of `ManuallyDrop` fields (`src/backend/autodetect.rs` lines 30 to 33) with no `Drop` implementation, so the CLMUL or software backend's own zeroizing `Drop` never runs and the GHASH key `H` is not wiped; and `curve25519-dalek` 4.1.3 `MontgomeryPoint::mul_clamped` (`src/montgomery.rs` lines 128 to 139) takes the private key bytes by value and builds a `Scalar` from the clamped copy, neither of which is wiped. Upstream enables `x25519-dalek` `zeroize` in 0.14 (F10).

### F2. Low. Secret intermediates are left in memory

Even with F1 closed, these copies are never wiped: the HKDF pseudorandom keys and HMAC states of `LabeledExtract` (the `eae_prk`, the key schedule `secret`, the exporter secret's HKDF context), because `hkdf` 0.12 and `hmac` 0.12 have no zeroization at all; the discarded PRK returned by `labeled_extract` (`kdf.rs` line 88, `setup.rs` line 100); the temporary `kex_res_eph.to_bytes()` holding the DH output (`kem/dhkem.rs` lines 175 and 337); the 32 random bytes that seed the ephemeral key (`kem.rs` line 52); the private key buffer of `DeriveKeyPair` (`dhkex/x25519.rs` line 163); the copies of a private key made by `PrivateKey::ct_eq` (two `to_bytes()` arrays, `dhkex/x25519.rs` line 25) and by every `Serializable::to_bytes()` call on a private key, which returns an unwiped `GenericArray`; the GHASH key held by `polyval`'s runtime-detection wrapper and the clamped scalar copy in `curve25519-dalek`'s `mul_clamped` (both in F1); and the plaintext `Vec` returned by `single_shot_open` and `AeadCtxR::open`.

Disposition: **accepted**. These are stack and heap residues inside the Core process, which holds HK and the member keys in clear while it uses them; reading them needs root on the host or a memory disclosure bug, the R1 class of key management section 10, and the Core already disables swap and core dumps for that reason. Usage rule U7 keeps Vilicus from adding private-key copies through comparisons, and usage rule U5 removes the one plaintext residue Vilicus controls: the household key and every wrapped key are opened with `single_shot_open_in_place_detached` into a buffer the Core owns, locks and zeroizes (`hpke_review::open_into`). The residual is stated in the proposed update to key management section 10.

### F3. Low. Private keys are not clamped on serialization, and equal keys can compare unequal

RFC 9180 section 7.1.2 says `SerializePrivateKey` MUST clamp its output and `DeserializePrivateKey` MUST clamp its input. `hpke` stores and returns the raw 32 bytes and clamps only inside the scalar multiplication. `PrivateKey`'s constant-time equality compares the raw bytes, with a comment that `StaticSecret` "is only ever constructed from a clamped scalar" (`dhkex/x25519.rs` line 24), which is false for x25519-dalek 2. Two keys that differ only in the clamped bits behave identically but compare unequal (`private_keys_are_not_clamped_on_serialization`).

Disposition: **accepted**. No interoperability or security effect: both implementations clamp at use, the published vectors carry unclamped `skRm` and pass, and half of the cross-test cases use raw unclamped private keys across implementations. Usage rule U7: Vilicus never compares private keys; it stores them as `to_bytes` returns them and reads them back with `from_bytes` of the same suite. A report upstream is optional.

### F4. Low. The scope of the D61 exception is wider than the `hpke` crate

AD-18 and D28 say AES-GCM and HKDF come from aws-lc-rs and that primitives come from audited libraries. `hpke` does not use aws-lc-rs: it brings its own primitive crates, `x25519-dalek` 2.0.1 and `curve25519-dalek` 4.1.3, `aes-gcm` 0.10.3, `aes` 0.8.4, `ghash` 0.5.1, `polyval` 0.6.2, `hkdf` 0.12.4, `hmac` 0.12.1, `sha2` 0.10.9 and `subtle` 2.6.1 (the authoritative list is `cargo tree -e normal` on this crate). Per their READMEs, `aes-gcm`, `aes`, `ghash` and `polyval` each received one security audit by NCC Group; `x25519-dalek`, `curve25519-dalek`, `hkdf`, `hmac`, `sha2` and `subtle` carry no audit statement in their READMEs, and this review did not establish one. So the household key wrap rests on primitives outside aws-lc-rs, partly without a stated audit.

Disposition: **accepted**, as the exception D61 already makes in substance, but it must be written: the proposed update to D61 and AD-18 states that the exception covers `hpke` and the primitive crates it depends on, and that `cargo deny` and `cargo vet` (D28) treat them as Core dependencies.

### F5. Info. Error variants distinguish decapsulation from decryption failure

`single_shot_open` returns `DecapError` only when the DH output is all zero, which depends on the public `enc` alone, and `OpenError` for every tag failure. Neither leaks a secret, and the AEAD verifies the tag before decrypting: `aes-gcm` 0.10.3 includes the fix of RUSTSEC-2023-0096, so a failed open leaves the ciphertext untouched in the buffer (`failed_open_leaves_the_ciphertext_in_the_buffer`).

Disposition: **closed** by usage rule U6: every HPKE error is one refusal to the caller and to the audit log.

### F6. Info. No input reaches a panic

Every length taken from outside (`enc`, keys, tags, ciphertexts shorter than a tag, exporter lengths) is checked and returned as an error; the `expect` and `assert` calls left in the code guard sizes fixed at compile time (`malformed_lengths_are_refused_without_panic`, cross-test random lengths from 0 to 1 500 bytes).

Disposition: **closed**.

### F7. Info. The sequence counter is 64 bits wide

RFC 9180 allows `2^96 - 1` messages per context; the crate stops at `2^64 - 1` and then refuses with `MessageLimitReached`. This is stricter than the RFC and never reached by single-shot use (sequence number 0 only).

Disposition: **closed**, no effect.

### F8. Info. Randomness cannot fail visibly

The crate takes a `rand_core` 0.9 `CryptoRng + RngCore`, whose `fill_bytes` cannot return an error; it draws exactly 32 bytes per seal (the ephemeral seed, checked by every cross-test case) and nothing else.

A repeated ephemeral seed is the dangerous case, not a failed one: if the generator returns the same 32 bytes twice (a virtual machine restored from a snapshot, a cloned host), two seals to the same recipient with the same `info` derive the same AEAD key and nonce, and AES-GCM under a repeated nonce leaks the XOR of the plaintexts and allows forgeries.

Disposition: **closed** by usage rule U3, the generator passed in is an adapter over the operating system generator (AWS-LC's system generator, as the key prototype does) that aborts on failure, never a seeded or user-space generator; and by usage rule U3b, the `info` of every seal binds a value unique to that seal, so a repeated seed still yields another key schedule.

### F9. Info. `DeriveKeyPair` takes any input length

RFC 9180 section 7.1.3 says `ikm` SHOULD be at least Nsk bytes with Nsk bytes of entropy; the crate accepts any length, an empty one included (`derive_keypair_accepts_any_ikm_length_and_the_profile_takes_32_bytes`). The profile's `derive_backup_keypair` takes `&[u8; 32]`, and the profile does not re-export the `Kem` trait.

Disposition: **closed** by usage rule U4: the backup key pair is derived from a 32-byte Argon2id output. Its entropy is bounded by the backup secret, at least 128 bits (D106), which is the security level of the suite.

### F10. Info. Version 0.14.1 now resolves and fixes part of F1

The key prototype's `Cargo.toml` comment says hpke 0.14 needs a prerelease `aes-gcm` that cargo does not resolve. On 2026-10-16, `hpke = "=0.14.1"` with features `x25519`, `alloc` and `aes` builds against `aes-gcm` 0.11.1, now released. Its manifest enables x25519-dalek `zeroize` (F1); the AES stack's zeroization in 0.14 was not checked. Moving to 0.14 changes the code reviewed here, and it would make `hpke` share the primitive versions of `hpke-rs-rust-crypto` 0.8 (`aes-gcm` 0.11, `x25519-dalek` 3, `hkdf` 0.13, `sha2` 0.11), which narrows the independence of the cross-test (F11).

Disposition: **accepted**: V0.1 stays on 0.13.0 with U1; a move to 0.14 is a new review and cross-test, best taken with the external review D61 requires before V1. The key prototype's comment is corrected in the proposed updates.

### F11. Info. Limits of the cross-test's independence

`hpke-rs` is a separate code base (the HPKE layer is written independently: its own labeled KDF, key schedule, nonce and KEM code), but its RustCrypto provider uses the same primitive projects as `hpke`, in other major versions. The shared lineage is sharpest on the X25519 path: both sides compute X25519 with dalek (`x25519-dalek` 2.0.1 over `curve25519-dalek` 4.1.3 in `hpke`, `x25519-dalek` 3 over `curve25519-dalek` 5 in the RustCrypto provider), and AES-GCM, HKDF and SHA-256 with RustCrypto. A defect common to both lineages could pass that cross-test; the RFC vectors bound the risk only for the one published key pair and message sequence.

Disposition: **closed**. `hpke-rs-libcrux` 0.8.0 builds cleanly as a dev-dependency (pure Rust, no build script, no C toolchain), so the cross-test and the vector test also run against the libcrux provider, whose X25519 (`libcrux-curve25519`, HACL*-derived), AES-GCM, HKDF and SHA-256 share no code with dalek or RustCrypto. The RustCrypto run stays, as the story's decision task chose it. What remains shared is the HPKE layer of `hpke-rs` between the two runs, which is independent of `hpke`.

### F12. Medium. Base mode authenticates no sender: a substituted wrap opens

This is a property of HPKE base mode (RFC 9180 section 5.1.1), not a defect of the crate, but it bears on every Vilicus use. Anyone who holds a member public key, which `wrappers.db` stores in clear, can seal a household key of their choice (HK') to it with the published `info` and the stored MAC tag as additional data, and the member's open succeeds (`a_substituted_wrap_opens_but_the_permanent_mac_refuses_it`). A disk writer without HK can therefore make a member adopt HK', write household data under it, and read that data later. The same holds for a backup: a writer who controls the archive can seal keys of their choice to the backup public key.

Confirming the opened key against the permanent MAC (verify the stored `pubkey_mac` under a key derived from the opened HK) refuses a writer who leaves the MAC untouched. It does not refuse a writer who chose HK': that writer can compute the permanent MAC under HK' and write it too, and the MAC then verifies (`a_writer_who_also_rewrites_the_mac_passes_the_mac_but_not_the_member_commitment`). Only an anchor the writer cannot compute refuses that case: the test models a commitment to HK under a key derived from the member's own DEK, written when the member first receives HK, which refuses HK'. The first receipt itself has no such anchor in the current design; it is a trust-on-first-unwrap point.

Disposition: **accepted with usage rule U10** and a design question. U10 requires a confirmation of every key opened from HPKE before use; the proposed design update adds the member commitment to key management section 2 and records the first receipt as an open question. A backup is confirmed by its manifest, whose sequence number and hash the remote sink holds (AD-31), before any unwrapped key is used.

### F13. Low. A non-canonical recipient public key seals but never opens

`PublicKey::from_bytes` accepts any 32 bytes. X25519 masks bit 255 and reduces modulo p, so a key with bit 255 set, or with a value from p to 2^255 - 1, gives the same DH output as its canonical form; but `kem_context` binds the key's bytes as given, and the recipient binds the canonical bytes it computes from its private key. The seal succeeds and can never be opened (`non_canonical_recipient_keys_seal_but_never_open_and_the_profile_refuses_them`). For the household key wrap this is a silent loss of access, not a confidentiality issue.

Disposition: **closed** in the profile: `seal` refuses a recipient key that is not canonically encoded (`ValidationError`), and usage rule U8 already requires recipient keys to be authenticated before use.

No High finding. No finding requires an upstream fix within the timebox, so the D107 fallback is not triggered.

## 5. Constant-time behaviour

In `hpke` itself, the only branches on secret-derived data are on public outcomes: the all-zero DH check uses `subtle`'s constant-time comparison and then branches on its public result, and the AEAD branches on tag validity. Private key equality is constant time, but copies the keys (F2). Below it, this review relies on the primitive crates' own statements and was not verified by measurement: X25519 is the Montgomery ladder of `curve25519-dalek` 4.1.3, which includes the fix of RUSTSEC-2024-0344 (timing variability in scalar subtraction); `aes` 0.8.4 uses AES-NI when the CPU has it, selected at run time, else a bitsliced constant-time software implementation; `polyval` uses CLMUL or a constant-time software multiplication; the tag comparison of `aes-gcm` uses `subtle`. HKDF, HMAC and SHA-256 have no data-dependent branches. No `Debug` implementation exists for `PrivateKey` or the contexts, so they cannot be logged by accident.

## 6. Dependency tree

Normal dependencies of `hpke` 0.13.0 as resolved here (`cargo tree -e normal`): `aead` 0.5.2, `aes-gcm` 0.10.3, `aes` 0.8.4, `cipher` 0.4.4, `ctr` 0.9.2, `ghash` 0.5.1, `polyval` 0.6.2, `universal-hash` 0.5.1, `chacha20poly1305` 0.10.1, `chacha20` 0.9.1, `poly1305` 0.8.0, `digest` 0.10.7, `hkdf` 0.12.4, `hmac` 0.12.1, `sha2` 0.10.9, `x25519-dalek` 2.0.1, `curve25519-dalek` 4.1.3, `subtle` 2.6.1, `zeroize` 1.9.1, `generic-array` 0.14.7, `rand_core` 0.9.5 and 0.6.4, `getrandom` 0.2.17, `cpufeatures` 0.2.17. This list is a snapshot for this review; `Cargo.lock` is authoritative. `chacha20poly1305` and its parts are compiled but unreachable from the profile; `getrandom` 0.2 comes from `aes-gcm`'s default features and is not called by `hpke`.

`cargo audit` (RustSec database of 2026-10-16, 1 329 advisories): no vulnerability in the tree. One warning, RUSTSEC-2026-0173 (`proc-macro-error2` unmaintained), comes from the lock entries of the dev-only `hpke-rs` chain and does not reach `hpke`. Past advisories of crates in the tree are all patched in the resolved versions: RUSTSEC-2023-0096 (`aes-gcm` >= 0.10.3), RUSTSEC-2024-0344 (`curve25519-dalek` >= 4.1.3), RUSTSEC-2020-0146 (`generic-array`), RUSTSEC-2021-0023 (`rand_core`), RUSTSEC-2021-0100 (`sha2`). No advisory has ever been filed against `hpke`. Audit statements of the primitive crates are in F4. The crate's README reports a security review of version 0.8 by Cloudflare; that review covered another version and is not an audit of 0.13.0.

## 7. Usage rules Vilicus must follow

These rules are the conditions under which the findings above are closed or accepted. The Core's key code follows them; `src/lib.rs` of this spike is the reference shape.

- **U1.** The Core's manifest enables the `zeroize` features of `x25519-dalek`, `aes`, `aes-gcm`, `ghash` and `polyval`, and a CI check verifies the resolved features (F1). `hpke` stays pinned with `=` to the reviewed version; any version change reopens this review.
- **U2.** Only the AD-18 profile: base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, through one Core module that fixes the suite and the mode in its types. No PSK, Auth, other KEM, other AEAD or exporter use without a review of that path.
- **U3.** Single-shot only, one seal per stored value, with a fresh ephemeral key per seal; the generator is an adapter over the operating system generator that aborts on failure (F8).
- **U3b.** The `info` of every seal binds a value unique to that seal, such as the wrapper identifier or the backup sequence number, so that a repeated ephemeral seed (a restored snapshot) cannot repeat an AEAD key and nonce (F8).
- **U4.** `DeriveKeyPair` is called only with at least 32 bytes of input keying material (F9).
- **U5.** Wrapped keys, the household key above all, are opened in place into a Core-owned, locked buffer that is zeroized after use and on failure; the `Vec`-returning `single_shot_open` is not used for keys (F2).
- **U6.** Every HPKE error maps to one refusal; the variant is neither shown to a client nor used to branch (F5).
- **U7.** Private keys are never compared, and are serialized and deserialized only by this crate's `to_bytes` and `from_bytes` (F3, F2). The Core's private key type implements no equality; this spike's `PrivateKey` is the crate's type alias and does not enforce the rule by itself.
- **U8.** Recipient public keys are accepted only after their authentication: the member public key after its MAC under HK (AD-36), the backup public key from `core.db`, inbox public keys after their MAC (key management section 2, step 6). HPKE itself authenticates no recipient. The profile also refuses a non-canonical recipient key (F13).
- **U9.** `info` and the additional data bind the context as key management section 2 fixes them (member, HK version, MAC tag); `every_binding_input_is_checked_on_open` checks that each of them is bound.
- **U10.** A key opened from HPKE is used only after it is confirmed against a value the party that wrote the wrap could not have produced (F12). For the household key: the permanent MAC verified under the opened HK, which refuses a substituted wrap that leaves the MAC in place, and a commitment to HK under a key derived from the member's DEK, which refuses a writer who also rewrote the MAC (proposed design update). For a backup: the manifest verified against the sequence number and hash held by the remote sink (AD-31) before any unwrapped key is used. `tests/sender_substitution.rs` models the household case.

## 8. Cross-test and vectors, results

On 2026-10-16, on the Windows development host and in `rust:1.94-trixie@sha256:652612f07bfbbdfa3af34761c1e435094c00dde4a98036132fca28c7bb2b165c` (Debian 13.4, rustc 1.94.1):

- RFC 9180 vectors: the base-mode vector of the suite passes for `hpke` and for `hpke-rs` with each provider (key derivation, `enc`, 257 sealed and opened messages, 3 exports).
- Cross-test, seed `0x56494c4943555331`, once per `hpke-rs` provider (RustCrypto, libcrux): 10 000 cases each; `hpke` to `hpke-rs` 10 000 opened, `hpke-rs` to `hpke` 10 000 opened, 10 000 byte-identical seals under the same ephemeral seed, 20 000 exports agreed, 20 000 tampered values refused by both.
- Error paths: 11 tests pass. Sender substitution: 3 tests pass.

Not run here: the CI job the story asks for, because the repository has no CI yet (spine AD-33). `run.sh` is the job's body.

## 9. Second-pass review, 2026-10-16

A second review raised twelve points; each was checked against the crate sources before any change.

- Upheld, changed: the `polyval` runtime-detection wrapper and `mul_clamped` copies (F1 now partially closed, F2 extended, `run.sh` comment); base mode sender substitution (F12, U10, `tests/sender_substitution.rs`); non-canonical recipient keys (F13, `seal` refuses them, tests, small-order points with bit 255 set added); repeated ephemeral seeds (F8, U3b); oversized output buffer and wrong-aad buffer state (tests added; the code already refused them); the reference shape (`open_into` returns a unit `Refused`, `derive_backup_keypair` takes 32 bytes, `Kem` is no longer re-exported); `run.sh` claims and image pinning (section 2, digest); the X25519 lineage (F11, libcrux provider adopted); `ct_eq` and `to_bytes` copies (F2); the vector source wording (`vectors/SOURCE.txt`).
- Upheld in part: U10 as first worded, confirming HK by its permanent MAC under the opened HK, refuses only a writer who leaves the MAC in place; a writer who chose HK' can recompute that MAC, which `a_writer_who_also_rewrites_the_mac_passes_the_mac_but_not_the_member_commitment` shows. U10 therefore also requires an anchor the writer cannot compute, and F12 records the first receipt of HK as an open design question.
- Not changed: U7 is not enforced by a newtype in this spike, whose `PrivateKey` stays the crate's alias so the tests can exercise the crate directly; U7 states that the Core's own type implements no equality.
