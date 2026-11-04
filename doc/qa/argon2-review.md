---
title: 'Internal security review of argon2 0.6.0 and blake2 0.11.0'
author: Rwx-G
story: doc/stories/story-4.4-passphrase-kek-argon2id-gate-and-strength-check.md
date: 2026-11-04
---

# Internal security review of `argon2` 0.6.0 and `blake2` 0.11.0

Author: Rwx-G. Prepared with model assistance as D129 requires (Claude Opus 5.5, 2026-11-04). This is the internal review of the D129 exception to D28, required before the passphrase-wrapping code of Story 4.4 (AC8). It is not an audit, and neither crate is audited: the reviewer knows of no published third-party audit of either, did not search beyond the packages, and neither README makes an audit statement. Nothing in this file or elsewhere may call them audited. Dispositions are the reviewer's; those marked **accepted** take effect with the owner's acknowledgement.

## 1. What was reviewed

| Item | `argon2` | `blake2` |
|---|---|---|
| Version | 0.6.0, crates.io, released 2026-08-27 (crate changelog) | 0.11.0, crates.io, released 2026-08-26 (crate changelog) |
| Upstream commit | `b1e0ad6fe229b1ba74e4696c7359ab45d7e931f0` (github.com/RustCrypto/password-hashes, path `argon2`, from `.cargo_vcs_info.json`) | `fa3084083d946ac12436567d5a59c0935d5db1fa` (github.com/RustCrypto/hashes, path `blake2`, from `.cargo_vcs_info.json`) |
| Package checksum | `134c52ddac6d63c576bef8168db10c83c49c26444ecbc68060fef078925a901c` | `5b5d4d889834ee8ecfc0f8426ad30faf7cdcb10f741a8e6d7224d95325479f6f` |
| Checksum source | `spikes/argon2id-params/Cargo.lock`, equal to the SHA-256 of the cached `.crate` file; the workspace lockfile has no `argon2` yet | same |
| Features reviewed | `default-features = false`, `zeroize` (the shape of usage rule U1); `alloc`, `parallel`, `password-hash`, `kdf` read for what they add | no features (as `argon2` declares it, `default-features = false`) |
| Source read | Every file of `src/` (2 195 lines) and `tests/` (1 052 lines), plus `Cargo.toml`, `Cargo.toml.orig`, `CHANGELOG.md`, `README.md` | Every file of `src/` (824 lines), `tests/` and `benches/` (149 lines), plus `Cargo.toml`, `CHANGELOG.md`, `README.md` |

Of the crates `argon2` and `blake2` bring, only the code they reach was read: `digest` 0.11.3 (`buffer_ct_variable!`, `block_api`, the `mac` and `zeroize` features), `block-buffer` 0.12.1 (`BlockBuffer`, `LazyBuffer`, its `Drop`), and `cpufeatures` 0.3.1 (`x86.rs`, `miri.rs`). `crypto-common` 0.2.2, `hybrid-array` 0.4.15, `typenum`, `base64ct` 1.8.3 and `zeroize` 1.9.1 were checked only at their call sites. `password-hash` 0.6.1 and `phc` 0.6.1 are not in the Vilicus build (U1) and were not reviewed.

Vilicus's uses of Argon2id in V0.1, each through the one limiter of D128:

- the passphrase KEK of a member DEK wrapper (Story 4.4; D128: Argon2id v0x13, t = 3, p = 4, m = 384 MiB provisional, 16-byte random salt, 32-byte output, passphrase normalised to NFC and encoded as UTF-8; floor and ceiling checked before the limiter);
- the recovery KEK (Story 4.5 AC6: Argon2id over the recovery secret, after its checksum);
- the backup secret stretch, whose 32-byte output feeds HPKE `DeriveKeyPair` (Story 4.8 AC2 and AC5; `spikes/hpke-review/REVIEW.md` U4);
- the admin recovery code, stored only as an Argon2id hash and checked at `vilicus admin recover` (D101, Stories 8.4 and 8.5);
- the key stretching function of `opaque-ke` implemented over this crate (D123), which the OPAQUE client runs; the Core runs it only where it plays the client, such as the D123 cross-test.

### Scope

In scope, read line by line against RFC 9106 and RFC 7693: H0, H', the initial blocks, data-independent and data-dependent indexing, the reference set and its mapping, the compression function G with BlaMka, version 0x13 against 0x10, the final XOR and tag; parameter validation and every arithmetic step on parameters; every place a secret or secret-derived value is created, copied or dropped; the contract of `hash_password_into_with_memory`; every panic site; every `unsafe` block; the code compiled with `parallel` off and with it on; BLAKE2b and the variable-output core `argon2` calls; the crates' history and advisories.

Out of scope: BLAKE2s (compiled, never called by `argon2`), `Blake2bMac` (compiled, never called by `argon2`), the PHC string API and its crates (`password-hash`, `phc`), the `kdf` traits, the `reset` and `size_opt` features of `blake2`, and the browser build of OPAQUE (D123 owns it).

## 2. Method

1. Line-by-line reading of the in-scope code against RFC 9106 sections 3.1 to 3.6 and RFC 7693 sections 2 and 3, recording each secret copy and each early return.
2. A scratch crate, outside the repository and not committed, built with the features of U1 against the spike's lockfile, run in `rust:1.99-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a` (Debian 13, rustc 1.99.1) on tmpfs, on the development host (x86_64 with AVX2):
   - the three RFC 9106 section 5 vectors and the eight Argon2id v0x13 cases of the reference implementation's `src/test.c`, all through `hash_password_into_with_memory`;
   - the buffer contract (section 4, F1) and each hostile-parameter case of F5, under `catch_unwind`;
   - 75 derivations over p in {1, 2, 3, 4, 8}, m from 8p to 4 096 KiB and t in {1, 2, 3}, plus one at the version 1 cost, compared between the serial build and a build with `parallel`;
   - an oracle in Python (`hashlib`, which carries the BLAKE2 reference C code) that recomputes, from RFC 9106 and not from the crate, H0 and the first two blocks of every lane, and the tag from the last blocks, for 8 shapes with tag lengths 4, 32, 64, 65, 100, 1 024 and 1 025 bytes, with and without secret and associated data; and 200 BLAKE2b digests (nine output lengths from 1 to 64 bytes, inputs of 0 to 1 100 bytes split across two updates);
   - the provenance of the vectors: the RFC tags were matched against the RFC 9106 text (SHA-256 `855c06f060379e34285e83a217e9069b5c72e161a1e54df9af5cd88dbb231f31`) and the reference cases against `src/test.c` of phc-winner-argon2 `master` (SHA-256 `ec518844e823fb6a1bd38f79f2b5d1bbddf23f490c0a343c450aa8e3f5af5988`), both fetched on 2026-11-04;
   - Miri (nightly 1.101.0 of 2026-11-03), under Stacked Borrows and Tree Borrows, on the RFC Argon2id vector and a p = 2 case.
3. Advisories from the local RustSec database (commit `965bf9ad083b58e6340d65829d85217b18be9290`, 2026-11-03), searched by crate name for every crate of the resolved tree. `cargo audit` was not run: no Vilicus lockfile holds `argon2` yet.

## 3. Conformance

| Element | Code | Result |
|---|---|---|
| H0 = H^64(LE32(p), LE32(T), LE32(m), LE32(t), LE32(v), LE32(y), then each of P, S, K, X preceded by its LE32 length) (RFC 9106 s3.2) | `src/lib.rs` lines 592 to 615 | Matches; m is the requested m, not m'; oracle 8 of 8 |
| B[i][0] = H'^1024(H0 \|\| LE32(0) \|\| LE32(i)), B[i][1] likewise with 1 (s3.2) | `src/lib.rs` lines 370 to 387 | Matches; oracle 8 of 8 |
| H' for T up to 64 (BLAKE2b with digest length T) and above (r = ceil(T/32) - 2 blocks of 32 bytes, then H^(T-32r)) (s3.3) | `src/blake2b_long.rs` lines 14 to 74 | Matches; oracle tags at T in {4, 32, 64, 65, 100, 1 024, 1 025} |
| m' = 4p x floor(m / 4p), lane length q = m' / p, segment q / 4 (s3.2) | `src/params.rs` lines 245 to 261 | Matches |
| Argon2id: data-independent addressing in pass 0, slices 0 and 1 only (s3.4.1.3) | `src/lib.rs` lines 395 to 398 | Matches |
| Address blocks G(0, G(0, Z \|\| LE64(i))), Z = r, l, sl, m', t, y, counter i from 1 (s3.4.1.2) | `src/lib.rs` lines 400 to 429, 443 to 454, 579 to 588 | Matches; regenerated every 128 blocks |
| J1 from the address block or from the previous block's first word; reference lane J2 mod p, own lane in pass 0 slice 0 (s3.4.1, s3.4.2) | `src/lib.rs` lines 443 to 465 | Matches |
| Reference set W (own lane: all finished blocks but the previous; other lane: the last three finished segments, minus its last block at a segment start), x = J1^2 / 2^32, y = \|W\| x / 2^32, zz = \|W\| - 1 - y, start position (s3.4.2) | `src/lib.rs` lines 467 to 503 | Matches; no underflow, since m >= 8p makes every segment at least 2 blocks |
| G: R = X xor Y, P on rows then columns, Z xor R; GB with a + b + 2 trunc(a) trunc(b), rotations 32, 24, 16, 63 (s3.5, s3.6) | `src/block.rs` lines 16 to 46, 80 to 114 | Matches; checked by the 11 vectors |
| Version 0x13: passes after the first XOR the new block into the old; 0x10 overwrites (s3.2 step 6) | `src/lib.rs` lines 511 to 515 | Matches |
| C = XOR of each lane's last block, Tag = H'^T(C) (s3.2 steps 7 and 8) | `src/lib.rs` lines 550 to 568 | Matches; oracle 8 of 8 |
| Input bounds (s3.1) | `src/params.rs` lines 123 to 171, `src/lib.rs` lines 315 to 323, 617 to 632 | Matches; salt at least 8 bytes and associated data at most 32 bytes are the crate's own limits, inside the RFC's |
| BLAKE2b IV, SIGMA, 12 rounds, rotations 32, 24, 16, 63 (RFC 7693 s2.1, s2.6, s2.7) | `blake2` `src/consts.rs`, `src/lib.rs` lines 40 to 54, `src/macros.rs` lines 163 to 176 | Matches |
| G, column then diagonal steps, counter and final flag, h xor v[0..8] xor v[8..16] (RFC 7693 s3.1, s3.2) | `blake2` `src/macros.rs` lines 106 to 180, 193 to 201, 219 to 227 | Matches; the counter is 64 bits, its high word fixed at 0 (inputs below 2^64 bytes) |
| Parameter block p[0] = 0x01010000 xor kk << 8 xor nn (RFC 7693 s3.3) | `blake2` `src/macros.rs` line 43 | Matches; salt and personalisation are empty on every `argon2` path |
| Last block always processed with the final flag, even when full | `block-buffer` `LazyBuffer`, `blake2` `src/macros.rs` lines 189 to 191, 219 to 227 | Matches; oracle 200 of 200, inputs on and across 128-byte boundaries |

## 4. Findings

Severity: **High** breaks the confidentiality or integrity of a Vilicus use; **Medium** weakens a property the design documents state; **Low** defense in depth; **Info** no security effect, recorded for the record.

### F1. Medium. The working memory is equivalent to the KEK, and the crate leaves it in the caller's buffer

`hash_password_into_with_memory` (`src/lib.rs` lines 307 to 329) returns with every block of the caller's buffer holding the final state, and never wipes it. That state is worth the KEK itself: the XOR of each lane's last block, hashed once with H', is the output (lines 550 to 568; `buffer_after_derivation_yields_the_kek` recomputes the RFC vector's tag from the buffer alone), and the first two blocks of every lane are H'(H0 ...) (lines 370 to 387), from which the whole derivation follows without the passphrase. A copy of the buffer therefore skips the Argon2id cost entirely: no guessing is needed. The documents state that this memory is wiped and that, being unlocked at E12 sizes, it needs swap disabled or encrypted (D131), but not that a swapped page of it gives the KEK.

The rest of the contract holds, checked by the run: the crate writes only `[..block_count]` and nothing past it (`no_write_beyond_block_count`), writes every block below it before reading it, so prior content and reuse change nothing (`prior_buffer_content_does_not_matter`, `reused_buffer_same_output`), and on every error it returns before touching the buffer or the output (F5).

Disposition: **partially closed** by U2 (the Core wipes every block on success, error and unwind, before freeing). The residue while a derivation runs, unlocked pages that the kernel may swap, is **accepted** under D131's condition (swap disabled or encrypted). Recommended to the owner: state in key management section 10 that the Argon2id buffer is KEK-equivalent, and have the Core warn at start when swap is active and unencrypted, which costs one check. Locking the buffer (up to 1 GiB of `LimitMEMLOCK` under the limiter) would close the residue at a memory cost D131 chose not to pay.

### F2. Medium. `hash_password_into` frees its blocks without wiping them

With `alloc`, `hash_password_into` (`src/lib.rs` lines 284 to 289) allocates a `Blocks` buffer whose `Drop` only deallocates (`src/block.rs` lines 190 to 201), whatever the `zeroize` feature; the freed heap holds the KEK-equivalent state of F1. The `kdf` traits (lines 635 to 644) and the PHC hasher (line 699) call it too. This confirms the "Memory wipe" finding of Story 1.8.

Disposition: **closed** by U1: built without `alloc`, the crate does not compile `hash_password_into` at all (line 284), so the compiler, not review, keeps every call site on `hash_password_into_with_memory`.

### F3. Low. Secret copies on the stack that the `zeroize` feature does not reach

The `zeroize` feature wipes only the variable holding H0 (`src/lib.rs` lines 389 and 390) and the final XOR block and its bytes (lines 570 to 574). It does not enable `blake2`'s own `zeroize` (`Cargo.toml` line 64, `zeroize = ["dep:zeroize"]`; the run's resolved features show `blake2` with none), and even that would not reach most copies. Left on the deriving thread's stack: the passphrase bytes in the BLAKE2b buffer of `initial_hash` and in the message words of each BLAKE2b compression (`blake2` `src/macros.rs` lines 142 to 146); copies of H0 in the hasher buffers of the 2p calls of `blake2b_long` for the first blocks (`src/lib.rs` lines 377 to 384); the 1 KiB `hash` array of each first block (line 383); the 2 KiB of temporaries of each G call (`src/block.rs` lines 81 to 113) and the returned `Block` (line 506); the 64-byte `full_out` of `blake2b_long`, which holds the 32-byte KEK and 32 further bytes of the final BLAKE2b state (`src/blake2b_long.rs` lines 31 to 34); the padded final block of each BLAKE2b (`block-buffer` `pad_with_zeros`, lines 226 to 232). On a `MemoryTooLittle` error H0 is computed (line 326) and dropped unwiped, because `fill_blocks` returns before line 390 (lines 360 to 362). None of these is on the heap: built as U1 says, the crate allocates nothing. Story 1.10 observed this class without the Core rules (a last-block copy and two KEK copies on the stack after drop) and nothing with them.

Disposition: **closed** by U3, the derivation runs whole inside one guarded call of D154, whose scrub reaches below the deepest frame (Story 1.10 measured 10 776 bytes for a passphrase unlock, under the 56 KiB bound). Naming `blake2` in Vilicus's manifest to enable its `zeroize` is not recommended: it adds little next to the scrub, and a direct dependency breaks the `brings_primitives` path rule of `ci/primitive_sources.toml` (D153).

### F4. Low. Data-dependent memory access after the first half of the first pass

Argon2id indexes the memory from the previous block's content from pass 0, slice 2 onward (`src/lib.rs` lines 395 to 398, 455 to 465): the access pattern, and the branch on `ref_lane == lane` (line 472), depend on the passphrase. This is the design of Argon2id (RFC 9106 s3.4.1.3), not a defect. For Vilicus: an attacker who shares the CPU caches with the Core during an unlock (a plugin or AI process on the same host, or a co-tenant VM) and records the access trace by cache timing can, once it also holds the wrapper's salt, reject a passphrase candidate after computing about half of the first pass instead of t passes, roughly a 2t = 6 fold saving at t = 3. It does not reveal the passphrase, and the salt sits in `wrappers.db`, which an attacker reaching it can already attack offline at full cost. The total derivation time does not depend on the passphrase's content. BlaMka's 32 x 32 multiplications and BLAKE2b's additions, XORs and rotations run in constant time on x86_64 (read, not measured).

Disposition: **accepted**. The FR-110 strength threshold is the margin against it; Argon2i would remove it at the cost of the trade-off attacks RFC 9106 recommends Argon2id against.

### F5. Info. Hostile parameters return errors, never a panic or a write outside the buffer

`Params::new` (`src/params.rs` lines 123 to 171) refuses m below 8 or below 8p, t of 0, p of 0 or above 2^24 - 1, and an output below 4 bytes, checking p before computing 8p, which cannot overflow (8 x (2^24 - 1) < 2^32). `hash_password_into_with_memory` refuses a salt below 8 bytes, an output length other than the configured one, and a buffer shorter than `block_count()`, before any write (14 cases under `catch_unwind`: `params_refuse_*`, and `refused_untouched_*`, which also check the buffer and the output untouched). The remaining panic sites guard invariants no parameter reaches: the segment-view asserts (`src/memory.rs` lines 133, 134, 149 to 151), `expect` on fixed lengths (`src/block.rs` line 67, `src/blake2b_long.rs` line 66), `LazyBuffer::new` on 4 and 64 bytes, and `blake2`'s parameter asserts on empty salt and personalisation (`src/macros.rs` lines 33 to 39). The crate accepts its own maxima, m = t = 2^32 - 1 and p = 2^24 - 1 (`params_accept_crate_maxima`), so a header can only be refused for its cost by Vilicus, and the buffer's length is the last bound (`refused_untouched_crate_maxima_small_buffer`).

Disposition: **closed** by U4.

### F6. Info. The crate takes the other variants and version 0x10

`Algorithm` has Argon2d and Argon2i (`src/algorithm.rs` lines 26 to 49) and `Version::try_from` accepts 0x10 (`src/version.rs` lines 34 to 44), which overwrites instead of XORing (section 3). A header mapped through the crate's types would accept them.

Disposition: **closed** by U5.

### F7. Info. m is in KiB, H0 binds it as given, and the memory used is rounded down

H0 binds the requested m (`src/lib.rs` line 596) while the blocks used are 4p x floor(m / 4p) (`block_count_floors_to_4p`: m = 1 000, p = 3 uses 996). This is RFC 9106 behaviour, but a buffer sized from m, or a unit mistake between the MiB of D128 and the KiB of the header (D153), would either refuse or overspend.

Disposition: **closed** by U4: costs are KiB everywhere below `vilicus-types`' named constants, and the buffer length comes from `Params::block_count()`.

### F8. Info. `blake2`'s own tests do not cover the variable output length `argon2` uses

`argon2` calls `Blake2bVarCore::new(T)` directly for every H' of 64 bytes or less, the 32-byte KEK included (`src/blake2b_long.rs` lines 24 to 37). In `blake2` 0.11.0 the `Blake2bVar` type was removed (changelog, #744), and `tests/data/blake2b_variable_kat.blb` still ships but no test reads it; the unkeyed BLAKE2b tests cover the 64-byte digest and one 16-byte personalised digest only. `VariableOutputCore::new` also accepts an output size of 0 (`src/macros.rs` lines 211 to 216), which `argon2` never passes (`src/blake2b_long.rs` lines 15 to 17).

Disposition: **closed**: the oracle agreed on 180 variable-length and 20 full-length digests, and the Argon2id vectors of U8 exercise the 32-byte path end to end in CI.

### F9. Info. Unsafe code and the AVX2 path

`argon2` has `unsafe` in three places. `src/memory.rs` (lines 44, 60, 103, 106, 122, 140, 156): raw-pointer segment views over the block slice, used with `parallel` off as well as on; each access asserts that the index is in bounds and either in the view's lane or in another slice (lines 133 and 134), and a write asserts it is inside the view's segment (lines 149 to 151), which RFC 9106 s3.4 guarantees for a correct index computation. `src/lib.rs` lines 529 to 538: `compress_avx2`, the portable `Block::compress` compiled under `#[target_feature(enable = "avx2")]`, called only after `cpufeatures` detects AVX2 through CPUID and the XCR0 YMM state bits (`cpufeatures` `src/x86.rs` lines 60 to 94, 126). `src/block.rs` lines 177 to 199: the `Blocks` allocator, compiled only with `alloc` (F2). `blake2` has one `unsafe` block, `as_bytes` on a `#[repr(C)]` struct of four equal words (`src/simd.rs` lines 113 to 116), sound and without a `SAFETY` comment; despite the file name, `blake2` 0.11.0 has no SIMD intrinsics (changelog, #898). Miri found no undefined behaviour in the serial build under either borrow model; Miri turns target features off (`cpufeatures` `src/miri.rs`), so it ran the portable path, and the native runs, on an AVX2 CPU, ran the AVX2 path.

Disposition: **closed**.

### F10. Info. The `parallel` feature's history, and what compiles without it

0.5.0 removed a `parallel` feature found unsound (changelog, #380, #247), and 0.6.0 restored one (#547) on the segment views of F9. With `parallel` off, `for_each_segment` (`src/memory.rs` lines 34 to 48) visits the lanes of each slice in order on the calling thread, one view at a time, and `rayon` is not compiled (`cargo tree`: no `rayon` without the feature, present with it). Segments of one slice never reference each other, so lane order does not change the result: the 75 derivations and the one at the version 1 cost gave identical KEKs in both builds (`lanes_serial_equals_parallel`), as D128 relies on ("lanes enter the hash and threads do not").

Disposition: **closed** by U1 (`parallel` forbidden).

### F11. Info. The spike's lockfile resolves `ctutils` 0.4.3, which RUSTSEC-2026-0385 affects

`blake2` enables `digest`'s `mac` feature unconditionally (`blake2` `Cargo.toml` lines 73 to 75), which brings `ctutils` (`digest` `Cargo.toml` line 51). `spikes/argon2id-params/Cargo.lock` resolves `ctutils` 0.4.3, below the patched 0.4.4 of RUSTSEC-2026-0385 (non-constant-time masks). `argon2` never calls the MAC comparison that uses it (`digest` `src/mac.rs` line 6), so the defect is not reached, but `cargo audit` fails on such a lockfile. `cmov` 0.5.4 is past RUSTSEC-2026-0003 (patched from 0.4.4).

Disposition: **closed** by U9.

### F12. Info. The backup secret's salt is not fixed

The crate requires a salt of at least 8 bytes (`src/lib.rs` lines 176, 623 to 625). Story 4.8 requires the same secret to give the same key pair, and a restore runs from the backup alone, but no document fixes the salt of that stretch.

Disposition: **closed** by U7, which leaves the choice to Story 4.8 with its constraints and a recommendation.

### F13. Info. No verifier for the admin recovery code is compiled

Without `password-hash`, the crate offers no `verify_password`; the "Argon2id hash" of the admin recovery code (D101) is a derivation the Core compares itself, and a comparison with `==` on slices is not constant time.

Disposition: **closed** by U7.

### F14. Info. The AVX2 path uses vector registers, and wider builds would use more

`compress_avx2` runs G on YMM registers, which the key-operation guard zeroes (D131, D154); a release build with `-C target-cpu=native` or AVX-512 target features could place secret blocks in zmm16 to zmm31, which D154 leaves outside its claim. The workspace sets no such flag today (no `.cargo/config.toml`, none in `Cargo.toml`).

Disposition: **closed** by U3.

### F15. Info. Young releases without an audit, and their advisories

`argon2` 0.6.0 (2026-08-27) and `blake2` 0.11.0 (2026-08-26) are about ten weeks old and carry large changes (the `digest` 0.11 migration, the restored `parallel`, `blake2`'s newtypes and removed SIMD). No RustSec advisory has ever been filed against `argon2`; the one against `blake2`, RUSTSEC-2019-0019 (HMAC block size), is fixed from 0.8.1 and concerns HMAC, which `argon2` does not use; none exists for `digest`, `block-buffer`, `crypto-common`, `hybrid-array`, `typenum`, `cpufeatures`, `base64ct` or `zeroize`.

Disposition: **accepted**, as D129 already accepts it: the vectors, the cross-test and the oracle of U8, and the external review before V1. Any version change reopens this review (U1).

No High finding. No finding needs an upstream fix.

## 5. Dependency tree

Normal dependencies of the build of U1, as resolved here (`cargo tree -e normal`): `argon2` 0.6.0, `base64ct` 1.8.3, `blake2` 0.11.0, `digest` 0.11.3, `block-buffer` 0.12.1, `crypto-common` 0.2.2, `hybrid-array` 0.4.15, `typenum` 1.20.1, `ctutils` 0.4.3 (F11), `cmov` 0.5.4, `cpufeatures` 0.3.1 (x86 only) and `zeroize` 1.9.1. `password-hash`, `phc` and `rayon` are absent. The checksums match `spikes/argon2id-params/Cargo.lock`. This list is a snapshot; the workspace lockfile becomes authoritative once `argon2` enters it.

## 6. Usage rules Vilicus must follow

These rules are the conditions under which the findings are closed or accepted. They bind every Argon2id call site of `vilicus-crypto`, the OPAQUE key stretching function of D123 included.

- **U1.** `vilicus-crypto` alone declares `argon2 = { version = "=0.6.0", default-features = false, features = ["zeroize"] }`, and no crate names `blake2`. The resolved features of `argon2` are exactly `zeroize`: `ci/primitive_sources.toml` adds `alloc`, `password-hash`, `kdf`, `getrandom` and `rand_core` to the `forbidden_features` it holds for `parallel` (F2, F10). Any version change of `argon2` or `blake2` reopens this review.
- **U2.** Derivations call `hash_password_into_with_memory` only, into a `[Block]` buffer the Core owns inside `vilicus-crypto`, of exactly `Params::block_count()` blocks, held by a type whose `Drop` wipes every block with `Zeroize` before freeing, so success, error and unwind all wipe; the buffer is never formatted, logged or copied, and Story 4.4's test checks it is all zeros afterwards (F1).
- **U3.** Each derivation runs whole inside one guarded call of D154 on its blocking-pool thread: non-inlined, the stack scrubbed below the deepest frame and the AVX registers zeroed, on success and on error; the KEK is written into a pool slot, never a heap buffer. Since the crate has no step at which the pool could be checked, the derivation takes D154's one-second bound. Release builds set no `target-cpu` or AVX-512 target feature. The `key_memory` regression test of D154 includes an Argon2id group with planted passphrase, H0 and KEK patterns (F3, F14).
- **U4.** `Params` are built only from the named constants of `vilicus-types` or from a header that passed D128's floor and ceiling before the limiter, as `Params::new(m_kib, t, p, Some(32))`, with every cost in KiB; every crate error is one refusal, never a panic or a retry (F5, F7).
- **U5.** The context is `Argon2::new(Algorithm::Argon2id, Version::V0x13, params)`, never `Argon2::default()`, `From<Params>`, `new_with_secret`, associated data or a key id. A header's Argon2 version field is checked against 0x13 by Vilicus (D153), never mapped through `Version::try_from` (F6).
- **U6.** The passphrase is normalised to NFC, encoded as UTF-8 into a buffer of its own that is wiped after use (D154), and refused above a maximum length the story fixes, before the limiter. Every salt of a wrapper is 16 bytes from the operating system generator; the output is 32 bytes.
- **U7.** The backup secret's salt is fixed by Story 4.8, at least 16 bytes and available at a restore from the backup alone; recommended, a constant label such as `vilicus/v1/backup-secret`, which a secret of at least 128 random bits does not need to vary, and which gives up only a per-instance salt (F12). The admin recovery code's stored value is a versioned record with its cost and salt, compared with the derived output in constant time (aws-lc-rs), never with `==` (F13).
- **U8.** Story 4.4's CI runs, through `hash_password_into_with_memory` with the features of U1: the three RFC 9106 vectors and the eight Argon2id v0x13 cases of the reference `test.c`; the buffer checks of F1 (no write past `block_count`, prior content irrelevant, all zeros after the wipe); the hostile-parameter cases of F5. The cross-test against phc-winner-argon2 and the OpenSSL 3.5 `EVP_KDF-ARGON2` oracle of D129 cover, beyond p in {1, 2, 4, 8}: p = 3, m not a multiple of 4p, m at the floor, at the version 1 cost and at the ceiling of 1 GiB, t from 1 to 4, empty and long passphrases and lengths that cross BLAKE2b's 128-byte block in H0 (around 96 and 224 bytes), non-ASCII passphrases after NFC, salts from 8 to 64 bytes, and the backup secret and recovery secret lengths (F8).
- **U9.** The workspace lockfile resolves `ctutils` 0.4.4 or later, and `cargo audit`, `cargo deny` and `cargo vet` run clean with `argon2` in it (F11).

## 7. Results of the runs

On 2026-11-04, in the image of section 2: 35 checks of the serial build, the lane comparison, 6 oracle groups and 4 Miri checks, 46 PASS and 0 FAIL. Timing, for information only (development host, no CPU cap, not the reference host): one derivation at the version 1 cost took 746 ms in the serial build and 308 ms with `parallel`, allocation and wipe included.

The scratch crate is not committed; Story 4.4 turns these checks into the committed tests of U8, which replace it as evidence.

## 8. What was not checked

- No independent implementation of G or of the indexing ran here: they rest on the 11 vectors and on reading. The random cross-test against phc-winner-argon2 and the OpenSSL oracle are Story 4.4's (U8).
- No side-channel measurement; the constant-time statements of F4 come from reading.
- The stack residue of F3 was not measured on the U1 build; Story 1.10 measured an earlier shape built with `alloc`, and the `key_memory` test of U3 measures this one.
- Big-endian and 32-bit targets, and aarch64, were not run.
- Upstream history beyond the changelogs: issue #380 and pull requests #247 and #547 were not read, nor the git history between releases. No search for a published audit was made beyond the READMEs.
- `cargo audit` did not run (F11); advisories come from the local RustSec copy of section 2.
- `password-hash`, `phc`, BLAKE2s, `Blake2bMac` and the `reset` feature, out of scope (section 1).
- The OPAQUE browser build and its own Argon2id (D123), and performance on the reference host (E12).

## 9. References

- RFC 9106, Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications (sections 3, 4 and 5).
- RFC 7693, The BLAKE2 Cryptographic Hash and Message Authentication Code (sections 2 and 3).
- phc-winner-argon2, `src/test.c` (github.com/P-H-C/phc-winner-argon2).
- `doc/decisions.md`: D28, D61, D101, D123, D128, D129, D131, D153, D154.
- `doc/key-management.md` sections 2, 3, 4 and 10.
- `doc/stories/story-4.4-passphrase-kek-argon2id-gate-and-strength-check.md` (AC7, AC8), `story-4.5-recovery-secret-format-and-recovery-kek.md` (AC6), `story-4.8-backup-key-pair-from-the-backup-secret.md` (AC2, AC5), `story-8.4-instance-admin-passkey-destination-and-backup-secret.md`, `story-8.5-admin-recovery-code-redemption.md`.
- `doc/stories/story-1.8-e12-argon2id-parameters-on-the-reference-host.md` ("Memory wipe") and `spikes/argon2id-params/`.
- `doc/stories/story-1.10-e16-locked-memory-and-zeroization.md` (Results, AC1 and stack depth).
- `spikes/hpke-review/REVIEW.md`, the review of the D61 exception this one follows.
- `ci/primitive_sources.toml`.
- RustSec advisories RUSTSEC-2019-0019, RUSTSEC-2026-0003, RUSTSEC-2026-0385.
