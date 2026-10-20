---
title: 'Wire framing and canonical encoding in vilicus-proto'
epic: 2
story: 5
status: done
author: Rwx-G
created: 2026-10-16
implements: [AD-12, AD-13, D19, E19, D130]
---

# Story 2.5: Wire framing and canonical encoding in vilicus-proto

As a project maintainer,
I want one framing layer and one canonical encoding for every internal socket and every hashed or signed value,
So that no adapter invents its own codec and every signer hashes exactly the bytes the Core hashed.

**Acceptance Criteria:**

**AC1 (AD-12, D19)**
**Given** a socket kind declared as control or data
**When** a frame is read
**Then** it is a 4-byte big-endian length followed by one CBOR message, and a length above the declared maximum (1 MiB for control, 16 MiB for data, spine assumption) is refused before any byte of the message is decoded
**And** a message nested deeper than the profile bound (32 arrays, maps or tags, D130) is refused before recursive decoding, since a 1 MiB control frame can hold a million levels and `dcbor` recurses without a bound (Story 1.9, finding 2).

**AC2 (AD-12)**
**Given** a new connection
**When** the first frame arrives
**Then** it must be `Hello` carrying protocol, supported versions, unit and build, answered with the chosen version or a refusal
**And** every request carries a `request_id`, writing requests a `call_id`, and `Cancel` (by `request_id`) and `Ping` are defined.

**AC3 (AD-12)**
**Given** a message with a field not declared in its closed type
**When** it is decoded
**Then** it is rejected, never ignored or repaired, through one closed-type check implemented once in `vilicus-proto`.

**AC4 (AD-13, D130)**
**Given** a value of a hashed or signed type
**When** it is encoded for hashing
**Then** it is encoded as dCBOR restricted by the D130 profile and hashed with SHA-256: no floating-point value, no indefinite-length item, no tag (the listed tag set is empty), integers within [-2^63, 2^64 - 1], simple values false, true and null only, at most 32 nested arrays, maps or tags, and text in NFC under the Core's pinned Unicode version
**And** hashed and signed types respect these limits, enforced by a test over every such type.

**AC5 (AD-13, E19, D130)**
**Given** a non-canonical encoding of a valid value
**When** the decoder receives it
**Then** it is rejected
**And** the shared E19 test vectors run in CI against the Rust encoder and decoder, on `dcbor` 0.25.2 behind the profile layer of `spikes/canonical-cbor/src/profile.rs` (a head walk without recursion before decoding, trailing bytes refused, the value check, the round-trip comparison, NFC text and unique keys on encode), with the vectors of `spikes/canonical-cbor/vectors/` and their generator (`gen_vectors`) moved into the test data of `vilicus-proto`, and the `unicode_version` header of the vectors checked against the pinned `unicode-normalization`; E19 took no fallback (D130).

**AC6 (D130, E19)**
**Given** the three `dcbor` 0.25.2 defects E19 found (gate E19-1)
**When** the profile layer's tests run
**Then** the integral float `fb43e0000000000001`, which raw `dcbor` decodes to the integer 2^63 + 2048, is refused; 10 000 nested arrays are refused without a stack overflow; a map built with the keys `caf\u{e9}` and `cafe\u{301}` is refused on construction instead of collapsing to one entry; and non-NFC text is refused on encode, never normalized
**And** closed types are mapped to and from `dcbor` values by hand in `vilicus-proto`, through the same profile layer.

**AC7 (D130)**
**Given** the Core's normalization tables
**When** the workspace builds
**Then** `unicode-normalization` is pinned exactly (`=0.1.25`, Unicode 17.0.0), because the Unicode version is part of the canonical form
**And** a stored hash is only ever checked against the stored canonical bytes it was computed from, never against a re-encoding of the stored value (test); a change of the Unicode version needs its own decision record, a new protocol version (AD-12) and regenerated vectors stating the new `unicode_version`.

**AC8 (D130, D28)**
**Given** `dcbor` in the Core's dependency tree
**When** `cargo audit` and `cargo deny` run (Story 2.2)
**Then** `deny.toml` lists RUSTSEC-2024-0436 (`paste`, unmaintained, a build-time proc-macro of `dcbor`, no known vulnerability) as an advisory exception with that reason and a review date of 2027-04-16, when `dcbor` is checked for a release without `paste` or the exception is renewed (Story 1.9, proposed update 8; gate E19-2).

**Dependencies:**
- Story 1.9 (dcbor and its profile layer, vectors in `spikes/canonical-cbor/vectors/`; settled by D130)
- Story 2.2 (`deny.toml` and the supply-chain gates)
- Story 2.4 (shared types)

**References:**
- `doc/architecture-spine.md` AD-12, AD-13, Stack (dcbor, unicode-normalization)
- `doc/decisions.md` D19, D130
- `doc/research-notes.md` E19
- `doc/stories/story-1.9-e19-canonical-cbor-in-rust-and-typescript.md` (Implementation Notes, Findings 1 to 7)
- `doc/qa/gates/1.9-e19-canonical-cbor-in-rust-and-typescript.yml` (E19-1, E19-2)

## Implementation Notes

**What was built**
- `crates/vilicus-proto/src/`:
  - `profile.rs`: the D130 profile over `dcbor` 0.25.2, moved from `spikes/canonical-cbor/src/profile.rs` with the same behaviour and the same rejection messages, which the vector files carry. `decode` runs the head walk without recursion (`scan_heads`: nesting bound `MAX_DEPTH`, the empty `LISTED_TAGS`, any float, trailing bytes), then `dcbor`, then `check_value` (no float, no unlisted tag, integers not below -2^63, NFC text, the depth bound), then `require_round_trip`. `decode_with_max_items` also counts every data item in the head walk (the top-level item, each array element, each map key and each map value) and refuses more than the caller's bound as `TooManyItems` before `dcbor` builds anything; the profile itself bounds nesting, not size, so `decode` passes no bound. `encode` runs `check_value` first, so non-NFC text is refused instead of normalized. `insert_unique` refuses a map key equal to an earlier one once canonicalized. The constants `INT_MIN`, `INT_MAX` and `UNICODE_VERSION` (from the exactly pinned `unicode-normalization`) are public, and the vector header is derived from them. The spike's `hash` was left out: this crate never hashes (AD-3).
  - `wire.rs`: the closed-type check, implemented once. The trait `Wire` (`to_cbor`, `from_cbor`) is implemented by hand for every type; `encode` and `decode` put the profile in front of it. `Fields` is the only reader of a record: a map whose keys must all be text (an integer field index or a byte string is `KeyNotText`), each field taken once by name, and `finish` refuses any field left over (`UnknownField`); a missing one is `MissingField`. `closed_name` reads a closed set by its name as text only, so an integer variant index is refused. `variant` reads a choice: a name alone, or a map of exactly one entry from the name to the payload; `no_payload` refuses a payload on a variant that has none. Duplicate and unsorted keys and trailing bytes are refused earlier by the profile. `bool`, `u16`, `u64`, `i64`, `String` and `Vec<T>` map to their CBOR kinds.
  - `vocabulary.rs`: the `vilicus-types` vocabulary on the wire. `Id` is its 16-byte stored form as a byte string, checked by `Id::from_bytes` (UUIDv7 only); `UtcMillis` its milliseconds as an integer, checked by `from_millis`; the closed sets (`Taint`, `Tier`, `Principal`, `DataType`, `ExceptionClass`, `RetryClass`, `OperatorSetting`) their names, through `ALL` and `as_str`; `ErrorCode`, `MessageKey` and `ModuleName` their text, checked by `parse`; `ClientError` a closed record; `Source` the shape `vilicus-types` gives it in serde (`"system"`, or `{"member": <id>}`).
  - `frame.rs`: `SocketKind` with, per kind, a maximum length (`Control` 1 MiB, `Data` 16 MiB, the spine's `[ASSUMPTION]`) and a maximum number of data items (`Control` 65 536, `Data` 262 144, this story's `[ASSUMPTION]`, see Decisions). `read_frame` reads the 4-byte big-endian length and refuses one above the maximum from the prefix alone; the message buffer then grows with the bytes received (`take(len).read_to_end`), never reserved from the declared length, and a stream that ends early is `UnexpectedEof`. `read_message` decodes under the kind's item bound, through the profile with its head walk, then the closed type. `write_frame` and `write_message` refuse a message above the maximum. Blocking `std::io`, since no async runtime is in the tree yet.
  - `message.rs`: the handshake has one wire form: the first frame is a bare `Hello` (protocol, versions, unit, build; `versions` non-empty and strictly increasing, so one set has one encoding), answered by a bare `HelloReply` (`accepted` with a version, or `refused` with a `HelloRefusal`: `not_hello`, `unknown_protocol`, `no_common_version`). `negotiate` chooses the highest version both sides support; `first_frame(message, kind)` decodes the first frame under the kind's item bound as a bare `Hello`, or refuses it as `not_hello`. After the handshake, `Message<B, R>` holds `request`, `response`, `cancel` (by `request_id`), `ping` and `pong`, and neither handshake message: a `Hello` cannot arrive later, nor wrapped. `Request<B>` carries `request_id` and a `call_id` present exactly when the body writes, through the trait `RequestBody::writes`; the constructors `read` and `write` refuse the wrong combination, and so does decoding. `Response<R>` carries `request_id` and a result, `ok` or a `ClientError`.
  - `canonical.rs`: `CanonicalBytes`, the bytes that are hashed or signed. Its only constructor from a value, `encode`, runs the profile; `from_stored` wraps stored bytes without decoding them; `matches_hash` hashes the stored bytes with the function the caller passes (SHA-256 of `vilicus-crypto` in the Core), never a re-encoding.
- Test data: the five files of `spikes/canonical-cbor/vectors/` copied byte for byte into `crates/vilicus-proto/tests/data/canonical-cbor/` (`SHA256SUMS` verifies), marked `-text` in `.gitattributes`. The spike's generator modules (`corpus`, `fuzz`, `notation`, `rng`, the generation in `mod.rs`, and a small `hex` helper replacing the `hex` crate) are in `tests/vectors/`, shared by the replay `tests/canonical_vectors.rs` and the generator `examples/gen_vectors.rs` (through `#[path]`, inside the package). They were ported by a script that rewrote only the imports and the hash function; the generator rewrites the five committed files byte for byte.
- Dependencies (`[workspace.dependencies]`, used by `vilicus-proto` only): `dcbor =0.25.2` (no default features, `std`) and `unicode-normalization =0.1.25`; dev-dependencies `serde_json =1.0.154` and `aws-lc-rs =1.18.2` with only its `aws-lc-sys` feature. 1.18.2 is the version a fresh lockfile of `rustls =0.23.46` resolves to (its requirement is `^1.18`), with `aws-lc-sys` 0.46.0. `Cargo.lock` grows from 25 to 83 packages; `vendor/` gains 58 crates (107 MB in all, `aws-lc-sys` alone 68 MB). On Linux, the shipped `vilicus` binary's tree gains `dcbor`, `chrono`, `half`, `hex`, `iana-time-zone`, `num-traits`, `paste`, `syn` 2, `thiserror`, `tinyvec`, `unicode-normalization` and `zerocopy`; `aws-lc-rs` and `serde_json` are absent from it (`cargo tree -p vilicus -e normal,build`).
- Gate entries:
  - `deny.toml`: `BSD-2-Clause-Patent` allowed (owner decision, with the OSI and ASF sources); `[advisories] ignore` holds RUSTSEC-2024-0436 with its reason and the review date 2027-04-16; `[bans] skip` holds `syn@2.0.119`, "forced by zerocopy-derive@0.8.63", with the Windows-only paths named in the reason.
  - `ci/audit-exceptions.toml` (new): RUSTSEC-2024-0436 with the same reason and date. The `audit` job now runs `cargo audit --json` and judges the report with `ci/check_audit_report.py` against this file, as the `hpke-review` job does for its spike; `WorkflowAgreementTest` pins the two new command lines in place of `cargo audit --deny warnings`. The spike audit is unchanged.
  - `ci/build_time_code.toml`: 20 entries, each with a reason written after reading the package's build script: `paste`, `thiserror`, `thiserror-impl`, `zerocopy`, `zerocopy-derive`, `crunchy`, `num-traits`, `libc`, `getrandom`, `iana-time-zone-haiku`, `windows-implement`, `windows-interface`, `wasm-bindgen`, `wasm-bindgen-macro`, `wasm-bindgen-shared`, `rustversion`, `serde_json`, `zmij`, `aws-lc-rs`, `aws-lc-sys`.
  - `supply-chain/`: `imports.lock` gains the imported audits that cover part of the tree (13 crates fully audited, 4 partially); `config.toml` gains 46 exemptions, generated by `cargo vet regenerate exemptions`. Each has a note saying it was not reviewed here, why the crate is in the tree, and the audit `cargo vet` proposes. There is no `[[trusted]]` entry. 44 exemptions pin the locked version. `cargo vet` exempted `futures-task` and `futures-util` at 0.3.21, the base from which imported delta audits reach the locked 0.3.34, and their notes say so. Estimated audit backlog before the exemptions: 2 578 393 lines, of which `aws-lc-sys` 0.46.0 accounts for 2 089 732, `libc` 135 905, `chrono` 34 862, `aws-lc-rs` 34 023 and `dcbor` 20 494.

**Decisions and why**
- *Ids as bytes, times as integers.* An `Id` crosses the wire as its 16 stored bytes and a time as its milliseconds: these are the stored forms (spine conventions) and the shapes of the spike's corpus. The text forms belong to the edges (AD-14), where the Gateway translates. No document fixed this; it is my choice. What it gives up: a CBOR dump is less readable by eye.
- *Absent means none.* An optional field is absent rather than `null`, so it has one encoding.
- *`Pong`.* AD-12 defines `Ping`; I added `Pong` as its answer, since a probe needs one. `Cancel` carries the `request_id` in a one-field record.
- *Item bounds per socket kind, `[ASSUMPTION]`.* Depth alone did not bound memory: before this bound, a 16 MiB data frame of `[0, 0, ...]` decoded to about 1.3 GiB of resident memory and a 1 MiB control frame to 86 MiB (review of this story). No document fixes an item bound, so these values are this story's assumption: 65 536 items for control and 262 144 for data. Measured peak resident memory for a worst-case frame at each bound (release build, the decoded tree kept alive, numbers in Result): at most 15 MiB for control and 92 MiB for data. The data figure is dominated by bytes, not items: one 16 MiB byte string alone peaks at 76 MiB, because the frame, `dcbor`'s copy and the round-trip re-encoding each hold it. Stated budget: 16 MiB per control frame and 96 MiB per data frame being decoded. The story that serves a socket may lower either bound for its protocol.
- *Request bodies are generic.* The bodies of each socket's protocol come with their stories; `RequestBody::writes` makes the `call_id` rule part of the type, checked on construction and on decoding.
- *`record` panics on a field named twice.* Field names are the type's own constants, so a repetition is a programming error that `dcbor` would otherwise merge silently; a test covers the panic.
- *SHA-256.* Runtime hashing stays out of `vilicus-proto` (AD-3): it exposes `CanonicalBytes`, and the Core hashes through `vilicus-crypto`. `aws-lc-rs` is a dev-dependency, used only for the vector files' `sha256` fields and `SHA256SUMS`.
- *`dcbor` values are not `Send`.* `CBOR` is reference-counted (`Rc`), so a decoded value stays on the thread that decoded it; bytes, verdicts and the mapped Rust types can cross threads.

**Files**
- `Cargo.toml`, `Cargo.lock`, `crates/vilicus-proto/Cargo.toml`
- `crates/vilicus-proto/src/lib.rs`, `canonical.rs`, `frame.rs`, `message.rs`, `profile.rs`, `vocabulary.rs`, `wire.rs`
- `crates/vilicus-proto/tests/canonical_vectors.rs`, `tests/vectors/` (`mod.rs`, `corpus.rs`, `fuzz.rs`, `hex.rs`, `notation.rs`, `rng.rs`), `tests/data/canonical-cbor/` (5 files), `examples/gen_vectors.rs`
- `.gitattributes`, `deny.toml`, `ci/audit-exceptions.toml` (new), `ci/build_time_code.toml`, `ci/test_check_supply_chain.py`, `.github/workflows/ci.yml`
- `supply-chain/config.toml`, `supply-chain/imports.lock`, `vendor/` (58 new crates)
- `doc/stories/sprint-status.yaml` (2.5 to `review`)

**Deviations**
- *Vectors copied, not moved.* The spike's `run.sh` and its TypeScript replay still read `spikes/canonical-cbor/vectors/`, and a spike is evidence, so the spike copy stays until the TypeScript replay of Story 10.6 takes the vectors from `vilicus-proto`. `the_spike_copy_of_the_vectors_is_byte_equal` keeps the two copies byte-equal, file by file. The copy in `vilicus-proto` is the one the product regenerates and replays.
- *AC4, "every such type".* No hashed or signed message type exists yet: light confirmations, step-up challenges and audit parameters come with their stories. `every_wire_type_respects_the_profile_limits` covers every type this crate maps, against limits the test states itself, and `CanonicalBytes::encode` runs the profile on every value at run time. Each hashed type must join that test when it lands.

**Open points**
- *Design documents name the spike path.* D130 says "The shared vectors of `spikes/canonical-cbor/vectors/` state the profile constants and the Unicode version, and every decoder replays them." Proposed wording, for the coordinator to apply: "The shared vectors of `crates/vilicus-proto/tests/data/canonical-cbor/`, generated by `crates/vilicus-proto/examples/gen_vectors.rs`, state the profile constants and the Unicode version, and every decoder replays them; `spikes/canonical-cbor/vectors/` keeps a byte-equal copy, checked by a `vilicus-proto` test, for the TypeScript replay until Story 10.6." Not applied here.
- *Protocol names and versions.* No document names the protocol of each socket or numbers its versions. `ProtocolVersion` is a `u16`, and the tests use `vilicus.peer` as a sample name. The story that first serves a socket fixes both.
- *Owner review of 46 exemptions.* They record that nobody here reviewed these versions. `aws-lc-sys` alone is 2 million lines, so the realistic path for it is the `rustls` work, where it becomes a Core dependency anyway.
- *Repository size.* `vendor/` grows by about 100 MB, two thirds of it `aws-lc-sys`, for a dev-dependency.
- *System AWS-LC.* `aws-lc-sys` links a system AWS-LC instead of its bundled sources when it finds one or when `AWS_LC_SYS_SYSTEM_DIR` is set. None is in the pinned image: the build there compiled the bundled sources (static `aws_lc_0_46_0_crypto`). Not checked on the GitHub runner image.
- *Field names in errors.* `DecodeError::UnknownField` and `UnknownName` carry the text the peer sent, bounded only by the frame size. The logging convention allows identifiers only, so a caller that logs a decode error should log its kind and type, not that text.
- *Story 2.2 text.* Story 2.2's notes still describe the `audit` job as `cargo audit --deny warnings`; they are history and were not edited.

## Result

All commands ran on 2026-10-20 in `rust:1.99-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a` (Docker Desktop on Windows), `rustc 1.99.0 (b940084d7 2026-09-28)`, with cargo-deny 0.20.2, cargo-vet 0.10.2 and cargo-audit 0.22.2. They ran on a copy of the repository made inside the container (build output and `node_modules` left out). Mutations ran on copies, never on the working tree.

Gates, as `.github/workflows/ci.yml` runs them:

- `cargo fmt --all --check`: exit 0.
- `cargo clippy --workspace --all-targets --frozen --config ci/cargo-vendored.toml -- -D warnings`: exit 0.
- `cargo build --workspace --frozen --config ci/cargo-vendored.toml`: exit 0. `aws-lc-sys` built from its bundled sources, without cmake (`cargo:rustc-link-lib=static=aws_lc_0_46_0_crypto`).
- `cargo test --workspace --frozen --config ci/cargo-vendored.toml`: in `vilicus-proto`, 47 unit tests, 10 vector tests and 1 doctest passed; in `vilicus-types`, 43 unit tests, 4 doctests and 4 `compile_fail` doctests passed. Exit 0.
- `python3 -m unittest discover -s ci`: `Ran 162 tests`, `OK`.
- `python3 ci/check_workspace.py`: `workspace checks passed: 18 crates`.
- `python3 ci/check_supply_chain.py`: `supply-chain checks passed: 83 packages`. Before the allowlist entries it named the 20 packages listed in Implementation Notes, exit 1.
- `python3 ci/check_supply_chain.py --vendor`: `vendor check passed`.
- `python3 ci/check_packaging.py`: `packaging check passed: 1 release artefacts, none built from or linking the 6 never-packaged crates`.
- `python3 ci/release_gates.py check`: `release gates declared: 2 package, 1 testbed`.
- `cargo deny --locked check`: `advisories ok, bans ok, licenses ok, sources ok`. Before the `deny.toml` changes: `licenses FAILED` (`BSD-2-Clause-Patent`, `dcbor`), `bans FAILED` (`syn` 2.0.119 and 3.0.9), `advisories FAILED` (RUSTSEC-2024-0436).
- `cargo vet --locked`: `Vetting Succeeded (13 fully audited, 4 partially audited, 48 exempted)`. Before: `46 unvetted dependencies`.
- `cargo audit --json`, judged by `python3 ci/check_audit_report.py ci/audit-exceptions.toml`: `audit report passed: no vulnerability, 1 warning(s), each a listed exception`.
- `sha256sum -c SHA256SUMS` in `crates/vilicus-proto/tests/data/canonical-cbor/`: all four files `OK`.
- `cargo run -p vilicus-proto --example gen_vectors --frozen --config ci/cargo-vendored.toml -- /tmp/gen`, with the hand-written `invalid.json` copied in first: `corpus.json`, `encode-invalid.json`, `fuzz.json`, `invalid.json` and `SHA256SUMS` are identical to the committed files (`cmp`).

| Criterion | Result | Tests and observed outcome |
|---|---|---|
| AC1 (AD-12, D19) | **Pass** | `frame::tests::a_length_above_the_maximum_is_refused_from_the_prefix_alone`: for each socket kind, a prefix of maximum + 1 gives `TooLarge` after exactly 4 bytes were read. `a_frame_at_the_maximum_is_read`: a 1 MiB control frame and a 16 MiB data frame are read and decode. `a_zero_length_frame_holds_no_message` (read as empty, refused as `Malformed` when decoded), `a_stream_that_stops_inside_a_frame_is_an_io_error` (a 16 MiB prefix followed by 10 bytes gives `UnexpectedEof`), `a_reader_giving_one_byte_at_a_time_reads_the_same_frames`, `writing_refuses_a_message_above_the_maximum`, `a_truncated_frame_is_an_io_error`, `messages_round_trip_through_frames`, `maxima_are_those_of_ad_12`. Item bound: `items_at_the_bound_are_decoded_and_one_more_is_refused_before_decoding` (for each kind, an array of exactly `max_items` items decodes, one more gives `TooManyItems`), `profile::tests::the_item_bound_counts_every_item_and_is_inclusive` (a map entry counts its key and its value; an array head declaring 2^32 elements is refused once the bound is passed). Depth: `a_frame_nested_deeper_than_the_profile_is_refused_before_decoding` (a full 1 MiB control frame of nested array heads, read on a 64 KiB stack, gives `Profile(TooDeep)` without a stack overflow), `profile::tests::depth_bound_is_inclusive`, `listed_tags_count_toward_depth`. Peak resident memory, measured with a throwaway release binary outside the repository that frames a worst-case message, records `VmRSS` after building the input and `VmHWM` after `read_message` keeps the decoded tree, for each shape at the bound: control, an array of zeros 6.6 MiB, a map of integers 14.7 MiB, an array of byte strings filling 1 MiB 11.4 MiB, of texts 11.3 MiB, one byte string 6.6 MiB; data, an array of zeros 20.8 MiB, a map 53.9 MiB, byte strings filling 16 MiB 88.4 MiB, texts 90.0 MiB, one byte string 76.0 MiB. One item over the bound is refused with no growth above the input (control 0 KiB, data at most 520 KiB). |
| AC2 (AD-12) | **Pass** | `message::tests::the_first_frame_must_be_a_hello`: a bare `Hello` is accepted; every message kind, and a `Hello` with an extra field, is `not_hello`. `a_wrapped_handshake_is_refused_at_any_point`: `{"hello": ...}` and `{"hello_reply": ...}` are refused as a first frame and as a later `Message`, and so is a bare `Hello` after the first frame. `the_handshake_round_trips_bare` (the `Hello` and every `HelloReply`). `hello_versions_are_non_empty_and_strictly_increasing`: `[]`, `[1, 1]`, `[2, 1]` and `[1, 3, 2]` are refused, `[1]` and `[1, 2, 7]` accepted. `the_highest_common_version_is_chosen`: with 1 and 2 offered, a Core supporting 1 to 3 chooses 2, a Core supporting 1 chooses 1, a Core supporting 3 refuses with `no_common_version`, and another protocol gets `unknown_protocol`. `a_writing_request_carries_a_call_id_and_a_reading_one_does_not`: constructors and decoding both refuse the wrong combination. `every_message_kind_round_trips`: a reading and a writing `request`, `response` with a value and with a `ClientError`, `cancel`, `ping`, `pong`. Also `ping_cancel_and_variants_have_one_encoding` and `every_refusal_round_trips_by_name`. The crate doctest frames a `Hello` and negotiates it. |
| AC3 (AD-12) | **Pass** | The check is `wire::Fields`, `wire::closed_name` and `wire::variant`; no other code reads a record or a name. `wire::tests::a_record_refuses_non_text_keys_unknown_and_missing_fields`, `a_variant_is_one_name_or_one_entry`. Against `vilicus-types`: `vocabulary::tests::a_closed_set_refuses_an_integer_index_bytes_and_other_names` refuses every index of `Taint::ALL` as an integer, `b"trusted"` as bytes, and `member`, `Trusted`, `trusted `. `source_refuses_index_tags_byte_keys_extra_entries_and_a_payload_on_system` refuses `{0: id}`, `{b"member": id}`, two entries, `{"system": null}`, `mail`, `member` without payload, and an empty map. `client_error_is_closed` refuses an extra `message`, integer field indices, a missing field, and a sentence as code. Also `ids_are_their_stored_uuidv7_bytes`, `times_are_milliseconds_within_the_range_of_vilicus_types`, `every_source_kind_round_trips` and `every_closed_set_member_round_trips_by_name`. The profile refuses duplicate keys, misordered keys and trailing bytes: `invalid_inputs_are_all_rejected` and `fuzz_verdicts_hold` below, and `trailing_bytes_are_refused_by_the_scan`. |
| AC4 (AD-13, D130) | **Pass** | `canonical::tests::every_wire_type_respects_the_profile_limits`: every message kind, every `source` kind, an id, both ends of the time range, a `ClientError` and every closed-set member encode through `CanonicalBytes` and decode under the profile. Each stays within limits the test states itself (no float, no tag outside `LISTED_TAGS`, integers within [-2^63, 2^64 - 1], at most 32 levels, NFC text; simple values are `dcbor`'s false, true and null) and round-trips. Also `a_value_outside_the_profile_has_no_canonical_bytes` and `profile::tests::encode_refuses_values_outside_the_profile` (float, tag 0, 33 levels, non-NFC text, -2^63 - 1). No hashed or signed message type exists yet (Deviations). |
| AC5 (AD-13, E19, D130) | **Pass** | `tests/canonical_vectors.rs`, on the committed vectors, in the `build-and-test` job: `committed_vectors_equal_a_fresh_generation`, `sha256sums_list_the_vector_files`, `every_committed_file_is_listed_in_sha256sums`, `the_spike_copy_of_the_vectors_is_byte_equal` (the same file names in both directories, each byte-equal), `corpus_header_states_the_profile_constants` (header, `unicode_version` included, equal to the constants), `corpus_encodes_hashes_and_round_trips` (722 values: bytes and SHA-256 equal, decode, re-encode), `encode_invalid_values_are_all_refused` (19), `invalid_inputs_are_all_rejected` (90 hand-written non-canonical inputs; a directory without `invalid.json` now fails instead of skipping), `fuzz_verdicts_hold` (2 507 inputs, every verdict equal, every targeted mutation refused). Mutations, each on a copy read through `VECTORS_DIR`: one hex digit of the first corpus item changed fails `corpus_encodes_hashes_and_round_trips` and `sha256sums_list_the_vector_files`; `unicode_version` set to `16.0.0` fails `corpus_header_states_the_profile_constants`; one fuzz verdict flipped fails `fuzz_verdicts_hold`. One space appended to the committed `encode-invalid.json` fails `committed_vectors_equal_a_fresh_generation` with `encode-invalid.json differs from a fresh generation`. |
| AC6 (D130, E19) | **Pass** | `profile::tests::dcbor_accepts_integral_floats_the_dcbor_rules_forbid`: raw `dcbor` reduces `fb43e0000000000001` to `1b8000000000000800`, and the profile refuses it as `Float`. `round_trip_comparison_refuses_a_reduced_float`. `deep_input_is_refused_without_recursion`: on a 64 KiB stack, 10 000 and 4 194 304 nested arrays are refused as `TooDeep`, and as many tags as `UnlistedTag(0)`. `keys_equal_after_nfc_do_not_collapse_silently`: inserting `caf\u{e9}` then `cafe\u{301}` gives `DuplicateKey`. `non_nfc_text_is_refused_never_normalized`: encode refuses `cafe\u{301}`, which raw `dcbor` would have encoded as `caf\u{e9}`, and decode refuses its bytes. Also `float_and_large_negative_are_refused_when_dcbor_accepts_them` and `marks_new_in_the_core_unicode_version_are_ordered_on_decode`. `the_stages_after_the_head_walk_refuse_a_reduced_float_by_round_trip_alone`: through `decode`, no known input reaches the round-trip refusal, since the head walk refuses every float first and neither the committed fuzz set nor the hand-written set has an input it refuses; the stages after the head walk, run on `fb43e0000000000001`, refuse it as `NotRoundTrip` alone, and the full decoder as `Float`. Closed types are mapped by hand in `wire.rs`, `vocabulary.rs` and `message.rs`, through the profile. |
| AC7 (D130) | **Pass** | `unicode_normalization_is_pinned_exactly`: the workspace manifest pins `unicode-normalization` with `version = "=0.1.25"`, `profile::UNICODE_VERSION` is `(17, 0, 0)`, and the vector header's `unicode_version` is `profile::UNICODE_VERSION` (17.0.0). `canonical::tests::a_stored_hash_is_checked_against_the_stored_bytes`: bytes a Unicode 16 Core would have stored (`a` U+1AE1 U+0337) no longer decode under the pinned Unicode 17 tables. Their stored SHA-256, computed with `aws-lc-rs` in the test, still verifies through `CanonicalBytes::from_stored(...).matches_hash`, which hashes the stored bytes and never re-encodes them. A change of the Unicode version takes a decision record, a protocol version and regenerated vectors (D130); until then, the pin test and the header gate fail CI. |
| AC8 (D130, D28) | **Pass** | `deny.toml` `[advisories] ignore` lists RUSTSEC-2024-0436 with the reason (`paste` unmaintained, no known vulnerability, build-time procedural macro of `dcbor`) and "Review by 2027-04-16". `ci/audit-exceptions.toml` lists it with the same reason and date, and the `audit` job judges `cargo audit --json` against that file (`ci/check_audit_report.py`, which also fails once the exception matches nothing). Both gates pass, above. `WorkflowAgreementTest` pins the new `audit` commands. |
