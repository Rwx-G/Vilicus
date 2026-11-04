---
title: 'Key hierarchy and derived file keys'
epic: 4
story: 3
status: review
author: Rwx-G
created: 2026-10-16
implements: [D3, D4, D9, AD-5, AD-4]
---

# Story 4.3: Key hierarchy and derived file keys

As a member,
I want each encrypted file opened with its own key derived from my partition root,
So that one file key reveals no other file and partition isolation rests on keys, not on code paths.

**Acceptance Criteria:**

**AC1 (D3, AD-5)**
**Given** a partition root (member DEK, household key or, for Core metadata, the instance key)
**When** the Core opens a `<module>.<partition>.db` file
**Then** the file's raw SQLCipher key is derived with HKDF-SHA-256 and the versioned label `vilicus/v1/db/<module>/<partition>/<generation>` of `doc/key-management.md` section 2
**And** two files of the same partition, or the same module in two partitions, get different keys (property test)

**AC2 (AD-5)**
**Given** a derived file key
**When** the file is created or re-keyed
**Then** its key epoch (partition root version, generation) is written atomically in the clear sidecar `<file>.epoch` and repeated in the file's `_meta` table
**And** an epoch mismatch between the sidecar and `_meta` refuses the open with a typed error

**AC3 (D9)**
**Given** the instance key delivered to the Core
**When** keys for Core metadata and the audit database are derived
**Then** Core metadata keys derive from the instance key and the audit database key derives from the audit key with the label `vilicus/v1/audit/db`
**And** no derivation from the instance key opens a personal or household partition file (test over every V0.1 label)

**AC4 (D4, AD-4)**
**Given** the `wrappers.db` schema
**When** it is created
**Then** it holds every member DEK wrapper (one per KEK) and member public key with format version, generation and algorithm identifiers, in its own file separate from `core.db`
**And** losing `core.db` or the instance key does not prevent unwrapping a member DEK from `wrappers.db` (test)

**AC5 (AD-4)**
**Given** a module that needs its data
**When** the Core hands it access
**Then** it receives an opened, partition-scoped handle, never a key or a path to a key

**Decision tasks:**
- [x] Decide how `wrappers.db` is authenticated as a whole (`doc/stories/deferred-work.md`, gate AD36-1): the AD-36 construction authenticates each record, not the set, so deleting a record raises no alert and restoring an older file can bring back a vetoed or suspended member's valid record (D119). Recommended (gate AD36-1, which assigns the design to the keys and storage epics): the candidate recorded with the deferred item, a monotonic counter and a MAC over the record set under an HK-derived key, cross-checked with `core.db`, decided here because this story creates the `wrappers.db` schema. Gives up: every wrapper write also rewrites the set MAC and the counter; deferring again keeps the limit of D119 stated instead.
  Decided by the owner, who approved the recommended option: a monotonic counter, a MAC over the record set under a key derived from the household key, and a cross-check of the counter with `core.db`, every wrapper write also rewriting the set MAC and the counter; built here, staged on story 4.6 for the household key (Implementation Notes).

**Dependencies:**
- Story 4.1 (crypto suite)
- Story 3.1 (storage layer and epoch sidecar)

**References:**
- `doc/key-management.md` sections 2 and 9
- `doc/architecture-spine.md` AD-4, AD-5
- `doc/decisions.md` D3, D4, D9, D119
- `doc/architecture.md` section 5.2
- `doc/stories/deferred-work.md`; `doc/qa/gates/1.1-key-prototype-ad36-public-key-authentication.yml` (AD36-1)

## Implementation Notes

**What was built**
- `crates/vilicus-types/src/partition.rs` (new): `Partition`, moved from `vilicus-storage`, which re-exports it, so that `vilicus-crypto` binds a file key to the partition without an edge to the storage layer (AD-3).
- `crates/vilicus-crypto/`:
  - `hierarchy.rs` (new): one type per role of key management section 2, each over the pool's slot, without `Clone`, `Debug` or `Display`: `InstanceKey` and `AuditKey` (`from_credential`, the credential read straight into a slot and refused unless it holds exactly 32 bytes), `MemberDek` (`generate`, `wrap` and `unwrap` under the purpose `vilicus/v1/wrap/member-dek`, bound to the member and the DEK version), `HouseholdKey` (no public constructor: story 4.6 creates it), `HomePartitionRoot`, `FileKey` (module, partition, key epoch, `with_sqlcipher_key_text`), `DatabaseKey` (`core.db`, `audit.db`); the sealed trait `PartitionRoot`, whose `file_key` derives a module file's key from the root; the sealed trait `Key`, every key type of the crate. Every derivation is a `Derivation` constant (label, parent role, child role) listed in `DERIVATIONS`; each call site goes through `derive_child!`, whose `const` block fails the build when the entry names another parent or child.
  - `wrapper_set.rs` (new): `WrapperSetKey` (`HouseholdKey::wrapper_set_key`) and `WrapperSetMac`, the MAC of the `wrappers.db` record set (decision task below), with its stored form.
  - `aws_lc.rs`: `hmac_sha256` and `verify_hmac_sha256` (`aws_lc_rs::hmac`, the tag compared with `constant_time::verify_slices_are_equal`), one operation per `#[inline(never)]` function, called only under a slot's guard (AC7 of story 4.1, AC8 of story 4.2); `aws_lc/tests.rs`: their known answers, and `Key` and `Context` added to the key objects the shape check refuses outside a function body.
  - `error.rs`: `CryptoError::Credential`, `CredentialLength`, `MacInputTooLong`, `Mac`, `HouseholdKeyVersion`; `WrapperError::UnknownMacAlgorithm`.
  - `lib.rs`: the suite's message authentication, and the table of the hierarchy, which a test holds to the registry.
  - `memory/testing.rs` (`testing` feature): `member_dek_from_file`, `household_key_from_file`, `household_key` (the stand-in for story 4.6's creation, in tests only), and `with_key` generic over every key type.
- `crates/vilicus-storage/`:
  - `handle.rs`: `FileKeying`, what keys a connection: it lends SQLCipher's raw key text for the one call that keys it, so the storage layer builds no key text and holds none (`raw_key_text` and the `zeroize` dependency are gone); `KEY_TEXT_LEN`; a text that is not `x'`, 64 lowercase hex digits, `'` is refused (`Error::MalformedKeyText`), its digits checked without a branch on them; `Handle<Write>::rekey`, the re-key of a file under a new key epoch; the setup split into `open_path` and `set_up`, which `wrappers.db` reuses without a key.
  - `ffi.rs`: `rekey`, `sqlite3_rekey_v2`, beside `sqlite3_key_v2`.
  - `wrappers.rs` (new): `wrappers.db`: `create_wrappers`, `open_wrappers`, `WrapperStore` (`set`, `dek_wrapper`, `public_keys`, `write`), `KekKind`, `PublicKeyKind`, `DekWrapperRow`, `PublicKeyRow`, `WrapperChange`, `WrapperSet`, `RECORD_TABLES`.
  - `error.rs`: `MalformedKeyText`, `KeyUnavailable` (environmental), `NotAWrapperFile`, `WrappersSchemaVersion`, `MalformedWrapperRow`, `WrapperRecordMissing`.
  - `maintenance.rs`, `migration_copy.rs`: the copies take a `&dyn FileKeying`.
- `crates/vilicus-core/`:
  - `keys.rs` (new): `file_key` (a module file's key from its root at the epoch its sidecar names), `KeyText` (a `FileKey` lent to the storage layer, refused for another module or partition), `open_file`, `create_file`, `rekey_file`, `epoch_of`; `Wrappers` over `WrapperStore`: `check_counter`, `verify`, `write`, `dek_wrapper_change`, `unwrap_member_dek`; `KeyError`, `CounterCheck`.
  - `registry`, `record/fuzz.rs`, `testing.rs`: keys are `&dyn FileKeying`; `testing` (also compiled in the Core's own test builds) gains `sqlcipher_key_text`, the key text of a test file's bytes, test code only.
- `crates/vilicus-module-api/src/tests.rs`, `testing/vilicus-mod-reference/src/lib.rs`: the AC5 checks.
- `crates/vilicus-crypto/examples/key_memory/` (`subject.rs`, `checks.rs`, `material.rs`): the paths `file-key`, `instance-key` and `set-mac`, below.
- `ci/crate_graph.toml`, `ci/test_check_workspace.py`: `[restricted.zeroize.linked]` names `vilicus-crypto` alone.
- `Cargo.lock`: one removed line, the `zeroize` dependency of `vilicus-storage`; no package added or removed.

**Decision task, gate AD36-1** (owner approval of the recommended option). `wrappers.db` is authenticated as a whole by a monotonic counter, a MAC over the record set under a key derived from the household key, and a cross-check of the counter with `core.db`; every wrapper write also rewrites the set MAC and the counter. As built:
- The set key is `HKDF-SHA-256(HK, vilicus/v1/hk/wrappers-set-mac/ || 0x00 || len || hk_version)`, held for one operation in a slot.
- The MAC is HMAC-SHA-256 under it over: the label `vilicus/v1/wrappers/set` and its end byte; the format version (1), the algorithm identifier (0x0001, HMAC-SHA-256), the household key version, the counter (`u64`) and the record count (`u32`); then each record, in ascending byte order, preceded by its `u32` length. The order makes the input the set's, whatever order the records are read in.
- A record is one row of a table of `RECORD_TABLES` (`_meta`, `member_dek_wrappers`, `member_public_keys`): its table's name with a `u16` length, then each column in schema order, tagged (null, integer as `i64`, blob or text with a `u32` length). The `wrapper_set` row, the counter and the MAC, is the set's state and no record; a test fails on a table that is neither.
- The stored MAC is the format version, the algorithm identifier, the household key version, then the tag (40 bytes); another version or algorithm is refused, never read.
- A write runs in one `BEGIN IMMEDIATE` transaction: it verifies the set as it is (a fresh file, counter 0 with no MAC, may hold its schema row only), applies its changes, raises the counter, seals the new set and stores the MAC, then checkpoints the WAL empty, so a removed wrapper does not stay there. A set changed behind the Core's back fails the verification, and the write is refused: the Core never seals a tampered set.
- The cross-check gives `Matches`; `Unchecked` when `core.db`'s copy is missing (core.db or the instance key lost: the DEK still unwraps, AC4); `Ahead { by }` when `wrappers.db` is ahead (by one: a crash between the two writes); `RolledBack` when it is behind. The copy is `core.db`'s, which story 5.2 creates, so `check_counter` takes it as a parameter.
- Staging, because the household key has no constructor before story 4.6: here, the set key and its MAC exist, tested with `vilicus_crypto::testing::household_key`, a stand-in compiled with the `testing` feature only; no product path seals a set yet, since no product path writes a wrapper. Story 4.6 completes it: the first member's ceremony creates HK and makes the first write of `wrappers.db` with HK's set key, so no set is ever written unsealed; the unlock path then verifies the set once it holds HK, before any record but the unlocking member's own DEK wrapper is used.

**Decisions and why** (drafted decision text under Open points)
- *Role types over one slot.* Each role is its own type, so a DEK cannot key a household file and the instance key has no method that derives a module file's key: the partition of a file key comes from its root, never from the caller. The registry is the one list of derivations, and the build refuses a call site its entry does not describe, which makes the AC3 test, which walks the registry, a statement about the code rather than about a list.
- *The context of a file key* is the module's name, the partition (a kind byte, 0x01 household, 0x02 home, 0x03 then the 16-byte member id), the root's version and the generation, each with its D153 length prefix, under the label `vilicus/v1/db/`. Key management section 2 writes `vilicus/v1/db/<module>/<partition>/<generation>`; the root version is added so the key binds the whole epoch the sidecar names, and the partition is binary, as D119 binds the member id.
- *Labels.* A label followed by context fields ends with `/`, one with none does not (`vilicus/v1/partition/home`, `vilicus/v1/audit/db`). Three labels are new: `vilicus/v1/core/db` (no document names the label of `core.db`'s key), `vilicus/v1/hk/wrappers-set-mac/` and `vilicus/v1/wrappers/set`; and the purpose `vilicus/v1/wrap/member-dek`.
- *The instance key's credential* is read straight into a slot, with no intermediate buffer, and must be exactly 32 bytes; its version is the caller's (the sidecars name the root version, and story 5.1 or 5.2 says where the Core reads it).
- *The storage layer takes a lent key text* (`FileKeying`) rather than a `vilicus-crypto` type, which would be a new edge (AD-3): the Core wraps a `FileKey` in `keys::KeyText`, and only the call that keys a connection runs under the guard, not the open around it. A fixed `[u8; KEY_TEXT_LEN]` implements the trait for tests and the build-time check. Its length is checked against `vilicus_crypto::SQLCIPHER_KEY_TEXT_LEN` in the Core, the one crate that sees both.
- *Re-key.* `sqlite3_rekey_v2` re-encrypts every page in one transaction of its own; the WAL is emptied before, so no frame under the old key stays, and after, so the file alone holds the new pages. The pending-sidecar protocol of `write_epoch` (D143) frames it.
- *`wrappers.db` is a plain SQLite file* (architecture section 5.2: "not encrypted by the instance key"), set up like a writer and run under the write policy, which refuses schema changes, `ATTACH` and the writes of `_meta`.
- *Tests that need a household key* sit in a `#[cfg(feature = "testing")]` module of `keys/tests.rs`: the workspace's test build compiles `vilicus-core` with the feature, which the testbed enables, so `cargo test --workspace` runs them; `cargo test -p vilicus-core` without `--features testing` does not.

**Files**
- `crates/vilicus-types/src/`: `partition.rs` (new), `lib.rs`
- `crates/vilicus-crypto/src/`: `hierarchy.rs`, `hierarchy/tests.rs`, `wrapper_set.rs`, `wrapper_set/tests.rs` (new), `aws_lc.rs`, `aws_lc/tests.rs`, `error.rs`, `lib.rs`, `memory/testing.rs`; `examples/key_memory/`: `checks.rs`, `material.rs`, `subject.rs`
- `crates/vilicus-storage/`: `Cargo.toml`; `src/`: `wrappers.rs`, `wrappers/tests.rs` (new), `error.rs`, `ffi.rs`, `file.rs`, `handle.rs`, `lib.rs`, `maintenance.rs`, `migration_copy.rs`, `tests/maintenance.rs`, `tests/mod.rs`, `tests/setup.rs`
- `crates/vilicus-core/src/`: `keys.rs`, `keys/tests.rs` (new), `lib.rs`, `testing.rs`, `record/fuzz.rs`, `record/tests.rs`, `record/tests_deletion.rs`, `record/tests_migration.rs`, `registry/migrate.rs`, `registry/mod.rs`, `registry/tests.rs`
- `crates/vilicus/src/registry.rs`, `crates/vilicus-module-api/src/tests.rs`, `testing/vilicus-mod-reference/src/lib.rs`, `testing/vilicus-testbed/src/registry.rs`, `testing/vilicus-testbed/src/support.rs`
- `ci/crate_graph.toml`, `ci/test_check_workspace.py`, `Cargo.lock`
- `doc/stories/deferred-work.md` (the AD36-1 item's resolution)

**Deviations**
- *AC1, "property test"*: a deterministic xorshift draw over modules, partitions, root versions and generations, 400 files from one root's bits; `proptest` is not a dependency and none was added.
- *AC2, "re-keyed"*: the re-key is built and tested in the storage layer and the Core (`rekey_file`); a crash inside it leaves the pending sidecar, so every open then fails with `EpochTransitionPending`, and the resolution (open with the key of each epoch, keep the one that opens) belongs to the re-key stage of the bring-up (D151), which runs once rotations exist (Epic 9); `startup::Rekey` stays `NothingToRekey`.
- *AC3, "Core metadata keys"*: the key of `core.db` (`InstanceKey::core_metadata_key`); `core.db` itself is story 5.2's. The inbox file keys of D114 (`vilicus/v1/inbox/<partition>`) ship with the home milestone. The `audit.db` key derives in `vilicus-crypto` (`AuditKey::database_key`), but the audit writer, `vilicus-audit`, cannot link `vilicus-crypto` (AD-3): story 6.1 decides how it reaches its key.
- *AC4*: the KEKs of the test are keys of the suite standing in for the passphrase and recovery KEKs (stories 4.4 and 4.5). A member public key is stored as the opaque value its format gives it, at least its format version and algorithm identifier (a `CHECK`), with its generation in a column; its encoding is story 4.6's.
- *AC5*: nothing a module receives changed; the property is shown by the reference module's `compile_fail` doc tests and the scan of `vilicus-module-api`'s sources.
- *Decision task*: no product path writes `wrappers.db` yet (staging above), and `core.db`'s copy of the counter is story 5.2's.
- *Environment*: the Docker disk was full (392 GB of other projects' volumes), so no named volume could be made. Builds and gates ran in one container whose target directory and rustup home were `tmpfs` mounts, on a fresh clone inside it; `ci/key_memory.py`, which makes two named volumes, could not run as is, and its five groups ran with the same options and image from a runner that bind-mounts the release harness built in that container (Result).
- *The harness* covers the key text up to the closure the Core lends it to, not into SQLCipher's keying call: a `vilicus-crypto` example cannot link `vilicus-storage` (AD-3), and SQLCipher's own copy is outside D131's claim. The audit key's credential path is the instance key's (`key_from_credential`), so `instance-key` covers both.

**Open points**
- *Design documents* (coordinator; none edited here but `doc/stories/deferred-work.md`, the spine and the PRD being published copies):
  - **Drafted D155**, "The key hierarchy in types, module file keys, the lent key text, the re-key, and `wrappers.db` authenticated as a whole", amending D119, D140, D143, D153, AD-5 and AD-36: "Context: story 4.3 builds the key hierarchy of key management section 2 and creates `wrappers.db`. D119 leaves `wrappers.db` unauthenticated as a whole, so a deleted record raises no alert and an older file can bring back a vetoed or suspended member's valid record (gate AD36-1); key management section 2 gives a file key's label but not its context's encoding, nor a label for `core.db`'s key; D153 lets `vilicus-storage` declare `zeroize` for a SQLCipher key text it builds from a raw key, which story 4.2 moved into the locked pool; and no decision says how a file is re-keyed. Decision: every key role is a type of `vilicus-crypto` (instance key, audit key, member DEK, household key, home partition root, module file key, `core.db` and `audit.db` keys, the set MAC key), and every derivation between roles is an entry of one registry that the build holds each call site to; no chain from the instance key or the audit key reaches a member DEK, the household key or a personal or household file key. A module file's key is HKDF-SHA-256 of its partition root under `vilicus/v1/db/` with the module's name, the partition (0x01 household, 0x02 home, 0x03 then the member id), the root's version and the generation, each length-prefixed as D153 fixes; the partition comes from the root. `core.db`'s key derives from the instance key under `vilicus/v1/core/db`, `audit.db`'s from the audit key under `vilicus/v1/audit/db`, the home partition root from the instance key under `vilicus/v1/partition/home`; a member DEK wrapper is bound to the purpose `vilicus/v1/wrap/member-dek` and to the member and the DEK version. The instance key and the audit key are read from their credential straight into a slot, exactly 32 bytes. The storage layer keys each connection from a SQLCipher key text the caller lends for that call, which the Core lends from the pool's text class, and refuses a text that is not a raw key's; only `vilicus-crypto` declares `zeroize`. A file is re-keyed with `sqlite3_rekey_v2`, a fourth FFI call of the storage layer, inside the pending-sidecar protocol of D143, its WAL emptied before and after. `wrappers.db` is a plain SQLite file run under the write policy, holding the member DEK wrappers, one per KEK, and the member public keys; its record set is authenticated by a monotonic counter, HMAC-SHA-256 over the counter and every record under a key derived from the household key and its version (`vilicus/v1/hk/wrappers-set-mac/`), stored versioned, and a copy of the counter in `core.db`; every write verifies the set, raises the counter and seals the new set in one transaction, and the unlock path verifies the set once it holds the household key, before any record but the unlocking member's own DEK wrapper is used; a counter below `core.db`'s copy is a rollback, one above it is confirmed only by a verified MAC, and a missing copy leaves the MAC as the only check. Consequences: the first write of `wrappers.db` is the first member's ceremony, sealed with the household key it creates (story 4.6); a write by a party that holds no household key (a new adult's enrollment while no adult is unlocked, a child's factor change) cannot seal the set, and waits for an unlocked adult or is staged until one exists, which the enrollment stories decide; a rollback of `wrappers.db` and `core.db` together, consistently, is not detected; a crash inside a re-key leaves both epochs named, resolved by the key that opens the file; the audit writer's access to its key is story 6.1's."
  - **D119's consequences**: "`wrappers.db` is not authenticated as a whole, so a deleted record raises no alert and a rolled-back file can restore a since-vetoed or suspended member's valid record" may read "`wrappers.db` is authenticated as a whole by a counter, a household-key MAC over the record set and `core.db`'s copy of the counter (D155)"; D119's status "Accepted, amended by D121, D153 and D155". Key management section 2, "Limits it states": the same.
  - **D153**: "only `vilicus-crypto` and `vilicus-storage` (its SQLCipher key text) declare `zeroize`" becomes "only `vilicus-crypto` declares `zeroize` (D155)".
  - **D143's amendment of D140**: "`vilicus-storage` also keys each file through `sqlite3_key_v2`, from a buffer zeroized on drop" becomes "from a key text the Core lends from its locked pool (D155), and re-keys it through `sqlite3_rekey_v2`".
  - **Spine AD-5**, after "one key derived per file (D3, `doc/key-management.md` section 2)": "under `vilicus/v1/db/` from the partition root with the module, the partition and the key epoch, the storage layer keying each connection from a key text the Core lends (D155)". **Spine AD-36**, at the end: "; the record set of `wrappers.db` is authenticated as a whole by a monotonic counter, a MAC under a key derived from the household key and a copy of the counter in `core.db` (D155)".
  - **Key management section 2**, the "Database keys" row: "HKDF from the partition root with the module name, the partition, the root version and the file generation (D155)"; the instance key row may name `vilicus/v1/core/db`.
  - **Glossary**: "record set" (of `wrappers.db`) and "set MAC", if the coordinator keeps those terms.
  - No test reads text these amendments change, except `test_the_repository_restricts_zeroize_and_the_primitive_sources`, updated here to the new rule.
- *Story 4.4* (passphrase KEK): the wrapper row is `Wrappers::dek_wrapper_change(dek, KekKind::Passphrase, kek, Kdf::Argon2id(..), KekDerivation::Direct, salt, ..)`; a passphrase change replaces the row (one per member and KEK kind) in a write sealed under the household key's set key, which an adult's unlock holds; `MemberDek::wrap` takes the KEK as a `SymmetricKey`, which a passphrase KEK type of the story may replace. The harness's `passphrase` path is the story's.
- *Story 4.5* (recovery): `KekKind::Recovery`; a new recovery wrapper replaces the old one in the same transaction (AC5) because the row's key is the member and the KEK kind.
- *Story 4.6* (household key and HPKE): `HouseholdKey`'s constructor and its version; the first member's ceremony makes the first write of `wrappers.db`, sealed with the new HK's set key; the stored encoding of a member public key (format version, algorithm identifier, key) in `member_public_keys`; the HK wraps need a table in `wrappers.db`, so a schema version 2 with a forward migration of `wrappers.db` (none exists: `open_wrappers` refuses any other version) and the new table in `RECORD_TABLES`, which `every_table_is_a_record_table_or_the_set_state` enforces; an HK rotation re-seals the set under HK n+1 (the MAC states its version).
- *Story 4.7* (AD-36): the enrollment key wrap, the tags and the permanent MACs are records of the set; every check of a record follows the set's verification, and a set that does not verify is alerted to every adult and wraps nothing.
- *Story 5.1* (Core start): `InstanceKey::from_credential` reads the credential from `$CREDENTIALS_DIRECTORY` after `start_key_memory`; where its version comes from.
- *Story 5.2* (`core.db`): opens it with `InstanceKey::core_metadata_key`; keeps the copy of the `wrappers.db` counter, written after each write of `wrappers.db`, updated when `Ahead` only once the set MAC verifies, and alerts on `RolledBack` and on an `Unchecked` start.
- *Story 6.1* (audit writer): the audit writer needs `AuditKey::database_key`, which `vilicus-audit` cannot reach (AD-3).
- *The key memory harness*: on Docker Desktop, `no-core-dump-SIGABRT` and `no-core-dump-SIGQUIT` intermittently see the hardened subject exit normally after the signal, before and after this story (Result); the check, unchanged here, needs a look at how the signal races the closing of the subject's stdin.
- *Epic 9* (rotations, enrollment): `keys::rekey_file` for a generation bump; the resolution of a pending epoch at the bring-up's re-key stage; writes by a party without HK (above).

## Result

All commands ran on 2026-11-04 in `rust:1.99-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a` (Docker Desktop on Windows, WSL2 kernel), `rustc 1.99.0 (b940084d7 2026-09-28)`, on a fresh clone of the branch made inside the build container, never on the working tree. The Docker disk was full, so the container's target directory and rustup home were `tmpfs` mounts instead of named volumes (Deviations); the container was removed afterwards, and no volume was left.

Each code commit of the story, checked out in turn on that clone, passes `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --frozen --config ci/cargo-vendored.toml -- -D warnings` and `cargo test --workspace --frozen --config ci/cargo-vendored.toml`, none failed: `f2c9a73` 660 passed (659 before the story), `25d7d1f` 672, `4ecdc9f` 673, `c8e0143` 675, `35b1701` 680, `7e0bc29` 687, `aaad851` 690, `67edfc8` 690.

Gates, as `.github/workflows/ci.yml` runs them, at `67edfc8`:
- `python3 -m unittest discover -s ci`: `Ran 261 tests`, `OK`.
- `python3 ci/check_workspace.py`: `workspace checks passed: 19 crates`.
- `python3 ci/check_supply_chain.py`: the primitive source lines, then `supply-chain checks passed: 93 packages`; `--vendor`: `vendor check passed`.
- `python3 ci/check_sqlcipher_source.py`: `sqlcipher source check passed: 3 files match SHA256SUMS`.
- `python3 ci/check_packaging.py`: `packaging check passed: 1 release artefacts, none built from or linking the 6 never-packaged crates`.
- `python3 ci/release_gates.py check`: `release gates declared: 2 package, 1 testbed`.
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --frozen --config ci/cargo-vendored.toml -- -D warnings`, `cargo build --workspace --frozen --config ci/cargo-vendored.toml`: exit 0.
- `cargo test --workspace --frozen --config ci/cargo-vendored.toml`: 690 passed, none failed: `vilicus-crypto` 54 unit tests (42 before), `vilicus-storage` 153, `vilicus-core` 224, the `testing` module of `keys/tests.rs` included; `vilicus-types` gains `Partition`'s doc test, the reference module two `compile_fail` doc tests.
- `Cargo.lock`: one removed line, the `zeroize` dependency of `vilicus-storage`; `cargo tree -p vilicus-storage -e normal --depth 1` is `libc`, `rusqlite`, `vilicus-types`. No dependency or edge was added.
- The key memory harness: below. `python3 ci/key_memory.py` itself did not run (it makes two named volumes, which the full disk refused).
- Not run here: `cargo deny`, `cargo vet` and `cargo audit` (not in the image, need the network; the package set is unchanged); the `key-memory` job on a GitHub runner and the Debian 13 VM run (not pushed); the nightly `fuzz` job (no change to `vilicus-proto`), `hpke-review`, `sqlcipher-regenerate` (no change under their paths) and `vm-smoke`.

**The key memory regression** at `67edfc8`: the release harness (`cargo build --release -p vilicus-crypto --features testing --example key_memory` on the clone), run in its five groups by a runner that starts each container of the pinned image with the options `ci/key_memory.py` gives it (`main` with `CAP_SYS_PTRACE` and an 8 MiB `RLIMIT_MEMLOCK`, `noptrace`, `nomemlock`, `ipclock`, `swap`), the binary bind-mounted and `/tmp` a `tmpfs`. `main` 66 `PASS`, no `FAIL`; `nomemlock` 1, `ipclock` 1, `swap` 2 `PASS`; `noptrace` 4 `PASS` and 2 `FAIL`, below. The pool is now 12 288 bytes (`VmLck 12 kB`): the text class's slots fill a third page.

| Path | Product shape, live (asserted) | After drop (asserted) | Default shape's copies, the planted input excluded (asserted) |
|---|---|---|---|
| file-key | the DEK and the file key in the pool, nothing elsewhere | nothing (8 patterns) | `file-key`, `file-key-hex`, `file-key-text`, `root` |
| instance-key | the instance key, the home root and the `core.db` key in the pool, nothing elsewhere | nothing (7 patterns) | `core-db-key`, `home-root`, `instance` |
| set-mac | the household key and the set key in the pool, nothing elsewhere | nothing (8 patterns) | `hk`, `set-key`, `set-key-hmac-ipad`, `set-key-hmac-opad` |

- Listed without a control, as for story 4.2's derive path: the four HKDF intermediates of each derivation (PRK, its HMAC states, the extract's inner digest), which aws-lc-rs computes in a context it cleanses.
- Stack depth of each guarded operation (canary, asserted at most 64 KiB minus 8 KiB): file key 2 696 bytes, its key text 112; instance key read 280, home root 2 696, `core.db` key 2 520; set key 2 696, seal 6 488, verify 6 472.
- `noptrace`: `no-core-dump-SIGABRT` and `no-core-dump-SIGQUIT` reported `exit status: 0, core dumped: false`: the hardened subject exited normally after the signal instead of dying of it, and wrote no dump. The same check fails on the harness built from `fabe7ea`, before this story (5 runs of the group each: 2, 1, 0, 1, 1 failures before; 2, 1, 1, 1, 0 after), so it is an intermittent of this Docker Desktop host, which pipes core dumps to `wsl-capture-crash`, not of this story; no failure ever showed a dump. It is an open point for the harness (below).

| Criterion | Result | Tests and observed outcome |
|---|---|---|
| AC1 (D3, AD-5) | **Pass** (Deviations) | `no_two_files_or_epochs_share_a_key` (400 files from one root's bits: two files of one partition, one module in two partitions, one file at two epochs never share a key), `each_derivation_matches_a_known_answer` (HKDF-SHA-256 computed with Python's `hmac` and `hashlib`, the `info` layout above), `a_file_opens_with_the_key_its_root_derives_at_its_epoch` (Core). |
| AC2 (AD-5) | **Pass** (Deviations) | `a_rekey_moves_the_file_to_its_new_key_and_epoch`, `a_refused_rekey_leaves_the_file_as_it_was` (storage); `a_rekey_moves_the_file_to_the_key_of_its_next_generation` (Core: the sidecar and `_meta` at the new epoch, the old key `WrongKey`, an edited sidecar `EpochMismatch`); story 3.1's `a_sidecar_that_disagrees_with_meta_fails_every_open`, `a_meta_that_disagrees_with_the_sidecar_fails_the_open`. |
| AC3 (D9) | **Pass** (Deviations) | `no_derivation_from_the_instance_key_opens_a_personal_or_household_file` (over every label of the crate, `every_label_of_the_crate_is_registered` holding the list to the source, `every_derivation_is_registered` holding the registry to the constants, `the_documented_hierarchy_is_the_registry`), `the_instance_key_keys_no_personal_or_household_file` (Core), `a_credential_holds_exactly_one_key`. |
| AC4 (D4, AD-4) | **Pass** (Deviations) | `a_member_dek_unwraps_without_core_db_or_the_instance_key` (Core: two wrappers, one per KEK, in `wrappers.db` with no `core.db` and no instance key; `Unchecked`; each KEK gives back the DEK, which opens the member's file; a stored wrapper reads back with its format version and identifiers), `wrappers_db_needs_no_key_and_holds_wrappers_and_public_keys`, `every_table_is_a_record_table_or_the_set_state`, `another_file_or_schema_is_refused` (storage), `a_member_dek_wrapper_opens_only_as_its_member_and_version` (crypto). |
| AC5 (AD-4) | **Pass** (Deviations) | The reference module's `compile_fail` doc tests (`vilicus_crypto::FileKey`, `vilicus_storage::FileKeying`, E0433), `the_module_port_names_no_key_and_no_path` (module API). |
| Decision task (AD36-1) | **Decided and built** (staged, above) | `a_deleted_record_or_an_older_file_is_seen` (a deleted record, an edited counter, a removed MAC, a reset counter refused; a write over a changed set refused, the counter unchanged; an older file refused by the counter, though its own MAC holds), `the_set_mac_is_bound_to_its_household_key_version` (Core); `the_set_mac_matches_a_known_answer_whatever_the_order`, `a_changed_set_counter_or_key_is_refused`, `the_stored_mac_is_versioned_and_refuses_any_other_shape`, `hmac_sha256_matches_known_answers_and_verifies_only_its_tag` (crypto); `a_write_checks_the_set_then_raises_the_counter_and_stores_its_seal`, `a_refused_write_changes_nothing` (storage); the harness's `set-mac` path. |
| Key text in the pool (open point of 4.2) | **Pass** | `a_malformed_key_text_is_refused_before_it_keys`, `the_key_text_is_lent_once_per_connection`, `the_storage_layer_takes_the_key_text_the_key_memory_writes`; the harness's `file-key` path. |

Mutations, each applied alone to the working tree at `67edfc8`'s content, the named tests run in the build container, then the file restored; each run's output showed its tests ran. 25 of 25 made the named tests fail, one after a test was strengthened:
- AC1: the partition, the generation, then the module left out of a file key's context (`no_two_files_or_epochs_share_a_key`, `each_derivation_matches_a_known_answer`).
- AC2: a re-key that skips `_meta`, one that skips `sqlite3_rekey_v2`, and an open that does not compare the sidecar with `_meta` (the storage and Core re-key and mismatch tests).
- AC3: the home root reporting the household partition (`no_derivation_from_the_instance_key...`, `the_instance_key_keys_no_personal_or_household_file`); a registry entry from the instance key to a household file key (`no_derivation_from_the_instance_key...`, `every_derivation_is_registered`); a derivation made under another entry than its parent's (the build fails, its `const` assertion); a credential of 33 bytes accepted (`a_credential_holds_exactly_one_key`).
- AC4: `Wrappers::open` requiring `core.db`, and a missing copy of the counter refused (`a_member_dek_unwraps_without_core_db_or_the_instance_key`).
- AC5: a function of the module API taking a `std::path::Path` (`the_module_port_names_no_key_and_no_path`).
- Decision task: the set MAC not verified; a write that does not check the set; the counter left out of the MAC input; a lower counter accepted; the counter not raised; an HMAC verification that ignores the tag (the Core, crypto and storage set tests).
- Key text: uppercase hex digits accepted; the Core lending another text than the key's (`a_file_opens_with...`, `a_rekey_moves...`, `the_instance_key_keys...`, `a_member_dek_unwraps...`). The uppercase mutation first survived: the test's uppercase case also uppercased the `x`, refused by the prefix before the digits were read; the digit cases now include `A` and `F` at every position, and it is killed.
- Harness (the release harness rebuilt, the `main` group run): a file key's text copied to the heap before it is lent (`file-key-core-live-only-in-pool`, `file-key-core-dropped`: `file-key-hex`, `file-key-text` on the heap); the instance key read into a heap buffer first (`instance-key-core-*`: `instance=1[heap:1]`); the set key copied to the heap for the seal (`set-mac-core-*`: `set-key=1[heap:1]`). The first run of these three reported survivors that were the driver's: from Windows Python, `bash` resolved to WSL's, which ran no container; run through Git Bash, all three were killed.
- Not mutated: the `compile_fail` doc tests of the reference module, the shape of story 4.1's AC4 test, whose mechanism is unchanged.
