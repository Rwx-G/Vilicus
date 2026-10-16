---
title: 'E17: secure_delete and WAL behaviour'
epic: 1
story: 11
status: 'done'
author: Rwx-G
created: 2026-10-16
implements: [E17, FR-29, D113, D2]
---

# Story 1.11: E17: secure_delete and WAL behaviour

As the owner,
I want deleted records checked in the database file and its WAL under `secure_delete`,
So that the V0.1 claim that expired undo journal entries are deleted holds.

**Acceptance Criteria:**

**AC1 (E17, FR-29, D113)**
**Given** a SQLCipher file in WAL mode with `secure_delete` on, under `spikes/e17-secure-delete/`, holding journal rows with before-images of known plaintext
**When** the rows are deleted, the WAL is checkpointed with `TRUNCATE`, and the file and WAL are decrypted and inspected
**Then** no plaintext of the deleted rows is found in the file or the WAL

**AC2 (E17, D2)**
**Given** the same file
**When** deletion happens without a checkpoint and the WAL is inspected before the next one
**Then** the record states whether plaintext remains in the WAL and for how long

**AC3 (E17)**
**Given** plaintext of deleted rows remains after AC1
**When** the result is recorded
**Then** the fallback is recorded in `doc/decisions.md`: vacuum after shredding, and the backup caveat documented

**Spike plan:**
- Question: does `secure_delete` plus WAL behaviour match the deletion claim for expired journal entries (E17)?
- Method: delete records, checkpoint, inspect the decrypted file and WAL.
- Pass criterion: no plaintext of deleted records in the file or WAL.
- Timebox: 2 working days.
- Fallback on failure: vacuum after shredding; document the backup caveat.
- Result record: E17 status in `doc/research-notes.md`; the procedure reused by Story 3.6.

**Dependencies:**
- None.

**References:**
- `doc/research-notes.md` section 3 (E17)
- `doc/prd.md` FR-29, section 9
- `doc/decisions.md` D2, D113
- `doc/architecture-spine.md` AD-26, AD-23

## Implementation Notes

**What was built.** A standalone crate, `spikes/secure-delete-wal/` (its own empty `[workspace]`, edition 2024, Apache-2.0, `publish = false`), and `spikes/secure-delete-wal/run.sh`, which builds and runs everything in a Debian 13 Rust container pinned by digest (`rust@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a`, the `rust:1-trixie` tag as pulled on 2026-10-16), prints one `PASS <name>` or `FAIL <name>` line per step and per check, and exits non-zero on any failure.

- `src/store.rs` creates one database per check in WAL mode, either as a SQLCipher file opened with a raw 256-bit key (the product case) or as the same pages with no key (plain), with `secure_delete` set to OFF, FAST or ON and read back. It writes two workloads:
  - the `_journal` table of spine AD-26: 48 rows in 4 transactions, half older than the 30-day retention and interleaved with live rows so both share b-tree pages, half of each kind with a before-image large enough to spill into overflow pages, and a unique index on `call_id` so index cells hold known content too. Before- and after-images are random bytes; `call_id` is random hex text. The purge is the Story 3.6 operation, one `DELETE FROM _journal WHERE created_at < cutoff`;
  - crypto-shredding: 20 records whose wrapped record keys sit in a `record_keys` table of the same file (`doc/architecture.md` section 5.1), plus a minimal `_journal`. Shredding deletes the key rows of half of them and leaves their ciphertext in place, either directly or through a journaled write that first copies the key row's before-image into `_journal`, as the typed record API of AD-9 and AD-26 would.
- `src/pages.rs` reads the main file, the WAL and the shm as bytes, never through SQL. It decrypts every page of the main file (free pages included) and every frame physically present in the WAL (stale frames of an earlier WAL generation included) with AES-256-CBC, using the SQLCipher 4 page layout (IV and HMAC in an 80-byte reserve, salt in clear at the start of page 1). Any layout surprise is an error, not a pass-through: a file length that is not whole 4096-byte pages, a decoded page 1 whose page size differs, a WAL page size other than 4096, a partial trailing WAL frame. It also parses the WAL header (checkpoint sequence and salts). The shm is not encrypted by SQLCipher and is scanned as is.
- `src/scan.rs` indexes every 16-byte and every 8-byte window of every known value and reports a value as found when a run of that many contiguous bytes of it appears anywhere.
- `src/checks.rs` holds the checks. Every expected absence is scanned with both windows and paired with a control from the same images: values that must still be there (live rows, kept keys) are found in the file. `src/main.rs` prints the checks; `tests/checks.rs` asserts that every check passes; `src/scan.rs` has unit tests for both windows.

**Dependencies** (exact versions from `Cargo.lock`):

- `rusqlite` 0.40.2 with features `bundled-sqlcipher-vendored-openssl` and `hooks` (the authorizer API; no extra crate), which brings `libsqlite3-sys` 0.38.2, SQLite 3.51.3, SQLCipher 4.14.0 community, `openssl-sys` 0.9.117 and `openssl-src` 300.6.1+3.6.3 (OpenSSL 3.6.3). SQLCipher is settled by D2.
- `openssl-sys` 0.9.117 declared directly. It is already in the tree as SQLCipher's crypto provider, so no new code enters the build; the inspection code uses its `EVP_*` AES-256-CBC functions to decrypt raw pages. That and one call to `sqlite3_wal_checkpoint_v2` are the only `unsafe` code in the crate, each with a `SAFETY` comment. No other crate.
- Toolchain in the container: rustc and cargo 1.99.1; `rustfmt` and `clippy` are added by `run.sh` because the image ships without them (so the run needs network access).

**Deviations.**

- Location: AC1 names `spikes/e17-secure-delete/`; the spike is in `spikes/secure-delete-wal/`, as the epic's spike dispatch asked. Nothing else depends on the path.
- The record cipher is not implemented. The record ciphertext and the wrapped record key are random bytes of the right sizes (a 48-byte wrapped key stands for a 32-byte key plus a 16-byte AEAD tag), because the question is only whether those bytes leave the disk. The unwrapped record key is never written to a file in the design, so the wrapped form is what the scans look for.
- Journal images are random bytes, not JSON text, so that the 8-byte pass cannot match by accident; what `secure_delete` does to a cell does not depend on its content type.
- The test content and the test SQLCipher key come from a fixed-seed SplitMix64 generator, so every run writes the same known plaintext. They are test values, not keys.
- The authorizer used by the spike refuses every PRAGMA, ATTACH and DETACH: stricter than story 1.7's allowlist, identical for the statements tested.
- Errors are `Box<dyn Error>` rather than a typed error: a spike crate, no new dependency.
- The crate was built and run only in Docker. A native Windows build was not attempted (the vendored OpenSSL build needs Perl and a C toolchain); Linux is the product platform.

**Open decision tasks settled.** The story lists none explicitly; the spike settles the ones its result forces, with the recommended answer:

1. `secure_delete` is ON, never FAST: FAST leaves the overflow pages of deleted rows on the freelist with their content (check `secure_delete_fast_leaves_freed_overflow_pages_*`).
2. Every connection the Core opens sets `PRAGMA secure_delete = ON` and reads the value back, before its authorizer is installed, the migration connection of AD-23 included. The pragma is per connection, not stored in the file. A connection given a SQLCipher key already reports ON without setting it (observed with SQLCipher 4.14.0; the build sets no `SQLITE_SECURE_DELETE` compile option, so the default comes from SQLCipher's key handling), but an unkeyed connection reports OFF, and the design should not rest on a library default.
3. The Story 3.6 retention purge is followed, in the same maintenance step, by a TRUNCATE checkpoint, retried until it reports not busy and the WAL is empty. Mechanism: runtime connections refuse PRAGMAs outside an allowlist (story 1.7, AD-9, Story 3.1), so `PRAGMA wal_checkpoint(TRUNCATE)` cannot run there; the Core calls the C API `sqlite3_wal_checkpoint_v2(..., SQLITE_CHECKPOINT_TRUNCATE, ...)`, which prepares no statement and is not seen by the authorizer (verified by `checkpoint_c_api_runs_under_the_authorizer`). Deleting under `secure_delete` alone does not remove rows from disk before a checkpoint, and a PASSIVE (automatic) checkpoint leaves them in the WAL (AC2). The same applies to crypto-shredding: destroying a wrapped record key is a delete followed by a TRUNCATE checkpoint.
4. A wrapped record key is never journaled with its value: either the typed record API excludes the wrapped key from before-images, or shredding also deletes the journal rows that hold it in the same step. Otherwise the destroyed key survives in `_journal` for the 30-day retention (check `journaled_shredding_keeps_keys_until_journal_rows_go_*`). Which of the two is chosen is open for Story 3.6; the recommended one is never journaling the wrapped key, because it keeps the key out of the journal entirely.
5. VACUUM is not needed after a purge when items 1 to 4 hold. It stays the fallback for content deleted while `secure_delete` was off, and it was verified to remove such content. VACUUM is refused under the authorizer (it attaches a temporary database internally), so it runs only on a dedicated Core maintenance connection with no module authorizer, opened for that purpose and closed after it (Story 3.1 owns the connection types).
6. `journal_size_limit` is set on every connection (value 0 in the spike) as defence in depth: the first commit after a WAL restart then cuts the WAL file to what that commit wrote, so stale frames do not outlive the restart even if a TRUNCATE checkpoint is missed (check `journal_size_limit_cuts_stale_wal_frames_*`). It does not replace item 3: before the restart, the stale frames are still there.
7. The build compiles `SQLITE_TEMP_STORE=2`, and a keyed connection's effective `temp_store` is 0 (use that default), so VACUUM and large sorts keep temporary data in memory. The product never sets `PRAGMA temp_store = FILE`, and the authorizer's pragma allowlist should not allow `temp_store`.

## Result

Command, from the repository root on the Windows development host with Docker Desktop: `bash spikes/secure-delete-wal/run.sh`. Run of 2026-10-16, after the review fixes: exit code 0, 29 `PASS` and 0 `FAIL` lines: `toolchain_components`, `build`, `fmt`, `clippy` (`-D warnings`, all targets), `tests` (5 tests), and 24 spike checks. Earlier runs during the spike printed `FAIL` lines and exited 1, which shows the failure path works.

Environment lines printed by the run: SQLite 3.51.3, SQLCipher 4.14.0 community, crypto provider OpenSSL 3.6.3, compile option `TEMP_STORE=2`.

Reading the numbers: "found" counts distinct known values of which at least one run of 16 bytes (and, where stated, of 8 bytes) appears; each journal set has 72 values (24 rows times `call_id`, before-image and after-image); each key set has 10. "Asserted" means the check fails if the value differs; "observed" means the number is printed by the run but not checked, so it may vary with SQLite versions or workload shape.

**Inspection controls.** `sqlcipher_pages_and_wal_frames_decrypt` (asserted): the raw page 1 starts with a salt, not the SQLite magic string; the decrypted page 1 header reads page size 4096, reserve 80, payload fractions 64/32/32; before any checkpoint all 72 live and 72 expired values are found in the decrypted WAL; after a TRUNCATE checkpoint all of them are found in the decrypted file; neither the live nor the expired values are found in the raw bytes of the file, the WAL or the shm. The shm scan has no positive control: no known value is ever expected in the shm (it holds the WAL index, never page content), so a zero there is consistent with both a working and a broken scan of that file.

**AC1: PASS.** `secure_delete = ON`, rows deleted, TRUNCATE checkpoint, file and WAL decrypted and scanned (all asserted):

- `ac1_purge_of_checkpointed_rows_*` (rows already in the main file, the 30-day case): 24 rows deleted; checkpoint not busy; WAL 0 bytes; no run of 16 bytes or more, and no run of 8 bytes or more, of any deleted value in the file, the WAL or the shm (0/72 each); live values in the file 72/72.
- `ac1_purge_of_uncheckpointed_rows_*` (rows still only in the WAL): same.
- In both, a following VACUUM and TRUNCATE checkpoint keeps the same result (file from 344 064 to 180 224 bytes, observed).

**AC2: PASS, with a finding.** Deletion without a checkpoint, files inspected before the next one:

- Rows still in the WAL when deleted (`ac2_wal_keeps_rows_until_truncate_or_close_*`), asserted: after the DELETE, every deleted value is in the WAL (72/72) and none in the file; the insert frames still hold them, the delete frames are zeroed. A PASSIVE checkpoint, which is what the automatic checkpoint runs, completes (observed `(0, 152, 152)`, asserted not busy and all frames copied), puts the live rows in the file (72/72) and leaves every deleted value in the WAL (72/72) with the WAL length unchanged (626 272 bytes, 152 frames). The next write restarts the WAL (the header's checkpoint sequence goes from 0 to 1 and both salts change) without changing its length, and every deleted value is still in the WAL (72/72). After the last connection closes, the WAL file is gone and no run of 16 or 8 bytes of a deleted value remains, with the live rows still in the file.
- Rows already checkpointed when deleted (`ac2_main_file_keeps_rows_until_checkpoint_*`), asserted: after the DELETE, the file still holds every deleted value (72/72) and the delete frames in the WAL hold none (0/72 with both windows). After a complete PASSIVE checkpoint (`(0, 48, 48)` observed), no run of 16 or 8 bytes remains anywhere, live rows 72/72 in the file.
- For how long: rows deleted from the main file stay there until the next checkpoint of any kind. Rows whose insert frames are still in the WAL stay in the WAL file until a TRUNCATE checkpoint, the close of the last connection, a WAL restart under `journal_size_limit` (item 6), or until later writes happen to overwrite those exact frames; an automatic or PASSIVE checkpoint does not remove them, and the WAL keeps its high-water size. With connections that stay open while a partition is unlocked, that is unbounded in time. Items 3 and 6 of the settled tasks close it. On disk the content stays encrypted under the file key throughout; the exposure is to whoever holds that key, which is the case a deletion claim is about.

**AC3: not triggered.** No plaintext of deleted rows remains after AC1, so the fallback is not needed for the claim. It was still exercised: `secure_delete_off_leaves_rows_vacuum_removes_them_*` asserts that with `secure_delete = OFF` deleted values remain in the file after a TRUNCATE checkpoint (68/72 observed), and that VACUUM plus a TRUNCATE checkpoint leaves no run of 16 or 8 bytes of them while keeping the live rows. The backup caveat stands whatever the result; because this spike does not edit `doc/decisions.md`, it is recorded as a proposed update below.

**Other checks (all PASS).**

- `secure_delete_fast_leaves_freed_overflow_pages_*`: under FAST, values of rows held inside b-tree pages leave no run of 16 or 8 bytes (asserted, 0/36, with live control 72/72), but values of rows with overflow pages remain in the file after a TRUNCATE checkpoint (asserted more than 0; 24/36 observed: the before- and after-images that sit in the overflow chain).
- `secure_delete_is_set_per_connection` (asserted): SQLCipher, a connection that set OFF reports 0 while a second connection on the same file that sets nothing reports 1; plain, a connection that set ON reports 1 while a second one reports 0.
- `temp_store_defaults_to_memory` (asserted): on a keyed SQLCipher connection, compile option `TEMP_STORE=2`, effective `temp_store` 0. SQLite unlinks temp files as soon as it opens them, so the check reads the settings; it does not watch the disk.
- `checkpoint_c_api_runs_under_the_authorizer` (SQLCipher, asserted): with an authorizer refusing PRAGMA, ATTACH and DETACH, `PRAGMA wal_checkpoint(TRUNCATE)` fails ("not authorized"); `sqlite3_wal_checkpoint_v2` in TRUNCATE mode succeeds, the WAL is 0 bytes and no run of 16 or 8 bytes of a deleted value remains, live control 72/72; VACUUM under the same authorizer fails ("authorization denied").
- `journal_size_limit_cuts_stale_wal_frames_*` (asserted): with `journal_size_limit = 0`, after a complete PASSIVE checkpoint the WAL still holds every deleted value (626 272 bytes, observed); after the next write the WAL is cut (4 152 bytes, one frame, observed; asserted smaller) and no run of 16 or 8 bytes of a deleted value remains, live control 72/72.
- `shredding_removes_wrapped_keys_*` (asserted): 10 wrapped keys deleted; before the checkpoint the file still holds 10/10 of them; after a TRUNCATE checkpoint no run of 16 or 8 bytes of a destroyed key remains, kept keys 10/10, and the shredded records' ciphertext is still present 10/10, as designed.
- `journaled_shredding_keeps_keys_until_journal_rows_go_*` (asserted): after a journaled delete of the 10 key rows and a TRUNCATE checkpoint, all 10 destroyed keys are still in the file (in `_journal`); after deleting the 10 journal rows that hold them and a TRUNCATE checkpoint, no run of 16 or 8 bytes remains, kept keys 10/10.
- `shredding_without_secure_delete_needs_vacuum_*`: with OFF, destroyed keys remain in the file after a TRUNCATE checkpoint (asserted more than 0; 10/10 observed); after VACUUM and TRUNCATE, no run of 16 or 8 bytes remains (asserted), kept keys 10/10. Crypto-shredding inside the same file is therefore only as good as the deletion of the wrapped key row.
- SQLCipher and plain runs printed the same counts for every check that runs in both modes (observed, not checked).

**Limits, not run here.**

- Detection threshold: a deleted value is reported absent when no run of 8 bytes or more of it remains. Shorter remnants are not detected.
- Filesystem and device remanence: a TRUNCATE checkpoint and a VACUUM shrink files, and the freed filesystem blocks and SSD wear-levelled copies may keep older page images. Those images are SQLCipher ciphertext under the file key. Not run here; out of reach of a file-level inspection.
- Backups and cold copies: a backup or a migration cold copy (`<file>.pre-<version>`, AD-23) taken before the purge keeps the expired entries until it expires (7 daily and 4 weekly backups) or is removed after the next verified backup. Not tested here; it follows from the design.
- Workload shape: one module file, one connection, no concurrent readers. A reader holding an old snapshot can make a TRUNCATE checkpoint return busy; the retry of item 3 covers it, but it was not exercised.
- The spike ran on the container filesystem under Docker Desktop, not on the reference host (Debian 13 on SSD). What it measures is the content SQLite and SQLCipher write into the files, which does not depend on the filesystem; Story 3.6 reuses the procedure on the product build.

## Proposed design document updates

Not applied: this spike does not edit shared design documents. D120 is the next free decision number at the time of writing; another V0.1 spike may take it first.

1. `doc/research-notes.md`, section 3, E17 row, Pass criterion column: after "...are deleted under `secure_delete` after 30 days (D113)", add: "**Passed** (story 1.11, `spikes/secure-delete-wal/`): with `secure_delete` ON and a TRUNCATE checkpoint after the delete, no run of 8 bytes or more of any deleted row or destroyed wrapped key remains in the decrypted file, WAL or shm; without the TRUNCATE checkpoint, rows stay in the file until the next checkpoint and in the WAL until a TRUNCATE checkpoint, the last close or a WAL restart under `journal_size_limit` (D120)."
2. `doc/research-notes.md`, status line: replace "Apart from the AD-36 construction (D119), nothing here has been proven by a prototype." with "Apart from the AD-36 construction (D119) and E17 (D120), nothing here has been proven by a prototype." At the end of the update paragraph, add: "Story 1.11 then passed E17 (D120)."
3. `doc/decisions.md`: add D120, "Deletion is `secure_delete` ON plus a TRUNCATE checkpoint", status Accepted, amending D2 and D113: "Context: D2 and D113 rely on `secure_delete` for deletions that must be real, and E17 tested it on SQLCipher files in WAL mode. Decision: every connection the Core opens sets `PRAGMA secure_delete = ON` (never FAST) and `journal_size_limit`, and reads them back, before its authorizer is installed; the journal retention purge and the destruction of wrapped record keys are each followed by a TRUNCATE checkpoint through `sqlite3_wal_checkpoint_v2`, which the connection authorizer does not see, retried until the WAL is empty; wrapped record keys are never journaled, or shredding also deletes the journal rows that hold the key; temporary storage stays in memory (`SQLITE_TEMP_STORE=2`, `temp_store` not in the authorizer allowlist); VACUUM, which the authorizer refuses, is the fallback for content deleted while `secure_delete` was off and runs only on a dedicated Core maintenance connection. Consequences: deleted rows leave the live files at the checkpoint, not at the delete; copies in existing backups and migration cold copies keep them until those expire, which is the backup caveat; filesystem and SSD remanence of freed blocks holds only ciphertext under the file key and is not covered by the claim."
4. `doc/architecture.md`, section 5.1, bullet "`secure_delete` is on. WAL files and journals live next to the database and are covered by the same encryption.": replace with "`secure_delete` is ON (never FAST) on every connection, set and read back at open because the pragma is per connection. WAL files and journals live next to the database and are covered by the same encryption. A deletion that must be real (journal retention, crypto-shredding) is followed by a TRUNCATE checkpoint through the SQLite C API: until a checkpoint the old pages stay in the file, and until a TRUNCATE checkpoint the WAL can keep the rows (E17, D120)."
5. `doc/architecture.md`, section 5.1, crypto-shredding bullet: after "deletion destroys that key (**crypto-shredding**).", add: "Destroying the key is a delete of its wrapped form under `secure_delete` followed by a TRUNCATE checkpoint, and the wrapped key is never copied into the write journal (or the journal rows that hold it are deleted with it); otherwise the wrapped key stays readable to whoever holds the file key (E17, D120)."
6. `doc/architecture.md`, section 12, "Journal" bullet, and `doc/architecture-spine.md`, AD-26 rule: replace "deleted under `secure_delete`" with "deleted under `secure_delete` = ON and followed by a TRUNCATE checkpoint", and add D120 to the citation ("[ADOPTED, D113, D120]" in AD-26). In AD-26, after "the before and after images", add: "(a wrapped record key is never part of an image, D120)".
7. `doc/architecture-spine.md`, AD-23 rule, after the last sentence "Every close of a file runs `checkpoint(TRUNCATE)`.", add: "The migration connection sets `secure_delete` = ON like every other connection; checkpoints on authorizer-guarded connections go through `sqlite3_wal_checkpoint_v2`, and VACUUM runs only on a dedicated Core maintenance connection (D120)."
8. `doc/key-management.md`, section 2 table, Record keys row, last column: replace "Crypto-shredding (delete = destroy key)" with "Crypto-shredding (delete = destroy the wrapped key under `secure_delete` ON, never journaled, then a TRUNCATE checkpoint, D120)".
9. `doc/prd.md`, FR-29 consequences, first bullet: replace "expired entries are deleted under `secure_delete` (DC-68)" with "expired entries are deleted under `secure_delete` and followed by a TRUNCATE checkpoint, so they leave the live files (DC-68, E17)".
10. `doc/stories/story-3.6-core-journal-tables-and-caller-idempotency.md`, AC6: the E17 result to apply is items 1 to 4 and 6 of "Open decision tasks settled" above, including the open choice of item 4; no fallback is taken. `doc/stories/story-3.1-sqlcipher-storage-layer-and-connection-authorizer.md`: add the per-connection `secure_delete` and `journal_size_limit` setup before the authorizer, checkpoints through `sqlite3_wal_checkpoint_v2`, and the dedicated maintenance connection for VACUUM.
