//! The spike's checks. Each one builds its own database, drives it through the steps it
//! names, inspects the bytes on disk after each step and returns the evidence lines, or
//! the first expectation that did not hold.
//!
//! Every expected absence is scanned twice (runs of 16 and of 8 bytes) and paired with a
//! control from the same images: values that must still be there are found in the file.

use rusqlite::Connection;

use crate::pages;
use crate::scan::NeedleSet;
use crate::store::{self, Images, Mode, Result, SecureDelete};

type Evidence = Vec<String>;

pub struct Check {
    pub name: String,
    run: Box<dyn Fn() -> Result<Evidence>>,
}

impl Check {
    pub fn run(&self) -> Result<Evidence> {
        (self.run)()
    }
}

fn check(name: impl Into<String>, run: impl Fn() -> Result<Evidence> + 'static) -> Check {
    Check {
        name: name.into(),
        run: Box::new(run),
    }
}

fn ensure(holds: bool, failure: impl FnOnce() -> String) -> Result<()> {
    if holds { Ok(()) } else { Err(failure().into()) }
}

/// No run of 16 or of 8 bytes of any `deleted` value in the decoded file, WAL or shm,
/// and every `kept` value found in the decoded file of the same images.
fn absent_with_control(
    stage: &str,
    images: &Images,
    deleted: &NeedleSet,
    kept: &NeedleSet,
) -> Result<String> {
    let long = images.decoded(deleted);
    let short = images.decoded_short(deleted);
    let control = images.decoded(kept);
    ensure(long.nowhere() && short.nowhere(), || {
        format!("{stage}: deleted values survive: 16-byte runs {long}; 8-byte runs {short}")
    })?;
    ensure(control.main == control.of, || {
        format!("{stage}: control values missing from the file: {control}")
    })?;
    Ok(format!(
        "{stage}: deleted, 16-byte runs {long}; deleted, 8-byte runs {short}; kept {control}; {}",
        images.sizes()
    ))
}

/// The checkpoint completed: not busy, and every frame of the WAL was copied back.
fn ensure_complete(stage: &str, (busy, log, done): (i64, i64, i64)) -> Result<()> {
    ensure(busy == 0 && log == done, || {
        format!("{stage}: checkpoint returned (busy {busy}, log {log}, checkpointed {done})")
    })
}

pub fn all() -> Vec<Check> {
    let mut checks = vec![
        check(
            "sqlcipher_pages_and_wal_frames_decrypt",
            sqlcipher_pages_and_wal_frames_decrypt,
        ),
        check(
            "secure_delete_is_set_per_connection",
            secure_delete_is_set_per_connection,
        ),
        check(
            "temp_store_defaults_to_memory",
            temp_store_defaults_to_memory,
        ),
        check(
            "checkpoint_c_api_runs_under_the_authorizer",
            checkpoint_c_api_runs_under_the_authorizer,
        ),
    ];
    for mode in [Mode::SqlCipher, Mode::Plain] {
        let m = mode.label();
        checks.extend([
            check(format!("ac1_purge_of_uncheckpointed_rows_{m}"), move || {
                ac1_purge(mode, false)
            }),
            check(format!("ac1_purge_of_checkpointed_rows_{m}"), move || {
                ac1_purge(mode, true)
            }),
            check(
                format!("ac2_wal_keeps_rows_until_truncate_or_close_{m}"),
                move || ac2_wal_keeps_rows_until_truncate_or_close(mode),
            ),
            check(
                format!("ac2_main_file_keeps_rows_until_checkpoint_{m}"),
                move || ac2_main_file_keeps_rows_until_checkpoint(mode),
            ),
            check(
                format!("journal_size_limit_cuts_stale_wal_frames_{m}"),
                move || journal_size_limit_cuts_stale_wal_frames(mode),
            ),
            check(
                format!("secure_delete_off_leaves_rows_vacuum_removes_them_{m}"),
                move || secure_delete_off_leaves_rows_vacuum_removes_them(mode),
            ),
            check(
                format!("secure_delete_fast_leaves_freed_overflow_pages_{m}"),
                move || secure_delete_fast_leaves_freed_overflow_pages(mode),
            ),
            check(format!("shredding_removes_wrapped_keys_{m}"), move || {
                shredding_removes_wrapped_keys(mode)
            }),
            check(
                format!("journaled_shredding_keeps_keys_until_journal_rows_go_{m}"),
                move || journaled_shredding_keeps_keys_until_journal_rows_go(mode),
            ),
            check(
                format!("shredding_without_secure_delete_needs_vacuum_{m}"),
                move || shredding_without_secure_delete_needs_vacuum(mode),
            ),
        ]);
    }
    checks
}

/// Library versions and compile options that decide the behaviour under test.
pub fn environment() -> Result<Evidence> {
    let conn = Connection::open_in_memory()?;
    // The cipher pragmas answer only on a connection that has a key.
    conn.pragma_update(None, "key", "environment-probe")?;
    let text = |sql: &str| -> Result<String> {
        Ok(conn.query_row(sql, [], |row| row.get::<_, String>(0))?)
    };
    let mut lines = vec![
        format!("SQLite {}", rusqlite::version()),
        format!("SQLCipher {}", text("PRAGMA cipher_version")?),
        format!(
            "crypto provider {} {}",
            text("PRAGMA cipher_provider")?,
            text("PRAGMA cipher_provider_version")?
        ),
    ];
    let relevant: Vec<String> = compile_options(&conn)?
        .into_iter()
        .filter(|option| option.contains("TEMP_STORE") || option.contains("SECURE_DELETE"))
        .collect();
    lines.push(format!("compile options: {}", relevant.join(", ")));
    Ok(lines)
}

fn compile_options(conn: &Connection) -> Result<Vec<String>> {
    let mut statement = conn.prepare("PRAGMA compile_options")?;
    Ok(statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Positive control for the inspection itself: page 1 keeps the salt in clear and decodes
/// to a valid header with the layout the decryption assumes; every row is found in the
/// decrypted WAL and in the decrypted file; no row is found in the raw bytes.
fn sqlcipher_pages_and_wal_frames_decrypt() -> Result<Evidence> {
    let in_wal = store::journal("decrypt-wal", Mode::SqlCipher, SecureDelete::On, false)?;
    let wal = in_wal.db.images()?;
    let wal_live = wal.decoded(&in_wal.live);
    let wal_expired = wal.decoded(&in_wal.expired);
    ensure(
        wal_live.wal == wal_live.of && wal_expired.wal == wal_expired.of,
        || format!("rows missing from the decrypted WAL: live {wal_live}, expired {wal_expired}"),
    )?;
    let wal_raw_live = wal.raw(&in_wal.live);
    let wal_raw_expired = wal.raw(&in_wal.expired);
    ensure(wal_raw_live.nowhere() && wal_raw_expired.nowhere(), || {
        format!("plaintext in the raw files: live {wal_raw_live}, expired {wal_raw_expired}")
    })?;

    let in_file = store::journal("decrypt-file", Mode::SqlCipher, SecureDelete::On, true)?;
    let file = in_file.db.images()?;
    ensure(!pages::starts_with_magic(&file.main_raw), || {
        "raw page 1 starts with the SQLite magic string, not a salt".to_string()
    })?;
    let header = pages::decoded_header(&file.main, in_file.db.encoding());
    let expected = pages::Header {
        page_size: pages::PAGE_SIZE,
        reserve: u8::try_from(pages::RESERVE)?,
        fractions: [64, 32, 32],
    };
    ensure(header == Some(expected), || {
        format!("decrypted page 1 header is {header:?}, expected {expected:?}")
    })?;
    let file_live = file.decoded(&in_file.live);
    let file_expired = file.decoded(&in_file.expired);
    ensure(
        file_live.main == file_live.of && file_expired.main == file_expired.of,
        || {
            format!(
                "rows missing from the decrypted file: live {file_live}, expired {file_expired}"
            )
        },
    )?;
    let file_raw_live = file.raw(&in_file.live);
    let file_raw_expired = file.raw(&in_file.expired);
    ensure(
        file_raw_live.nowhere() && file_raw_expired.nowhere(),
        || format!("plaintext in the raw files: live {file_raw_live}, expired {file_raw_expired}"),
    )?;
    Ok(vec![
        format!("raw page 1 starts with a salt; decoded header {header:?}"),
        format!("before any checkpoint, decrypted: live {wal_live}; expired {wal_expired}"),
        format!("after a TRUNCATE checkpoint, decrypted: live {file_live}; expired {file_expired}"),
        format!("raw bytes before any checkpoint: live {wal_raw_live}; expired {wal_raw_expired}"),
        format!(
            "raw bytes after a TRUNCATE checkpoint: live {file_raw_live}; expired {file_raw_expired}"
        ),
    ])
}

/// `secure_delete` is a connection setting, not a file property: a connection that does
/// not set it gets the default whatever another connection on the file set. The default
/// differs: a connection given a SQLCipher key reports ON, an unkeyed one OFF (the build
/// sets no SQLITE_SECURE_DELETE compile option, see the environment lines). Each mode
/// sets the opposite of its default so that the second connection shows the default.
fn secure_delete_is_set_per_connection() -> Result<Evidence> {
    let read = |conn: &Connection| -> Result<i64> {
        Ok(conn.query_row("PRAGMA secure_delete", [], |row| row.get(0))?)
    };
    let mut evidence = Vec::new();
    for (mode, setting, expected_default) in [
        (Mode::SqlCipher, SecureDelete::Off, 1),
        (Mode::Plain, SecureDelete::On, 0),
    ] {
        let journal = store::journal("per-connection", mode, setting, false)?;
        let configured = read(journal.db.conn())?;
        let default = read(&journal.db.open_keyed()?)?;
        ensure(default == expected_default && default != configured, || {
            format!(
                "{}: configured connection reports {configured}, a second one that sets nothing reports {default}, expected default {expected_default}",
                mode.label()
            )
        })?;
        evidence.push(format!(
            "{}: connection that set {setting:?} reports {configured}; a second connection on the same file that sets nothing reports {default}",
            mode.label()
        ));
    }
    Ok(evidence)
}

/// On a keyed SQLCipher connection, temporary storage (VACUUM, large sorts) defaults to
/// memory: the build compiles SQLITE_TEMP_STORE=2 and the connection's effective
/// `temp_store` is 0 (use the compile default) or 2 (memory). SQLite unlinks its temp
/// files as soon as it opens them, so a directory listing cannot observe them; this
/// check therefore reads the settings, it does not watch the disk.
fn temp_store_defaults_to_memory() -> Result<Evidence> {
    let journal = store::journal("temp-store", Mode::SqlCipher, SecureDelete::On, false)?;
    let conn = journal.db.conn();
    let compiled: Vec<String> = compile_options(conn)?
        .into_iter()
        .filter(|option| option.starts_with("TEMP_STORE="))
        .collect();
    let effective: i64 = conn.query_row("PRAGMA temp_store", [], |row| row.get(0))?;
    ensure(compiled == ["TEMP_STORE=2"], || {
        format!("compile option is {compiled:?}, expected TEMP_STORE=2")
    })?;
    ensure(effective == 0 || effective == 2, || {
        format!("effective temp_store on a keyed connection is {effective}")
    })?;
    Ok(vec![format!(
        "keyed connection: compile option {}, PRAGMA temp_store = {effective}",
        compiled.join(", ")
    )])
}

/// Runtime connections carry an authorizer that refuses PRAGMAs outside an allowlist
/// (story 1.7, AD-9). Under it `PRAGMA wal_checkpoint(TRUNCATE)` is refused, while
/// `sqlite3_wal_checkpoint_v2`, which prepares no statement, checkpoints and empties the
/// WAL. VACUUM is reported as observed under the same authorizer.
fn checkpoint_c_api_runs_under_the_authorizer() -> Result<Evidence> {
    let journal = store::journal("authorizer", Mode::SqlCipher, SecureDelete::On, false)?;
    journal.purge_expired()?;
    store::refuse_pragmas_and_attach(journal.db.conn())?;
    let pragma = journal.db.checkpoint("TRUNCATE");
    ensure(pragma.is_err(), || {
        format!("PRAGMA wal_checkpoint ran under the authorizer: {pragma:?}")
    })?;
    let (log, checkpointed) = store::checkpoint_truncate_c_api(journal.db.conn())?;
    let after = journal.db.images()?;
    ensure(after.wal_raw.is_empty(), || {
        format!(
            "WAL not empty after the C API checkpoint: {}",
            after.sizes()
        )
    })?;
    let scan = absent_with_control(
        "after the C API checkpoint",
        &after,
        &journal.expired,
        &journal.live,
    )?;
    let vacuum = journal.db.vacuum();
    ensure(vacuum.is_err(), || {
        "VACUUM ran under an authorizer that refuses ATTACH".to_string()
    })?;
    Ok(vec![
        format!(
            "PRAGMA wal_checkpoint(TRUNCATE) refused: {}",
            pragma
                .err()
                .map(|error| error.to_string())
                .unwrap_or_default()
        ),
        format!("sqlite3_wal_checkpoint_v2(TRUNCATE): log {log}, checkpointed {checkpointed}"),
        scan,
        format!(
            "VACUUM under the same authorizer refused: {}",
            vacuum
                .err()
                .map(|error| error.to_string())
                .unwrap_or_default()
        ),
    ])
}

/// AC1: rows deleted under `secure_delete` = ON, then `wal_checkpoint(TRUNCATE)`; no run
/// of 16 or 8 bytes of a deleted value in the file, the WAL or the shm, while every live
/// row is still found. A following VACUUM keeps it so.
fn ac1_purge(mode: Mode, checkpoint_before_purge: bool) -> Result<Evidence> {
    let journal = store::journal("ac1", mode, SecureDelete::On, checkpoint_before_purge)?;
    let deleted = journal.purge_expired()?;
    let checkpoint = journal.db.checkpoint("TRUNCATE")?;
    ensure(checkpoint.0 == 0, || {
        format!("TRUNCATE checkpoint busy: {checkpoint:?}")
    })?;
    let after = journal.db.images()?;
    ensure(after.wal_raw.is_empty(), || {
        format!(
            "WAL not empty after TRUNCATE: {} bytes",
            after.wal_raw.len()
        )
    })?;
    let truncated = absent_with_control("after TRUNCATE", &after, &journal.expired, &journal.live)?;

    journal.db.vacuum()?;
    journal.db.checkpoint("TRUNCATE")?;
    let vacuumed = absent_with_control(
        "after VACUUM and TRUNCATE",
        &journal.db.images()?,
        &journal.expired,
        &journal.live,
    )?;
    Ok(vec![
        format!(
            "rows {} before the purge; {deleted} deleted; checkpoint (busy, log, done) {checkpoint:?}",
            if checkpoint_before_purge {
                "checkpointed into the file"
            } else {
                "only in the WAL"
            }
        ),
        truncated,
        vacuumed,
    ])
}

/// AC2, rows still in the WAL when they are deleted (inserted since the last checkpoint):
/// the insert frames keep every deleted row after the delete, after a complete PASSIVE
/// checkpoint (what the automatic checkpoint runs) and after the WAL restarts, and the
/// WAL keeps its length; only a TRUNCATE checkpoint (AC1) or the last close removes them.
fn ac2_wal_keeps_rows_until_truncate_or_close(mode: Mode) -> Result<Evidence> {
    let mut journal = store::journal("ac2-wal", mode, SecureDelete::On, false)?;
    journal.purge_expired()?;
    let purged = journal.db.images()?;
    let after_purge = purged.decoded(&journal.expired);
    ensure(
        after_purge.main == 0 && after_purge.wal == after_purge.of,
        || format!("expected every deleted row in the WAL and none in the file: {after_purge}"),
    )?;

    let passive_result = journal.db.checkpoint("PASSIVE")?;
    ensure_complete("PASSIVE", passive_result)?;
    ensure(passive_result.1 > 0, || {
        "PASSIVE found an empty WAL".to_string()
    })?;
    let passive = journal.db.images()?;
    let after_passive = passive.decoded(&journal.expired);
    let live_after_passive = passive.decoded(&journal.live);
    ensure(
        after_passive.main == 0 && after_passive.wal == after_passive.of,
        || format!("after PASSIVE, expected rows in the WAL only: {after_passive}"),
    )?;
    ensure(live_after_passive.main == live_after_passive.of, || {
        format!("after PASSIVE, live rows missing from the file: {live_after_passive}")
    })?;
    ensure(passive.wal_raw.len() == purged.wal_raw.len(), || {
        format!(
            "PASSIVE changed the WAL length: {} then {}",
            purged.sizes(),
            passive.sizes()
        )
    })?;

    // One small write after a complete checkpoint restarts the WAL from its first frame.
    journal.db.conn().execute_batch("PRAGMA user_version = 1")?;
    let restarted = journal.db.images()?;
    let after_restart = restarted.decoded(&journal.expired);
    let live_after_restart = restarted.decoded(&journal.live);
    let (before_header, after_header) = (passive.wal_header, restarted.wal_header);
    let restart_observed = match (before_header, after_header) {
        (Some(before), Some(after)) => {
            after.checkpoint_sequence == before.checkpoint_sequence.wrapping_add(1)
                && after.salts != before.salts
        }
        _ => false,
    };
    ensure(restart_observed, || {
        format!("no WAL restart: header {before_header:?} then {after_header:?}")
    })?;
    ensure(restarted.wal_raw.len() == passive.wal_raw.len(), || {
        format!(
            "the restart changed the WAL length: {} then {}",
            passive.sizes(),
            restarted.sizes()
        )
    })?;
    ensure(after_restart.wal == after_restart.of, || {
        format!("after the restart, expected every deleted row still in the WAL: {after_restart}")
    })?;
    ensure(live_after_restart.main == live_after_restart.of, || {
        format!("after the restart, live rows missing from the file: {live_after_restart}")
    })?;

    journal.db.close()?;
    let wal_exists = journal.db.wal_exists();
    ensure(!wal_exists, || {
        "the WAL file survives the last close".to_string()
    })?;
    let closed = absent_with_control(
        "after closing the last connection",
        &journal.db.images()?,
        &journal.expired,
        &journal.live,
    )?;
    Ok(vec![
        format!(
            "after DELETE, no checkpoint: deleted {after_purge}; {}",
            purged.sizes()
        ),
        format!(
            "after PASSIVE checkpoint {passive_result:?}: deleted {after_passive}; live {live_after_passive}; {}",
            passive.sizes()
        ),
        format!(
            "after the next write: WAL header {before_header:?} became {after_header:?}; deleted {after_restart}; live {live_after_restart}; {}",
            restarted.sizes()
        ),
        format!("WAL file exists after the last close: {wal_exists}"),
        closed,
    ])
}

/// AC2, rows already checkpointed into the file when they are deleted (the 30-day case):
/// the WAL frames of the delete are already zeroed, but the file keeps the old pages
/// until the next checkpoint of any kind copies the new ones over them.
fn ac2_main_file_keeps_rows_until_checkpoint(mode: Mode) -> Result<Evidence> {
    let journal = store::journal("ac2-file", mode, SecureDelete::On, true)?;
    journal.purge_expired()?;
    let purged = journal.db.images()?;
    let after_purge = purged.decoded(&journal.expired);
    let wal_short = purged.decoded_short(&journal.expired);
    ensure(after_purge.main == after_purge.of, || {
        format!("expected the file to keep every row until the checkpoint: {after_purge}")
    })?;
    ensure(after_purge.wal == 0 && wal_short.wal == 0, || {
        format!("expected the delete frames to hold no row: {after_purge}; 8-byte runs {wal_short}")
    })?;

    let passive_result = journal.db.checkpoint("PASSIVE")?;
    ensure_complete("PASSIVE", passive_result)?;
    let passive = absent_with_control(
        "after PASSIVE checkpoint",
        &journal.db.images()?,
        &journal.expired,
        &journal.live,
    )?;
    Ok(vec![
        format!(
            "after DELETE, no checkpoint: deleted {after_purge}; {}",
            purged.sizes()
        ),
        format!("PASSIVE checkpoint returned {passive_result:?}"),
        passive,
    ])
}

/// Defence in depth for AC2: with `journal_size_limit` = 0, the first commit after a WAL
/// restart truncates the WAL to what that commit wrote, so stale frames from before the
/// restart are cut off even without a TRUNCATE checkpoint.
fn journal_size_limit_cuts_stale_wal_frames(mode: Mode) -> Result<Evidence> {
    let journal = store::journal("size-limit", mode, SecureDelete::On, false)?;
    let limit = journal.db.set_journal_size_limit(0)?;
    journal.purge_expired()?;
    let passive_result = journal.db.checkpoint("PASSIVE")?;
    ensure_complete("PASSIVE", passive_result)?;
    let passive = journal.db.images()?;
    let after_passive = passive.decoded(&journal.expired);
    journal.db.conn().execute_batch("PRAGMA user_version = 1")?;
    let restarted = journal.db.images()?;
    ensure(restarted.wal_raw.len() < passive.wal_raw.len(), || {
        format!(
            "WAL not cut: {} then {}",
            passive.sizes(),
            restarted.sizes()
        )
    })?;
    let scan = absent_with_control(
        "after the next write",
        &restarted,
        &journal.expired,
        &journal.live,
    )?;
    Ok(vec![
        format!("journal_size_limit = {limit}"),
        format!(
            "after PASSIVE checkpoint: deleted {after_passive}; {}",
            passive.sizes()
        ),
        scan,
    ])
}

/// Control for AC1: with `secure_delete` = OFF the purge leaves rows in the file after a
/// TRUNCATE checkpoint. The fallback, VACUUM then TRUNCATE, removes them.
fn secure_delete_off_leaves_rows_vacuum_removes_them(mode: Mode) -> Result<Evidence> {
    let journal = store::journal("off", mode, SecureDelete::Off, true)?;
    journal.purge_expired()?;
    journal.db.checkpoint("TRUNCATE")?;
    let purged = journal.db.images()?;
    let after_purge = purged.decoded(&journal.expired);
    ensure(after_purge.main > 0, || {
        format!("expected deleted rows to stay in the file without secure_delete: {after_purge}")
    })?;

    journal.db.vacuum()?;
    journal.db.checkpoint("TRUNCATE")?;
    let vacuumed = absent_with_control(
        "after VACUUM and TRUNCATE",
        &journal.db.images()?,
        &journal.expired,
        &journal.live,
    )?;
    Ok(vec![
        format!(
            "after DELETE and TRUNCATE: deleted {after_purge}; {}",
            purged.sizes()
        ),
        vacuumed,
    ])
}

/// `secure_delete` = FAST zeroes deleted content inside b-tree pages but does not
/// overwrite pages it moves to the freelist, so the overflow pages of deleted rows keep
/// their content. ON is the setting that meets the claim.
fn secure_delete_fast_leaves_freed_overflow_pages(mode: Mode) -> Result<Evidence> {
    let journal = store::journal("fast", mode, SecureDelete::Fast, true)?;
    journal.purge_expired()?;
    journal.db.checkpoint("TRUNCATE")?;
    let purged = journal.db.images()?;
    let inline = absent_with_control(
        "after DELETE and TRUNCATE, rows inside b-tree pages",
        &purged,
        &journal.expired_inline,
        &journal.live,
    )?;
    let overflow = purged.decoded(&journal.expired_overflow);
    ensure(overflow.main > 0, || {
        format!("expected freed overflow pages to keep content under FAST: {overflow}")
    })?;
    Ok(vec![
        inline,
        format!("after DELETE and TRUNCATE, rows with overflow pages: {overflow}"),
    ])
}

/// Crypto-shredding with the wrapped record keys in the same file, `secure_delete` = ON:
/// the destroyed keys are gone after a TRUNCATE checkpoint, kept keys remain, and the
/// record ciphertext remains (unreadable without its key, which is the point).
fn shredding_removes_wrapped_keys(mode: Mode) -> Result<Evidence> {
    let shredding = store::shredding("shred", mode, SecureDelete::On)?;
    let destroyed = shredding.shred()?;
    let before_checkpoint = shredding.db.images()?.decoded(&shredding.shredded_keys);
    ensure(before_checkpoint.main == before_checkpoint.of, || {
        format!("expected the file to keep the keys until the checkpoint: {before_checkpoint}")
    })?;
    shredding.db.checkpoint("TRUNCATE")?;
    let after = shredding.db.images()?;
    let scan = absent_with_control(
        "after TRUNCATE",
        &after,
        &shredding.shredded_keys,
        &shredding.kept_keys,
    )?;
    let ciphertexts = after.decoded(&shredding.shredded_ciphertexts);
    ensure(ciphertexts.main == ciphertexts.of, || {
        format!("ciphertext of shredded records missing: {ciphertexts}")
    })?;
    Ok(vec![
        format!("{destroyed} wrapped keys deleted"),
        format!("before checkpoint: destroyed keys {before_checkpoint}"),
        scan,
        format!(
            "after TRUNCATE: ciphertext of shredded records {ciphertexts} (left in place by design)"
        ),
    ])
}

/// Shredding through a journaled write (the typed record API journals before-images,
/// spine AD-9 and AD-26): the destroyed keys survive in `_journal` after the delete and a
/// TRUNCATE checkpoint, and leave only when the journal rows holding them are deleted too.
fn journaled_shredding_keeps_keys_until_journal_rows_go(mode: Mode) -> Result<Evidence> {
    let shredding = store::shredding("shred-journaled", mode, SecureDelete::On)?;
    let destroyed = shredding.shred_journaled()?;
    shredding.db.checkpoint("TRUNCATE")?;
    let journaled = shredding.db.images()?.decoded(&shredding.shredded_keys);
    ensure(journaled.main == journaled.of, || {
        format!("expected every destroyed key in the journal before-images: {journaled}")
    })?;
    let purged = shredding.purge_key_journal()?;
    shredding.db.checkpoint("TRUNCATE")?;
    let scan = absent_with_control(
        "after deleting the journal rows and TRUNCATE",
        &shredding.db.images()?,
        &shredding.shredded_keys,
        &shredding.kept_keys,
    )?;
    Ok(vec![
        format!(
            "{destroyed} wrapped keys deleted through a journaled write; after TRUNCATE: destroyed keys {journaled}"
        ),
        format!("{purged} journal rows holding them deleted"),
        scan,
    ])
}

/// Crypto-shredding is only as good as the deletion of the wrapped key inside the file:
/// with `secure_delete` = OFF the destroyed keys stay readable after a checkpoint, and a
/// VACUUM is needed to remove them.
fn shredding_without_secure_delete_needs_vacuum(mode: Mode) -> Result<Evidence> {
    let shredding = store::shredding("shred-off", mode, SecureDelete::Off)?;
    shredding.shred()?;
    shredding.db.checkpoint("TRUNCATE")?;
    let after = shredding.db.images()?.decoded(&shredding.shredded_keys);
    ensure(after.main > 0, || {
        format!("expected destroyed keys to stay without secure_delete: {after}")
    })?;
    shredding.db.vacuum()?;
    shredding.db.checkpoint("TRUNCATE")?;
    let vacuumed = absent_with_control(
        "after VACUUM and TRUNCATE",
        &shredding.db.images()?,
        &shredding.shredded_keys,
        &shredding.kept_keys,
    )?;
    Ok(vec![
        format!("after DELETE and TRUNCATE: destroyed keys {after}"),
        vacuumed,
    ])
}
