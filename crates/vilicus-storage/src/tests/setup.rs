//! AC1, AC4, AC5, AC6, AC10 and AC11: keying, the setup order and its read-back, the key epoch,
//! closing and checkpointing.

use std::fs;
use std::path::Path;

use rusqlite::Connection;

use super::{EPOCH, KEY, create_module_file, module_file, raw_connection, scratch_dir};
use crate::authorizer::{self, Policy};
use crate::error::Error;
use crate::handle::{Setup, raw_key_text};
use crate::{
    BUSY_TIMEOUT, Handle, JOURNAL_SIZE_LIMIT, KeyEpoch, Migration, Read, Role, RoleKind, Settings,
    Write, create, open, read_epoch,
};

const OTHER_KEY: [u8; 32] = [0xa5; 32];

/// A value no page of a file holds unless it was written there, to look for in raw bytes.
const MARKER: &str = "vilicus-storage-plaintext-marker-6d1f0c";

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn wal_len(path: &Path) -> u64 {
    fs::metadata(path).map_or(0, |metadata| metadata.len())
}

// --- AC1 ---

#[test]
fn create_writes_an_encrypted_file_named_module_dot_partition() {
    let dir = scratch_dir("ac1-create");
    let file = module_file(&dir);
    let handle = create(&file, &KEY, EPOCH).expect("create");
    handle
        .execute("CREATE TABLE IF NOT EXISTS t (v TEXT)", [])
        .expect_err("schema is refused on a write handle");
    handle.close().expect("close");
    raw_connection(&file.path())
        .execute_batch(&format!(
            "CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('{MARKER}');"
        ))
        .expect("write marker");
    assert_eq!(file.path(), dir.join("fixture.household.db"));
    let bytes = fs::read(file.path()).expect("read file");
    assert!(
        !bytes.starts_with(b"SQLite format 3\0"),
        "the file has a plaintext header"
    );
    assert!(
        !contains(&bytes, MARKER.as_bytes()),
        "the marker is in the file in clear"
    );
}

/// The file key is the raw key itself: the same 64 hex digits given as a passphrase, which
/// SQLCipher would run through its KDF, do not open the file.
#[test]
fn the_file_is_keyed_with_the_raw_key_not_a_passphrase_kdf() {
    let dir = scratch_dir("ac1-raw");
    let file = create_module_file(&dir);
    let hex: String = KEY.iter().map(|byte| format!("{byte:02x}")).collect();
    let as_passphrase = Connection::open(file.path()).expect("open");
    as_passphrase
        .execute_batch(&format!("PRAGMA key = '{hex}';"))
        .expect("key as passphrase");
    let read = as_passphrase.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    });
    assert!(
        read.is_err(),
        "the hex digits as a passphrase opened the file: {read:?}"
    );
    let raw = raw_connection(&file.path());
    assert!(
        raw.query_row("SELECT count(*) FROM items", [], |row| row.get::<_, i64>(0))
            .is_ok()
    );
}

#[test]
fn another_key_fails_without_exposing_content() {
    let dir = scratch_dir("ac1-wrong-key");
    let file = create_module_file(&dir);
    raw_connection(&file.path())
        .execute_batch(&format!("INSERT INTO items (label) VALUES ('{MARKER}')"))
        .expect("write marker");
    let outcomes = [
        open::<Migration>(&file, &OTHER_KEY).map(drop),
        open::<Write>(&file, &OTHER_KEY).map(drop),
        open::<Read>(&file, &OTHER_KEY).map(drop),
    ];
    for outcome in outcomes {
        let error = outcome.expect_err("another key opened the file");
        assert!(matches!(error, Error::WrongKey), "{error:?}");
        let shown = format!("{error} {error:?}");
        assert!(
            !shown.contains(MARKER) && !shown.contains("items"),
            "{shown}"
        );
    }
}

// --- AC6 ---

fn expected_settings(kind: RoleKind) -> Settings {
    Settings {
        secure_delete: 1,
        trusted_schema: false,
        journal_size_limit: JOURNAL_SIZE_LIMIT,
        journal_mode: "wal".to_owned(),
        synchronous: 2,
        query_only: kind == RoleKind::Read,
        foreign_keys: true,
        temp_store: 0,
        defensive: true,
        extension_loading_api: false,
    }
}

/// AC6: every setting reads back as set on every role, `secure_delete` 1 on a migration
/// connection as on the others, and the extension loading C API off.
#[test]
fn every_role_reads_back_the_setup() {
    let dir = scratch_dir("ac6-settings");
    let file = create_module_file(&dir);
    fn check<R: Role>(file: &crate::ModuleFile) {
        let handle = open::<R>(file, &KEY).expect("open");
        assert_eq!(
            handle.settings(),
            &expected_settings(R::KIND),
            "{:?}",
            R::KIND
        );
    }
    check::<Migration>(&file);
    check::<Write>(&file);
    check::<Read>(&file);
}

/// A setting that does not read back as required fails the open, with a typed error.
#[test]
fn a_setting_that_reads_back_wrong_is_a_typed_error() {
    let wrong = [
        Settings {
            secure_delete: 2,
            ..expected_settings(RoleKind::Write)
        },
        Settings {
            trusted_schema: true,
            ..expected_settings(RoleKind::Write)
        },
        Settings {
            journal_mode: "delete".to_owned(),
            ..expected_settings(RoleKind::Write)
        },
        Settings {
            synchronous: 1,
            ..expected_settings(RoleKind::Write)
        },
        Settings {
            query_only: true,
            ..expected_settings(RoleKind::Write)
        },
        Settings {
            temp_store: 1,
            ..expected_settings(RoleKind::Write)
        },
        Settings {
            defensive: false,
            ..expected_settings(RoleKind::Write)
        },
        Settings {
            extension_loading_api: true,
            ..expected_settings(RoleKind::Write)
        },
    ];
    for settings in wrong {
        let outcome = settings.clone().require(Setup::Role(RoleKind::Write));
        assert!(
            matches!(outcome, Err(Error::SetupMismatch { .. })),
            "{settings:?}: {outcome:?}"
        );
    }
    let read = Settings {
        query_only: false,
        ..expected_settings(RoleKind::Read)
    };
    assert!(matches!(
        read.require(Setup::Role(RoleKind::Read)),
        Err(Error::SetupMismatch { .. })
    ));
}

/// The read-back runs on a real open: a read handle, which does not set the journal mode, on a
/// file left in rollback-journal mode reads `delete` back and refuses to open.
#[test]
fn an_open_whose_setting_reads_back_wrong_fails() {
    let dir = scratch_dir("ac6-open-mismatch");
    let file = create_module_file(&dir);
    raw_connection(&file.path())
        .execute_batch("PRAGMA journal_mode = DELETE")
        .expect("leave WAL mode");
    let outcome = open::<Read>(&file, &KEY);
    assert!(
        matches!(&outcome, Err(Error::SetupMismatch { setting: "journal_mode", found, .. }) if found == "delete"),
        "{outcome:?}"
    );
}

/// Why the authorizer goes on last: SQLCipher's `key` and the setup pragmas go through it, so a
/// connection that installed it first could not be set up (Story 1.7, finding 6).
#[test]
fn the_setup_pragmas_are_refused_once_the_authorizer_is_on() {
    let dir = scratch_dir("ac6-order");
    let file = create_module_file(&dir);
    let connection = Connection::open(file.path()).expect("open");
    authorizer::install(&connection, Policy::Write).expect("install");
    for sql in [
        super::raw_key_pragma(&KEY),
        "PRAGMA secure_delete = ON".to_owned(),
        "PRAGMA trusted_schema = OFF".to_owned(),
        format!("PRAGMA journal_size_limit = {JOURNAL_SIZE_LIMIT}"),
        "PRAGMA journal_mode = WAL".to_owned(),
        "PRAGMA synchronous = FULL".to_owned(),
    ] {
        let outcome = connection.execute_batch(&sql).map_err(Error::from);
        assert!(
            outcome.as_ref().is_err_and(Error::is_refusal),
            "{sql}: {outcome:?}"
        );
    }
}

// --- AC5 ---

#[test]
fn the_epoch_is_in_the_sidecar_and_in_meta() {
    let dir = scratch_dir("ac5-epoch");
    let file = create_module_file(&dir);
    assert_eq!(read_epoch(&file).expect("sidecar"), EPOCH);
    assert_eq!(
        fs::read_to_string(file.epoch_path()).expect("sidecar text"),
        "vilicus key epoch 1\npartition_root_version 1\ngeneration 0\n"
    );
    let meta: Vec<(String, i64)> = raw_connection(&file.path())
        .prepare("SELECT key, value FROM _meta ORDER BY key")
        .expect("prepare")
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("read");
    assert_eq!(
        meta,
        [
            ("generation".to_owned(), 0),
            ("partition_root_version".to_owned(), 1)
        ]
    );
    assert_eq!(open::<Read>(&file, &KEY).expect("open").epoch(), EPOCH);
}

#[test]
fn write_epoch_updates_both_and_leaves_no_staging_file() {
    let dir = scratch_dir("ac5-write");
    let file = create_module_file(&dir);
    let next = KeyEpoch {
        partition_root_version: 2,
        generation: 5,
    };
    let mut handle = open::<Write>(&file, &KEY).expect("open");
    handle.write_epoch(next).expect("write epoch");
    assert_eq!(handle.epoch(), next);
    handle.close().expect("close");
    assert_eq!(read_epoch(&file).expect("sidecar"), next);
    assert_eq!(open::<Write>(&file, &KEY).expect("reopen").epoch(), next);
    let names: Vec<String> = fs::read_dir(&dir)
        .expect("list")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert!(
        !names.iter().any(|name| name.ends_with(".tmp")),
        "{names:?}"
    );
}

#[test]
fn a_sidecar_that_disagrees_with_meta_fails_every_open() {
    let dir = scratch_dir("ac5-mismatch-sidecar");
    let file = create_module_file(&dir);
    let other = KeyEpoch {
        partition_root_version: 1,
        generation: 1,
    };
    crate::file::write_epoch_sidecar(&file, other).expect("rewrite sidecar");
    let outcomes = [
        open::<Migration>(&file, &KEY).map(drop),
        open::<Write>(&file, &KEY).map(drop),
        open::<Read>(&file, &KEY).map(drop),
    ];
    for outcome in outcomes {
        assert!(
            matches!(outcome, Err(Error::EpochMismatch { sidecar, file: in_file }) if sidecar == other && in_file == EPOCH),
            "{outcome:?}"
        );
    }
}

#[test]
fn a_meta_that_disagrees_with_the_sidecar_fails_the_open() {
    let dir = scratch_dir("ac5-mismatch-meta");
    let file = create_module_file(&dir);
    raw_connection(&file.path())
        .execute_batch("UPDATE _meta SET value = 9 WHERE key = 'partition_root_version'")
        .expect("edit _meta");
    let outcome = open::<Write>(&file, &KEY);
    assert!(
        matches!(outcome, Err(Error::EpochMismatch { .. })),
        "{outcome:?}"
    );
}

#[test]
fn a_missing_or_malformed_epoch_fails_the_open() {
    let dir = scratch_dir("ac5-malformed");
    let file = create_module_file(&dir);
    fs::write(
        file.epoch_path(),
        "vilicus key epoch 1\npartition_root_version one\ngeneration 0\n",
    )
    .expect("write");
    assert!(matches!(
        open::<Read>(&file, &KEY),
        Err(Error::MalformedEpoch(_))
    ));

    let dir = scratch_dir("ac5-missing-meta");
    let file = create_module_file(&dir);
    raw_connection(&file.path())
        .execute_batch("DELETE FROM _meta")
        .expect("empty _meta");
    assert!(matches!(
        open::<Read>(&file, &KEY),
        Err(Error::MissingEpoch)
    ));

    let dir = scratch_dir("ac5-missing-sidecar");
    let file = create_module_file(&dir);
    fs::write(file.epoch_path(), "").expect("truncate sidecar");
    assert!(matches!(
        open::<Read>(&file, &KEY),
        Err(Error::MalformedEpoch(_))
    ));
}

#[test]
fn create_refuses_an_existing_file_or_sidecar() {
    let dir = scratch_dir("ac5-exists");
    let file = create_module_file(&dir);
    assert!(matches!(
        create(&file, &KEY, EPOCH),
        Err(Error::AlreadyExists(_))
    ));
    let dir = scratch_dir("ac5-sidecar-exists");
    let file = module_file(&dir);
    fs::write(file.epoch_path(), "").expect("write sidecar");
    assert!(matches!(
        create(&file, &KEY, EPOCH),
        Err(Error::AlreadyExists(_))
    ));
}

// --- AC4 ---

fn write_rows(handle: &Handle<Write>, count: usize) {
    for index in 0..count {
        handle
            .execute(
                "INSERT INTO items (label) VALUES (?1)",
                [format!("row {index}")],
            )
            .expect("insert");
    }
}

/// The writer's close truncates the WAL even while a reader is still open, and the last close,
/// here the reader's, leaves no WAL file.
#[test]
fn the_last_close_leaves_no_wal_content() {
    let dir = scratch_dir("ac4-close");
    let file = create_module_file(&dir);
    let writer = open::<Write>(&file, &KEY).expect("writer");
    let reader = open::<Read>(&file, &KEY).expect("reader");
    write_rows(&writer, 20);
    assert!(wal_len(&file.wal_path()) > 0, "the writes went to the WAL");
    writer.close().expect("close writer");
    assert_eq!(
        wal_len(&file.wal_path()),
        0,
        "the writer's close truncated the WAL"
    );
    reader.close().expect("close reader");
    assert!(!file.wal_path().exists(), "the last close removed the WAL");
}

/// A reader that holds a snapshot keeps the writer's checkpoint from completing; when the reader
/// is the last connection, its close checkpoints and no WAL content remains.
#[test]
fn a_reader_closing_last_leaves_no_wal_content() {
    let dir = scratch_dir("ac4-reader-last");
    let file = create_module_file(&dir);
    let writer = open::<Write>(&file, &KEY).expect("writer");
    let reader = open::<Read>(&file, &KEY).expect("reader");
    reader
        .execute_batch("BEGIN; SELECT count(*) FROM items;")
        .expect("hold a snapshot");
    write_rows(&writer, 20);
    writer.close().expect("close writer");
    assert!(
        wal_len(&file.wal_path()) > 0,
        "the snapshot kept the WAL content"
    );
    reader
        .execute_batch("COMMIT")
        .expect("release the snapshot");
    reader.close().expect("close reader");
    assert!(
        wal_len(&file.wal_path()) == 0,
        "WAL content after the last close"
    );
}

// --- AC10 ---

#[test]
fn the_checkpoint_pragma_is_refused_on_every_handle() {
    let dir = scratch_dir("ac10-pragma");
    let file = create_module_file(&dir);
    let sql = "PRAGMA wal_checkpoint(TRUNCATE)";
    for outcome in [
        open::<Migration>(&file, &KEY)
            .expect("open")
            .execute_batch(sql),
        open::<Write>(&file, &KEY).expect("open").execute_batch(sql),
        open::<Read>(&file, &KEY).expect("open").execute_batch(sql),
    ] {
        assert!(
            outcome.as_ref().is_err_and(Error::is_refusal),
            "{outcome:?}"
        );
    }
}

/// After a deletion, the C API checkpoint runs under the authorizer and empties the WAL; while a
/// reader holds a snapshot it is retried and then reported incomplete, never silently partial.
#[test]
fn checkpoint_truncate_empties_the_wal_and_reports_a_busy_one() {
    let dir = scratch_dir("ac10-checkpoint");
    let file = create_module_file(&dir);
    let writer = open::<Write>(&file, &KEY).expect("writer");
    let reader = open::<Read>(&file, &KEY).expect("reader");
    write_rows(&writer, 20);
    reader
        .execute_batch("BEGIN; SELECT count(*) FROM items;")
        .expect("hold a snapshot");
    writer
        .execute("DELETE FROM items WHERE label LIKE 'row %'", [])
        .expect("delete");
    let started = std::time::Instant::now();
    let busy = writer.checkpoint_truncate();
    assert!(
        matches!(busy, Err(Error::CheckpointIncomplete { .. })),
        "{busy:?}"
    );
    assert!(
        started.elapsed() >= BUSY_TIMEOUT,
        "the checkpoint did not wait for the reader"
    );
    reader
        .execute_batch("COMMIT")
        .expect("release the snapshot");
    writer
        .checkpoint_truncate()
        .expect("checkpoint once the reader is done");
    assert_eq!(wal_len(&file.wal_path()), 0);
    let left: i64 = writer
        .query_row("SELECT count(*) FROM items", [], |row| row.get(0))
        .expect("count");
    assert_eq!(left, 1);
}

// --- AC11 ---

/// The hex form of the key is built in a buffer allocated once at its final size, so no
/// reallocation leaves a copy behind, and it is a `Zeroizing` buffer, wiped on drop.
#[test]
fn the_key_text_is_one_buffer_of_its_final_size() {
    let text: zeroize::Zeroizing<Vec<u8>> = raw_key_text(&KEY);
    assert_eq!(text.len(), text.capacity());
    assert_eq!(text.len(), 67);
    assert!(text.starts_with(b"x'") && text.ends_with(b"'"));
    let hex: String = KEY.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(&text[2..66], hex.as_bytes());
}

/// No product source builds `PRAGMA key` SQL text, which SQLite would keep in its statement
/// memory and `rusqlite` in its errors; keying goes through `sqlite3_key_v2` (AC11).
#[test]
fn no_product_source_keys_through_sql_text() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    for entry in fs::read_dir(&src).expect("list src") {
        let path = entry.expect("entry").path();
        if path.extension().is_some_and(|extension| extension == "rs") {
            let source = fs::read_to_string(&path).expect("read source");
            let code: String = source
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join(
                    "
",
                )
                .to_ascii_lowercase();
            if code.contains("pragma key") || code.contains("\"key\"") || code.contains("rekey") {
                offenders.push(path);
            }
        }
    }
    assert!(offenders.is_empty(), "{offenders:?}");
}

/// Neither a handle's `Debug` nor an error shows the key or its hex form.
#[test]
fn the_key_is_never_printed() {
    let dir = scratch_dir("ac11-print");
    let file = create_module_file(&dir);
    let hex: String = KEY.iter().map(|byte| format!("{byte:02x}")).collect();
    let handle = open::<Write>(&file, &KEY).expect("open");
    let error = open::<Write>(&file, &OTHER_KEY).expect_err("wrong key");
    let shown = format!("{handle:?} {error} {error:?}");
    assert!(
        !shown.contains(&hex) && !shown.contains("5a5a5a5a"),
        "{shown}"
    );
}
