//! Story 4.3, AC4 and the decision task (gate AD36-1): the `wrappers.db` schema, its record set
//! and the transaction of a write, with closures standing in for the Core's MAC.

use std::fs;

use rusqlite::Connection;

use super::*;
use crate::tests::scratch_dir;

fn member(last: u8) -> Id {
    let mut bytes = *b"\x01\x7f\x22\xe2\x79\xb0\x7c\xc3\x98\xc4\xdc\x0c\x0c\x07\x39\x00";
    bytes[15] = last;
    Id::from_bytes(bytes).expect("a UUIDv7")
}

fn wrapper_row(last: u8, kek: KekKind) -> DekWrapperRow {
    DekWrapperRow {
        member: member(last),
        kek,
        dek_version: 1,
        wrapper: vec![0x00, 0x01, last, 0xaa],
    }
}

fn public_key(last: u8) -> PublicKeyRow {
    PublicKeyRow {
        member: member(last),
        kind: PublicKeyKind::Member,
        generation: 0,
        public_key: vec![0x00, 0x01, 0x00, 0x20, last],
    }
}

/// A stand-in for the Core's MAC: the counter and the records, joined, so a test can see what
/// `seal` was given.
fn seal_of(counter: u64, records: &[&[u8]]) -> Vec<u8> {
    let mut mac = counter.to_be_bytes().to_vec();
    for record in records {
        mac.extend_from_slice(record);
    }
    mac
}

fn accept(_: &WrapperSet) -> Result<()> {
    Ok(())
}

fn tables(path: &Path) -> Vec<String> {
    let connection = Connection::open(path).expect("open");
    let mut statement = connection
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .expect("prepare");
    statement
        .query_map([], |row| row.get(0))
        .expect("query")
        .collect::<rusqlite::Result<_>>()
        .expect("read")
}

/// The schema holds the record tables of [`RECORD_TABLES`] and the set state, nothing else; a new
/// table must join one or the other, so the set the MAC covers is every record of the file.
#[test]
fn every_table_is_a_record_table_or_the_set_state() {
    let dir = scratch_dir("story43-wrappers-tables");
    create_wrappers(&dir)
        .expect("create")
        .close()
        .expect("close");
    let mut expected: Vec<String> = RECORD_TABLES
        .iter()
        .map(|table| table.name.to_string())
        .collect();
    expected.push("wrapper_set".to_string());
    expected.sort();
    let path = dir.join(WRAPPERS_FILE_NAME);
    assert_eq!(tables(&path), expected);
    let connection = Connection::open(&path).expect("open");
    for table in RECORD_TABLES {
        let mut statement = connection
            .prepare(&format!(
                "SELECT name FROM pragma_table_info('{}')",
                table.name
            ))
            .expect("prepare");
        let mut columns: Vec<String> = statement
            .query_map([], |row| row.get(0))
            .expect("query")
            .collect::<rusqlite::Result<_>>()
            .expect("read");
        let mut named: Vec<String> = table.columns.iter().map(ToString::to_string).collect();
        columns.sort();
        named.sort();
        assert_eq!(columns, named, "{}", table.name);
    }
}

/// AC4: the file holds the DEK wrappers, one per KEK, and the public keys, in a file of its own
/// that needs no key: a plain SQLite connection with no key reads every row. A second creation is
/// refused, and the file's connection is set up like a writer's.
#[test]
fn wrappers_db_needs_no_key_and_holds_wrappers_and_public_keys() {
    let dir = scratch_dir("story43-wrappers-plain");
    let mut store = create_wrappers(&dir).expect("create");
    assert_eq!(store.path(), dir.join(WRAPPERS_FILE_NAME));
    assert!(store.settings().secure_delete == 1 && store.settings().defensive);
    let empty = store.snapshot().expect("snapshot").set;
    assert_eq!((empty.counter, empty.mac.clone()), (0, None));
    let changes = [
        WrapperChange::PutDekWrapper(wrapper_row(1, KekKind::Passphrase)),
        WrapperChange::PutDekWrapper(wrapper_row(1, KekKind::Recovery)),
        WrapperChange::PutPublicKey(public_key(1)),
    ];
    store
        .write(&changes, accept, |counter, records| {
            Ok(seal_of(counter, records))
        })
        .expect("write");
    store.close().expect("close");
    assert!(matches!(
        create_wrappers(&dir),
        Err(Error::AlreadyExists(_))
    ));
    let plain = Connection::open(dir.join(WRAPPERS_FILE_NAME)).expect("open with no key");
    let count: i64 = plain
        .query_row("SELECT count(*) FROM member_dek_wrappers", [], |row| {
            row.get(0)
        })
        .expect("read with no key");
    assert_eq!(count, 2);
    drop(plain);
    let store = open_wrappers(&dir).expect("open");
    assert_eq!(
        store
            .own_dek_wrapper(member(1), KekKind::Recovery)
            .expect("read"),
        Some(wrapper_row(1, KekKind::Recovery))
    );
    assert_eq!(
        store
            .own_dek_wrapper(member(2), KekKind::Recovery)
            .expect("read"),
        None
    );
    assert_eq!(
        store.snapshot().expect("snapshot").public_keys,
        vec![public_key(1)]
    );
}

/// A write gives `check` the set as it is and `seal` the raised counter with the new records, and
/// stores what `seal` returned; the records are each table's rows in schema order, so the set
/// changes with any record.
#[test]
fn a_write_checks_the_set_then_raises_the_counter_and_stores_its_seal() {
    let dir = scratch_dir("story43-wrappers-write");
    let mut store = create_wrappers(&dir).expect("create");
    let mut seen = None;
    let counter = store
        .write(
            &[WrapperChange::PutDekWrapper(wrapper_row(
                1,
                KekKind::Passphrase,
            ))],
            |set| {
                seen = Some(set.clone());
                Ok::<(), Error>(())
            },
            |counter, records| Ok(seal_of(counter, records)),
        )
        .expect("write");
    assert_eq!((counter.counter, counter.checkpoint.is_none()), (1, true));
    let schema = expected_schema().expect("schema").len();
    let before = seen.expect("check ran");
    assert_eq!(
        (before.counter, before.mac, before.records.len()),
        (0, None, schema + 1)
    );
    let after = store.snapshot().expect("snapshot").set;
    assert_eq!(after.counter, 1);
    assert_eq!(after.mac, Some(seal_of(1, &after.record_slices())));
    assert_eq!(after.records.len(), schema + 2);
    assert!(
        after
            .records
            .iter()
            .any(|record| record.starts_with(b"\x00\x13member_dek_wrappers"))
    );
    let removed = store
        .write(
            &[WrapperChange::RemoveDekWrapper {
                member: member(1),
                kek: KekKind::Passphrase,
            }],
            |set| {
                assert_eq!(set.counter, 1);
                Ok::<(), Error>(())
            },
            |counter, records| Ok(seal_of(counter, records)),
        )
        .expect("remove");
    assert_eq!(removed.counter, 2);
    assert_eq!(
        store.snapshot().expect("snapshot").set.records,
        before.records
    );
}

/// A refusal by `check` or `seal`, or the removal of a record that is not there, rolls the whole
/// write back: the records, the counter and the MAC stay as they were.
#[test]
fn a_refused_write_changes_nothing() {
    let dir = scratch_dir("story43-wrappers-refused");
    let mut store = create_wrappers(&dir).expect("create");
    store
        .write(
            &[WrapperChange::PutPublicKey(public_key(1))],
            accept,
            |c, r| Ok(seal_of(c, r)),
        )
        .expect("write");
    let before = store.snapshot().expect("snapshot");
    let put = [WrapperChange::PutDekWrapper(wrapper_row(
        2,
        KekKind::Passphrase,
    ))];
    let refused_check = store.write(
        &put,
        |_| Err(Error::MalformedWrapperRow),
        |c, r| Ok(seal_of(c, r)),
    );
    assert!(matches!(refused_check, Err(Error::MalformedWrapperRow)));
    let refused_seal = store.write(&put, accept, |_, _| Err(Error::KeyUnavailable));
    assert!(matches!(refused_seal, Err(Error::KeyUnavailable)));
    let missing = [
        WrapperChange::PutDekWrapper(wrapper_row(2, KekKind::Passphrase)),
        WrapperChange::RemovePublicKey {
            member: member(3),
            kind: PublicKeyKind::Inbox,
        },
    ];
    let refused_removal = store.write(&missing, accept, |c, r| Ok(seal_of(c, r)));
    assert!(matches!(refused_removal, Err(Error::WrapperRecordMissing)));
    assert_eq!(store.snapshot().expect("snapshot"), before);
}

/// A file that is not a database, and one of another schema version, are refused at open; the
/// file's own statements cannot change its schema or attach another file.
#[test]
fn another_file_or_schema_is_refused() {
    let dir = scratch_dir("story43-wrappers-other");
    fs::write(dir.join(WRAPPERS_FILE_NAME), vec![0x5a; 4096]).expect("garbage");
    assert!(matches!(
        open_wrappers(&dir),
        Err(Error::NotAWrapperFile(_))
    ));
    fs::remove_file(dir.join(WRAPPERS_FILE_NAME)).expect("remove");
    create_wrappers(&dir)
        .expect("create")
        .close()
        .expect("close");
    Connection::open(dir.join(WRAPPERS_FILE_NAME))
        .expect("open")
        .execute_batch("UPDATE _meta SET value = 2 WHERE key = 'wrappers_schema_version'")
        .expect("edit");
    assert!(matches!(
        open_wrappers(&dir),
        Err(Error::WrappersSchemaVersion { found: Some(2) })
    ));
    Connection::open(dir.join(WRAPPERS_FILE_NAME))
        .expect("open")
        .execute_batch("UPDATE _meta SET value = 1 WHERE key = 'wrappers_schema_version'")
        .expect("edit back");
    let store = open_wrappers(&dir).expect("open");
    for sql in [
        "DROP TABLE member_dek_wrappers",
        "CREATE TABLE extra (x INTEGER)",
        "ATTACH DATABASE ':memory:' AS other",
        "UPDATE _meta SET value = 3",
    ] {
        let outcome = store.raw().execute_batch(sql).map_err(Error::from);
        assert!(
            outcome.as_ref().is_err_and(Error::is_refusal),
            "{sql}: {outcome:?}"
        );
    }
}

/// Plants `sql` in the file of `dir` outside the storage layer, as a writer of the disk would.
fn plant(dir: &Path, sql: &str) {
    Connection::open(dir.join(WRAPPERS_FILE_NAME))
        .expect("open with no key")
        .execute_batch(sql)
        .expect("plant");
}

/// The review's attack (H1): a trigger planted in the file restores an older recovery wrapper
/// whenever the Core inserts a passphrase wrapper. The trigger, a view, and the table rebuilt with
/// its columns in another order are each refused at open, at a snapshot and inside a write, with
/// nothing written.
#[test]
fn a_planted_trigger_view_or_rebuilt_table_is_refused() {
    let planted = [
        "CREATE TRIGGER restore_old AFTER INSERT ON member_dek_wrappers WHEN NEW.kek_kind = 1 \
         BEGIN INSERT OR REPLACE INTO member_dek_wrappers VALUES (NEW.member_id, 2, 1, x'00010203'); END;",
        "CREATE VIEW wrappers AS SELECT * FROM member_dek_wrappers;",
        "BEGIN;
         CREATE TABLE rebuilt (
             kek_kind INTEGER NOT NULL CHECK (kek_kind IN (1, 2)),
             member_id BLOB NOT NULL CHECK (length(member_id) = 16),
             dek_version INTEGER NOT NULL CHECK (dek_version BETWEEN 0 AND 4294967295),
             wrapper BLOB NOT NULL,
             PRIMARY KEY (member_id, kek_kind)
         ) STRICT, WITHOUT ROWID;
         INSERT INTO rebuilt (kek_kind, member_id, dek_version, wrapper)
             SELECT kek_kind, member_id, dek_version, wrapper FROM member_dek_wrappers;
         DROP TABLE member_dek_wrappers;
         ALTER TABLE rebuilt RENAME TO member_dek_wrappers;
         COMMIT;",
    ];
    for (index, sql) in planted.into_iter().enumerate() {
        let dir = scratch_dir(&format!("h1-planted-{index}"));
        let mut store = create_wrappers(&dir).expect("create");
        store
            .write(
                &[WrapperChange::PutDekWrapper(wrapper_row(
                    1,
                    KekKind::Recovery,
                ))],
                accept,
                |c, r| Ok(seal_of(c, r)),
            )
            .expect("first write");
        plant(&dir, sql);
        assert!(
            matches!(store.snapshot(), Err(Error::WrappersSchemaChanged)),
            "snapshot, {index}"
        );
        let outcome = store.write(
            &[WrapperChange::PutDekWrapper(wrapper_row(
                1,
                KekKind::Passphrase,
            ))],
            accept,
            |c, r| Ok(seal_of(c, r)),
        );
        assert!(
            matches!(outcome, Err(Error::WrappersSchemaChanged)),
            "write, {index}: {outcome:?}"
        );
        drop(store);
        assert!(
            matches!(open_wrappers(&dir), Err(Error::WrappersSchemaChanged)),
            "open, {index}"
        );
        let counter: i64 = Connection::open(dir.join(WRAPPERS_FILE_NAME))
            .expect("open")
            .query_row("SELECT counter FROM wrapper_set", [], |row| row.get(0))
            .expect("counter");
        assert_eq!(counter, 1, "nothing was written, {index}");
    }
}

/// Defence in depth behind the schema check: on the store's connection, a statement that fires a
/// trigger planted after the open fails, because the authorizer denies every action a trigger
/// body takes; the same statement with no trigger runs.
#[test]
fn the_connection_denies_what_a_trigger_does() {
    let dir = scratch_dir("h1-accessor");
    let store = create_wrappers(&dir).expect("create");
    let insert =
        "INSERT INTO member_dek_wrappers VALUES (x'017f22e279b07cc398c4dc0c0c073901', 1, 1, x'00')";
    plant(
        &dir,
        "CREATE TRIGGER copy AFTER INSERT ON member_dek_wrappers \
         BEGIN UPDATE wrapper_set SET counter = 9; END;",
    );
    let outcome = store.raw().execute_batch(insert).map_err(Error::from);
    assert!(
        outcome.as_ref().is_err_and(Error::is_refusal),
        "{outcome:?}"
    );
    plant(&dir, "DROP TRIGGER copy;");
    // A statement prepared on the schema the connection last read would still compile the
    // dropped trigger: a read first loads the new schema.
    store
        .raw()
        .execute_batch("SELECT count(*) FROM wrapper_set")
        .expect("read the new schema");
    store
        .raw()
        .execute_batch(insert)
        .expect("the same insert with no trigger");
}

/// Each record names its columns: a table whose columns sit in another order encodes the same
/// rows into the same records, so the MAC covers values, never a column position.
#[test]
fn records_name_their_columns() {
    let dir = scratch_dir("h1-columns");
    let mut store = create_wrappers(&dir).expect("create");
    store
        .write(
            &[WrapperChange::PutDekWrapper(wrapper_row(
                1,
                KekKind::Recovery,
            ))],
            accept,
            |c, r| Ok(seal_of(c, r)),
        )
        .expect("write");
    let data = |records: Vec<Vec<u8>>| -> Vec<Vec<u8>> {
        records
            .into_iter()
            .filter(|record| !record.starts_with(b"\x00\x0dsqlite_master"))
            .collect()
    };
    let before = data(read_records(store.raw()).expect("records"));
    drop(store);
    let reordered = Connection::open(dir.join(WRAPPERS_FILE_NAME)).expect("open");
    reordered
        .execute_batch(
            "CREATE TABLE rebuilt (wrapper BLOB, dek_version INTEGER, kek_kind INTEGER, member_id BLOB);
             INSERT INTO rebuilt SELECT wrapper, dek_version, kek_kind, member_id FROM member_dek_wrappers;
             DROP TABLE member_dek_wrappers;
             ALTER TABLE rebuilt RENAME TO member_dek_wrappers;",
        )
        .expect("rebuild");
    assert_eq!(data(read_records(&reordered).expect("records")), before);
}

/// The schema's rows are records of the set, first, one per object of [`SCHEMA`].
#[test]
fn the_schema_is_a_record_of_the_set() {
    let dir = scratch_dir("h1-schema-records");
    let store = create_wrappers(&dir).expect("create");
    let set = store.snapshot().expect("snapshot").set;
    let schema = expected_schema().expect("schema");
    let schema_records: Vec<&Vec<u8>> = set
        .records
        .iter()
        .take_while(|record| record.starts_with(b"\x00\x0dsqlite_master"))
        .collect();
    assert_eq!(schema_records.len(), schema.len());
    assert!(!set.holds_member_records);
}

/// Story 4.3 review, L5: a checkpoint that fails after the commit (a reader holds the WAL) does
/// not lose the committed write: its counter comes back with the checkpoint's failure.
#[test]
fn a_failed_checkpoint_after_the_commit_keeps_the_counter() {
    let dir = scratch_dir("l5-checkpoint");
    let mut store = create_wrappers(&dir).expect("create");
    let reader = Connection::open(dir.join(WRAPPERS_FILE_NAME)).expect("reader");
    reader
        .execute_batch("BEGIN; SELECT count(*) FROM wrapper_set;")
        .expect("hold a snapshot");
    let written = store
        .write(
            &[WrapperChange::PutDekWrapper(wrapper_row(
                1,
                KekKind::Recovery,
            ))],
            accept,
            |c, r| Ok(seal_of(c, r)),
        )
        .expect("the write commits");
    assert_eq!(written.counter, 1);
    assert!(
        matches!(written.checkpoint, Some(Error::CheckpointIncomplete { .. })),
        "{:?}",
        written.checkpoint
    );
    reader.execute_batch("COMMIT").expect("release");
    drop(store);
    assert_eq!(
        open_wrappers(&dir)
            .expect("open")
            .snapshot()
            .expect("snapshot")
            .set
            .counter,
        1
    );
}
