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
    let mut expected: Vec<String> = RECORD_TABLES.iter().map(ToString::to_string).collect();
    expected.push("wrapper_set".to_string());
    expected.sort();
    assert_eq!(tables(&dir.join(WRAPPERS_FILE_NAME)), expected);
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
    let empty = store.set().expect("set");
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
            .dek_wrapper(member(1), KekKind::Recovery)
            .expect("read"),
        Some(wrapper_row(1, KekKind::Recovery))
    );
    assert_eq!(
        store
            .dek_wrapper(member(2), KekKind::Recovery)
            .expect("read"),
        None
    );
    assert_eq!(store.public_keys().expect("read"), vec![public_key(1)]);
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
    assert_eq!(counter, 1);
    let before = seen.expect("check ran");
    assert_eq!(
        (before.counter, before.mac, before.records.len()),
        (0, None, 1)
    );
    let after = store.set().expect("set");
    assert_eq!(after.counter, 1);
    assert_eq!(after.mac, Some(seal_of(1, &after.record_slices())));
    assert_eq!(after.records.len(), 2);
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
    assert_eq!(removed, 2);
    assert_eq!(store.set().expect("set").records, before.records);
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
    let before = store.set().expect("set");
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
    assert_eq!(store.set().expect("set"), before);
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
