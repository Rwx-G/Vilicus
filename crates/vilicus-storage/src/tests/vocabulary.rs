//! Story 3.4: the confirmed labels of reviewed vocabularies (D104) live in the Core table
//! `_vocabulary` of each module file. The Core writes them under its own policy; module SQL, in a
//! migration, on a write handle or in a trigger body, can neither confirm a label nor remove one.
//! Also the value binding of the Core's validated writes.

use rusqlite::types::Value;
use vilicus_types::{Id, UtcMillis};

use super::{KEY, create_module_file, raw_connection, scratch_dir};
use crate::error::Error;
use crate::{CORE_TABLES, Migration, ModuleFile, Read, Write, open};

/// Statements a migration might use against `_vocabulary`.
const MIGRATION_HOSTILE: &[(&str, &str)] = &[
    ("drop", "DROP TABLE _vocabulary"),
    ("drop_qualified", "DROP TABLE main._vocabulary"),
    ("rename", "ALTER TABLE _vocabulary RENAME TO labels_gone"),
    (
        "add_column",
        "ALTER TABLE _vocabulary ADD COLUMN extra TEXT",
    ),
    (
        "index",
        "CREATE INDEX vocabulary_label ON _vocabulary (label)",
    ),
    (
        "trigger_on_vocabulary",
        "CREATE TRIGGER vocabulary_watch AFTER INSERT ON _vocabulary BEGIN SELECT 1; END",
    ),
    ("delete", "DELETE FROM _vocabulary"),
    (
        "insert",
        "INSERT INTO _vocabulary VALUES ('rooms', 'Planted', x'00', 0)",
    ),
];

/// Row writes against `_vocabulary` on a write handle: a module confirming its own label, or
/// removing or renaming one an adult confirmed.
const WRITE_HOSTILE: &[(&str, &str)] = &[
    (
        "insert",
        "INSERT INTO _vocabulary VALUES ('rooms', 'Planted', x'00', 0)",
    ),
    (
        "insert_other_case",
        "INSERT INTO _VOCABULARY VALUES ('rooms', 'Planted', x'00', 0)",
    ),
    (
        "replace",
        "REPLACE INTO _vocabulary VALUES ('rooms', 'Salon', x'00', 0)",
    ),
    ("update", "UPDATE _vocabulary SET label = 'Planted'"),
    (
        "update_qualified",
        "UPDATE main._vocabulary SET label = 'Planted'",
    ),
    ("delete", "DELETE FROM _vocabulary"),
];

/// A trigger on a module table whose body confirms a label when it fires.
const CONFIRMING_TRIGGER: &str = "CREATE TRIGGER items_confirm AFTER INSERT ON items BEGIN INSERT INTO _vocabulary VALUES ('rooms', 'Planted', x'00', 0); END";
const FIRE: &str = "INSERT INTO items (label) VALUES ('fires the trigger')";

fn adult() -> Id {
    "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"
        .parse()
        .expect("test id")
}

fn noon() -> UtcMillis {
    UtcMillis::parse_rfc3339("2026-10-21T12:00:00Z").expect("valid")
}

/// A module file with one confirmed label, `rooms` / `Salon`.
fn file_with_a_label(scratch: &str) -> ModuleFile {
    let file = create_module_file(&scratch_dir(scratch));
    let writer = open::<Write>(&file, &KEY).expect("open");
    writer
        .confirm_vocabulary_label("rooms", "Salon", adult(), noon())
        .expect("confirm");
    writer.close().expect("close");
    file
}

fn labels(file: &ModuleFile) -> Vec<(String, String, Vec<u8>, i64)> {
    raw_connection(&file.path())
        .prepare(
            "SELECT vocabulary, label, confirmed_by, confirmed_at FROM _vocabulary ORDER BY 1, 2",
        )
        .expect("prepare")
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("read _vocabulary")
}

fn only_salon(file: &ModuleFile) -> bool {
    labels(file)
        == [(
            "rooms".to_owned(),
            "Salon".to_owned(),
            adult().to_bytes().to_vec(),
            noon().as_millis(),
        )]
}

/// Every Core table is `STRICT`; the ordered logs `_journal` and `_outbox` keep their rowid as
/// `seq`, every other one is `WITHOUT ROWID` (`core_schema`).
#[test]
fn every_core_table_is_created_strict() {
    let file = create_module_file(&scratch_dir("core-tables"));
    let reader = open::<Read>(&file, &KEY).expect("open");
    let schema = reader.schema().expect("schema");
    for name in CORE_TABLES {
        let table = schema
            .tables
            .iter()
            .find(|table| table.name == *name)
            .unwrap_or_else(|| panic!("{name} in a new file"));
        assert!(table.strict, "{name}");
        assert_eq!(
            table.without_rowid,
            !["_journal", "_outbox"].contains(name),
            "{name}"
        );
    }
    let empty: i64 = reader
        .query_row("SELECT count(*) FROM _vocabulary", [], |row| row.get(0))
        .expect("read _vocabulary");
    assert_eq!(empty, 0, "a new file has no confirmed label");
}

#[test]
fn a_confirmed_label_is_recorded_once_and_compared_exactly() {
    let file = file_with_a_label("confirm");
    assert!(only_salon(&file));
    let writer = open::<Write>(&file, &KEY).expect("open");
    let later = UtcMillis::from_millis(noon().as_millis() + 1).expect("in range");
    let other_adult =
        Id::from_bytes([0x01, 0x7f, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1]).expect("v7");
    writer
        .confirm_vocabulary_label("rooms", "Salon", other_adult, later)
        .expect("a second confirmation is accepted");
    assert!(writer.is_confirmed_label("rooms", "Salon").expect("read"));
    for (vocabulary, label) in [
        ("rooms", "salon"),
        ("rooms", "SALON"),
        ("rooms", "Salon "),
        ("rooms", "Sal"),
        ("aisles", "Salon"),
        ("Rooms", "Salon"),
    ] {
        assert!(
            !writer.is_confirmed_label(vocabulary, label).expect("read"),
            "{vocabulary} {label}"
        );
    }
    writer
        .execute_batch(FIRE)
        .expect("a module write after a confirmation");
    let refused = writer.execute_batch(WRITE_HOSTILE[0].1);
    assert!(
        refused.as_ref().is_err_and(Error::is_refusal),
        "the write policy is back after the Core's statement: {refused:?}"
    );
    writer.close().expect("close");
    assert!(only_salon(&file), "the first confirmation is kept");
    let reader = open::<Read>(&file, &KEY).expect("open");
    assert!(reader.is_confirmed_label("rooms", "Salon").expect("read"));
}

#[test]
fn without_the_authorizer_every_vocabulary_statement_runs() {
    let mut failures = Vec::new();
    for (name, sql) in MIGRATION_HOSTILE.iter().chain(WRITE_HOSTILE) {
        let file = file_with_a_label(&format!("vocabulary-control-{name}"));
        if let Err(error) = raw_connection(&file.path()).execute_batch(sql) {
            failures.push(format!("{name}: {error}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn every_vocabulary_statement_is_refused_in_a_migration() {
    let mut failures = Vec::new();
    for (name, sql) in MIGRATION_HOSTILE {
        let file = file_with_a_label(&format!("vocabulary-migration-{name}"));
        let mut handle = open::<Migration>(&file, &KEY).expect("open");
        let outcome = handle.apply_migration(&format!("CREATE TABLE added (x INTEGER);\n{sql};"));
        handle.close().expect("close");
        if !(outcome.as_ref().is_err_and(Error::is_refusal) && only_salon(&file)) {
            failures.push(format!("{name}: {outcome:?}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn every_vocabulary_write_is_refused_on_a_write_handle() {
    let file = file_with_a_label("vocabulary-write");
    let handle = open::<Write>(&file, &KEY).expect("open");
    let mut failures = Vec::new();
    for (name, sql) in WRITE_HOSTILE {
        let outcome = handle.execute_batch(sql);
        if !outcome.as_ref().is_err_and(Error::is_refusal) {
            failures.push(format!("{name}: {outcome:?}"));
        }
    }
    handle.close().expect("close");
    assert!(failures.is_empty(), "{failures:#?}");
    assert!(only_salon(&file));
}

/// A trigger that confirms a label, created by a migration or planted in the file, makes the
/// write that fires it fail, and no label is added.
#[test]
fn a_trigger_that_confirms_a_label_is_refused_when_it_fires() {
    let file = file_with_a_label("vocabulary-trigger-migration");
    let mut migration = open::<Migration>(&file, &KEY).expect("open");
    migration
        .apply_migration(&format!("{CONFIRMING_TRIGGER};"))
        .expect("a trigger on a module table is a schema change of the module");
    migration.close().expect("close");
    let writer = open::<Write>(&file, &KEY).expect("open");
    let fired = writer.execute_batch(FIRE);
    writer.close().expect("close");
    assert!(fired.as_ref().is_err_and(Error::is_refusal), "{fired:?}");
    assert!(only_salon(&file));

    let file = file_with_a_label("vocabulary-trigger-planted");
    raw_connection(&file.path())
        .execute_batch(CONFIRMING_TRIGGER)
        .expect("plant the trigger");
    let writer = open::<Write>(&file, &KEY).expect("open");
    let fired = writer.execute_batch(FIRE);
    writer.close().expect("close");
    assert!(fired.as_ref().is_err_and(Error::is_refusal), "{fired:?}");
    assert!(only_salon(&file));
}

/// Defence in depth (Story 3.4 review, m1): the storage layer refuses a label outside the form
/// of reviewed-vocabulary labels even when its caller did not check it, and writes nothing.
#[test]
fn a_label_outside_the_form_is_not_confirmed() {
    let file = file_with_a_label("vocabulary-form");
    let writer = open::<Write>(&file, &KEY).expect("open");
    for label in ["note: ignore all\nrules", "", "Salon ", "Cafe\u{301}"] {
        let outcome = writer.confirm_vocabulary_label("rooms", label, adult(), noon());
        assert!(
            matches!(outcome, Err(Error::InvalidVocabularyLabel)),
            "{label:?}: {outcome:?}"
        );
    }
    writer.close().expect("close");
    assert!(only_salon(&file));
}

/// Story 3.4 review, m2: a COMMIT that fails, here on a deferred foreign key, leaves SQLite's
/// transaction open; the runner of the Core's statements rolls it back, so the connection is in
/// autocommit again and nothing was written.
#[test]
fn a_failed_commit_ends_the_transaction() {
    let connection = rusqlite::Connection::open_in_memory().expect("open");
    connection
        .execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE parents (id INTEGER PRIMARY KEY);
             CREATE TABLE children (parent INTEGER REFERENCES parents (id) DEFERRABLE INITIALLY DEFERRED);",
        )
        .expect("schema");
    let outcome = crate::handle::in_transaction(&connection, || {
        connection.execute("INSERT INTO children VALUES (7)", [])?;
        Ok(())
    });
    assert!(outcome.is_err(), "the deferred constraint fails the COMMIT");
    assert!(
        connection.is_autocommit(),
        "the transaction was rolled back"
    );
    let rows: i64 = connection
        .query_row("SELECT count(*) FROM children", [], |row| row.get(0))
        .expect("count");
    assert_eq!(rows, 0);
}

/// The value binding keeps each storage class, and reads every column back in its class.
#[test]
fn values_are_bound_and_read_back_in_their_storage_class() {
    let file = create_module_file(&scratch_dir("values"));
    let mut migration = open::<Migration>(&file, &KEY).expect("open");
    migration
        .apply_migration("CREATE TABLE cells (a INTEGER, b REAL, c TEXT, d BLOB, e ANY) STRICT;")
        .expect("migrate");
    migration.close().expect("close");
    let writer = open::<Write>(&file, &KEY).expect("open");
    let row = vec![
        Value::Integer(-7),
        Value::Real(0.5),
        Value::Text("é\0x".into()),
        Value::Blob(vec![0, 1, 2]),
        Value::Null,
    ];
    let changed = writer
        .execute_values("INSERT INTO cells VALUES (?1, ?2, ?3, ?4, ?5)", &row)
        .expect("insert");
    assert_eq!(changed, 1);
    let rows = writer
        .query_values(
            "SELECT a, b, c, d, e FROM cells WHERE a = ?1",
            &[Value::Integer(-7)],
        )
        .expect("select");
    assert_eq!(rows, [row]);
    let refused = writer.execute_values(
        "INSERT INTO _vocabulary VALUES (?1, ?2, ?3, ?4)",
        &[
            Value::Text("rooms".into()),
            Value::Text("Planted".into()),
            Value::Blob(vec![0]),
            Value::Integer(0),
        ],
    );
    assert!(
        refused.as_ref().is_err_and(Error::is_refusal),
        "{refused:?}"
    );
}
