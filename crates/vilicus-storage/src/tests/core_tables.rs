//! M1 of the Story 3.1 review: module SQL, in a migration, on a write handle or in a trigger body,
//! cannot write, drop, alter, index or watch the Core table `_meta`, whose key epoch every open
//! cross-checks (AD-5, AD-26). Each statement is also run without the authorizer, to show it
//! would succeed there.

use super::{EPOCH, KEY, create_module_file, raw_connection, scratch_dir};
use crate::error::Error;
use crate::{Migration, ModuleFile, Read, Write, open};

/// Statements a migration might use against `_meta`, schema-qualified and in other cases too.
const MIGRATION_HOSTILE: &[(&str, &str)] = &[
    ("drop", "DROP TABLE _meta"),
    ("drop_qualified", "DROP TABLE main._meta"),
    ("drop_other_case", "DROP TABLE \"_META\""),
    ("rename", "ALTER TABLE _meta RENAME TO meta_gone"),
    ("add_column", "ALTER TABLE _meta ADD COLUMN extra TEXT"),
    ("index", "CREATE INDEX meta_value ON _meta (value)"),
    (
        "trigger_on_meta",
        "CREATE TRIGGER meta_watch AFTER UPDATE ON _meta BEGIN SELECT 1; END",
    ),
    ("delete", "DELETE FROM _meta"),
    ("update_qualified", "UPDATE main._meta SET value = 7"),
    (
        "insert",
        "INSERT INTO _meta (key, value) VALUES ('generation_2', 2)",
    ),
    (
        "replace",
        "REPLACE INTO _meta (key, value) VALUES ('generation', 9)",
    ),
];

/// Row writes against `_meta` on a write handle.
const WRITE_HOSTILE: &[(&str, &str)] = &[
    ("delete", "DELETE FROM _meta"),
    ("update", "UPDATE _meta SET value = 7"),
    ("update_qualified", "UPDATE main._meta SET value = 7"),
    ("update_other_case", "UPDATE _MeTa SET value = 7"),
    (
        "insert",
        "INSERT INTO _meta (key, value) VALUES ('generation_2', 2)",
    ),
    (
        "replace",
        "REPLACE INTO _meta (key, value) VALUES ('generation', 9)",
    ),
];

/// A trigger on a module table whose body destroys `_meta` when it fires.
const WIPING_TRIGGER: &str = "CREATE TRIGGER items_wipe AFTER INSERT ON items BEGIN DELETE FROM _meta; UPDATE _meta SET value = 7; END";
const FIRE: &str = "INSERT INTO items (label) VALUES ('fires the trigger')";

fn meta_rows(file: &ModuleFile) -> Vec<(String, i64)> {
    raw_connection(&file.path())
        .prepare("SELECT key, value FROM _meta ORDER BY key")
        .expect("prepare")
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("read _meta")
}

fn intact(file: &ModuleFile) -> bool {
    open::<Read>(file, &KEY).is_ok_and(|handle| handle.epoch() == EPOCH)
        && meta_rows(file)
            == [
                ("generation".to_owned(), 0),
                ("partition_root_version".to_owned(), 1),
            ]
}

#[test]
fn without_the_authorizer_every_meta_statement_runs() {
    let mut failures = Vec::new();
    for (name, sql) in MIGRATION_HOSTILE.iter().chain(WRITE_HOSTILE) {
        let dir = scratch_dir(&format!("meta-control-{name}"));
        let file = create_module_file(&dir);
        if let Err(error) = raw_connection(&file.path()).execute_batch(sql) {
            failures.push(format!("{name}: {error}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
    let dir = scratch_dir("meta-control-drop-bricks");
    let file = create_module_file(&dir);
    raw_connection(&file.path())
        .execute_batch("DROP TABLE _meta")
        .expect("drop");
    assert!(matches!(
        open::<Read>(&file, &KEY),
        Err(Error::MissingEpoch)
    ));
}

#[test]
fn every_meta_statement_is_refused_in_a_migration() {
    let mut failures = Vec::new();
    for (name, sql) in MIGRATION_HOSTILE {
        let dir = scratch_dir(&format!("meta-migration-{name}"));
        let file = create_module_file(&dir);
        let mut handle = open::<Migration>(&file, &KEY).expect("open");
        let outcome = handle.apply_migration(&format!("CREATE TABLE added (x INTEGER);\n{sql};"));
        handle.close().expect("close");
        if !(outcome.as_ref().is_err_and(Error::is_refusal) && intact(&file)) {
            failures.push(format!("{name}: {outcome:?}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn every_meta_write_is_refused_on_a_write_handle() {
    let dir = scratch_dir("meta-write");
    let file = create_module_file(&dir);
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
    assert!(intact(&file));
}

/// A trigger body is authorized when it fires: a trigger that destroys `_meta`, created by a
/// migration or planted in the file, makes the write that fires it fail, and `_meta` stays.
#[test]
fn a_trigger_that_writes_meta_is_refused_when_it_fires() {
    let dir = scratch_dir("meta-trigger-migration");
    let file = create_module_file(&dir);
    let mut migration = open::<Migration>(&file, &KEY).expect("open");
    migration
        .apply_migration(&format!("{WIPING_TRIGGER};"))
        .expect("a trigger on a module table is a schema change of the module");
    migration.close().expect("close");
    let writer = open::<Write>(&file, &KEY).expect("open");
    let fired = writer.execute_batch(FIRE);
    writer.close().expect("close");
    assert!(fired.as_ref().is_err_and(Error::is_refusal), "{fired:?}");
    assert!(intact(&file));

    let dir = scratch_dir("meta-trigger-planted");
    let file = create_module_file(&dir);
    raw_connection(&file.path())
        .execute_batch(WIPING_TRIGGER)
        .expect("plant the trigger");
    let writer = open::<Write>(&file, &KEY).expect("open");
    let fired = writer.execute_batch(FIRE);
    writer.close().expect("close");
    assert!(fired.as_ref().is_err_and(Error::is_refusal), "{fired:?}");
    assert!(intact(&file));

    let dir = scratch_dir("meta-trigger-in-migration");
    let file = create_module_file(&dir);
    let mut migration = open::<Migration>(&file, &KEY).expect("open");
    let fired = migration.apply_migration(&format!("{WIPING_TRIGGER};\n{FIRE};"));
    migration.close().expect("close");
    assert!(fired.as_ref().is_err_and(Error::is_refusal), "{fired:?}");
    assert!(intact(&file));
}

/// Module SQL may still read `_meta`: the epoch is a counter, not a secret.
#[test]
fn meta_stays_readable() {
    let dir = scratch_dir("meta-read");
    let file = create_module_file(&dir);
    let reader = open::<Read>(&file, &KEY).expect("open");
    let count: i64 = reader
        .query_row("SELECT count(*) FROM _meta", [], |row| row.get(0))
        .expect("read _meta");
    assert_eq!(count, 2);
}
