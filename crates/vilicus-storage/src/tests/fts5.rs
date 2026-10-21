//! Story 3.7, AC9 and its decision task (D127, E15): FTS5 tables made by a module migration
//! through the runner and used by read and write handles, their shadow tables read-only to
//! module SQL under `SQLITE_DBCONFIG_DEFENSIVE`, and FTS5's `integrity-check` after a migration.

use super::{KEY, create_module_file, disk_state, raw_connection, scratch_dir};
use crate::authorizer::{self, Policy};
use crate::{Migration, ModuleFile, Read, SqlValue, TableKind, Write, open};

/// Three FTS5 tables, one per kind of content: an external-content index over a table of the
/// module, a contentless one and one that keeps its own copy of the text (`_content`), each with
/// `secure-delete` set as D132 asks, the module name in three case spellings.
const CREATE: &str = "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL);
     CREATE VIRTUAL TABLE notes_search USING fts5(body, content='notes', tokenize='porter');
     INSERT INTO notes_search (notes_search, rank) VALUES ('secure-delete', 1);
     CREATE VIRTUAL TABLE words USING FTS5(body, content='');
     INSERT INTO words (words, rank) VALUES ('secure-delete', 1);
     CREATE VIRTUAL TABLE stored USING Fts5(body);
     INSERT INTO stored (stored, rank) VALUES ('secure-delete', 1);";

const FTS5_TABLES: [&str; 3] = ["notes_search", "words", "stored"];

fn migrate(file: &ModuleFile, sql: &str) -> crate::Result<()> {
    let mut handle = open::<Migration>(file, &KEY).expect("open the migration handle");
    let outcome = handle.apply_migration(sql);
    handle.close().expect("close");
    outcome
}

/// The file with the three FTS5 tables made by a migration, and one row in each.
fn fts5_file(label: &str) -> ModuleFile {
    let file = create_module_file(&scratch_dir(label));
    migrate(&file, CREATE).expect("a module migration creates FTS5 tables");
    let writer = open::<Write>(&file, &KEY).expect("writer");
    writer
        .execute_batch(
            "BEGIN;
             INSERT INTO notes (id, body) VALUES (1, 'the porter runs');
             INSERT INTO notes_search (rowid, body) VALUES (1, 'the porter runs');
             INSERT INTO words (rowid, body) VALUES (1, 'contentless words');
             INSERT INTO stored (body) VALUES ('stored words');
             COMMIT;",
        )
        .expect("a write handle writes FTS5 tables");
    writer.close().expect("close");
    file
}

/// The shadow tables of the file and their columns, as the read handle reports them.
fn shadow_tables(file: &ModuleFile) -> Vec<(String, Vec<String>)> {
    let reader = open::<Read>(file, &KEY).expect("reader");
    let shadows = reader
        .schema()
        .expect("schema")
        .tables
        .into_iter()
        .filter(|table| table.kind == TableKind::Shadow)
        .map(|table| {
            let columns = reader
                .query_values(
                    "SELECT name FROM pragma_table_info(?1) ORDER BY cid",
                    &[SqlValue::Text(table.name.clone())],
                )
                .expect("columns")
                .into_iter()
                .map(|row| match &row[0] {
                    SqlValue::Text(name) => name.clone(),
                    other => panic!("a column name: {other:?}"),
                })
                .collect();
            (table.name, columns)
        })
        .collect();
    reader.close().expect("close");
    shadows
}

fn integrity_check(file: &ModuleFile, table: &str) -> crate::Result<()> {
    let writer = open::<Write>(file, &KEY).expect("writer");
    let outcome = writer.execute_batch(&format!(
        "INSERT INTO {table} ({table}) VALUES ('integrity-check')"
    ));
    writer.close().expect("close");
    outcome
}

/// AC9: a module migration creates FTS5 tables of each kind, with `secure-delete`, through the
/// runner and under the migration policy; read and write handles use them, which needs FTS5's
/// `PRAGMA data_version`; a later migration drops one, shadow tables included.
#[test]
fn a_module_migration_creates_and_drops_fts5_tables() {
    let file = fts5_file("fts5-created");
    let reader = open::<Read>(&file, &KEY).expect("reader");
    let schema = reader.schema().expect("schema");
    for table in FTS5_TABLES {
        let kind = schema
            .tables
            .iter()
            .find(|found| found.name == table)
            .map(|found| found.kind.clone());
        assert_eq!(kind, Some(TableKind::Virtual), "{table}");
        assert_eq!(
            reader.fts5_option(table, "secure-delete").expect("option"),
            Some(1),
            "{table}"
        );
    }
    let found: i64 = reader
        .query_row(
            "SELECT count(*) FROM notes_search WHERE notes_search MATCH 'run'",
            [],
            |row| row.get(0),
        )
        .expect("a read handle searches an FTS5 table");
    assert_eq!(found, 1, "the porter tokenizer stems 'runs'");
    reader.close().expect("close");

    migrate(&file, "DROP TABLE words;").expect("a module migration drops an FTS5 table");
    let shadows = shadow_tables(&file);
    assert!(
        shadows.iter().all(|(name, _)| !name.starts_with("words_")),
        "{shadows:?}"
    );
    assert!(shadows.iter().any(|(name, _)| name == "stored_content"));
}

/// The decision task of AC9 (D127, E15): every shadow table FTS5 made is read-only to module SQL
/// under `SQLITE_DBCONFIG_DEFENSIVE`, on a write handle and in a migration, which cannot drop or
/// alter one either, with nothing written; the authorizer alone would let the same statements
/// run, so defensive mode is the guard, as D127 says.
#[test]
fn fts5_shadow_tables_are_read_only_to_module_sql_under_defensive_mode() {
    let file = fts5_file("fts5-shadows");
    let shadows = shadow_tables(&file);
    assert!(
        ["_data", "_idx", "_docsize", "_config", "_content"]
            .iter()
            .all(|suffix| shadows.iter().any(|(name, _)| name.ends_with(suffix))),
        "every kind of shadow table is covered: {shadows:?}"
    );
    let before = disk_state(&file);
    let mut failures = Vec::new();
    for (table, columns) in &shadows {
        let column = &columns[0];
        let writes = [
            format!("INSERT INTO {table} SELECT * FROM {table}"),
            format!("UPDATE {table} SET {column} = {column}"),
            format!("DELETE FROM {table}"),
        ];
        let schema_changes = [
            format!("DROP TABLE {table}"),
            format!("ALTER TABLE {table} ADD COLUMN extra"),
            format!("ALTER TABLE {table} RENAME TO renamed_shadow"),
        ];
        for sql in &writes {
            let writer = open::<Write>(&file, &KEY).expect("writer");
            assert!(writer.settings().defensive);
            let outcome = writer.execute_batch(sql);
            writer.close().expect("close");
            if !outcome
                .as_ref()
                .is_err_and(|error| error.to_string().contains("may not be"))
            {
                failures.push(format!("write handle {sql}: {outcome:?}"));
            }
        }
        for sql in writes.iter().chain(&schema_changes) {
            let outcome = migrate(&file, sql);
            if !outcome
                .as_ref()
                .is_err_and(|error| error.to_string().contains("may not be"))
            {
                failures.push(format!("migration {sql}: {outcome:?}"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
    assert_eq!(disk_state(&file), before, "nothing was written");
    for (table, _) in &shadows {
        let control = raw_connection(&file.path());
        authorizer::install(&control, Policy::Write).expect("the write policy alone");
        let delete = control.execute_batch(&format!("DELETE FROM {table}"));
        control.close().expect("close the control");
        assert!(delete.is_ok(), "control {table}: {delete:?}");
    }
}

/// The decision task of AC9: FTS5's `integrity-check` passes on every table after the migration
/// and the writes, and fails once the index and its content disagree, which a connection outside
/// defensive mode can make happen; so the check checks something.
#[test]
fn fts5_integrity_check_passes_after_a_migration() {
    let file = fts5_file("fts5-integrity");
    for table in FTS5_TABLES {
        integrity_check(&file, table).unwrap_or_else(|error| panic!("{table}: {error}"));
    }
    raw_connection(&file.path())
        .execute_batch("DELETE FROM stored_content")
        .expect("damage the index outside defensive mode");
    let damaged = integrity_check(&file, "stored");
    assert!(damaged.is_err(), "{damaged:?}");
}
