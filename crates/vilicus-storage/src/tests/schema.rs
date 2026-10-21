//! Story 3.2: the versioned migrations of the two tracks, written by the runner in the migration's
//! own transaction and never by module SQL (AD-26), and the schema the module registry reads
//! through a read or write handle (AD-9). Story 3.6: the Core track runs first, from the Core's
//! own migrations, and a module migration waits for it.

use super::{EPOCH, KEY, module_file, raw_connection, scratch_dir};
use crate::error::Error;
use crate::{
    CORE_SCHEMA_VERSION, ColumnInfo, ForeignKey, Inspect, Migration, MigrationTrack, ModuleFile,
    Read, TableKind, Write, create, open,
};

/// A module file as `create` leaves it: `_meta` with the key epoch and the Core tables.
fn new_file(label: &str) -> ModuleFile {
    let file = module_file(&scratch_dir(label));
    create(&file, &KEY, EPOCH)
        .expect("create")
        .close()
        .expect("close");
    file
}

fn versions(file: &ModuleFile) -> (u32, u32) {
    let reader = open::<Read>(file, &KEY).expect("open");
    let versions = (
        reader.schema_version(MigrationTrack::Core).expect("core"),
        reader
            .schema_version(MigrationTrack::Module)
            .expect("module"),
    );
    reader.close().expect("close");
    versions
}

fn table_names(file: &ModuleFile) -> Vec<String> {
    let reader = open::<Read>(file, &KEY).expect("open");
    let names = reader
        .schema()
        .expect("schema")
        .tables
        .into_iter()
        .map(|table| table.name)
        .filter(|name| !name.starts_with("sqlite_"))
        .collect();
    reader.close().expect("close");
    names
}

fn migrate(file: &ModuleFile, version: u32, sql: &str) -> crate::Result<()> {
    let mut handle = open::<Migration>(file, &KEY).expect("open");
    let outcome = handle.apply_module_migration(version, sql);
    handle.close().expect("close");
    outcome
}

const CORE: u32 = CORE_SCHEMA_VERSION;

#[test]
fn a_new_file_has_its_core_track_current_and_its_module_track_at_zero() {
    const { assert!(CORE >= 1, "the Core track has a migration") };
    assert_eq!(versions(&new_file("version-zero")), (CORE, 0));
}

#[test]
fn versioned_migrations_apply_in_order_and_record_their_version() {
    let file = new_file("version-order");
    migrate(&file, 1, "CREATE TABLE one (x INTEGER);").expect("first");
    assert_eq!(versions(&file), (CORE, 1));
    migrate(&file, 2, "CREATE TABLE two (x INTEGER);").expect("second");
    assert_eq!(versions(&file), (CORE, 2));

    for (version, current) in [(2, 2), (1, 2), (4, 2), (0, 2)] {
        let outcome = migrate(&file, version, "CREATE TABLE out_of_order (x INTEGER);");
        assert!(
            matches!(
                outcome,
                Err(Error::MigrationOutOfOrder { track: MigrationTrack::Module, current: found, version: refused })
                    if found == current && refused == version
            ),
            "version {version}: {outcome:?}"
        );
    }
    assert_eq!(versions(&file), (CORE, 2));
    assert!(
        !table_names(&file).contains(&"out_of_order".to_owned()),
        "an out-of-order migration ran its SQL"
    );
}

/// A migration that fails or is refused leaves its version, as it leaves its schema: the version
/// row is written in the migration's own transaction.
#[test]
fn a_failed_migration_keeps_the_previous_version() {
    let file = new_file("version-failed");
    migrate(&file, 1, "CREATE TABLE one (x INTEGER);").expect("first");
    for sql in [
        "CREATE TABLE two (x INTEGER); ATTACH DATABASE 'other.db' AS other;",
        "CREATE TABLE two (x INTEGER); CREATE TABLE one (y INTEGER);",
    ] {
        assert!(migrate(&file, 2, sql).is_err(), "{sql}");
        assert_eq!(versions(&file), (CORE, 1), "{sql}");
        assert!(!table_names(&file).contains(&"two".to_owned()), "{sql}");
    }
}

/// Module SQL cannot write a schema version, its own or the Core's, in any form.
#[test]
fn migration_sql_cannot_write_a_schema_version() {
    let file = new_file("version-forged");
    for sql in [
        "INSERT INTO _meta (key, value) VALUES ('module_schema_version', 9)",
        "REPLACE INTO _meta (key, value) VALUES ('core_schema_version', 9)",
        "UPDATE _meta SET value = 9 WHERE key = 'generation'",
        "UPDATE _meta SET value = 0 WHERE key = 'core_schema_version'",
    ] {
        let outcome = migrate(&file, 1, sql);
        assert!(
            outcome.as_ref().is_err_and(Error::is_refusal),
            "{sql}: {outcome:?}"
        );
    }
    assert_eq!(versions(&file), (CORE, 0));
}

/// A file whose Core track is behind the code, as a file of an older release would be: `create`
/// made it, then everything the Core track made was taken out without the authorizer.
fn file_before_the_core_track(label: &str) -> ModuleFile {
    let file = new_file(label);
    let connection = raw_connection(&file.path());
    let core_tables: Vec<String> = connection
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name <> '_meta'")
        .expect("prepare")
        .query_map([], |row| row.get(0))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("read");
    for table in core_tables {
        connection
            .execute_batch(&format!("DROP TABLE {table}"))
            .expect("drop a Core table");
    }
    connection
        .execute_batch("DELETE FROM _meta WHERE key = 'core_schema_version'")
        .expect("forget the Core version");
    file
}

/// AC1 of Story 3.6, Core first: a module migration is refused while the Core track is behind,
/// with nothing written; once the Core's migrations ran, the module's apply.
#[test]
fn a_module_migration_waits_for_the_core_track() {
    let file = file_before_the_core_track("core-first");
    assert_eq!(versions(&file), (0, 0));
    let outcome = migrate(&file, 1, "CREATE TABLE one (x INTEGER);");
    assert!(
        matches!(outcome, Err(Error::CoreSchemaNotCurrent { found: 0, latest }) if latest == CORE),
        "{outcome:?}"
    );
    assert_eq!(table_names(&file), ["_meta"]);

    let mut handle = open::<Migration>(&file, &KEY).expect("open");
    assert_eq!(handle.apply_core_migrations().expect("Core track"), CORE);
    assert_eq!(handle.apply_core_migrations().expect("again"), 0);
    handle.close().expect("close");
    assert_eq!(versions(&file), (CORE, 0));
    migrate(&file, 1, "CREATE TABLE one (x INTEGER);").expect("the module's now");
    assert_eq!(versions(&file), (CORE, 1));
    assert_eq!(
        table_names(&file),
        table_names(&new_file("core-first-control"))
            .into_iter()
            .chain(["one".to_owned()])
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    );
}

/// A file whose Core track is newer than the code is neither migrated back nor given a module
/// migration.
#[test]
fn a_file_newer_than_the_core_is_left_alone() {
    let file = new_file("core-newer");
    raw_connection(&file.path())
        .execute_batch(&format!(
            "UPDATE _meta SET value = {} WHERE key = 'core_schema_version'",
            CORE + 1
        ))
        .expect("plant a newer version");
    let mut handle = open::<Migration>(&file, &KEY).expect("open");
    let core = handle.apply_core_migrations();
    let module = handle.apply_module_migration(1, "CREATE TABLE one (x INTEGER);");
    handle.close().expect("close");
    for outcome in [core.map(drop), module] {
        assert!(
            matches!(outcome, Err(Error::CoreSchemaNotCurrent { found, latest }) if found == CORE + 1 && latest == CORE),
            "{outcome:?}"
        );
    }
    assert_eq!(versions(&file), (CORE + 1, 0));
}

#[test]
fn a_malformed_schema_version_is_a_typed_error() {
    let file = new_file("version-malformed");
    raw_connection(&file.path())
        .execute_batch("INSERT INTO _meta (key, value) VALUES ('module_schema_version', -1)")
        .expect("plant");
    let reader = open::<Read>(&file, &KEY).expect("open");
    assert!(matches!(
        reader.schema_version(MigrationTrack::Module),
        Err(Error::MalformedSchemaVersion(MigrationTrack::Module))
    ));
    reader.close().expect("close");

    // `_meta` is STRICT, so only a file rewritten outside the storage layer holds a version that
    // is not an integer; it is malformed, not read as 0 or as a number parsed from text.
    raw_connection(&file.path())
        .execute_batch(
            "CREATE TABLE meta_copy AS SELECT * FROM _meta; DROP TABLE _meta;
             CREATE TABLE _meta (key TEXT PRIMARY KEY NOT NULL, value NOT NULL);
             INSERT INTO _meta SELECT * FROM meta_copy WHERE key <> 'module_schema_version';
             INSERT INTO _meta VALUES ('module_schema_version', '2'); DROP TABLE meta_copy;",
        )
        .expect("rewrite _meta");
    let reader = open::<Read>(&file, &KEY).expect("open");
    assert!(matches!(
        reader.schema_version(MigrationTrack::Module),
        Err(Error::MalformedSchemaVersion(MigrationTrack::Module))
    ));
}

/// The order check reads the version under the write lock (`BEGIN IMMEDIATE`): while another
/// connection holds a write transaction, a migration fails as busy and changes nothing.
#[test]
fn a_migration_waits_for_no_concurrent_writer() {
    let file = new_file("version-busy");
    let writer = open::<Write>(&file, &KEY).expect("open writer");
    writer
        .execute_batch("BEGIN IMMEDIATE")
        .expect("hold the write lock");
    let outcome = migrate(&file, 1, "CREATE TABLE one (x INTEGER);");
    assert!(
        matches!(&outcome, Err(Error::Sqlite(error)) if error.sqlite_error_code() == Some(rusqlite::ErrorCode::DatabaseBusy)),
        "{outcome:?}"
    );
    writer.execute_batch("COMMIT").expect("release");
    writer.close().expect("close");
    assert_eq!(versions(&file), (CORE, 0));
}

const ITEMS: &str = "CREATE TABLE items (
    id BLOB NOT NULL PRIMARY KEY,
    label TEXT NOT NULL,
    quantity INTEGER,
    total INTEGER GENERATED ALWAYS AS (quantity * 2) VIRTUAL
) STRICT;
CREATE INDEX items_label ON items (label);
CREATE UNIQUE INDEX items_lower ON items (lower(label)) WHERE quantity > 0;
CREATE TABLE loose (x INTEGER PRIMARY KEY, y REFERENCES items (id) ON DELETE CASCADE) WITHOUT ROWID;
CREATE VIEW labels AS SELECT label FROM items;
CREATE TRIGGER items_touch AFTER INSERT ON items BEGIN SELECT 1; END;";

fn column(
    name: &str,
    declared_type: &str,
    not_null: bool,
    primary_key: u32,
    hidden: i64,
) -> ColumnInfo {
    ColumnInfo {
        name: name.to_owned(),
        declared_type: declared_type.to_owned(),
        not_null,
        primary_key,
        hidden,
    }
}

fn check_schema<R: Inspect>(file: &ModuleFile) {
    let handle = open::<R>(file, &KEY).expect("open");
    let schema = handle
        .schema()
        .expect("the schema reads under the role's authorizer");
    handle.close().expect("close");

    let items = schema
        .tables
        .iter()
        .find(|table| table.name == "items")
        .expect("items");
    assert_eq!(items.kind, TableKind::Ordinary);
    assert!(items.strict && !items.without_rowid);
    assert_eq!(
        items.columns,
        [
            column("id", "BLOB", true, 1, 0),
            column("label", "TEXT", true, 0, 0),
            column("quantity", "INTEGER", false, 0, 0),
            column("total", "INTEGER", false, 0, 2),
        ]
    );
    let loose = schema
        .tables
        .iter()
        .find(|table| table.name == "loose")
        .expect("loose");
    assert!(!loose.strict && loose.without_rowid);
    assert_eq!(loose.columns[1], column("y", "", false, 0, 0));
    assert_eq!(
        loose.foreign_keys,
        [ForeignKey {
            table: "items".to_owned(),
            from: "y".to_owned()
        }]
    );
    assert!(items.foreign_keys.is_empty());
    let index = |name: &str| {
        items
            .indexes
            .iter()
            .find(|index| index.name == name)
            .unwrap_or_else(|| panic!("index {name} in {:?}", items.indexes))
    };
    let plain = index("items_label");
    assert_eq!(
        (plain.unique, plain.origin.as_str(), plain.partial),
        (false, "c", false)
    );
    let key_columns: Vec<(i64, Option<&str>, Option<&str>)> = plain
        .columns
        .iter()
        .filter(|column| column.key)
        .map(|column| {
            (
                column.cid,
                column.name.as_deref(),
                column.collation.as_deref(),
            )
        })
        .collect();
    assert_eq!(key_columns, [(1, Some("label"), Some("BINARY"))]);
    let expression = index("items_lower");
    assert!(expression.unique && expression.partial);
    assert_eq!(expression.columns[0].cid, -2, "an expression column");
    let primary = items
        .indexes
        .iter()
        .find(|index| index.origin == "pk")
        .expect("the index of the BLOB primary key");
    assert!(primary.unique);
    let view = schema
        .tables
        .iter()
        .find(|table| table.name == "labels")
        .expect("view");
    assert_eq!(view.kind, TableKind::View);
    assert!(view.columns.is_empty());
    let meta = schema
        .tables
        .iter()
        .find(|table| table.name == "_meta")
        .expect("_meta");
    assert!(meta.strict && meta.without_rowid);

    let objects: Vec<(&str, &str, &str)> = schema
        .objects
        .iter()
        .map(|object| {
            (
                object.kind.as_str(),
                object.name.as_str(),
                object.table.as_str(),
            )
        })
        .collect();
    for expected in [
        ("index", "items_label", "items"),
        ("table", "items", "items"),
        ("table", "_meta", "_meta"),
        ("trigger", "items_touch", "items"),
        ("view", "labels", "labels"),
    ] {
        assert!(objects.contains(&expected), "{expected:?} in {objects:?}");
    }
    let index_sql = schema
        .objects
        .iter()
        .find(|object| object.name == "items_label")
        .and_then(|object| object.sql.as_deref());
    assert_eq!(index_sql, Some("CREATE INDEX items_label ON items (label)"));
}

#[test]
fn read_and_write_handles_read_the_schema() {
    let file = new_file("schema");
    migrate(&file, 1, ITEMS).expect("migrate");
    check_schema::<Read>(&file);
    check_schema::<Write>(&file);
}

/// The registry reads an FTS5 table, its shadow tables and its `secure-delete` option through a
/// read handle. The file is set up without the authorizer, since one table here writes its
/// `_config` shadow table directly, which no module SQL can under defensive mode; `tests::fts5`
/// makes FTS5 tables through the migration runner (Story 3.7).
#[test]
fn fts5_tables_and_their_options_are_read() {
    let file = new_file("schema-fts5");
    raw_connection(&file.path())
        .execute_batch(
            "CREATE VIRTUAL TABLE notes USING fts5(body, content='', tokenize='porter');
             INSERT INTO notes (notes, rank) VALUES ('secure-delete', 1);
             CREATE VIRTUAL TABLE plain USING fts5(body);
             CREATE VIRTUAL TABLE texty USING fts5(body);
             INSERT INTO texty_config (k, v) VALUES ('secure-delete', 'on');",
        )
        .expect("create the FTS5 tables without an authorizer");
    let reader = open::<Read>(&file, &KEY).expect("open");
    let schema = reader.schema().expect("schema");
    let kind = |name: &str| {
        schema
            .tables
            .iter()
            .find(|table| table.name == name)
            .map(|table| table.kind.clone())
    };
    assert_eq!(kind("notes"), Some(TableKind::Virtual));
    for shadow in ["notes_data", "notes_idx", "notes_config", "notes_docsize"] {
        assert_eq!(kind(shadow), Some(TableKind::Shadow), "{shadow}");
    }
    assert_eq!(
        kind("notes_content"),
        None,
        "a contentless table keeps no content"
    );
    let sql = schema
        .objects
        .iter()
        .find(|object| object.name == "notes")
        .and_then(|object| object.sql.clone());
    assert_eq!(
        sql.as_deref(),
        Some("CREATE VIRTUAL TABLE notes USING fts5(body, content='', tokenize='porter')")
    );
    assert_eq!(
        reader.fts5_option("notes", "secure-delete").expect("read"),
        Some(1)
    );
    assert_eq!(
        reader.fts5_option("plain", "secure-delete").expect("read"),
        None
    );
    assert_eq!(
        reader.fts5_option("texty", "secure-delete").expect("read"),
        None,
        "only an integer value counts"
    );
}

/// Story 3.2's finding, settled by Story 3.7: SQLite checks a column added to a `STRICT` table
/// with `quick_check`, which the migration policies allow since that story, so a migration adds
/// a column to a `STRICT` table as it does to any other; `quick_check` is still refused on read
/// and write handles.
#[test]
fn a_column_is_added_to_a_strict_table_under_the_migration_authorizer() {
    let file = new_file("strict-add-column");
    migrate(
        &file,
        1,
        "CREATE TABLE strict_items (id BLOB NOT NULL PRIMARY KEY) STRICT;
         CREATE TABLE loose_items (id BLOB NOT NULL PRIMARY KEY);",
    )
    .expect("create");
    migrate(
        &file,
        2,
        "ALTER TABLE strict_items ADD COLUMN label TEXT;
         ALTER TABLE loose_items ADD COLUMN label TEXT;",
    )
    .expect("STRICT or not, a table takes a new column");
    for role in ["read", "write"] {
        let outcome = if role == "read" {
            let handle = open::<Read>(&file, &KEY).expect("open");
            handle.execute_batch("PRAGMA quick_check")
        } else {
            let handle = open::<Write>(&file, &KEY).expect("open");
            handle.execute_batch("PRAGMA quick_check")
        };
        assert!(
            outcome.as_ref().is_err_and(Error::is_refusal),
            "{role}: {outcome:?}"
        );
    }
}
