//! AC3: the hostile-statement tests of Story 1.7 (`spikes/sqlite-authorizer/tests/`), replayed
//! on the connections of this crate with the lists of `hostile.rs`, a byte-for-byte copy of the
//! spike's, and the controls that show each statement would run without the authorizer.
//!
//! One change from the spike follows from AC7: extension loading is compiled out, so the
//! `load_extension` statements fail as `no such function` with or without the authorizer, where
//! the spike saw an authorizer refusal. The replay accepts that outcome for the extension loading
//! class only.

use std::fs;
use std::path::Path;

use rusqlite::Connection;

use super::hostile::{
    self, Class, HOSTILE_STATEMENTS, HostileStatement, RUNTIME_HOSTILE_STATEMENTS,
};
use super::{
    KEY, create_module_file, disk_state, logical_state, no_such_function, raw_connection, schema,
    scratch_dir, without_authorizer,
};
use crate::authorizer::{
    self, ALLOWED_FUNCTIONS, ALLOWED_MODULES, COMPILED_OUT_FUNCTIONS, DENIED_FUNCTIONS,
    DENIED_MODULES, Policy, listed,
};
use crate::error::Error;
use crate::{Handle, Migration, ModuleFile, Read, Role, RoleKind, Write, open};

const PLAINTEXT_HEADER: &[u8] = b"SQLite format 3\0";

/// The copy of the spike's lists is the spike's file, byte for byte, so "unchanged" is checked,
/// not claimed. Both paths are read from the checkout, so line endings agree.
#[test]
fn the_hostile_lists_are_the_spike_file_unchanged() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let copy = fs::read(manifest.join("src/tests/hostile.rs")).expect("read the copy");
    let spike = fs::read(manifest.join("../../spikes/sqlite-authorizer/src/hostile.rs"))
        .expect("read the spike");
    assert!(
        copy == spike,
        "src/tests/hostile.rs differs from spikes/sqlite-authorizer/src/hostile.rs"
    );
}

/// What a hostile statement is allowed to fail with: an authorizer refusal, or for extension
/// loading the missing function of a build without it (AC7).
fn refused(statement: &HostileStatement, error: &Error) -> bool {
    error.is_refusal() || (statement.class == Class::ExtensionLoading && no_such_function(error))
}

/// Opens `file` for role `R` with an in-memory database attached as `other` before the
/// authorizer goes on, so `DETACH other` and `sqlcipher_export('other')` have a target.
fn open_with_other_attached<R: Role>(file: &ModuleFile) -> Handle<R> {
    let handle = open::<R>(file, &KEY).expect("open module file");
    without_authorizer(&handle, |raw| {
        raw.execute_batch("ATTACH DATABASE ':memory:' AS other")
            .expect("attach setup database")
    });
    handle
}

fn raw_with_other_attached(file: &ModuleFile) -> Connection {
    let connection = raw_connection(&file.path());
    connection
        .execute_batch("ATTACH DATABASE ':memory:' AS other")
        .expect("attach setup database");
    connection
}

// --- Controls (spike tests/control.rs) ---

#[test]
fn without_the_authorizer_no_hostile_statement_is_an_auth_refusal() {
    let mut failures = Vec::new();
    for statement in HOSTILE_STATEMENTS.iter().chain(RUNTIME_HOSTILE_STATEMENTS) {
        let dir = scratch_dir(&format!("control-{}", statement.name));
        let file = create_module_file(&dir);
        let connection = raw_with_other_attached(&file);
        let outcome = connection
            .execute_batch(&statement.sql_in(&dir))
            .map_err(Error::from);
        let passed = match statement.class {
            Class::ExtensionLoading => outcome.as_ref().is_err_and(no_such_function),
            _ => outcome.is_ok(),
        };
        if !passed {
            failures.push(format!("{}: {outcome:?}", statement.name));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Without the authorizer, `ATTACH ... KEY ''` plus `sqlcipher_export` writes the encrypted
/// module file out as a plaintext SQLite file: the escape D21 forbids.
#[test]
fn without_the_authorizer_a_plaintext_copy_can_be_written() {
    let dir = scratch_dir("control-plaintext-export");
    let file = create_module_file(&dir);
    let copy = dir.join("plaintext.db");
    let outcome = raw_connection(&file.path()).execute_batch(&format!(
        "ATTACH DATABASE '{}' AS plain KEY '';
         SELECT sqlcipher_export('plain');
         DETACH DATABASE plain;",
        hostile::escape_for_sql_string(&copy)
    ));
    let plaintext = fs::read(&copy).is_ok_and(|bytes| bytes.starts_with(PLAINTEXT_HEADER));
    assert!(
        outcome.is_ok() && plaintext,
        "{outcome:?}, plaintext copy: {plaintext}"
    );
}

#[test]
fn without_the_authorizer_vacuum_into_writes_a_copy() {
    let dir = scratch_dir("control-vacuum-into");
    let file = create_module_file(&dir);
    let copy = dir.join("vacuumed.db");
    let outcome = raw_connection(&file.path()).execute_batch(&format!(
        "VACUUM INTO '{}'",
        hostile::escape_for_sql_string(&copy)
    ));
    assert!(outcome.is_ok() && copy.exists(), "{outcome:?}");
}

// --- Migration connection (spike tests/migration.rs) ---

/// Statements that run before the hostile one inside the same migration, so a refusal that did
/// not roll the migration back would leave them behind.
const LEGITIMATE_PREFIX: &str = "CREATE TABLE added (x INTEGER);
INSERT INTO items (label) VALUES ('written by the migration');";

/// SQLite's refusal of VACUUM inside a transaction.
const VACUUM_IN_TRANSACTION: &str = "cannot VACUUM from within a transaction";

/// Runs `hostile_sql` at the end of a migration on a fresh module file and checks that it was
/// refused and that the file, its directory and its content are unchanged. SQLite's own refusal
/// of `VACUUM` inside the runner's transaction is accepted only for a `VACUUM` statement.
fn hostile_migration_is_refused_without_writing(
    label: &str,
    hostile_sql_for: impl Fn(&Path) -> String,
    accept: impl Fn(&Error) -> bool,
) -> Result<(), String> {
    let dir = scratch_dir(label);
    let file = create_module_file(&dir);
    let disk_before = disk_state(&file);
    let logical_before = logical_state(&file);

    let hostile_sql = hostile_sql_for(&dir);
    let is_vacuum = hostile_sql.trim_start().starts_with("VACUUM");
    let mut handle = open_with_other_attached::<Migration>(&file);
    let outcome = handle.apply_migration(&format!("{LEGITIMATE_PREFIX}\n{hostile_sql};"));
    handle.close().expect("close migration connection");

    let denied = outcome.as_ref().is_err_and(|error| {
        accept(error) || (is_vacuum && error.to_string().contains(VACUUM_IN_TRANSACTION))
    });
    let disk_unchanged = disk_state(&file) == disk_before;
    let logical_unchanged = logical_state(&file) == logical_before;
    if denied && disk_unchanged && logical_unchanged {
        Ok(())
    } else {
        Err(format!(
            "{label}: {outcome:?}; disk unchanged {disk_unchanged}; content unchanged {logical_unchanged}"
        ))
    }
}

#[test]
fn every_hostile_statement_is_refused_in_a_migration_and_nothing_is_written() {
    let failures: Vec<String> = HOSTILE_STATEMENTS
        .iter()
        .filter_map(|statement| {
            hostile_migration_is_refused_without_writing(
                &format!("migration.{}", statement.name),
                |dir| statement.sql_in(dir),
                |error| refused(statement, error),
            )
            .err()
        })
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The runner owns the transaction; a migration that ends or splits it is refused.
#[test]
fn transaction_control_inside_a_migration_is_refused() {
    let statements = [
        ("commit", "COMMIT"),
        ("end", "END"),
        ("rollback", "ROLLBACK"),
        ("begin", "BEGIN"),
        ("savepoint", "SAVEPOINT split"),
        ("release", "RELEASE split"),
    ];
    let failures: Vec<String> = statements
        .iter()
        .filter_map(|(name, sql)| {
            hostile_migration_is_refused_without_writing(
                &format!("migration.transaction_control.{name}"),
                |_| (*sql).to_owned(),
                Error::is_refusal,
            )
            .err()
        })
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Temporary objects and virtual tables are outside the migration allowlist. D127 opens FTS5
/// virtual tables to migrations; that is Story 3.7, AC9, with the registry's argument check.
#[test]
fn temporary_objects_and_virtual_tables_are_refused_in_a_migration() {
    let statements = [
        ("temp_table", "CREATE TEMP TABLE scratch (x)"),
        ("temp_view", "CREATE TEMP VIEW scratch AS SELECT 1"),
        (
            "temp_trigger",
            "CREATE TEMP TRIGGER scratch AFTER INSERT ON items BEGIN SELECT 1; END",
        ),
        (
            "virtual_table",
            "CREATE VIRTUAL TABLE scratch USING fts5(body)",
        ),
    ];
    let failures: Vec<String> = statements
        .iter()
        .filter_map(|(name, sql)| {
            hostile_migration_is_refused_without_writing(
                &format!("migration.not_allowlisted.{name}"),
                |_| (*sql).to_owned(),
                Error::is_refusal,
            )
            .err()
        })
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The statements an ordinary forward migration uses keep working under the authorizer, and their
/// effect is committed. `ANALYZE`, in Story 1.7's list, is refused since the Story 3.6 review
/// (M1; `tests::statistics`), so it is left out here.
#[test]
fn an_ordinary_migration_applies_under_the_authorizer() {
    let dir = scratch_dir("allowed-migration");
    let file = create_module_file(&dir);
    let mut handle = open::<Migration>(&file, &KEY).expect("open migration connection");
    let outcome = handle.apply_migration(
        "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL, item_id INTEGER REFERENCES items (id));
         CREATE INDEX notes_item ON notes (item_id);
         ALTER TABLE items ADD COLUMN done INTEGER NOT NULL DEFAULT 0;
         ALTER TABLE items RENAME COLUMN label TO title;
         ALTER TABLE items ADD COLUMN scratch TEXT;
         ALTER TABLE items DROP COLUMN scratch;
         CREATE TABLE staging (x INTEGER);
         ALTER TABLE staging RENAME TO renamed_staging;
         UPDATE items SET done = 1 WHERE title = 'first';
         INSERT INTO notes (body, item_id) SELECT 'backfilled', id FROM items;
         WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 3)
             INSERT INTO notes (body) SELECT 'seed ' || i FROM n;
         DELETE FROM notes WHERE body = 'seed 3';
         CREATE VIEW open_items AS SELECT id, title FROM items WHERE done = 0;
         CREATE TRIGGER items_touch AFTER UPDATE ON items BEGIN UPDATE notes SET body = body WHERE item_id = new.id; END;
         DROP INDEX notes_item;
         CREATE INDEX notes_body ON notes (body);
         PRAGMA table_info(items);
         PRAGMA TABLE_INFO(items);
         INSERT INTO counters (n) VALUES (2);
         PRAGMA foreign_key_check;
         SELECT count(*), upper(title), json_object('k', 1) FROM items;",
    );
    handle.close().expect("close migration connection");
    assert!(outcome.is_ok(), "{outcome:?}");
    let schema = schema(&file);
    assert!(
        ["notes", "notes_body", "open_items", "items_touch"]
            .iter()
            .all(|name| schema.iter().any(|entry| entry.contains(name)))
            && schema
                .iter()
                .any(|entry| entry.contains("title TEXT NOT NULL")),
        "{schema:#?}"
    );
}

#[test]
fn a_refused_migration_leaves_the_connection_usable() {
    let dir = scratch_dir("after-refusal");
    let file = create_module_file(&dir);
    let mut handle = open::<Migration>(&file, &KEY).expect("open migration connection");
    let refused = handle.apply_migration("PRAGMA writable_schema = ON;");
    let next = handle.apply_migration("CREATE TABLE later (x INTEGER);");
    assert!(
        refused.as_ref().is_err_and(Error::is_refusal) && next.is_ok(),
        "{refused:?}, {next:?}"
    );
}

/// Statements outside the runner, each of which a closed connection refuses.
fn refused_outside_the_runner(handle: &Handle<Migration>) -> Vec<String> {
    let statements = [
        ("create_table", "CREATE TABLE outside (x INTEGER)"),
        ("insert", "INSERT INTO items (label) VALUES ('outside')"),
        ("select", "SELECT count(*) FROM items"),
        ("attach", "ATTACH DATABASE ':memory:' AS outside"),
    ];
    statements
        .iter()
        .filter_map(|(name, sql)| {
            let outcome = handle.execute_batch(sql);
            (!outcome.as_ref().is_err_and(Error::is_refusal))
                .then(|| format!("{name}: {outcome:?}"))
        })
        .collect()
}

/// A migration connection is closed to everything outside the runner, before any migration,
/// after a successful one and after a refused one.
#[test]
fn a_migration_connection_is_closed_outside_the_runner() {
    let dir = scratch_dir("closed-outside");
    let file = create_module_file(&dir);
    let mut handle = open::<Migration>(&file, &KEY).expect("open migration connection");
    assert_eq!(
        refused_outside_the_runner(&handle),
        Vec::<String>::new(),
        "at open"
    );
    handle
        .apply_migration("CREATE TABLE inside (x INTEGER);")
        .expect("migration applies");
    assert_eq!(
        refused_outside_the_runner(&handle),
        Vec::<String>::new(),
        "after success"
    );
    let refused = handle.apply_migration("PRAGMA writable_schema = ON;");
    assert!(
        refused.as_ref().is_err_and(Error::is_refusal),
        "{refused:?}"
    );
    assert_eq!(
        refused_outside_the_runner(&handle),
        Vec::<String>::new(),
        "after failure"
    );
}

/// When the runner cannot even begin its transaction, the connection is still closed: ATTACH is
/// refused afterwards.
#[test]
fn a_failed_begin_leaves_the_connection_closed() {
    let dir = scratch_dir("failed-begin");
    let file = create_module_file(&dir);
    let mut handle = open::<Migration>(&file, &KEY).expect("open migration connection");
    without_authorizer(&handle, |raw| {
        raw.execute_batch("BEGIN")
            .expect("open a transaction so the runner's BEGIN fails")
    });
    let outcome = handle.apply_migration("CREATE TABLE inside (x INTEGER);");
    assert!(
        outcome.as_ref().is_err_and(|error| !error.is_refusal()),
        "{outcome:?}"
    );
    let attach = handle.execute_batch("ATTACH DATABASE ':memory:' AS escape_after_failure");
    assert!(attach.as_ref().is_err_and(Error::is_refusal), "{attach:?}");
}

/// The internal functions `ALTER TABLE` needs are allowed under the migration policy, but SQL
/// text cannot call them.
#[test]
fn internal_alter_functions_cannot_be_called_from_migration_sql() {
    let dir = scratch_dir("internal-functions");
    let file = create_module_file(&dir);
    let mut handle = open::<Migration>(&file, &KEY).expect("open migration connection");
    let outcome = handle.apply_migration(
        "SELECT sqlite_rename_test('main', 'CREATE TABLE t (x)', 'table', 't', 0, 'x', 0);",
    );
    assert!(outcome.as_ref().is_err_and(no_such_function), "{outcome:?}");
}

// --- Read and write connections (spike tests/runtime.rs) ---

fn select_items<R: Role>(handle: &Handle<R>) -> crate::Result<i64> {
    handle.query_row("SELECT count(*) FROM items", [], |row| row.get(0))
}

/// Every hostile statement on one connection of role `R`, each followed by an allowed `SELECT`,
/// then the file and directory checked unchanged.
fn hostile_statements_are_refused_on<R: Role>(label: &str) -> Vec<String> {
    let dir = scratch_dir(label);
    let file = create_module_file(&dir);
    let disk_before = disk_state(&file);
    let handle = open_with_other_attached::<R>(&file);
    let mut failures = Vec::new();
    for statement in HOSTILE_STATEMENTS.iter().chain(RUNTIME_HOSTILE_STATEMENTS) {
        let outcome = handle.execute_batch(&statement.sql_in(&dir));
        if !outcome
            .as_ref()
            .is_err_and(|error| refused(statement, error))
        {
            failures.push(format!("{label}.{}: {outcome:?}", statement.name));
        }
        if let Err(error) = select_items(&handle) {
            failures.push(format!(
                "{label}.select_after_{}: {error:?}",
                statement.name
            ));
        }
    }
    handle.close().expect("close connection");
    let disk_after = disk_state(&file);
    if disk_after != disk_before {
        failures.push(format!(
            "{label}: directory before {:?}, after {:?}, file bytes equal {}",
            disk_before.directory,
            disk_after.directory,
            disk_before.file_bytes == disk_after.file_bytes
        ));
    }
    failures
}

#[test]
fn hostile_statements_are_refused_on_a_read_connection_and_select_succeeds() {
    let failures = hostile_statements_are_refused_on::<Read>("read");
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn hostile_statements_are_refused_on_a_write_connection_and_select_succeeds() {
    let failures = hostile_statements_are_refused_on::<Write>("write");
    assert!(failures.is_empty(), "{failures:#?}");
}

fn runs<R: Role>(file: &ModuleFile, sql: &str) -> crate::Result<()> {
    let handle = open::<R>(file, &KEY).expect("open connection");
    let outcome = handle.execute_batch(sql);
    handle.close().expect("close connection");
    outcome
}

/// Each role refuses what lies outside its allowlist and runs what lies inside it. AC2: a read
/// handle refuses every statement other than `SELECT`.
#[test]
fn each_runtime_role_runs_only_its_own_statements() {
    let cases: [(RoleKind, &str, &str, bool); 15] = [
        (
            RoleKind::Read,
            "select_with_function",
            "SELECT upper(label), json_object('k', 1) FROM items",
            true,
        ),
        (
            RoleKind::Read,
            "explicit_read_transaction",
            "BEGIN; SELECT count(*) FROM items; COMMIT",
            true,
        ),
        (
            RoleKind::Read,
            "introspection_pragma",
            "PRAGMA table_info(items)",
            true,
        ),
        (
            RoleKind::Read,
            "insert",
            "INSERT INTO items (label) VALUES ('x')",
            false,
        ),
        (
            RoleKind::Read,
            "update",
            "UPDATE items SET label = 'x'",
            false,
        ),
        (RoleKind::Read, "delete", "DELETE FROM items", false),
        (
            RoleKind::Read,
            "create_table",
            "CREATE TABLE extra (x)",
            false,
        ),
        (
            RoleKind::Read,
            "uppercase_introspection_pragma",
            "PRAGMA TABLE_INFO(items)",
            true,
        ),
        (
            RoleKind::Write,
            "autoincrement_insert",
            "INSERT INTO counters (n) VALUES (2)",
            true,
        ),
        (
            RoleKind::Write,
            "insert_sqlite_sequence",
            "INSERT INTO sqlite_sequence (name, seq) VALUES ('items', 99)",
            false,
        ),
        (
            RoleKind::Write,
            "insert_update_delete",
            "BEGIN; INSERT INTO items (label) VALUES ('x'); UPDATE items SET label = 'y' WHERE label = 'x'; DELETE FROM items WHERE label = 'y'; COMMIT",
            true,
        ),
        (
            RoleKind::Write,
            "savepoint",
            "SAVEPOINT s; INSERT INTO items (label) VALUES ('x'); ROLLBACK TO s; RELEASE s",
            true,
        ),
        (
            RoleKind::Write,
            "create_table",
            "CREATE TABLE extra (x)",
            false,
        ),
        (RoleKind::Write, "drop_table", "DROP TABLE items", false),
        // Plain VACUUM attaches a temporary database internally; the authorizer sees that ATTACH.
        (RoleKind::Write, "vacuum", "VACUUM", false),
    ];
    let dir = scratch_dir("roles");
    let file = create_module_file(&dir);
    let mut failures = Vec::new();
    for (role, name, sql, expect_allowed) in cases {
        let outcome = match role {
            RoleKind::Read => runs::<Read>(&file, sql),
            RoleKind::Write => runs::<Write>(&file, sql),
            RoleKind::Migration => runs::<Migration>(&file, sql),
        };
        let passed = if expect_allowed {
            outcome.is_ok()
        } else {
            outcome.as_ref().is_err_and(Error::is_refusal)
        };
        if !passed {
            failures.push(format!("{role:?}.{name}: {outcome:?}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// A trigger or view planted in the file cannot call a denied function. The authorizer is checked
/// on its own first, with `trusted_schema` switched back on so only it can refuse; then the same
/// objects run on handles, where `trusted_schema` is off as well.
#[test]
fn planted_trigger_and_view_cannot_call_a_denied_function() {
    let dir = scratch_dir("planted");
    let file = create_module_file(&dir);
    raw_connection(&file.path())
        .execute_batch(
            "CREATE TRIGGER planted AFTER INSERT ON items BEGIN SELECT sqlcipher_export('main'); END;
             CREATE VIEW planted_view AS SELECT sqlcipher_export('main') AS exported;",
        )
        .expect("plant trigger and view");
    let fire_trigger = "INSERT INTO items (label) VALUES ('fires the trigger')";
    let read_view = "SELECT * FROM planted_view";

    for (policy, sql) in [(Policy::Write, fire_trigger), (Policy::Read, read_view)] {
        let connection = raw_connection(&file.path());
        connection
            .pragma_update(None, "trusted_schema", true)
            .expect("trusted_schema on");
        authorizer::install(&connection, policy).expect("install authorizer");
        let outcome = connection.execute_batch(sql).map_err(Error::from);
        assert!(
            outcome.as_ref().is_err_and(Error::is_refusal),
            "{policy:?}: {outcome:?}"
        );
    }
    let insert = runs::<Write>(&file, fire_trigger);
    assert!(insert.is_err(), "write handle: {insert:?}");
    let view = runs::<Read>(&file, read_view);
    assert!(view.is_err(), "read handle: {view:?}");
}

/// `sqlite_dbpage`, which writes raw pages, is not compiled into this build either.
#[test]
fn sqlite_dbpage_is_not_compiled_in() {
    let dir = scratch_dir("dbpage");
    let file = create_module_file(&dir);
    let outcome = raw_connection(&file.path())
        .execute_batch("INSERT INTO sqlite_dbpage (pgno, data) VALUES (1, zeroblob(4096))");
    assert!(
        outcome.as_ref().is_err_and(|error| error
            .to_string()
            .starts_with("no such table: sqlite_dbpage")),
        "{outcome:?}"
    );
}

/// AC8: a statement prepared before the authorizer is installed is expired by the install and
/// re-checked when it runs, so a statement cache cannot carry a forbidden statement past it.
#[test]
fn a_statement_prepared_before_the_authorizer_is_rechecked() {
    let dir = scratch_dir("prepared-before");
    let file = create_module_file(&dir);
    let connection = raw_connection(&file.path());
    let mut statement = connection
        .prepare("PRAGMA secure_delete = OFF")
        .expect("prepare before the authorizer");
    authorizer::install(&connection, Policy::Write).expect("install authorizer");
    let outcome = statement.execute([]).map(drop).map_err(Error::from);
    assert!(
        outcome.as_ref().is_err_and(Error::is_refusal),
        "{outcome:?}"
    );
}

// --- Function allowlist coverage (spike tests/function_list.rs) and AC8 ---

/// Every SQL function this build offers is reviewed exactly once; a reviewed function the build
/// does not offer is stale, except those `build.rs` compiles out, which must indeed be absent.
#[test]
fn every_engine_function_is_reviewed_exactly_once() {
    let connection = raw_connection(&scratch_dir("functions").join("f.db"));
    let engine: Vec<String> = connection
        .prepare("SELECT DISTINCT name FROM pragma_function_list ORDER BY name")
        .expect("prepare function list")
        .query_map([], |row| row.get(0))
        .expect("query function list")
        .collect::<Result<_, _>>()
        .expect("read function list");
    let offered = |name: &str| {
        engine
            .iter()
            .any(|offered| offered.eq_ignore_ascii_case(name))
    };

    let unreviewed: Vec<&String> = engine
        .iter()
        .filter(|name| !listed(ALLOWED_FUNCTIONS, name) && !listed(DENIED_FUNCTIONS, name))
        .collect();
    let in_both: Vec<&&str> = ALLOWED_FUNCTIONS
        .iter()
        .filter(|name| listed(DENIED_FUNCTIONS, name))
        .collect();
    let stale: Vec<&&str> = ALLOWED_FUNCTIONS
        .iter()
        .chain(DENIED_FUNCTIONS)
        .filter(|name| !offered(name) && !listed(COMPILED_OUT_FUNCTIONS, name))
        .collect();
    let compiled_in: Vec<&&str> = COMPILED_OUT_FUNCTIONS
        .iter()
        .filter(|name| offered(name))
        .collect();
    let not_denied: Vec<&&str> = COMPILED_OUT_FUNCTIONS
        .iter()
        .filter(|name| !listed(DENIED_FUNCTIONS, name))
        .collect();
    assert!(
        unreviewed.is_empty()
            && in_both.is_empty()
            && stale.is_empty()
            && compiled_in.is_empty()
            && not_denied.is_empty(),
        "{} offered; unreviewed {unreviewed:?}; in both {in_both:?}; stale {stale:?}; \
         compiled out but offered {compiled_in:?}; compiled out but not denied {not_denied:?}",
        engine.len()
    );
}

/// AC8: `sqlcipher_export` and `fts5` are refused by the authorizer on every runtime role, as
/// `SQLITE_ERROR` "not authorized to use function", classified as a refusal; `load_extension`
/// does not exist (AC7).
#[test]
fn denied_functions_are_refused_and_classified_as_refusals() {
    let dir = scratch_dir("denied-functions");
    let file = create_module_file(&dir);
    for sql in ["SELECT sqlcipher_export('main')", "SELECT fts5(NULL)"] {
        for outcome in [runs::<Write>(&file, sql), runs::<Read>(&file, sql)] {
            let error = outcome.expect_err(sql);
            let shape = match &error {
                Error::Refused(rusqlite::Error::SqlInputError { error, msg, .. })
                | Error::Refused(rusqlite::Error::SqliteFailure(error, Some(msg))) => {
                    error.extended_code == rusqlite::ffi::SQLITE_ERROR
                        && msg.starts_with("not authorized to use function: ")
                }
                _ => false,
            };
            assert!(shape, "{sql}: {error:?}");
        }
    }
}

/// AC8: writes to SQLite's internal tables are refused outside migrations, on every runtime role.
#[test]
fn internal_table_writes_are_refused_outside_migrations() {
    let dir = scratch_dir("internal-tables");
    let file = create_module_file(&dir);
    for sql in [
        "INSERT INTO sqlite_sequence (name, seq) VALUES ('counters', 7)",
        "UPDATE sqlite_sequence SET seq = 0",
        "DELETE FROM sqlite_sequence",
    ] {
        for outcome in [runs::<Write>(&file, sql), runs::<Read>(&file, sql)] {
            assert!(
                outcome.as_ref().is_err_and(Error::is_refusal),
                "{sql}: {outcome:?}"
            );
        }
    }
}

/// Review item 5: every virtual table module the engine offers is reviewed exactly once, like the
/// functions of AC8, and every reviewed module is offered.
#[test]
fn every_engine_module_is_reviewed_exactly_once() {
    let connection = raw_connection(&scratch_dir("modules").join("m.db"));
    let engine: Vec<String> = connection
        .prepare("SELECT name FROM pragma_module_list ORDER BY name")
        .expect("prepare module list")
        .query_map([], |row| row.get(0))
        .expect("query module list")
        .collect::<Result<_, _>>()
        .expect("read module list");
    let offered = |name: &str| {
        engine
            .iter()
            .any(|module| module.eq_ignore_ascii_case(name))
    };
    let unreviewed: Vec<&String> = engine
        .iter()
        .filter(|name| !listed(ALLOWED_MODULES, name) && !listed(DENIED_MODULES, name))
        .collect();
    let in_both: Vec<&&str> = ALLOWED_MODULES
        .iter()
        .filter(|name| listed(DENIED_MODULES, name))
        .collect();
    let stale: Vec<&&str> = ALLOWED_MODULES
        .iter()
        .chain(DENIED_MODULES)
        .filter(|name| !offered(name))
        .collect();
    assert!(
        unreviewed.is_empty() && in_both.is_empty() && stale.is_empty(),
        "{engine:?}; unreviewed {unreviewed:?}; in both {in_both:?}; stale {stale:?}"
    );
}

/// Review item 5: `dbstat`, an eponymous table any statement could read, is refused on every
/// runtime role, while it runs without the authorizer.
#[test]
fn dbstat_is_refused() {
    let dir = scratch_dir("dbstat");
    let file = create_module_file(&dir);
    for sql in [
        "SELECT count(*) FROM dbstat",
        "SELECT name, pgsize FROM dbstat",
    ] {
        raw_connection(&file.path())
            .execute_batch(sql)
            .unwrap_or_else(|error| panic!("control {sql}: {error}"));
        for outcome in [runs::<Write>(&file, sql), runs::<Read>(&file, sql)] {
            assert!(
                outcome.as_ref().is_err_and(Error::is_refusal),
                "{sql}: {outcome:?}"
            );
        }
    }
}
