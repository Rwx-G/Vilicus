//! AC1: on the migration connection, every hostile statement is refused by the authorizer and
//! the migration that carries it writes nothing.

mod common;

use common::without_authorizer;
use common::{
    KEY, create_module_file, describe, disk_state, logical_state, open_with_other_attached, report,
    schema, scratch_dir,
};
use rusqlite::Connection;
use sqlite_authorizer::hostile::HOSTILE_STATEMENTS;
use sqlite_authorizer::{Policy, Role, apply_migration, is_authorizer_denial, open};

/// Statements that run before the hostile one inside the same migration, so a refusal that
/// did not roll the migration back would leave them behind.
const LEGITIMATE_PREFIX: &str = "CREATE TABLE added (x INTEGER);
INSERT INTO items (label) VALUES ('written by the migration');";

/// SQLite's refusal of VACUUM inside a transaction.
const VACUUM_IN_TRANSACTION: &str = "cannot VACUUM from within a transaction";

/// Runs `hostile_sql` at the end of a migration on a fresh module file and checks that the
/// authorizer refused it and that the file, its directory and its content are unchanged.
/// SQLite's own refusal of `VACUUM` inside the runner's transaction is accepted only for a
/// statement that is a `VACUUM`.
fn hostile_migration_is_refused_without_writing(
    check: &str,
    hostile_sql_for: impl Fn(&std::path::Path) -> String,
) -> bool {
    let dir = scratch_dir(check);
    let path = create_module_file(&dir);
    let disk_before = disk_state(&path);
    let logical_before = logical_state(&path);

    let hostile_sql = hostile_sql_for(&dir);
    let is_vacuum = hostile_sql.trim_start().starts_with("VACUUM");
    let mut connection = open_with_other_attached(&path, Role::Migration);
    let outcome = apply_migration(
        &mut connection,
        &format!("{LEGITIMATE_PREFIX}\n{hostile_sql};"),
    );
    connection.close().expect("close migration connection");

    // VACUUM is refused inside the runner's transaction before the authorizer is consulted;
    // the runtime tests show the authorizer refusing it outside a transaction.
    let denied = outcome.as_ref().is_err_and(|error| {
        is_authorizer_denial(error)
            || (is_vacuum && error.to_string().starts_with(VACUUM_IN_TRANSACTION))
    });
    let disk_unchanged = disk_state(&path) == disk_before;
    let logical_unchanged = logical_state(&path) == logical_before;
    report(
        denied && disk_unchanged && logical_unchanged,
        check,
        &format!(
            "{}; file and directory unchanged: {disk_unchanged}; schema and rows unchanged: {logical_unchanged}",
            describe(&outcome)
        ),
    )
}

#[test]
fn every_hostile_statement_is_refused_in_a_migration_and_nothing_is_written() {
    let failures: Vec<&str> = HOSTILE_STATEMENTS
        .iter()
        .filter(|statement| {
            !hostile_migration_is_refused_without_writing(
                &format!("migration.{}", statement.name),
                |dir| statement.sql_in(dir),
            )
        })
        .map(|statement| statement.name)
        .collect();
    assert!(
        failures.is_empty(),
        "not refused or wrote something: {failures:?}"
    );
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
    let failures: Vec<&str> = statements
        .iter()
        .filter(|(name, sql)| {
            !hostile_migration_is_refused_without_writing(
                &format!("migration.transaction_control.{name}"),
                |_| (*sql).to_owned(),
            )
        })
        .map(|(name, _)| *name)
        .collect();
    assert!(
        failures.is_empty(),
        "not refused or wrote something: {failures:?}"
    );
}

/// Temporary objects and virtual tables are outside the migration allowlist.
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
    let failures: Vec<&str> = statements
        .iter()
        .filter(|(name, sql)| {
            !hostile_migration_is_refused_without_writing(
                &format!("migration.not_allowlisted.{name}"),
                |_| (*sql).to_owned(),
            )
        })
        .map(|(name, _)| *name)
        .collect();
    assert!(
        failures.is_empty(),
        "not refused or wrote something: {failures:?}"
    );
}

/// The statements an ordinary forward migration uses keep working under the authorizer, and
/// their effect is committed.
#[test]
fn an_ordinary_migration_applies_under_the_authorizer() {
    let dir = scratch_dir("allowed-migration");
    let path = create_module_file(&dir);
    let mut connection = open(&path, &KEY, Role::Migration).expect("open migration connection");
    let outcome = apply_migration(
        &mut connection,
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
         ANALYZE;
         SELECT count(*), upper(title), json_object('k', 1) FROM items;",
    );
    let applied = report(
        outcome.is_ok(),
        "migration.allowed.ordinary_migration_applies",
        &describe(&outcome),
    );
    connection.close().expect("close migration connection");

    let schema = schema(&path);
    let committed = report(
        ["notes", "notes_body", "open_items", "items_touch"]
            .iter()
            .all(|name| schema.iter().any(|entry| entry.contains(name)))
            && schema
                .iter()
                .any(|entry| entry.contains("title TEXT NOT NULL")),
        "migration.allowed.effects_committed",
        "",
    );
    assert!(
        applied && committed,
        "ordinary migration failed: {outcome:?}"
    );
}

/// After a refused migration the connection is still usable for the next one.
#[test]
fn a_refused_migration_leaves_the_connection_usable() {
    let dir = scratch_dir("after-refusal");
    let path = create_module_file(&dir);
    let mut connection = open(&path, &KEY, Role::Migration).expect("open migration connection");
    let refused = apply_migration(&mut connection, "PRAGMA writable_schema = ON;");
    let next = apply_migration(&mut connection, "CREATE TABLE later (x INTEGER);");
    let passed = report(
        refused.as_ref().is_err_and(is_authorizer_denial) && next.is_ok(),
        "migration.connection_usable_after_refusal",
        &format!("first: {}; next: {}", describe(&refused), describe(&next)),
    );
    assert!(passed);
}

/// Runs each statement outside the runner and reports whether all were refused by the
/// authorizer.
fn refused_outside_the_runner(connection: &Connection, check: &str) -> bool {
    let statements = [
        ("create_table", "CREATE TABLE outside (x INTEGER)"),
        ("insert", "INSERT INTO items (label) VALUES ('outside')"),
        ("select", "SELECT count(*) FROM items"),
        ("attach", "ATTACH DATABASE ':memory:' AS outside"),
    ];
    statements.iter().fold(true, |all, (name, sql)| {
        let outcome = connection.execute_batch(sql);
        report(
            outcome.as_ref().is_err_and(is_authorizer_denial),
            &format!("{check}.{name}"),
            &describe(&outcome),
        ) && all
    })
}

/// A migration connection is closed to everything outside `apply_migration`, before any
/// migration, after a successful one and after a refused one.
#[test]
fn a_migration_connection_is_closed_outside_the_runner() {
    let dir = scratch_dir("closed-outside");
    let path = create_module_file(&dir);
    let mut connection = open(&path, &KEY, Role::Migration).expect("open migration connection");
    let at_open = refused_outside_the_runner(&connection, "migration.closed_at_open");
    let applied = apply_migration(&mut connection, "CREATE TABLE inside (x INTEGER);");
    let after_success =
        report(
            applied.is_ok(),
            "migration.closed_after_success.migration_applied",
            &describe(&applied),
        ) && refused_outside_the_runner(&connection, "migration.closed_after_success");
    let refused = apply_migration(&mut connection, "PRAGMA writable_schema = ON;");
    let after_failure =
        report(
            refused.as_ref().is_err_and(is_authorizer_denial),
            "migration.closed_after_failure.migration_refused",
            &describe(&refused),
        ) && refused_outside_the_runner(&connection, "migration.closed_after_failure");
    assert!(at_open && after_success && after_failure);
}

/// `apply_migration` on a connection opened for another role leaves it closed, never under the
/// migration policy.
#[test]
fn apply_migration_on_a_write_connection_leaves_it_closed() {
    let dir = scratch_dir("migration-on-write");
    let path = create_module_file(&dir);
    let mut connection = open(&path, &KEY, Role::Write).expect("open write connection");
    let applied = apply_migration(&mut connection, "CREATE TABLE inside (x INTEGER);");
    let passed = report(
        applied.is_ok(),
        "write.apply_migration.migration_applied",
        &describe(&applied),
    ) && refused_outside_the_runner(&connection, "write.closed_after_apply_migration");
    assert!(passed);
}

/// When the runner cannot even begin its transaction, the connection is still under an
/// authorizer: ATTACH is refused afterwards.
#[test]
fn a_failed_begin_leaves_the_connection_closed() {
    let dir = scratch_dir("failed-begin");
    let path = create_module_file(&dir);
    let mut connection = open(&path, &KEY, Role::Migration).expect("open migration connection");
    without_authorizer(&connection, Policy::Closed, |raw| {
        raw.execute_batch("BEGIN")
            .expect("open a transaction so the runner's BEGIN fails")
    });
    let outcome = apply_migration(&mut connection, "CREATE TABLE inside (x INTEGER);");
    let begin_failed = report(
        outcome
            .as_ref()
            .is_err_and(|error| !is_authorizer_denial(error)),
        "migration.failed_begin.migration_not_applied",
        &describe(&outcome),
    );
    let attach = connection.execute_batch("ATTACH DATABASE ':memory:' AS escape_after_failure");
    let attach_refused = report(
        attach.as_ref().is_err_and(is_authorizer_denial),
        "migration.failed_begin.attach_refused_afterwards",
        &describe(&attach),
    );
    assert!(begin_failed && attach_refused);
}

/// The internal functions `ALTER TABLE` needs are allowed under the migration policy, but SQL
/// text cannot call them.
#[test]
fn internal_alter_functions_cannot_be_called_from_migration_sql() {
    let dir = scratch_dir("internal-functions");
    let path = create_module_file(&dir);
    let mut connection = open(&path, &KEY, Role::Migration).expect("open migration connection");
    let outcome = apply_migration(
        &mut connection,
        "SELECT sqlite_rename_test('main', 'CREATE TABLE t (x)', 'table', 't', 0, 'x', 0);",
    );
    let passed = report(
        outcome.as_ref().is_err_and(|error| {
            error
                .to_string()
                .starts_with("no such function: sqlite_rename_test")
        }),
        "migration.internal_alter_function_not_callable",
        &describe(&outcome),
    );
    assert!(passed);
}
