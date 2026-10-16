//! AC2 and AD-5: the same authorizer on ordinary read and write connections refuses the hostile
//! statements, while the statements those roles exist for keep working.

mod common;

use common::{
    KEY, create_module_file, describe, disk_state, open_with_other_attached, report, scratch_dir,
    without_authorizer,
};
use rusqlite::Connection;
use sqlite_authorizer::hostile::{HOSTILE_STATEMENTS, RUNTIME_HOSTILE_STATEMENTS};
use sqlite_authorizer::{
    Policy, Role, apply_raw_key, install_authorizer, is_authorizer_denial, open,
};

fn role_label(role: Role) -> &'static str {
    match role {
        Role::Read => "read",
        Role::Write => "write",
        Role::Migration => "migration",
    }
}

fn select_items(connection: &Connection) -> rusqlite::Result<()> {
    connection
        .query_row("SELECT count(*) FROM items", [], |row| row.get::<_, i64>(0))
        .map(|_| ())
}

/// Submits every hostile statement on one connection of `role`, each followed by an allowed
/// `SELECT` on the same connection, then checks that the file and directory are unchanged.
fn hostile_statements_are_refused_on(role: Role) -> Vec<String> {
    let label = role_label(role);
    let dir = scratch_dir(label);
    let path = create_module_file(&dir);
    let disk_before = disk_state(&path);

    let connection = open_with_other_attached(&path, role);
    let mut failures = Vec::new();
    for statement in HOSTILE_STATEMENTS.iter().chain(RUNTIME_HOSTILE_STATEMENTS) {
        let outcome = connection.execute_batch(&statement.sql_in(&dir));
        let check = format!("{label}.{}", statement.name);
        if !report(
            outcome.as_ref().is_err_and(is_authorizer_denial),
            &check,
            &describe(&outcome),
        ) {
            failures.push(check);
        }
        let select = select_items(&connection);
        let check = format!("{label}.select_after_{}", statement.name);
        if !report(select.is_ok(), &check, &describe(&select)) {
            failures.push(check);
        }
    }
    connection.close().expect("close connection");

    let check = format!("{label}.file_and_directory_unchanged");
    let disk_after = disk_state(&path);
    if !report(
        disk_after == disk_before,
        &check,
        &format!(
            "directory before {:?}, after {:?}, file bytes equal: {}",
            disk_before.directory,
            disk_after.directory,
            disk_before.file_bytes == disk_after.file_bytes
        ),
    ) {
        failures.push(check);
    }
    failures
}

#[test]
fn hostile_statements_are_refused_on_a_read_connection_and_select_succeeds() {
    let failures = hostile_statements_are_refused_on(Role::Read);
    assert!(failures.is_empty(), "{failures:?}");
}

#[test]
fn hostile_statements_are_refused_on_a_write_connection_and_select_succeeds() {
    let failures = hostile_statements_are_refused_on(Role::Write);
    assert!(failures.is_empty(), "{failures:?}");
}

/// Each role refuses what lies outside its allowlist, and runs what lies inside it.
#[test]
fn each_runtime_role_runs_only_its_own_statements() {
    let cases: [(Role, &str, &str, bool); 13] = [
        (
            Role::Read,
            "select_with_function",
            "SELECT upper(label), json_object('k', 1) FROM items",
            true,
        ),
        (
            Role::Read,
            "explicit_read_transaction",
            "BEGIN; SELECT count(*) FROM items; COMMIT",
            true,
        ),
        (
            Role::Read,
            "introspection_pragma",
            "PRAGMA table_info(items)",
            true,
        ),
        (
            Role::Read,
            "insert",
            "INSERT INTO items (label) VALUES ('x')",
            false,
        ),
        (Role::Read, "create_table", "CREATE TABLE extra (x)", false),
        (
            Role::Read,
            "uppercase_introspection_pragma",
            "PRAGMA TABLE_INFO(items)",
            true,
        ),
        (
            Role::Write,
            "autoincrement_insert",
            "INSERT INTO counters (n) VALUES (2)",
            true,
        ),
        (
            Role::Write,
            "insert_sqlite_sequence",
            "INSERT INTO sqlite_sequence (name, seq) VALUES ('items', 99)",
            false,
        ),
        (
            Role::Write,
            "insert_update_delete",
            "BEGIN; INSERT INTO items (label) VALUES ('x'); UPDATE items SET label = 'y' WHERE label = 'x'; DELETE FROM items WHERE label = 'y'; COMMIT",
            true,
        ),
        (
            Role::Write,
            "savepoint",
            "SAVEPOINT s; INSERT INTO items (label) VALUES ('x'); ROLLBACK TO s; RELEASE s",
            true,
        ),
        (Role::Write, "create_table", "CREATE TABLE extra (x)", false),
        (Role::Write, "drop_table", "DROP TABLE items", false),
        // Plain VACUUM attaches a temporary database internally; the authorizer sees that ATTACH.
        (Role::Write, "vacuum", "VACUUM", false),
    ];
    let dir = scratch_dir("roles");
    let path = create_module_file(&dir);
    let mut failures = Vec::new();
    for (role, name, sql, expect_allowed) in cases {
        let connection = open(&path, &KEY, role).expect("open connection");
        let outcome = connection.execute_batch(sql);
        let passed = if expect_allowed {
            outcome.is_ok()
        } else {
            outcome.as_ref().is_err_and(is_authorizer_denial)
        };
        let verdict = if expect_allowed { "allowed" } else { "refused" };
        let check = format!("{}.{verdict}.{name}", role_label(role));
        if !report(passed, &check, &describe(&outcome)) {
            failures.push(check);
        }
        connection.close().expect("close connection");
    }
    assert!(failures.is_empty(), "{failures:?}");
}

/// A trigger or view planted in the file (by a hostile migration that predates the authorizer,
/// or by an attacker who can write the file and holds its key) cannot call a denied function.
/// The authorizer is checked on its own first: `trusted_schema` is switched back on, so only the
/// authorizer can refuse. Then the same objects are run on connections from `open`, where
/// `trusted_schema` is off as well and either layer may refuse first.
#[test]
fn planted_trigger_and_view_cannot_call_a_denied_function() {
    let dir = scratch_dir("planted");
    let path = create_module_file(&dir);
    {
        let planting = Connection::open(&path).expect("open for planting");
        apply_raw_key(&planting, &KEY).expect("key for planting");
        planting
            .execute_batch(
                "CREATE TRIGGER planted AFTER INSERT ON items BEGIN SELECT sqlcipher_export('main'); END;
                 CREATE VIEW planted_view AS SELECT sqlcipher_export('main') AS exported;",
            )
            .expect("plant trigger and view");
    }
    let fire_trigger = "INSERT INTO items (label) VALUES ('fires the trigger')";
    let read_view = "SELECT * FROM planted_view";

    let mut passed = true;
    for (label, policy, sql) in [
        ("write", Policy::Write, fire_trigger),
        ("read", Policy::Read, read_view),
    ] {
        let connection = Connection::open(&path).expect("open with trusted schema");
        apply_raw_key(&connection, &KEY).expect("key");
        connection
            .pragma_update(None, "trusted_schema", true)
            .expect("trusted_schema on");
        install_authorizer(&connection, policy).expect("install authorizer");
        let outcome = connection.execute_batch(sql);
        passed &= report(
            outcome.as_ref().is_err_and(is_authorizer_denial),
            &format!("{label}.planted_sqlcipher_export_refused_by_authorizer"),
            &describe(&outcome),
        );
    }

    let writer = open(&path, &KEY, Role::Write).expect("open write connection");
    let insert = writer.execute_batch(fire_trigger);
    passed &= report(
        insert.is_err(),
        "write.planted_trigger_refused_on_open_connection",
        &describe(&insert),
    );
    let reader = open(&path, &KEY, Role::Read).expect("open read connection");
    let view = reader.execute_batch(read_view);
    passed &= report(
        view.is_err(),
        "read.planted_view_refused_on_open_connection",
        &describe(&view),
    );
    assert!(passed);
}

/// `open` runs its setup pragmas before the authorizer; read them back with it removed.
#[test]
fn open_applies_the_setup_pragmas() {
    let dir = scratch_dir("setup-pragmas");
    let path = create_module_file(&dir);
    let mut passed = true;
    for role in [Role::Migration, Role::Write, Role::Read] {
        let label = role_label(role);
        let connection = open(&path, &KEY, role).expect("open connection");
        let (secure_delete, trusted_schema, journal_mode) =
            without_authorizer(&connection, role.opening_policy(), |raw| {
                let read_int = |pragma: &str| -> i64 {
                    raw.pragma_query_value(None, pragma, |row| row.get(0))
                        .expect("read pragma")
                };
                let journal: String = raw
                    .pragma_query_value(None, "journal_mode", |row| row.get(0))
                    .expect("read journal_mode");
                (
                    read_int("secure_delete"),
                    read_int("trusted_schema"),
                    journal,
                )
            });
        passed &= report(
            secure_delete == 1,
            &format!("{label}.setup.secure_delete_on"),
            &format!("secure_delete = {secure_delete}"),
        );
        passed &= report(
            trusted_schema == 0,
            &format!("{label}.setup.trusted_schema_off"),
            &format!("trusted_schema = {trusted_schema}"),
        );
        if role != Role::Read {
            passed &= report(
                journal_mode == "wal",
                &format!("{label}.setup.journal_mode_wal"),
                &format!("journal_mode = {journal_mode}"),
            );
        }
        connection.close().expect("close connection");
    }
    assert!(passed);
}

/// `sqlite_dbpage`, which writes raw pages, is not compiled into this build, so a statement
/// against it fails before the authorizer is asked.
#[test]
fn sqlite_dbpage_is_not_compiled_in() {
    let dir = scratch_dir("dbpage");
    let path = create_module_file(&dir);
    let connection = Connection::open(&path).expect("open without authorizer");
    apply_raw_key(&connection, &KEY).expect("key");
    let outcome = connection
        .execute_batch("INSERT INTO sqlite_dbpage (pgno, data) VALUES (1, zeroblob(4096))");
    let passed = report(
        outcome.as_ref().is_err_and(|error| {
            error
                .to_string()
                .starts_with("no such table: sqlite_dbpage")
        }),
        "control.sqlite_dbpage_not_compiled_in",
        &describe(&outcome),
    );
    assert!(passed);
}

/// A statement prepared before the authorizer is installed is expired by the install and
/// re-checked when it runs, so a statement cache cannot carry a forbidden statement past it.
#[test]
fn a_statement_prepared_before_the_authorizer_is_rechecked() {
    let dir = scratch_dir("prepared-before");
    let path = create_module_file(&dir);
    let connection = Connection::open(&path).expect("open without authorizer");
    apply_raw_key(&connection, &KEY).expect("key");
    let mut statement = connection
        .prepare("PRAGMA secure_delete = OFF")
        .expect("prepare before the authorizer");
    install_authorizer(&connection, Policy::Write).expect("install authorizer");
    let outcome = statement.execute([]).map(|_| ());
    let passed = report(
        outcome.as_ref().is_err_and(is_authorizer_denial),
        "write.statement_prepared_before_authorizer",
        &describe(&outcome),
    );
    assert!(passed);
}
