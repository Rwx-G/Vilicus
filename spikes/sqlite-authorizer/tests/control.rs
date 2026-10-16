//! Controls: without the authorizer, the hostile statements are not refused with
//! `SQLITE_AUTH`, so the refusals in the other tests come from the authorizer. Also shows the
//! escape the authorizer closes: a plaintext copy of an encrypted module file.

mod common;

use std::fs;

use common::{KEY, create_module_file, describe, report, scratch_dir};
use rusqlite::Connection;
use rusqlite::hooks::{AuthContext, Authorization};
use sqlite_authorizer::hostile::{
    Class, HOSTILE_STATEMENTS, RUNTIME_HOSTILE_STATEMENTS, escape_for_sql_string,
};
use sqlite_authorizer::{apply_raw_key, is_authorizer_denial};

const PLAINTEXT_HEADER: &[u8] = b"SQLite format 3\0";

fn connection_without_authorizer(dir: &std::path::Path) -> Connection {
    let path = create_module_file(dir);
    let connection = Connection::open(&path).expect("open without authorizer");
    apply_raw_key(&connection, &KEY).expect("key");
    connection
        .execute_batch("ATTACH DATABASE ':memory:' AS other")
        .expect("attach setup database");
    connection
}

#[test]
fn without_the_authorizer_no_hostile_statement_is_an_auth_refusal() {
    let mut failures = Vec::new();
    for statement in HOSTILE_STATEMENTS.iter().chain(RUNTIME_HOSTILE_STATEMENTS) {
        let dir = scratch_dir(&format!("control-{}", statement.name));
        let connection = connection_without_authorizer(&dir);
        // A sanity check that the authorizer API is the only difference: none installed here.
        connection
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
            .expect("no authorizer");
        let outcome = connection.execute_batch(&statement.sql_in(&dir));
        // Extension loading still fails without the authorizer, because the loading switch is
        // off, but not with SQLITE_AUTH; every other statement runs.
        let passed = match statement.class {
            Class::ExtensionLoading => outcome.as_ref().is_err_and(|error| {
                !is_authorizer_denial(error) && error.to_string() == "not authorized"
            }),
            _ => outcome.is_ok(),
        };
        let check = format!("control.{}", statement.name);
        if !report(passed, &check, &describe(&outcome)) {
            failures.push(check);
        }
    }
    assert!(failures.is_empty(), "{failures:?}");
}

/// Without the authorizer, `ATTACH ... KEY ''` plus `sqlcipher_export` writes the encrypted
/// module file out as a plaintext SQLite file. This is the escape D21 forbids.
#[test]
fn without_the_authorizer_a_plaintext_copy_can_be_written() {
    let dir = scratch_dir("control-plaintext-export");
    let connection = connection_without_authorizer(&dir);
    let copy = dir.join("plaintext.db");
    let outcome = connection.execute_batch(&format!(
        "ATTACH DATABASE '{}' AS plain KEY '';
         SELECT sqlcipher_export('plain');
         DETACH DATABASE plain;",
        escape_for_sql_string(&copy)
    ));
    let plaintext = fs::read(&copy)
        .map(|bytes| bytes.starts_with(PLAINTEXT_HEADER))
        .unwrap_or(false);
    let passed = report(
        outcome.is_ok() && plaintext,
        "control.plaintext_export_possible_without_authorizer",
        &format!(
            "{}; copy is plaintext SQLite: {plaintext}",
            describe(&outcome)
        ),
    );
    assert!(passed);
}

/// Records what `VACUUM INTO` writes on this build without the authorizer.
#[test]
fn without_the_authorizer_vacuum_into_writes_a_copy() {
    let dir = scratch_dir("control-vacuum-into");
    let connection = connection_without_authorizer(&dir);
    let copy = dir.join("vacuumed.db");
    let outcome =
        connection.execute_batch(&format!("VACUUM INTO '{}'", escape_for_sql_string(&copy)));
    let header = fs::read(&copy).ok();
    let written = header.is_some();
    let plaintext = header.is_some_and(|bytes| bytes.starts_with(PLAINTEXT_HEADER));
    let passed = report(
        outcome.is_ok() && written,
        "control.vacuum_into_writes_a_copy_without_authorizer",
        &format!("{}; copy plaintext: {plaintext}", describe(&outcome)),
    );
    assert!(passed);
}

/// Prints the engine versions the run used, for the result record.
#[test]
fn engine_versions() {
    let connection = Connection::open_in_memory().expect("open in memory");
    apply_raw_key(&connection, &KEY).expect("key");
    let sqlite: String = connection
        .query_row("SELECT sqlite_version()", [], |row| row.get(0))
        .expect("sqlite version");
    let cipher: String = connection
        .query_row("PRAGMA cipher_version", [], |row| row.get(0))
        .expect("cipher version");
    let provider: String = connection
        .query_row("PRAGMA cipher_provider_version", [], |row| row.get(0))
        .expect("cipher provider version");
    println!("CHECK INFO engine SQLite {sqlite}, SQLCipher {cipher}, crypto provider {provider}");
}
