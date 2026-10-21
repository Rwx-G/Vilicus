//! The SQLCipher build itself (D143): the pinned version, the OpenSSL provider, the compile
//! options of `build.rs`, temporary storage in memory and extension loading compiled out.

use rusqlite::Connection;

use super::{
    KEY, create_module_file, no_such_function, raw_connection, raw_key_pragma, scratch_dir,
};
use crate::{Migration, Read, Write, open};

/// The version this build pins (D143); `sqlcipher/regenerate.sh` names the same release tag,
/// which the test below compares.
const PINNED_SQLCIPHER: &str = "4.19.0";

const REGENERATE_SCRIPT: &str = include_str!("../../sqlcipher/regenerate.sh");

fn keyed_in_memory() -> Connection {
    let connection = Connection::open_in_memory().expect("open in memory");
    connection
        .execute_batch(&raw_key_pragma(&KEY))
        .expect("key");
    connection
}

fn text(connection: &Connection, sql: &str) -> String {
    connection.query_row(sql, [], |row| row.get(0)).expect(sql)
}

fn compile_options(connection: &Connection) -> Vec<String> {
    connection
        .prepare("PRAGMA compile_options")
        .expect("prepare compile_options")
        .query_map([], |row| row.get(0))
        .expect("query compile_options")
        .collect::<Result<_, _>>()
        .expect("read compile_options")
}

#[test]
fn the_engine_is_the_pinned_sqlcipher_on_openssl() {
    let connection = keyed_in_memory();
    let version = text(&connection, "PRAGMA cipher_version");
    let tag = REGENERATE_SCRIPT
        .lines()
        .find_map(|line| line.strip_prefix("TAG=v"))
        .expect("TAG line in regenerate.sh");
    assert_eq!(
        tag, PINNED_SQLCIPHER,
        "regenerate.sh names another tag than the pin"
    );
    assert_eq!(
        version.split(' ').next(),
        Some(PINNED_SQLCIPHER),
        "cipher_version {version:?}"
    );
    assert_eq!(text(&connection, "PRAGMA cipher_provider"), "openssl");
    let provider = text(&connection, "PRAGMA cipher_provider_version");
    assert!(
        provider.starts_with("OpenSSL 3."),
        "cipher_provider_version {provider:?}"
    );
    println!(
        "engine: SQLite {}, SQLCipher {version}, {provider}",
        rusqlite::version()
    );
}

/// Every `SQLITE_` define of `build.rs` is in `PRAGMA compile_options`, which names it without
/// the prefix, and a boolean set to 1 without its value. `SQLITE_CORE` is not an option SQLite
/// reports, and `SQLITE_ENABLE_JSON1` no longer exists (JSON is built in since SQLite 3.38); both
/// stay in `build.rs` because `libsqlite3-sys` passes them.
#[test]
fn the_build_carries_the_defines_of_build_rs() {
    const UNREPORTED: &[&str] = &["SQLITE_CORE", "SQLITE_ENABLE_JSON1"];
    let options = compile_options(&keyed_in_memory());
    let reported = |define: &str| {
        let name = &define["SQLITE_".len()..];
        options
            .iter()
            .any(|option| option == name || Some(option.as_str()) == name.strip_suffix("=1"))
    };
    let missing: Vec<&str> = env!("VILICUS_SQLCIPHER_DEFINES")
        .split(' ')
        .filter(|define| define.starts_with("SQLITE_") && !UNREPORTED.contains(define))
        .filter(|define| !reported(define))
        .collect();
    assert!(
        missing.is_empty(),
        "defines not reported: {missing:?}; options {options:?}"
    );
}

/// AC7 and AC10: extension loading is compiled out, temporary storage is memory.
#[test]
fn extension_loading_is_compiled_out_and_temp_store_is_memory() {
    let options = compile_options(&keyed_in_memory());
    assert!(
        options.iter().any(|option| option == "OMIT_LOAD_EXTENSION"),
        "{options:?}"
    );
    assert!(
        !options
            .iter()
            .any(|option| option.starts_with("ENABLE_LOAD_EXTENSION")),
        "{options:?}"
    );
    let temp_store: Vec<&String> = options
        .iter()
        .filter(|option| option.starts_with("TEMP_STORE="))
        .collect();
    assert_eq!(temp_store, ["TEMP_STORE=2"]);
}

/// AC7: `load_extension` does not exist, without the authorizer and on every role.
#[test]
fn load_extension_is_no_such_function_on_every_connection() {
    let dir = scratch_dir("load-extension");
    let file = create_module_file(&dir);
    let sql = "SELECT load_extension('x')";
    let raw = raw_connection(&file.path())
        .execute_batch(sql)
        .map_err(crate::Error::from);
    assert!(
        raw.as_ref().is_err_and(no_such_function),
        "without the storage layer: {raw:?}"
    );
    let outcomes = [
        (
            "migration",
            open::<Migration>(&file, &KEY)
                .expect("open")
                .execute_batch(sql),
        ),
        (
            "write",
            open::<Write>(&file, &KEY).expect("open").execute_batch(sql),
        ),
        (
            "read",
            open::<Read>(&file, &KEY).expect("open").execute_batch(sql),
        ),
    ];
    for (role, outcome) in outcomes {
        // A migration connection is closed, so the authorizer may refuse before name resolution.
        let refused = outcome
            .as_ref()
            .is_err_and(|error| no_such_function(error) || error.is_refusal());
        assert!(refused, "{role}: {outcome:?}");
    }
}

/// AC10: on a keyed connection of every role, the effective `temp_store` is 0, the build default.
#[test]
fn a_keyed_connection_keeps_the_build_temp_store() {
    let dir = scratch_dir("temp-store");
    let file = create_module_file(&dir);
    assert_eq!(
        open::<Migration>(&file, &KEY)
            .expect("open")
            .settings()
            .temp_store,
        0
    );
    assert_eq!(
        open::<Write>(&file, &KEY)
            .expect("open")
            .settings()
            .temp_store,
        0
    );
    assert_eq!(
        open::<Read>(&file, &KEY)
            .expect("open")
            .settings()
            .temp_store,
        0
    );
}

/// Review nit: the library is compiled with the stack protector of `build.rs`, so its object
/// calls `__stack_chk_fail`; `_FORTIFY_SOURCE` applies to optimized builds only, which the tests
/// are not.
#[test]
fn the_library_is_compiled_with_the_stack_protector() {
    let archive = std::fs::read(env!("VILICUS_SQLCIPHER_ARCHIVE")).expect("read the archive");
    let needle = b"__stack_chk_fail";
    assert!(
        archive.windows(needle.len()).any(|window| window == needle),
        "no stack protector reference in {}",
        env!("VILICUS_SQLCIPHER_ARCHIVE")
    );
}
