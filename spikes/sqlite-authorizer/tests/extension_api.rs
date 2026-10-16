//! AC1, extension loading through the C API. The authorizer sees SQL only; it is never asked
//! about `sqlite3_load_extension`. These tests show that the bundled build leaves that call on
//! by default, that `open` turns it off, and that the authorizer still refuses the SQL function
//! when loading is switched on.

// The C API is the subject of these tests; each unsafe block states its invariant.
#![allow(unsafe_code)]

mod common;

use std::ffi::{CStr, CString, c_char, c_int};

use common::{KEY, create_module_file, describe, report, scratch_dir};
use rusqlite::{Connection, ffi};
use sqlite_authorizer::hostile::escape_for_sql_string;
use sqlite_authorizer::{Role, is_authorizer_denial, open};

/// Calls `sqlite3_load_extension` on `connection` and returns its result code and message.
fn load_extension_through_api(connection: &Connection, library: &str) -> (c_int, String) {
    let library = CString::new(library).expect("library path without NUL");
    let mut message: *mut c_char = std::ptr::null_mut();
    // SAFETY: the handle belongs to a live connection used on this thread only; the path is a
    // NUL-terminated string that outlives the call; a null entry point is allowed by the API.
    let code = unsafe {
        ffi::sqlite3_load_extension(
            connection.handle(),
            library.as_ptr(),
            std::ptr::null(),
            &mut message,
        )
    };
    let text = if message.is_null() {
        String::new()
    } else {
        // SAFETY: SQLite returned a NUL-terminated message allocated with sqlite3_malloc, read
        // once and then released with sqlite3_free as the API requires.
        unsafe {
            let text = CStr::from_ptr(message).to_string_lossy().into_owned();
            ffi::sqlite3_free(message.cast());
            text
        }
    };
    (code, text)
}

/// Reads the `SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION` switch of `connection`.
fn load_extension_switch(connection: &Connection) -> c_int {
    let mut current: c_int = -1;
    // SAFETY: the handle is live; this op takes an int (-1 queries without changing) and an
    // int pointer that SQLite writes the current value to.
    let code = unsafe {
        ffi::sqlite3_db_config(
            connection.handle(),
            ffi::SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION,
            -1 as c_int,
            &mut current as *mut c_int,
        )
    };
    assert_eq!(code, ffi::SQLITE_OK, "sqlite3_db_config query failed");
    current
}

fn enable_extension_loading(connection: &Connection) {
    // SAFETY: the handle is live and used on this thread only.
    let code = unsafe { ffi::sqlite3_enable_load_extension(connection.handle(), 1) };
    assert_eq!(code, ffi::SQLITE_OK, "enable extension loading");
}

/// Control: a connection opened without `open` has the C API switch on, because
/// `libsqlite3-sys` compiles the bundled SQLCipher with `SQLITE_ENABLE_LOAD_EXTENSION`.
#[test]
fn control_the_bundled_build_turns_the_api_on_by_default() {
    let dir = scratch_dir("extension-default");
    let path = create_module_file(&dir);
    let connection = Connection::open(&path).expect("open without the spike's setup");
    let switch = load_extension_switch(&connection);
    let library = dir.join("evil.so");
    let (code, message) = load_extension_through_api(&connection, &library.to_string_lossy());
    let passed = report(
        switch == 1 && code != ffi::SQLITE_OK && message != "not authorized",
        "control.load_extension_api_on_by_default_in_bundled_build",
        &format!("switch {switch}, code {code}, message {message:?}"),
    );
    assert!(passed);
}

#[test]
fn open_turns_the_extension_loading_api_off_on_every_role() {
    let dir = scratch_dir("extension-switch");
    let path = create_module_file(&dir);
    let mut all_off = true;
    for (label, role) in [
        ("migration", Role::Migration),
        ("write", Role::Write),
        ("read", Role::Read),
    ] {
        let connection = open(&path, &KEY, role).expect("open connection");
        let switch = load_extension_switch(&connection);
        let library = dir.join("evil.so");
        let (code, message) = load_extension_through_api(&connection, &library.to_string_lossy());
        let refused = switch == 0 && code != ffi::SQLITE_OK && message == "not authorized";
        all_off &= report(
            refused,
            &format!("{label}.load_extension_api_refused"),
            &format!("switch {switch}, code {code}, message {message:?}"),
        );
    }
    assert!(all_off);
}

/// Control: once the switch is on, the API call reaches the loader (it fails only because the
/// library does not exist), so the switch, not the authorizer, is what refuses the API call.
#[test]
fn control_the_switch_is_what_refuses_the_api_call() {
    let dir = scratch_dir("extension-control");
    let path = create_module_file(&dir);
    let connection = open(&path, &KEY, Role::Write).expect("open connection");
    enable_extension_loading(&connection);
    let library = dir.join("evil.so");
    let (code, message) = load_extension_through_api(&connection, &library.to_string_lossy());
    let reached_loader =
        code != ffi::SQLITE_OK && message != "not authorized" && !message.is_empty();
    let passed = report(
        reached_loader,
        "control.load_extension_api_reaches_loader_when_switched_on",
        &format!("code {code}, message {message:?}"),
    );
    assert!(passed);
}

/// Even with loading switched on, the SQL function stays refused by the authorizer.
#[test]
fn the_authorizer_refuses_the_sql_function_even_when_loading_is_on() {
    let dir = scratch_dir("extension-sql-on");
    let path = create_module_file(&dir);
    let connection = open(&path, &KEY, Role::Write).expect("open connection");
    enable_extension_loading(&connection);
    let outcome = connection.execute_batch(&format!(
        "SELECT load_extension('{}/evil.so')",
        escape_for_sql_string(&dir)
    ));
    let passed = report(
        outcome.as_ref().is_err_and(is_authorizer_denial),
        "write.load_extension_function_refused_with_loading_on",
        &describe(&outcome),
    );
    assert!(passed);
}
