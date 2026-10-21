//! The SQLite and SQLCipher C calls that `rusqlite` does not wrap safely (D140): the extension
//! loading switch (D126), keying from a buffer the caller wipes (AD-4) and the TRUNCATE checkpoint
//! that the authorizer does not see (D132); and the one system call of the maintenance path, the
//! free space of a file system (`statvfs`, AD-23). Every `unsafe` block of the crate is here, each
//! with the invariant it relies on; the functions are safe to call.

use std::ffi::c_int;

use rusqlite::{Connection, ffi};

fn check(code: c_int, what: &str) -> rusqlite::Result<()> {
    if code == ffi::SQLITE_OK {
        Ok(())
    } else {
        Err(rusqlite::Error::SqliteFailure(
            ffi::Error::new(code),
            Some(format!("could not {what}")),
        ))
    }
}

/// Sets `SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION`, the switch of the `sqlite3_load_extension` C
/// call, which the authorizer never sees.
#[allow(unsafe_code)] // One FFI call; rusqlite's `DbConfig` omits this option (D126).
pub(crate) fn set_extension_loading_api(
    connection: &Connection,
    enabled: bool,
) -> rusqlite::Result<()> {
    // SAFETY: the handle belongs to a live connection borrowed for the call and used by one thread
    // (rusqlite's `Connection` is not `Sync`); this op takes an int and a nullable int pointer.
    let code = unsafe {
        ffi::sqlite3_db_config(
            connection.handle(),
            ffi::SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION,
            c_int::from(enabled),
            std::ptr::null_mut::<c_int>(),
        )
    };
    check(code, "set the extension loading switch")
}

/// Reads `SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION` without changing it.
#[allow(unsafe_code)] // One FFI call; rusqlite's `DbConfig` omits this option (D126).
pub(crate) fn extension_loading_api(connection: &Connection) -> rusqlite::Result<bool> {
    let mut current: c_int = -1;
    // SAFETY: as in `set_extension_loading_api`; -1 queries without changing, and SQLite writes
    // the current value through the pointer, which points at a live local.
    let code = unsafe {
        ffi::sqlite3_db_config(
            connection.handle(),
            ffi::SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION,
            -1 as c_int,
            &raw mut current,
        )
    };
    check(code, "read the extension loading switch")?;
    Ok(current != 0)
}

/// Hands `key_text` to SQLCipher for the main database with `sqlite3_key_v2`, which `PRAGMA key`
/// calls too. No SQL text holds the key, so no prepared statement or error message carries it.
#[allow(unsafe_code)] // One FFI call; rusqlite keys only through SQL text (AD-4).
pub(crate) fn key(connection: &Connection, key_text: &[u8]) -> rusqlite::Result<()> {
    let length = c_int::try_from(key_text.len()).map_err(|_| {
        rusqlite::Error::SqliteFailure(
            ffi::Error::new(ffi::SQLITE_MISUSE),
            Some("key too long".to_owned()),
        )
    })?;
    // SAFETY: the handle is live and used by one thread; the database name is a NUL-terminated
    // literal; SQLCipher reads exactly `length` bytes from `key_text`, which outlives the call, and
    // copies them into its own context, so the caller may wipe the buffer afterwards.
    let code = unsafe {
        ffi::sqlite3_key_v2(
            connection.handle(),
            c"main".as_ptr(),
            key_text.as_ptr().cast(),
            length,
        )
    };
    check(code, "key the database")
}

/// The outcome of one `sqlite3_wal_checkpoint_v2` call in TRUNCATE mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CheckpointFrames {
    /// `SQLITE_BUSY` was returned: another connection kept the checkpoint from completing.
    pub(crate) busy: bool,
    /// Frames in the WAL when the checkpoint ran, -1 when SQLite could not tell.
    pub(crate) log: c_int,
    /// Frames copied back into the database file.
    pub(crate) checkpointed: c_int,
}

/// One TRUNCATE checkpoint of the main database through the C API, which prepares no statement,
/// so no authorizer sees it (E17). `SQLITE_BUSY` is reported, not an error.
#[allow(unsafe_code)] // One FFI call; rusqlite has no TRUNCATE checkpoint outside SQL (D132).
pub(crate) fn checkpoint_truncate(connection: &Connection) -> rusqlite::Result<CheckpointFrames> {
    let mut log: c_int = -1;
    let mut checkpointed: c_int = -1;
    // SAFETY: the handle is live and used by one thread; the database name is a NUL-terminated
    // literal; both out pointers point at live locals.
    let code = unsafe {
        ffi::sqlite3_wal_checkpoint_v2(
            connection.handle(),
            c"main".as_ptr(),
            ffi::SQLITE_CHECKPOINT_TRUNCATE,
            &raw mut log,
            &raw mut checkpointed,
        )
    };
    if code == ffi::SQLITE_BUSY {
        return Ok(CheckpointFrames {
            busy: true,
            log,
            checkpointed,
        });
    }
    check(code, "checkpoint the WAL")?;
    Ok(CheckpointFrames {
        busy: false,
        log,
        checkpointed,
    })
}

/// The bytes an unprivileged process may still write to the file system holding `directory`,
/// from `statvfs` (`f_bavail` blocks of `f_frsize` bytes): what the migration runner checks
/// before it copies a file (AD-23). The standard library has no call for it.
#[allow(unsafe_code)] // One FFI call; no approved dependency wraps statvfs safely (AD-23, D140).
pub(crate) fn available_bytes(directory: &std::path::Path) -> std::io::Result<u64> {
    use std::os::unix::ffi::OsStrExt as _;

    let path = std::ffi::CString::new(directory.as_os_str().as_bytes())
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `path` is a NUL-terminated string that outlives the call; `stats` points at
    // writable memory of the size of `statvfs`, which the call fills when it returns 0.
    let code = unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) };
    if code != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `statvfs` returned 0, so it wrote the whole structure.
    let stats = unsafe { stats.assume_init() };
    Ok(stats.f_bavail.saturating_mul(stats.f_frsize))
}
