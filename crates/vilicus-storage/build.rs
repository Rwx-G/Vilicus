//! Compiles the vendored SQLCipher amalgamation, `sqlcipher/sqlite3.c`, into the static library
//! `libsqlcipher.a` that rusqlite's `sqlcipher` feature links (D143).
//!
//! The defines are those `libsqlite3-sys` 0.38.2 passes for `bundled-sqlcipher`, which the E11 and
//! E17 spikes ran on, with extension loading compiled out (D126, Story 3.1 AC7) and the OpenSSL
//! provider named explicitly. `CFLAGS` and `LIBSQLITE3_FLAGS` are not read: no environment
//! variable can change what the library is compiled with. The source is checked against
//! `sqlcipher/SHA256SUMS` by `ci/check_sqlcipher_source.py`, not here.
//!
//! Linking: `libsqlite3-sys` asks for `-lsqlcipher` (dynamic) and nothing else. This script
//! bundles the archive into this crate with `+whole-archive`, so every SQLite symbol is defined
//! wherever this crate sits in the link order, and puts the archive on the search path, so that
//! request resolves to the same archive instead of any system SQLCipher. `libcrypto` follows the
//! archive in this crate's own link line, so `--as-needed` keeps it.

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

const SOURCE: &str = "sqlcipher/sqlite3.c";

const DEFINES: &[&str] = &[
    // libsqlite3-sys 0.38.2, `build_bundled`, common to every bundled build.
    "SQLITE_CORE",
    "SQLITE_DEFAULT_FOREIGN_KEYS=1",
    "SQLITE_ENABLE_API_ARMOR",
    "SQLITE_ENABLE_COLUMN_METADATA",
    "SQLITE_ENABLE_DBSTAT_VTAB",
    "SQLITE_ENABLE_FTS3",
    "SQLITE_ENABLE_FTS3_PARENTHESIS",
    "SQLITE_ENABLE_FTS5",
    "SQLITE_ENABLE_JSON1",
    "SQLITE_ENABLE_MEMORY_MANAGEMENT",
    "SQLITE_ENABLE_RTREE",
    "SQLITE_ENABLE_STAT4",
    "SQLITE_SOUNDEX",
    "SQLITE_THREADSAFE=1",
    "SQLITE_USE_URI",
    "HAVE_USLEEP=1",
    "HAVE_ISNAN",
    "_POSIX_THREAD_SAFE_FUNCTIONS",
    "HAVE_LOCALTIME_R",
    // libsqlite3-sys 0.38.2, `bundled-sqlcipher` only.
    "SQLITE_HAS_CODEC",
    "SQLITE_TEMP_STORE=2",
    "SQLITE_EXTRA_INIT=sqlcipher_extra_init",
    "SQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown",
    "HAVE_STDINT_H=1",
    // Vilicus: the OpenSSL provider, which is also SQLCipher's default, linked against the system
    // libcrypto (spine Stack); extension loading compiled out in place of libsqlite3-sys's
    // `SQLITE_ENABLE_LOAD_EXTENSION=1` (D126).
    "SQLCIPHER_CRYPTO_OPENSSL",
    "SQLITE_OMIT_LOAD_EXTENSION",
];

fn main() {
    println!("cargo:rerun-if-changed={SOURCE}");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=AR");

    if env::var_os("CARGO_CFG_UNIX").is_none() || env::var("TARGET") != env::var("HOST") {
        panic!(
            "vilicus-storage builds SQLCipher for a native Unix target only (Debian 13, spine Stack)"
        );
    }

    let manifest_dir = PathBuf::from(required("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(required("OUT_DIR"));
    let object = out_dir.join("sqlite3.o");
    let archive = out_dir.join("libsqlcipher.staging.a");
    let library = out_dir.join("libsqlcipher.a");

    let mut compile = Command::new(env::var_os("CC").unwrap_or_else(|| "cc".into()));
    compile.args(["-c", "-fPIC", "-ffunction-sections", "-fdata-sections"]);
    compile.arg(format!("-O{}", required("OPT_LEVEL").to_string_lossy()));
    if env::var("DEBUG").is_ok_and(|debug| debug == "true") {
        compile.arg("-g");
    }
    compile.args(DEFINES.iter().map(|define| format!("-D{define}")));
    compile
        .arg("-o")
        .arg(&object)
        .arg(manifest_dir.join(SOURCE));
    run(compile, "compile the SQLCipher amalgamation");

    // A fresh archive each time, renamed into place, so no member of an earlier build survives.
    let mut pack = Command::new(env::var_os("AR").unwrap_or_else(|| "ar".into()));
    pack.arg("crsD").arg(&archive).arg(&object);
    if archive.exists() {
        std::fs::remove_file(&archive).expect("remove the previous staging archive");
    }
    run(pack, "archive the SQLCipher object");
    std::fs::rename(&archive, &library).expect("move the SQLCipher archive into place");

    println!("cargo:rustc-link-search=native={}", display(&out_dir));
    println!("cargo:rustc-link-lib=static:+whole-archive=sqlcipher");
    println!("cargo:rustc-link-lib=dylib=crypto");
    println!(
        "cargo:rustc-env=VILICUS_SQLCIPHER_DEFINES={}",
        DEFINES.join(" ")
    );
}

fn required(name: &str) -> OsString {
    env::var_os(name).unwrap_or_else(|| panic!("cargo did not set {name}"))
}

fn run(mut command: Command, what: &str) {
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("could not {what}: {error} ({command:?})"));
    assert!(status.success(), "could not {what}: {status} ({command:?})");
}

fn display(path: &Path) -> String {
    path.to_str()
        .unwrap_or_else(|| panic!("OUT_DIR is not UTF-8: {path:?}"))
        .to_owned()
}
