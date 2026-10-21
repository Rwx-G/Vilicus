//! Compiles the vendored SQLCipher amalgamation, `sqlcipher/sqlite3.c`, into the static library
//! `libsqlcipher.a` that rusqlite's `sqlcipher` feature links (D143).
//!
//! The defines are those `libsqlite3-sys` 0.38.2 passes for `bundled-sqlcipher`, which the E11 and
//! E17 spikes ran on, with extension loading compiled out (D126, Story 3.1 AC7), URI filenames no
//! longer on by default, and the OpenSSL provider named explicitly; the compile adds the usual
//! hardening flags. `CC` and `AR` choose the compiler and the archiver; `CFLAGS` and
//! `LIBSQLITE3_FLAGS` are not read, so no environment variable changes the defines or the flags.
//! The source is checked against `sqlcipher/SHA256SUMS` by `ci/check_sqlcipher_source.py`, and
//! against the release tag by the `sqlcipher-regenerate` CI job, not here.
//!
//! Linking: `libsqlite3-sys` asks for `-lsqlcipher` (dynamic) and nothing else. This script
//! bundles the archive into this crate with `+whole-archive`, so every SQLite symbol is defined
//! wherever this crate sits in the link order, and puts the archive on the search path, so that
//! request resolves to the same archive instead of any system SQLCipher. `libcrypto` follows the
//! archive in this crate's own link line, so `--as-needed` keeps it. A binary that links
//! `rusqlite` without linking this crate gets no `-lcrypto` and fails to link. Only this crate
//! depends on `rusqlite`, besides the registry tests of `vilicus-core` (a dev-dependency), and
//! both test binaries link this crate.

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
    // `SQLITE_USE_URI` left out: no dependency opens a URI, and without it a filename is a path
    // unless a connection asks for URIs with `SQLITE_OPEN_URI`, which this crate never does.
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

/// Hardening flags of the compile, as Debian's own packages use them: stack protector, stack
/// clash protection and position-independent code always; `_FORTIFY_SOURCE=2` when optimizing,
/// which it requires (the toolchain's own default, 3 on Ubuntu, is undefined first).
const HARDENING: &[&str] = &[
    "-fPIC",
    "-fstack-protector-strong",
    "-fstack-clash-protection",
];
const FORTIFY: &[&str] = &["-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=2"];

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
    compile.args(["-c", "-ffunction-sections", "-fdata-sections"]);
    compile.args(HARDENING);
    let opt_level = required("OPT_LEVEL").to_string_lossy().into_owned();
    compile.arg(format!("-O{opt_level}"));
    if opt_level != "0" {
        compile.args(FORTIFY);
    }
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
    println!(
        "cargo:rustc-env=VILICUS_SQLCIPHER_ARCHIVE={}",
        display(&library)
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
