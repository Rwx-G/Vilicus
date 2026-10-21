//! AC9: copies and VACUUM on the Core maintenance path, which module handles refuse. A copy is
//! published with its sidecar, never as a partial file, and never over an existing file.

use std::fs;
use std::time::Duration;

use super::{EPOCH, KEY, create_module_file, module_file, raw_connection, scratch_dir};
use crate::error::Error;
use crate::{Read, Write, maintenance, open, read_epoch};

fn labels(path: &std::path::Path) -> Vec<String> {
    raw_connection(path)
        .prepare("SELECT label FROM items ORDER BY id")
        .expect("prepare")
        .query_map([], |row| row.get(0))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("read")
}

fn names(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("list")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

#[test]
fn vacuum_runs_on_the_maintenance_path_only() {
    let dir = scratch_dir("ac9-vacuum");
    let file = create_module_file(&dir);
    let writer = open::<Write>(&file, &KEY).expect("writer");
    let refused = writer.execute_batch("VACUUM");
    assert!(
        refused.as_ref().is_err_and(Error::is_refusal),
        "{refused:?}"
    );
    writer.close().expect("close");
    maintenance::vacuum(&file, &KEY).expect("vacuum");
    assert_eq!(labels(&file.path()), ["first"]);
    assert!(!file.wal_path().exists() || fs::metadata(file.wal_path()).expect("wal").len() == 0);
}

/// The online backup, while a writer is open, gives a file the storage layer opens like the
/// original: same key, same epoch in its sidecar and in `_meta`, same rows.
#[test]
fn the_online_backup_writes_a_copy_with_its_sidecar() {
    let dir = scratch_dir("ac9-backup");
    let file = create_module_file(&dir);
    let writer = open::<Write>(&file, &KEY).expect("writer");
    for index in 0..200 {
        writer
            .execute(
                "INSERT INTO items (label) VALUES (?1)",
                [format!("row {index}")],
            )
            .expect("insert");
    }
    let target_dir = scratch_dir("ac9-backup-target");
    let copy = module_file(&target_dir);
    maintenance::backup(&file, &KEY, &copy.path(), 4, Duration::from_millis(1)).expect("backup");
    writer.close().expect("close");
    assert_eq!(labels(&copy.path()), labels(&file.path()));
    assert_eq!(read_epoch(&copy).expect("copy sidecar"), EPOCH);
    assert_eq!(
        open::<Read>(&copy, &KEY).expect("open the copy").epoch(),
        EPOCH
    );
    let header = fs::read(copy.path()).expect("read copy");
    assert!(
        !header.starts_with(b"SQLite format 3\0"),
        "the copy is plaintext"
    );
    assert!(
        !names(&target_dir)
            .iter()
            .any(|name| name.contains(".partial"))
    );
}

#[test]
fn a_copy_never_replaces_an_existing_file_or_sidecar() {
    let dir = scratch_dir("ac9-existing");
    let file = create_module_file(&dir);
    let target_dir = scratch_dir("ac9-existing-target");
    let taken = target_dir.join("taken.db");
    fs::write(&taken, b"keep me").expect("existing destination");
    let sidecar_only = target_dir.join("sidecar-only.db");
    fs::write(target_dir.join("sidecar-only.db.epoch"), b"keep me").expect("existing sidecar");
    for destination in [&taken, &sidecar_only] {
        assert!(matches!(
            maintenance::backup(&file, &KEY, destination, 4, Duration::ZERO),
            Err(Error::AlreadyExists(_))
        ));
        assert!(matches!(
            maintenance::copy_file(&file, destination),
            Err(Error::AlreadyExists(_))
        ));
    }
    assert_eq!(fs::read(&taken).expect("read"), b"keep me");
}

/// A failed backup, here under a key that does not open the file, leaves nothing at the
/// destination: no partial file, no sidecar.
#[test]
fn a_failed_backup_leaves_no_partial_file() {
    let dir = scratch_dir("ac9-failed-backup");
    let file = create_module_file(&dir);
    let target_dir = scratch_dir("ac9-failed-backup-target");
    let outcome = maintenance::backup(
        &file,
        &[0xa5; 32],
        &target_dir.join("copy.db"),
        4,
        Duration::ZERO,
    );
    assert!(matches!(outcome, Err(Error::WrongKey)), "{outcome:?}");
    assert_eq!(names(&target_dir), Vec::<String>::new());
}

#[test]
fn a_file_copy_needs_an_empty_wal_and_carries_the_sidecar() {
    let dir = scratch_dir("ac9-copy");
    let file = create_module_file(&dir);
    let writer = open::<Write>(&file, &KEY).expect("writer");
    writer
        .execute("INSERT INTO items (label) VALUES ('second')", [])
        .expect("insert");
    let target_dir = scratch_dir("ac9-copy-target");
    let copy = module_file(&target_dir);
    assert!(matches!(
        maintenance::copy_file(&file, &copy.path()),
        Err(Error::WalNotEmpty(_))
    ));
    assert_eq!(names(&target_dir), Vec::<String>::new());
    writer.close().expect("close");
    maintenance::copy_file(&file, &copy.path()).expect("copy");
    assert_eq!(labels(&copy.path()), ["first", "second"]);
    assert_eq!(
        open::<Read>(&copy, &KEY).expect("open the copy").epoch(),
        EPOCH
    );
}

/// A copy that fails after the partial file is written, here at its sidecar, whose temporary
/// name is taken by a directory, removes the partial file: nothing is published.
#[test]
fn a_copy_that_fails_late_leaves_no_partial_file() {
    let dir = scratch_dir("ac9-late-failure");
    let file = create_module_file(&dir);
    for (label, backup) in [("backup", true), ("copy", false)] {
        let target_dir = scratch_dir(&format!("ac9-late-failure-{label}"));
        let destination = target_dir.join("copy.db");
        fs::create_dir(target_dir.join("copy.db.epoch.tmp")).expect("block the sidecar");
        let outcome = if backup {
            maintenance::backup(&file, &KEY, &destination, 4, Duration::ZERO)
        } else {
            maintenance::copy_file(&file, &destination)
        };
        assert!(matches!(outcome, Err(Error::Io(_))), "{label}: {outcome:?}");
        assert_eq!(names(&target_dir), ["copy.db.epoch.tmp"], "{label}");
    }
}
