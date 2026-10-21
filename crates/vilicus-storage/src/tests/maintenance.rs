//! AC9: copies and VACUUM on the Core maintenance path, which module handles refuse.

use std::time::Duration;

use super::{KEY, create_module_file, raw_connection, scratch_dir};
use crate::error::Error;
use crate::{Write, maintenance, open};

fn labels(path: &std::path::Path) -> Vec<String> {
    raw_connection(path)
        .prepare("SELECT label FROM items ORDER BY id")
        .expect("prepare")
        .query_map([], |row| row.get(0))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("read")
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
    assert!(
        !file.wal_path().exists() || std::fs::metadata(file.wal_path()).expect("wal").len() == 0
    );
}

#[test]
fn the_online_backup_writes_a_copy_under_the_same_key() {
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
    let destination = dir.join("copy.db");
    maintenance::backup(&file, &KEY, &destination, 4, Duration::from_millis(1)).expect("backup");
    writer.close().expect("close");
    assert_eq!(labels(&destination), labels(&file.path()));
    let header = std::fs::read(&destination).expect("read copy");
    assert!(
        !header.starts_with(b"SQLite format 3\0"),
        "the copy is plaintext"
    );
    assert!(matches!(
        maintenance::backup(&file, &KEY, &destination, 4, Duration::ZERO),
        Err(Error::AlreadyExists(_))
    ));
}

#[test]
fn a_file_copy_needs_an_empty_wal() {
    let dir = scratch_dir("ac9-copy");
    let file = create_module_file(&dir);
    let writer = open::<Write>(&file, &KEY).expect("writer");
    writer
        .execute("INSERT INTO items (label) VALUES ('second')", [])
        .expect("insert");
    let destination = dir.join("copy.db");
    assert!(matches!(
        maintenance::copy_file(&file, &destination),
        Err(Error::WalNotEmpty(_))
    ));
    writer.close().expect("close");
    maintenance::copy_file(&file, &destination).expect("copy");
    assert_eq!(labels(&destination), ["first", "second"]);
}
