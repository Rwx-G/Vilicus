//! Story 3.7: migrations on a copy swapped in on success (AC2, AC8), the cold copies they leave
//! and their limit (AC3), the previous file kept untouched when a migration fails (AC4, AC7),
//! the free space the runner reads (AC6), and the states a crash can leave.

use std::fs;
use std::path::Path;

use super::{EPOCH, KEY, create_module_file, disk_state, frozen_all, raw_connection, scratch_dir};
use crate::error::Error;
use crate::maintenance::{
    self, ColdCopy, MAX_COLD_COPIES, SchemaVersions, VerifiedBackup, copy_for_migration,
};
use crate::{CORE_SCHEMA_VERSION, Migration, MigrationTrack, ModuleFile, Read, Write, open};

const CORE: u32 = CORE_SCHEMA_VERSION;

/// The module migrations of these tests, in order; the third deletes a row, for D132.
const MIGRATIONS: [&str; 5] = [
    "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL);",
    "ALTER TABLE items ADD COLUMN done INTEGER;",
    "DELETE FROM items WHERE label = 'first';",
    "CREATE INDEX notes_body ON notes (body);",
    "CREATE TABLE later (x INTEGER);",
];

fn versions(core: u32, module: u32) -> SchemaVersions {
    SchemaVersions { core, module }
}

fn names(dir: &Path) -> Vec<String> {
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

fn labels(path: &Path) -> Vec<String> {
    raw_connection(path)
        .prepare("SELECT label FROM items ORDER BY id")
        .expect("prepare")
        .query_map([], |row| row.get(0))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("read")
}

fn module_version(file: &ModuleFile) -> u32 {
    let reader = open::<Read>(file, &KEY).expect("open");
    let version = reader
        .schema_version(MigrationTrack::Module)
        .expect("version");
    reader.close().expect("close");
    version
}

/// Migrates `file` on a copy to the first `count` of [`MIGRATIONS`] and swaps it in.
fn migrate_on_copy(file: &ModuleFile, count: usize, backup: Option<VerifiedBackup>) -> ColdCopy {
    let copy = copy_for_migration(file, &KEY, backup).expect("copy");
    let mut migration = open::<Migration>(copy.file(), &KEY).expect("open the copy");
    migration
        .apply_module_migrations(&frozen_all(&MIGRATIONS[..count]))
        .expect("migrate the copy");
    migration.close().expect("close");
    let swapped = copy.swap_in().expect("swap in");
    assert!(swapped.cleanup.is_none(), "{:?}", swapped.cleanup);
    swapped.cold_copy
}

/// AC2 and AC8: the copy is made from the checkpointed file, migrated on a migration handle set
/// up like every other (`secure_delete` ON, `SQLITE_DBCONFIG_DEFENSIVE`), then swapped in; the
/// original stays beside it as its cold copy, under the versions it holds, with its sidecar and
/// its key; the working directory is gone, no WAL is left, and the epoch is the file's.
#[test]
fn a_migration_runs_on_a_copy_swapped_in_with_the_original_as_its_cold_copy() {
    let dir = scratch_dir("copy-swap");
    let file = create_module_file(&dir);
    let writer = open::<Write>(&file, &KEY).expect("writer");
    writer
        .execute("INSERT INTO items (label) VALUES ('second')", [])
        .expect("a row left in the WAL");
    writer.close().expect("close");
    let original = fs::read(file.path()).expect("read the original");

    let copy = copy_for_migration(&file, &KEY, None).expect("copy");
    assert_eq!(copy.from(), versions(CORE, 0));
    assert_eq!(
        copy.file().directory(),
        dir.join("fixture.household.db.migration")
    );
    assert_eq!(
        fs::read(copy.file().path()).expect("read the copy"),
        original
    );
    let mut migration = open::<Migration>(copy.file(), &KEY).expect("open the copy");
    assert_eq!(migration.settings().secure_delete, 1);
    assert!(migration.settings().defensive);
    migration
        .apply_module_migrations(&frozen_all(&MIGRATIONS[..3]))
        .expect("migrate the copy");
    migration.close().expect("close");
    assert_eq!(
        fs::read(file.path()).expect("read"),
        original,
        "the live file is untouched"
    );

    let cold = copy.swap_in().expect("swap in").cold_copy;
    assert_eq!(cold.versions(), versions(CORE, 0));
    assert_eq!(
        cold.path(),
        dir.join(format!("fixture.household.db.pre-{CORE}.0"))
    );
    assert_eq!(fs::read(cold.path()).expect("read the cold copy"), original);
    assert_eq!(cold.epoch().expect("cold epoch"), EPOCH);
    assert_eq!(labels(cold.path()), ["first", "second"]);
    assert_eq!(labels(&file.path()), ["second"]);
    assert_eq!(module_version(&file), 3);
    assert_eq!(crate::read_epoch(&file).expect("epoch"), EPOCH);
    assert_eq!(open::<Read>(&file, &KEY).expect("open").epoch(), EPOCH);
    assert_eq!(
        names(&dir),
        [
            "fixture.household.db".to_owned(),
            "fixture.household.db.epoch".to_owned(),
            format!("fixture.household.db.pre-{CORE}.0"),
            format!("fixture.household.db.pre-{CORE}.0.epoch"),
        ]
    );
}

/// AC4 and AC7: a migration that fails on the copy, here on a refused statement, leaves the
/// previous file in place untouched: its bytes, the directory listing, its schema, its rows and
/// its version, once the copy is discarded or dropped.
#[test]
fn a_failed_migration_leaves_the_previous_file_untouched() {
    let dir = scratch_dir("copy-failed");
    let file = create_module_file(&dir);
    let before = disk_state(&file);
    for discard in [true, false] {
        let copy = copy_for_migration(&file, &KEY, None).expect("copy");
        let mut migration = open::<Migration>(copy.file(), &KEY).expect("open the copy");
        let outcome = migration.apply_module_migrations(&frozen_all(&[
            MIGRATIONS[0],
            "CREATE TABLE added (x); ATTACH DATABASE ':memory:' AS hijack;",
        ]));
        migration.close().expect("close");
        assert!(
            matches!(
                &outcome,
                Err(Error::MigrationFailed { track: MigrationTrack::Module, version: 2, .. })
                    if outcome.as_ref().is_err_and(Error::is_refusal)
            ),
            "{outcome:?}"
        );
        if discard {
            copy.discard().expect("discard");
        } else {
            drop(copy);
        }
        assert_eq!(disk_state(&file), before, "discard {discard}");
        assert_eq!(labels(&file.path()), ["first"]);
        assert_eq!(module_version(&file), 0);
    }
}

/// AC2: the copy is refused, with nothing written, while a change of key epoch is pending, and
/// while a reader keeps the WAL from emptying.
#[test]
fn no_copy_is_made_while_the_epoch_is_pending_or_the_wal_cannot_empty() {
    let dir = scratch_dir("copy-refused");
    let file = create_module_file(&dir);
    fs::copy(file.epoch_path(), file.pending_epoch_path()).expect("plant a pending sidecar");
    let outcome = copy_for_migration(&file, &KEY, None);
    assert!(
        matches!(outcome, Err(Error::EpochTransitionPending { .. })),
        "{outcome:?}"
    );
    fs::remove_file(file.pending_epoch_path()).expect("resolve the epoch change");
    let before = names(&dir);

    let writer = open::<Write>(&file, &KEY).expect("writer");
    let reader = open::<Read>(&file, &KEY).expect("reader");
    reader.execute_batch("BEGIN").expect("begin");
    let _: i64 = reader
        .query_row("SELECT count(*) FROM items", [], |row| row.get(0))
        .expect("hold a snapshot");
    writer
        .execute("INSERT INTO items (label) VALUES ('kept in the WAL')", [])
        .expect("write");
    let outcome = copy_for_migration(&file, &KEY, None);
    assert!(
        matches!(outcome, Err(Error::CheckpointIncomplete { .. })),
        "{outcome:?}"
    );
    reader.execute_batch("COMMIT").expect("end the snapshot");
    reader.close().expect("close");
    writer.close().expect("close");
    assert_eq!(names(&dir), before);
}

/// Review of Story 3.7, H1: a connection opened on the live file after the copy, which writes
/// and stays open across the swap, keeps its write in the live WAL, where neither the file's
/// length nor its times show it; the swap is refused, before the link, so the write is neither
/// lost into the old inode nor read by a later connection from the old WAL into the new file.
/// The same holds for a connection that only stays open. Once they close, the live file holds
/// the write, opens and reads, and a new migration of it completes.
#[test]
fn a_connection_held_open_across_the_swap_refuses_it() {
    let dir = scratch_dir("copy-held-open");
    let file = create_module_file(&dir);
    for writes in [true, false] {
        let copy = copy_for_migration(&file, &KEY, None).expect("copy");
        let held = open::<Write>(&file, &KEY).expect("a connection opened after the copy");
        if writes {
            held.execute("INSERT INTO items (label) VALUES ('held')", [])
                .expect("a write committed into the WAL");
        }
        let mut migration = open::<Migration>(copy.file(), &KEY).expect("open the copy");
        migration
            .apply_module_migrations(&frozen_all(&MIGRATIONS[..1]))
            .expect("migrate the copy");
        migration.close().expect("close");
        let outcome = copy.swap_in();
        assert!(
            matches!(outcome, Err(Error::CopyRaced(_))),
            "writes {writes}: {outcome:?}"
        );
        assert!(maintenance::cold_copies(&file).expect("list").is_empty());
        held.close().expect("close the held connection");
        assert_eq!(module_version(&file), 0, "writes {writes}");
    }
    assert_eq!(labels(&file.path()), ["first", "held"]);
    let integrity: String = raw_connection(&file.path())
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .expect("integrity check");
    assert_eq!(integrity, "ok");
    migrate_on_copy(&file, 1, None);
    assert_eq!(module_version(&file), 1);
    assert_eq!(labels(&file.path()), ["first", "held"]);
}

/// A connection open on the live file when the copy is made, idle so the checkpoint passes,
/// refuses the copy: its shared-memory file shows it.
#[test]
fn no_copy_is_made_while_a_connection_is_open() {
    let dir = scratch_dir("copy-open-connection");
    let file = create_module_file(&dir);
    let reader = open::<Read>(&file, &KEY).expect("an idle reader");
    let outcome = copy_for_migration(&file, &KEY, None);
    assert!(matches!(outcome, Err(Error::CopyRaced(_))), "{outcome:?}");
    reader.close().expect("close");
    assert!(!dir.join("fixture.household.db.migration").exists());
    copy_for_migration(&file, &KEY, None)
        .expect("once it closed")
        .discard()
        .expect("discard");
}

/// AC2: a connection that writes the live file after it was copied makes the swap fail; the live
/// file keeps the write and no cold copy is made.
#[test]
fn a_write_after_the_copy_refuses_the_swap() {
    let dir = scratch_dir("copy-raced");
    let file = create_module_file(&dir);
    let copy = copy_for_migration(&file, &KEY, None).expect("copy");
    let writer = open::<Write>(&file, &KEY).expect("writer");
    writer
        .execute("INSERT INTO items (label) VALUES ('late')", [])
        .expect("write");
    writer.close().expect("close");
    let outcome = copy.swap_in();
    assert!(matches!(outcome, Err(Error::CopyRaced(_))), "{outcome:?}");
    assert_eq!(labels(&file.path()), ["first", "late"]);
    assert!(maintenance::cold_copies(&file).expect("list").is_empty());
    assert!(!dir.join("fixture.household.db.migration").exists());
}

/// AC3: each migration leaves one cold copy; at most three are kept, and none goes before the
/// caller's verified-backup marker covers it, so a fourth migration does not start until a
/// verified backup holds a later state of the file. A cold copy of the state the backup holds is
/// not covered.
#[test]
fn at_most_three_cold_copies_are_kept_until_a_verified_backup_covers_them() {
    let dir = scratch_dir("cold-copies");
    let file = create_module_file(&dir);
    for count in 1..=MAX_COLD_COPIES {
        migrate_on_copy(&file, count, None);
    }
    let kept: Vec<SchemaVersions> = maintenance::cold_copies(&file)
        .expect("list")
        .iter()
        .map(ColdCopy::versions)
        .collect();
    assert_eq!(
        kept,
        [versions(CORE, 0), versions(CORE, 1), versions(CORE, 2)]
    );

    let before = disk_state(&file);
    let listing = names(&dir);
    let outcome = copy_for_migration(&file, &KEY, None);
    assert!(
        matches!(outcome, Err(Error::ColdCopiesFull { kept: 3 })),
        "{outcome:?}"
    );
    let outcome = copy_for_migration(
        &file,
        &KEY,
        Some(VerifiedBackup {
            versions: versions(CORE, 0),
        }),
    );
    assert!(
        matches!(outcome, Err(Error::ColdCopiesFull { kept: 3 })),
        "a backup of the state a cold copy holds covers none: {outcome:?}"
    );
    assert_eq!((disk_state(&file), names(&dir)), (before, listing));

    let cold = migrate_on_copy(
        &file,
        4,
        Some(VerifiedBackup {
            versions: versions(CORE, 1),
        }),
    );
    let kept: Vec<SchemaVersions> = maintenance::cold_copies(&file)
        .expect("list")
        .iter()
        .map(ColdCopy::versions)
        .collect();
    assert_eq!(
        kept,
        [versions(CORE, 1), versions(CORE, 2), versions(CORE, 3)]
    );
    assert_eq!(cold.versions(), versions(CORE, 3));
    assert!(
        !dir.join(format!("fixture.household.db.pre-{CORE}.0.epoch"))
            .exists()
    );

    let removed = maintenance::remove_covered_cold_copies(
        &file,
        VerifiedBackup {
            versions: versions(CORE, 4),
        },
    )
    .expect("remove");
    assert_eq!(removed, 3);
    assert_eq!(
        names(&dir),
        ["fixture.household.db", "fixture.household.db.epoch"]
    );
}

/// Review of Story 3.7, L3: a cold copy goes with the WAL and shared-memory file a connection to
/// it would leave, and those left without their cold copy are cleared by the next migration.
#[test]
fn a_cold_copy_goes_with_its_wal_and_shared_memory_file() {
    let dir = scratch_dir("cold-companions");
    let file = create_module_file(&dir);
    let cold = migrate_on_copy(&file, 1, None);
    let companions: Vec<std::path::PathBuf> = ["-wal", "-shm"]
        .iter()
        .map(|suffix| {
            let mut path = cold.path().as_os_str().to_owned();
            path.push(suffix);
            std::path::PathBuf::from(path)
        })
        .collect();
    for path in &companions {
        fs::write(path, b"left by a connection").expect("a companion");
    }
    let orphan = dir.join("fixture.household.db.pre-9.9-wal");
    fs::write(&orphan, b"without its cold copy").expect("an orphan");
    let removed = maintenance::remove_covered_cold_copies(
        &file,
        VerifiedBackup {
            versions: versions(CORE, 1),
        },
    )
    .expect("remove");
    assert_eq!(removed, 1);
    for path in &companions {
        assert!(!path.exists(), "{} goes with its cold copy", path.display());
    }
    assert!(orphan.exists(), "not a covered cold copy");
    copy_for_migration(&file, &KEY, None)
        .expect("copy")
        .discard()
        .expect("discard");
    assert_eq!(
        names(&dir),
        ["fixture.household.db", "fixture.household.db.epoch"]
    );
}

/// What a crash in the middle of a migration can leave is cleared by the next one before it
/// copies anything: the working directory, a cold copy that is still the live file (the crash
/// fell between the link and the rename of the swap) and a cold copy's sidecar alone. The live
/// file is never touched, and the next migration completes.
#[test]
fn an_interrupted_migration_is_cleared_by_the_next_one() {
    let dir = scratch_dir("copy-interrupted");
    let file = create_module_file(&dir);
    let working = dir.join("fixture.household.db.migration");
    fs::create_dir(&working).expect("a working directory");
    fs::write(working.join("fixture.household.db"), b"a partial copy").expect("leftover");
    fs::write(working.join("fixture.household.db.epoch"), b"leftover").expect("leftover");
    let stale = dir.join(format!("fixture.household.db.pre-{CORE}.0"));
    fs::hard_link(file.path(), &stale).expect("a link the swap left");
    fs::copy(
        file.epoch_path(),
        dir.join(format!("fixture.household.db.pre-{CORE}.0.epoch")),
    )
    .expect("its sidecar");
    fs::write(dir.join("fixture.household.db.pre-7.7.epoch"), b"alone").expect("an orphan");
    let live = fs::read(file.path()).expect("read");

    let copy = copy_for_migration(&file, &KEY, None).expect("copy");
    assert_eq!(fs::read(file.path()).expect("read"), live);
    assert!(maintenance::cold_copies(&file).expect("list").is_empty());
    assert_eq!(
        names(&dir),
        [
            "fixture.household.db",
            "fixture.household.db.epoch",
            "fixture.household.db.migration"
        ]
    );
    let mut migration = open::<Migration>(copy.file(), &KEY).expect("open the copy");
    migration
        .apply_module_migrations(&frozen_all(&MIGRATIONS[..1]))
        .expect("migrate");
    migration.close().expect("close");
    let cold = copy.swap_in().expect("swap in").cold_copy;
    assert_eq!(fs::read(cold.path()).expect("read"), live);
    assert_eq!(module_version(&file), 1);
}

/// Review of Story 3.7, L1: once the migrated copy is renamed over the file, the file is
/// migrated; a working copy that cannot be removed afterwards, here because its directory holds
/// what the removal does not take, is reported as the swap's cleanup, not as a failed swap, and
/// the next migration of the file clears it.
#[test]
fn a_cleanup_that_fails_after_the_rename_is_not_a_failed_swap() {
    let dir = scratch_dir("copy-cleanup");
    let file = create_module_file(&dir);
    let copy = copy_for_migration(&file, &KEY, None).expect("copy");
    let mut migration = open::<Migration>(copy.file(), &KEY).expect("open the copy");
    migration
        .apply_module_migrations(&frozen_all(&MIGRATIONS[..1]))
        .expect("migrate the copy");
    migration.close().expect("close");
    let blocker = copy.file().directory().join("blocker");
    fs::create_dir(&blocker).expect("a directory the removal does not take");
    let swapped = copy.swap_in().expect("the file is swapped in");
    assert!(swapped.cleanup.is_some());
    assert_eq!(module_version(&file), 1);
    assert_eq!(swapped.cold_copy.versions(), versions(CORE, 0));
    fs::remove_dir(&blocker).expect("unblock");
    migrate_on_copy(&file, 2, None);
    assert!(!dir.join("fixture.household.db.migration").exists());
}

/// AC6: the free space of the file system that holds the files, as an unprivileged process may
/// use it, equal to what coreutils' `stat -f` reports independently (blocks available to a
/// non-superuser times the fundamental block size), within what other processes may write
/// meanwhile. A missing block size differs anywhere; the blocks free to the superuser differ
/// wherever the file system keeps some for it, as the test image's does.
#[test]
fn the_free_space_of_the_data_directory_is_read() {
    const DRIFT: u64 = 64 << 20;
    let dir = scratch_dir("free-space");
    let available = maintenance::available_space(&dir).expect("statvfs");
    let output = std::process::Command::new("stat")
        .args(["-f", "-c", "%a %S"])
        .arg(&dir)
        .output()
        .expect("run stat");
    assert!(output.status.success(), "{output:?}");
    let fields: Vec<u64> = String::from_utf8(output.stdout)
        .expect("text")
        .split_whitespace()
        .map(|field| field.parse().expect("a number"))
        .collect();
    let [blocks_available, block_size] = fields[..] else {
        panic!("{fields:?}");
    };
    let expected = blocks_available * block_size;
    assert!(
        available.abs_diff(expected) < DRIFT,
        "statvfs {available}, stat {expected}"
    );

    let missing = maintenance::available_space(&dir.join("missing"));
    assert!(matches!(missing, Err(Error::Io(_))), "{missing:?}");
}

#[test]
fn a_state_precedes_every_later_one_and_no_other() {
    let at = versions(2, 3);
    for later in [versions(2, 4), versions(3, 3), versions(3, 9)] {
        assert!(at.precedes(later), "{at} before {later}");
        assert!(!later.precedes(at), "{later} not before {at}");
    }
    for other in [at, versions(1, 9), versions(3, 2)] {
        assert!(!at.precedes(other), "{at} not before {other}");
    }
}

/// Story 3.9: the mark of a failed migration sits beside the file, never in it, is read back as
/// written, is replaced by a later mark, refused when malformed and removed with what an
/// interrupted write left; removing no mark is no error.
#[test]
fn a_failed_migration_mark_is_written_beside_the_file_read_back_and_cleared() {
    let dir = scratch_dir("failure-mark");
    let file = create_module_file(&dir);
    let before = fs::read(file.path()).expect("read the file");
    assert_eq!(
        maintenance::failed_migration_mark(&file).expect("read"),
        None
    );
    let mark = maintenance::FailedMigrationMark {
        code: [7; 32],
        track: MigrationTrack::Module,
        version: 3,
    };
    maintenance::mark_failed_migration(&file, mark).expect("mark");
    assert_eq!(
        maintenance::failed_migration_mark(&file).expect("read"),
        Some(mark)
    );
    assert_eq!(
        maintenance::failed_migration_mark_path(&file),
        dir.join(format!("{}.migration-failed", file.file_name()))
    );
    assert_eq!(fs::read(file.path()).expect("read the file"), before);
    let later = maintenance::FailedMigrationMark {
        code: [8; 32],
        track: MigrationTrack::Core,
        version: 1,
    };
    maintenance::mark_failed_migration(&file, later).expect("mark again");
    assert_eq!(
        maintenance::failed_migration_mark(&file).expect("read"),
        Some(later)
    );
    fs::write(
        maintenance::failed_migration_mark_path(&file),
        "vilicus failed migration 1\n",
    )
    .expect("damage the mark");
    assert!(matches!(
        maintenance::failed_migration_mark(&file),
        Err(Error::MalformedFailureMark(_))
    ));
    let staging = dir.join(format!("{}.migration-failed.tmp", file.file_name()));
    fs::write(&staging, "torn").expect("an interrupted write");
    maintenance::clear_failed_migration_mark(&file).expect("clear");
    assert_eq!(
        maintenance::failed_migration_mark(&file).expect("read"),
        None
    );
    assert!(!staging.exists());
    maintenance::clear_failed_migration_mark(&file).expect("clear nothing");
    assert_eq!(fs::read(file.path()).expect("read the file"), before);
}
