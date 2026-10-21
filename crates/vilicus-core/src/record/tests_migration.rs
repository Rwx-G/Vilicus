//! Story 3.7: the Core's migration runner, `Registry::migrate_files`, on real module files:
//! migrations on a copy swapped in, the original kept cold (AC2, AC3, AC8, D132), a failure that
//! keeps the previous file and alerts while other files proceed (AC4), a file newer than the code
//! (AC5), a changed migration (AC1), the free space (AC6) and the checks of the migrated copy
//! (D127, D146). Story 3.9: a failed migration held across runs by its mark until the code
//! changes, and a failure of the host's state not held.

use std::fs;
use std::path::Path;

use vilicus_module_api::{
    DataType, Field, FieldKind, Fts5Content, Fts5Table, Fts5Tokenizer, ModuleDeclaration,
    Structured, Table, Value,
};
use vilicus_storage::maintenance::{self, FailedMigrationMark, SchemaVersions, VerifiedBackup};
use vilicus_storage::{
    CORE_SCHEMA_VERSION, KeyEpoch, Migration, MigrationTrack, ModuleFile, Partition, Read, Write,
};
use vilicus_types::ModuleName;

use super::inspect::{Needles, Rng, inspect};
use super::tests::{KEY, create_sql, envelope_of, registry_of, scratch_dir, text, uuid};
use crate::alert::InstanceAdminAlert;
use crate::registry::{
    FileError, FileMigration, FileToMigrate, MigrationError, MigrationRunError, frozen,
    migration_code,
};

const CORE: u32 = CORE_SCHEMA_VERSION;

const EPOCH: KeyEpoch = KeyEpoch {
    partition_root_version: 1,
    generation: 0,
};

const FIELDS: &[Field] = &[
    Field {
        name: "label",
        kind: FieldKind::FreeText { max_len: 64 },
        optional: false,
    },
    Field {
        name: "quantity",
        kind: FieldKind::Structured(Structured::Integer { min: 0, max: 999 }),
        optional: true,
    },
];

const NOTE: Field = Field {
    name: "note",
    kind: FieldKind::FreeText { max_len: 200 },
    optional: true,
};

const SEARCH: Fts5Table = Fts5Table {
    name: "items_search",
    columns: &["label"],
    tokenizer: Fts5Tokenizer::Unicode61,
    content: Fts5Content::Table("items"),
};

/// The `shop` module at its first version, or at its second when `second` is given: the second
/// migration adds the optional `note` field, then runs `second`.
fn shop(second: Option<&str>, fts5: bool) -> &'static ModuleDeclaration {
    let table = Table {
        name: "items",
        data_types: &[DataType::ShoppingList],
        fields: FIELDS,
        elevation_exempt: false,
    };
    let mut first = create_sql(&table);
    if fts5 {
        first.push_str(
            "\nCREATE VIRTUAL TABLE items_search USING fts5(label, content='items');
             INSERT INTO items_search (items_search, rank) VALUES ('secure-delete', 1);",
        );
    }
    let mut migrations = vec![frozen(first.leak())];
    let mut fields = FIELDS.to_vec();
    if let Some(sql) = second {
        migrations.push(frozen(
            format!("ALTER TABLE items ADD COLUMN note TEXT;\n{sql}").leak(),
        ));
        fields.push(NOTE);
    }
    Box::leak(Box::new(ModuleDeclaration {
        name: "shop",
        tables: vec![Table {
            fields: fields.leak(),
            ..table
        }]
        .leak(),
        fts5_tables: if fts5 { vec![SEARCH].leak() } else { &[] },
        migrations: migrations.leak(),
        matrix_sections: &[],
        topics: &[],
        consumers: &[],
        tools: &[],
        queries: &[],
    }))
}

/// A new file of `module` in `partition` under `dir`, migrated to the module's last version.
fn create_at(module: &'static ModuleDeclaration, dir: &Path, partition: Partition) -> ModuleFile {
    let file = ModuleFile::new(dir, ModuleName::from_static("shop"), partition);
    vilicus_storage::create(&file, &KEY, EPOCH)
        .expect("create")
        .close()
        .expect("close");
    let mut migration = vilicus_storage::open::<Migration>(&file, &KEY).expect("open");
    migration
        .apply_module_migrations(&crate::registry::frozen_migrations(module).expect("frozen"))
        .expect("migrate");
    migration.close().expect("close");
    file
}

/// Inserts an `items` record of `label` and `quantity` through the row writer.
fn insert_item(file: &ModuleFile, module: &'static ModuleDeclaration, label: &str, quantity: i64) {
    let handle = registry_of(vec![module])
        .open::<Write>(file, &KEY)
        .expect("open");
    super::insert(
        &handle,
        module,
        "items",
        &envelope_of(
            &[DataType::ShoppingList],
            uuid(quantity.unsigned_abs() as u8),
        ),
        &[
            ("label", text(label)),
            ("quantity", Value::Integer(quantity)),
        ],
        &[],
    )
    .expect("insert");
    handle.close().expect("close");
}

fn target(file: &ModuleFile) -> FileToMigrate<'_> {
    FileToMigrate {
        file,
        key: &KEY,
        verified_backup: None,
    }
}

/// The bytes of the file and the names of its directory, every connection closed. The mark of a
/// failed migration beside a file (Story 3.9) is checked on its own.
fn disk(file: &ModuleFile) -> (Vec<u8>, Vec<String>) {
    let mut names: Vec<String> = fs::read_dir(file.directory())
        .expect("list")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| {
            !name.ends_with("-shm")
                && !name.ends_with("-wal")
                && !name.ends_with(".migration-failed")
        })
        .collect();
    names.sort();
    (fs::read(file.path()).expect("read"), names)
}

fn versions(file: &ModuleFile) -> SchemaVersions {
    let reader = vilicus_storage::open::<Read>(file, &KEY).expect("open");
    let versions = SchemaVersions {
        core: reader.schema_version(MigrationTrack::Core).expect("core"),
        module: reader
            .schema_version(MigrationTrack::Module)
            .expect("module"),
    };
    reader.close().expect("close");
    versions
}

fn labels_at(path: &Path) -> Vec<String> {
    let connection = rusqlite::Connection::open(path).expect("open");
    let hex: String = KEY.iter().map(|byte| format!("{byte:02x}")).collect();
    connection
        .execute_batch(&format!("PRAGMA key = \"x'{hex}'\";"))
        .expect("key");
    connection
        .prepare("SELECT label FROM items ORDER BY label")
        .expect("prepare")
        .query_map([], |row| row.get(0))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("read")
}

/// AC2, AC8 and D132: a pending file is migrated on a copy, Core track first, checked and
/// swapped in; the Core opens it at the code's versions; the original stays as its cold copy,
/// holding what the migration deleted, while the migrated file, written under `secure_delete`,
/// holds no run of 8 bytes or more of it.
#[test]
fn a_pending_file_is_migrated_on_a_copy_and_its_original_kept_cold() {
    let mut rng = Rng::new(37);
    let secret = rng.text(64);
    let v1 = shop(None, false);
    let v2 = shop(
        Some(&format!("DELETE FROM items WHERE label = '{secret}';")),
        false,
    );
    let dir = scratch_dir("migrate-copy");
    let file = create_at(v1, &dir, Partition::Household);
    insert_item(&file, v1, "kept", 1);
    insert_item(&file, v1, &secret, 2);
    let mut needles = Needles::default();
    needles.add(secret.as_bytes());
    assert_eq!(
        needles.found_in(&inspect(&file, &KEY).file),
        1,
        "the control"
    );

    let outcomes = registry_of(vec![v2])
        .migrate_files(&[target(&file)])
        .expect("run");
    let [
        FileMigration::Migrated {
            from,
            to,
            cold_copy,
            cleanup: None,
        },
    ] = outcomes.as_slice()
    else {
        panic!("{outcomes:?}");
    };
    assert_eq!(
        *from,
        SchemaVersions {
            core: CORE,
            module: 1
        }
    );
    assert_eq!(
        *to,
        SchemaVersions {
            core: CORE,
            module: 2
        }
    );
    assert_eq!(
        cold_copy.path(),
        dir.join(format!("shop.household.db.pre-{CORE}.1"))
    );
    assert_eq!(versions(&file), *to);
    registry_of(vec![v2])
        .open::<Read>(&file, &KEY)
        .expect("the Core opens the migrated file")
        .close()
        .expect("close");
    assert_eq!(labels_at(&file.path()), ["kept"]);
    assert_eq!(labels_at(cold_copy.path()), {
        let mut labels = vec!["kept".to_owned(), secret.clone()];
        labels.sort();
        labels
    });
    let inspected = inspect(&file, &KEY);
    for (part, bytes) in inspected.parts() {
        assert_eq!(needles.found_in_short(bytes), 0, "{part}");
    }
    assert_eq!(inspected.wal_frames, 0);
    assert_eq!(
        registry_of(vec![v2])
            .migrate_files(&[target(&file)])
            .expect("again")
            .len(),
        1
    );
}

/// Review of Story 3.7, L2: what a crash in a migration left beside a file (its working copy,
/// which may hold a record shredded in the live file since, D132, and a cold copy that is still
/// the live file) is cleared by the next run for every file, not only those with a migration
/// pending; the current file is served as it is.
#[test]
fn a_run_clears_interrupted_migrations_of_every_file() {
    let v1 = shop(None, false);
    let dir = scratch_dir("migrate-leftovers");
    let file = create_at(v1, &dir, Partition::Household);
    let working = dir.join("shop.household.db.migration");
    fs::create_dir(&working).expect("a working directory");
    fs::copy(file.path(), working.join("shop.household.db")).expect("a working copy");
    let stale = dir.join(format!("shop.household.db.pre-{CORE}.0"));
    fs::hard_link(file.path(), &stale).expect("a link the swap left");
    let before = fs::read(file.path()).expect("read");
    let outcomes = registry_of(vec![v1])
        .migrate_files(&[target(&file)])
        .expect("run");
    assert!(
        matches!(outcomes.as_slice(), [FileMigration::Current]),
        "{outcomes:?}"
    );
    assert!(!working.exists(), "the working copy is gone");
    assert!(!stale.exists(), "the stale link is gone");
    assert_eq!(fs::read(file.path()).expect("read"), before);
}

/// AC4: one file's migration fails, here on a back-fill the declaration refuses in that file
/// only; its previous file stays in place untouched, the Core still refuses to start the module
/// on it, and the alert names the file and the version; the other file of the run is migrated.
#[test]
fn a_failed_migration_keeps_the_previous_file_and_the_others_proceed() {
    let v1 = shop(None, false);
    let v2 = shop(Some("UPDATE items SET quantity = quantity * 1000;"), false);
    let dir = scratch_dir("migrate-failed");
    let household = create_at(v1, &dir, Partition::Household);
    insert_item(&household, v1, "five", 5);
    let member = create_at(v1, &dir, Partition::Member(uuid(9)));
    let before = disk(&household);

    let registry = registry_of(vec![v2]);
    let outcomes = registry
        .migrate_files(&[target(&household), target(&member)])
        .expect("run");
    let [
        FileMigration::Failed { alert, error },
        FileMigration::Migrated { .. },
    ] = outcomes.as_slice()
    else {
        panic!("{outcomes:?}");
    };
    assert_eq!(
        *alert,
        InstanceAdminAlert::MigrationFailed {
            module: ModuleName::from_static("shop"),
            partition: Partition::Household,
            file_name: "shop.household.db".to_owned(),
            track: MigrationTrack::Module,
            version: 2,
        }
    );
    assert!(matches!(error, MigrationError::StoredRow(_)), "{error:?}");
    let (bytes, names) = disk(&household);
    assert_eq!(bytes, before.0, "the previous file's bytes");
    assert_eq!(
        names
            .iter()
            .filter(|name| name.starts_with("shop.household"))
            .collect::<Vec<_>>(),
        before
            .1
            .iter()
            .filter(|name| name.starts_with("shop.household"))
            .collect::<Vec<_>>(),
        "no cold copy, no working copy"
    );
    assert_eq!(versions(&household).module, 1);
    assert!(matches!(
        registry.open::<Read>(&household, &KEY),
        Err(FileError::MigrationPending {
            found: 1,
            latest: 2
        })
    ));
    assert_eq!(versions(&member).module, 2);
    assert_eq!(
        maintenance::failed_migration_mark(&household).expect("read"),
        Some(FailedMigrationMark {
            code: migration_code(v2),
            track: MigrationTrack::Module,
            version: 2,
        }),
        "Story 3.9: the failure is held beside the file"
    );
    assert_eq!(
        maintenance::failed_migration_mark(&member).expect("read"),
        None
    );
}

/// AC5 (D21): a file newer than the code, on either track, is left alone by the runner, refused
/// at open, and reported with a typed alert.
#[test]
fn a_file_newer_than_the_code_is_refused_with_an_alert() {
    let v1 = shop(None, false);
    let v2 = shop(Some(""), false);
    let dir = scratch_dir("migrate-newer");
    let file = create_at(v2, &dir, Partition::Household);
    let before = disk(&file);
    let registry = registry_of(vec![v1]);
    let outcomes = registry.migrate_files(&[target(&file)]).expect("run");
    let expected = InstanceAdminAlert::NewerThanCode {
        module: ModuleName::from_static("shop"),
        partition: Partition::Household,
        file_name: "shop.household.db".to_owned(),
        track: MigrationTrack::Module,
        found: 2,
        latest: 1,
    };
    assert!(
        matches!(outcomes.as_slice(), [FileMigration::NewerThanCode { alert }] if *alert == expected),
        "{outcomes:?}"
    );
    assert_eq!(disk(&file), before);
    let refused = registry
        .open::<Read>(&file, &KEY)
        .expect_err("a file newer than the code");
    assert!(matches!(
        refused,
        FileError::NewerThanCode {
            found: 2,
            latest: 1
        }
    ));
    assert_eq!(refused.admin_alert(&file), Some(expected));

    let core_ahead = create_at(v1, &scratch_dir("migrate-newer-core"), Partition::Household);
    super::tests::raw_connection(&core_ahead)
        .execute_batch(&format!(
            "UPDATE _meta SET value = {} WHERE key = 'core_schema_version'",
            CORE + 1
        ))
        .expect("plant a newer Core track");
    let outcomes = registry.migrate_files(&[target(&core_ahead)]).expect("run");
    assert!(
        matches!(
            outcomes.as_slice(),
            [FileMigration::NewerThanCode {
                alert: InstanceAdminAlert::NewerThanCode {
                    track: MigrationTrack::Core,
                    ..
                }
            }]
        ),
        "{outcomes:?}"
    );
    let refused = registry
        .open::<Read>(&core_ahead, &KEY)
        .expect_err("a Core track newer than the code");
    assert!(refused.admin_alert(&core_ahead).is_some());
}

/// AC1 (D21): a migration whose SQL differs from its frozen hash fails the file before anything
/// runs, and so does a file that ran a migration since changed and frozen again; the file is
/// untouched and the alert names the migration.
#[test]
fn a_changed_migration_fails_the_file_before_anything_runs() {
    let v1 = shop(None, false);
    let dir = scratch_dir("migrate-changed");
    let file = create_at(v1, &dir, Partition::Household);
    let before = disk(&file);

    let mut unfrozen = *shop(Some(""), false);
    let mut migrations = unfrozen.migrations.to_vec();
    migrations[1].sql = format!("{} ", migrations[1].sql).leak();
    unfrozen.migrations = migrations.leak();
    let mut refrozen = *shop(Some(""), false);
    let mut migrations = refrozen.migrations.to_vec();
    migrations[0] = frozen(format!("{} ", migrations[0].sql).leak());
    refrozen.migrations = migrations.leak();
    let mut current = *shop(None, false);
    let mut migrations = current.migrations.to_vec();
    migrations[0] = frozen(format!("{} ", migrations[0].sql).leak());
    current.migrations = migrations.leak();
    for (module, version) in [(unfrozen, 2), (refrozen, 1), (current, 1)] {
        let outcomes = registry_of(vec![Box::leak(Box::new(module))])
            .migrate_files(&[target(&file)])
            .expect("run");
        let [FileMigration::Failed { alert, error }] = outcomes.as_slice() else {
            panic!("{outcomes:?}");
        };
        assert!(
            matches!(
                alert,
                InstanceAdminAlert::MigrationFailed { track: MigrationTrack::Module, version: found, .. }
                    if *found == version
            ),
            "{alert:?}"
        );
        assert!(
            matches!(
                error,
                MigrationError::File(FileError::ChangedMigration { track: MigrationTrack::Module, version: found })
                    if *found == version
            ),
            "{error:?}"
        );
        assert_eq!(disk(&file), before);
        assert_eq!(
            maintenance::failed_migration_mark(&file).expect("read"),
            None,
            "Story 3.9 review: a failure found before any copy is not marked"
        );
    }
}

/// AC6 (AD-23): the run does not start, and touches no file, unless the data directory has at
/// least twice the size of the largest file it would copy, the file and its WAL. The free space
/// is a fixed value the test gives the runner: read from the shared disk, it moves with every
/// test that runs beside this one.
#[test]
fn a_run_without_twice_the_largest_file_free_does_not_start() {
    let v1 = shop(None, false);
    let v2 = shop(Some(""), false);
    let dir = scratch_dir("migrate-space");
    let small = create_at(v1, &dir, Partition::Member(uuid(1)));
    let large = create_at(v1, &dir, Partition::Household);
    let length = |file: &ModuleFile| {
        fs::metadata(file.path()).map_or(0, |metadata| metadata.len())
            + fs::metadata(file.wal_path()).map_or(0, |metadata| metadata.len())
    };
    let largest = length(&small).max(length(&large));
    let registry = registry_of(vec![v2]);
    let small_before = disk(&small);
    let large_before = disk(&large);
    for available in [0, largest, 2 * largest - 1] {
        let outcome = registry
            .migrate_files_with_space(&[target(&small), target(&large)], &|_| Ok(available));
        assert!(
            matches!(
                &outcome,
                Err(MigrationRunError::InsufficientSpace { required, available: seen, directory })
                    if *required == 2 * largest && *seen == available && *directory == dir
            ),
            "{available}: {outcome:?}"
        );
        assert_eq!(disk(&small), small_before);
        assert_eq!(disk(&large), large_before);
        assert_eq!(versions(&small).module, 1);
    }
    let outcome = registry
        .migrate_files_with_space(&[target(&small), target(&large)], &|_| Ok(2 * largest))
        .expect("twice the largest file is enough");
    assert!(
        outcome
            .iter()
            .all(|file| matches!(file, FileMigration::Migrated { .. })),
        "{outcome:?}"
    );
    assert_eq!(versions(&small).module, 2);
}

/// AC3 through the runner: a file with three cold copies none of which a verified backup covers
/// fails its migration, untouched, until the marker the caller gives covers the oldest.
#[test]
fn a_file_with_three_uncovered_cold_copies_waits_for_a_verified_backup() {
    let v1 = shop(None, false);
    let v2 = shop(Some(""), false);
    let dir = scratch_dir("migrate-cold");
    let file = create_at(v1, &dir, Partition::Household);
    for earlier in ["0.0", "0.1", "1.0"] {
        let cold = dir.join(format!("shop.household.db.pre-{earlier}"));
        fs::copy(file.path(), &cold).expect("a cold copy");
        fs::copy(
            file.epoch_path(),
            dir.join(format!("shop.household.db.pre-{earlier}.epoch")),
        )
        .expect("its sidecar");
    }
    let before = disk(&file);
    let registry = registry_of(vec![v2]);
    let outcomes = registry.migrate_files(&[target(&file)]).expect("run");
    assert!(
        matches!(
            outcomes.as_slice(),
            [FileMigration::Failed {
                error: MigrationError::Storage(vilicus_storage::Error::ColdCopiesFull { kept: 3 }),
                ..
            }]
        ),
        "{outcomes:?}"
    );
    assert_eq!(disk(&file), before);
    let outcomes = registry
        .migrate_files(&[FileToMigrate {
            verified_backup: Some(VerifiedBackup {
                versions: SchemaVersions { core: 1, module: 0 },
            }),
            ..target(&file)
        }])
        .expect("run");
    assert!(
        matches!(outcomes.as_slice(), [FileMigration::Migrated { .. }]),
        "{outcomes:?}"
    );
    assert!(!dir.join("shop.household.db.pre-0.0").exists());
    for kept in ["0.1", "1.0", "1.1"] {
        assert!(
            dir.join(format!("shop.household.db.pre-{kept}")).exists(),
            "{kept}"
        );
    }
}

/// D127 through the runner: the FTS5 index of the migrated copy is checked with FTS5's
/// `integrity-check` before the swap; a file whose index is damaged, which no module SQL can do
/// under defensive mode, fails its migration and keeps its file.
#[test]
fn the_fts5_indexes_of_the_migrated_copy_are_checked() {
    let v1 = shop(None, true);
    let v2 = shop(Some(""), true);
    let registry = registry_of(vec![v2]);
    let mut outcomes = Vec::new();
    for damaged in [false, true] {
        let file = create_at(v1, &scratch_dir("migrate-fts5"), Partition::Household);
        insert_item(&file, v1, "indexed words", 3);
        let writer = registry_of(vec![v1])
            .open::<Write>(&file, &KEY)
            .expect("open");
        writer
            .execute_batch("INSERT INTO items_search (rowid, label) SELECT rowid, label FROM items")
            .expect("index the row");
        writer.close().expect("close");
        if damaged {
            super::tests::raw_connection(&file)
                .execute_batch("DELETE FROM items_search_data WHERE id > 10")
                .expect("damage the index outside defensive mode");
        }
        let before = disk(&file);
        let outcome = registry.migrate_files(&[target(&file)]).expect("run");
        if damaged {
            assert_eq!(disk(&file), before);
        }
        outcomes.extend(outcome);
    }
    assert!(
        matches!(
            outcomes.as_slice(),
            [
                FileMigration::Migrated { .. },
                FileMigration::Failed {
                    error: MigrationError::Fts5Index {
                        table: "items_search",
                        ..
                    },
                    ..
                }
            ]
        ),
        "{outcomes:?}"
    );
}

/// AC7 through the runner (D126): a migration whose SQL is refused, an `ATTACH` or a statement
/// of transaction control, ends with nothing written: the file's bytes, the directory listing,
/// its versions and its rows are as before, and the alert names the refused version.
#[test]
fn a_refused_statement_ends_the_migration_with_nothing_written() {
    let v1 = shop(None, false);
    for (index, sql) in [
        "ATTACH DATABASE ':memory:' AS hijack;",
        "COMMIT;",
        "SAVEPOINT split;",
    ]
    .into_iter()
    .enumerate()
    {
        let file = create_at(
            v1,
            &scratch_dir(&format!("migrate-refused-{index}")),
            Partition::Household,
        );
        insert_item(&file, v1, "before", 4);
        let before = disk(&file);
        let outcomes = registry_of(vec![shop(Some(sql), false)])
            .migrate_files(&[target(&file)])
            .expect("run");
        let [FileMigration::Failed { alert, error }] = outcomes.as_slice() else {
            panic!("{sql}: {outcomes:?}");
        };
        assert!(
            matches!(
                error,
                MigrationError::Storage(refused @ vilicus_storage::Error::MigrationFailed {
                    track: MigrationTrack::Module,
                    version: 2,
                    ..
                }) if refused.is_refusal()
            ),
            "{sql}: {error:?}"
        );
        assert!(
            matches!(
                alert,
                InstanceAdminAlert::MigrationFailed { version: 2, .. }
            ),
            "{alert:?}"
        );
        assert_eq!(disk(&file), before, "{sql}");
        assert_eq!(versions(&file).module, 1);
        assert_eq!(labels_at(&file.path()), ["before"]);
    }
}

// Story 3.9: a failed migration is held across starts until the code changes.

/// A file whose migration failed is held by its mark: the next run, as at the next start, reports
/// it still failed under the same code without copying or migrating it or alerting again, and the
/// Core still refuses it; a forward release, whose code differs, tries it again and the mark goes.
#[test]
fn a_failed_migration_is_held_across_runs_until_the_code_changes() {
    let v1 = shop(None, false);
    let failing = shop(Some("UPDATE items SET quantity = quantity * 1000;"), false);
    let fixed = shop(Some("UPDATE items SET quantity = quantity * 10;"), false);
    assert_ne!(migration_code(failing), migration_code(fixed));
    let dir = scratch_dir("migrate-held");
    let file = create_at(v1, &dir, Partition::Household);
    insert_item(&file, v1, "five", 5);
    let registry = registry_of(vec![failing]);
    let first = registry.migrate_files(&[target(&file)]).expect("run");
    assert!(
        matches!(first.as_slice(), [FileMigration::Failed { .. }]),
        "{first:?}"
    );
    let before = disk(&file);
    let mark = maintenance::failed_migration_mark(&file)
        .expect("read")
        .expect("marked");
    for _ in 0..2 {
        let again = registry_of(vec![failing])
            .migrate_files(&[target(&file)])
            .expect("run");
        let [FileMigration::StillFailed { mark: held }] = again.as_slice() else {
            panic!("{again:?}");
        };
        assert_eq!(*held, mark);
        assert_eq!(disk(&file), before, "nothing copied, migrated or swapped");
    }
    assert!(matches!(
        registry.open::<Read>(&file, &KEY),
        Err(FileError::MigrationPending { .. })
    ));
    let released = registry_of(vec![fixed])
        .migrate_files(&[target(&file)])
        .expect("run");
    assert!(
        matches!(released.as_slice(), [FileMigration::Migrated { .. }]),
        "{released:?}"
    );
    assert_eq!(versions(&file).module, 2);
    assert_eq!(
        maintenance::failed_migration_mark(&file).expect("read"),
        None
    );
}

/// A failure of the host's state is not held: three cold copies no verified backup covers fail
/// the migration without a mark, and a later run tries it again.
#[test]
fn a_failure_of_the_hosts_state_is_not_held() {
    let v1 = shop(None, false);
    let v2 = shop(Some(""), false);
    let dir = scratch_dir("migrate-not-held");
    let file = create_at(v1, &dir, Partition::Household);
    for earlier in ["0.0", "0.1", "1.0"] {
        fs::copy(
            file.path(),
            dir.join(format!("shop.household.db.pre-{earlier}")),
        )
        .expect("a cold copy");
    }
    let registry = registry_of(vec![v2]);
    let outcomes = registry.migrate_files(&[target(&file)]).expect("run");
    let [FileMigration::Failed { error, .. }] = outcomes.as_slice() else {
        panic!("{outcomes:?}");
    };
    assert!(error.is_environmental(), "{error:?}");
    assert_eq!(
        maintenance::failed_migration_mark(&file).expect("read"),
        None
    );
    let again = registry.migrate_files(&[target(&file)]).expect("run");
    assert!(
        matches!(again.as_slice(), [FileMigration::Failed { .. }]),
        "tried again: {again:?}"
    );
}

/// A mark that names another code, or that does not read, holds nothing: it is cleared and the
/// migration runs; a mark beside a file with nothing to migrate is stale and cleared too.
#[test]
fn a_mark_of_another_code_or_malformed_is_cleared_and_the_migration_runs() {
    let v1 = shop(None, false);
    let v2 = shop(Some(""), false);
    let registry = registry_of(vec![v2]);
    for (label, written) in [
        (
            "other-code",
            Some(FailedMigrationMark {
                code: [0; 32],
                track: MigrationTrack::Module,
                version: 2,
            }),
        ),
        ("malformed", None),
    ] {
        let dir = scratch_dir(&format!("migrate-mark-{label}"));
        let file = create_at(v1, &dir, Partition::Household);
        match written {
            Some(mark) => maintenance::mark_failed_migration(&file, mark).expect("mark"),
            None => fs::write(maintenance::failed_migration_mark_path(&file), "torn")
                .expect("a torn mark"),
        }
        let outcomes = registry.migrate_files(&[target(&file)]).expect("run");
        assert!(
            matches!(outcomes.as_slice(), [FileMigration::Migrated { .. }]),
            "{label}: {outcomes:?}"
        );
        assert_eq!(
            maintenance::failed_migration_mark(&file).expect("read"),
            None,
            "{label}"
        );
        maintenance::mark_failed_migration(
            &file,
            FailedMigrationMark {
                code: migration_code(v2),
                track: MigrationTrack::Module,
                version: 2,
            },
        )
        .expect("a stale mark");
        let current = registry.migrate_files(&[target(&file)]).expect("run");
        assert!(
            matches!(current.as_slice(), [FileMigration::Current]),
            "{label}: {current:?}"
        );
        assert_eq!(
            maintenance::failed_migration_mark(&file).expect("read"),
            None,
            "{label}: a file with nothing to migrate is held by no mark"
        );
    }
}
