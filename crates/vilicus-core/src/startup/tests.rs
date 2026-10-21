//! Story 3.9, AC3 (AD-54, FR-11): a partition is usable once its keys are derived, its files
//! `opening`; the bring-up then re-keys, migrates and opens each file, and only then delivers the
//! outboxes, in that order. A file that cannot serve stops in its state with its alert, a failed
//! migration held across starts, and the other files proceed.

use std::cell::RefCell;
use std::path::Path;
use std::time::Duration;

use vilicus_module_api::{
    Consumer, DataType, Event, Field, FieldKind, ModuleDeclaration, Records, Table, Topic, Value,
    WriteError,
};
use vilicus_storage::{KeyEpoch, Migration, MigrationTrack, ModuleFile, Partition, Read, Write};
use vilicus_types::{
    AvailabilityState, CallId, HANDLER_TIME_BUDGET, Id, ModuleName, Principal, RetryClass, Source,
    Taint,
};

use super::{
    BringUpError, BringUpReport, Delivery, FileOutcome, NothingToRekey, PartitionFiles, Rekey,
    bring_up, bring_up_with_space,
};
use crate::alert::InstanceAdminAlert;
use crate::availability::{ModuleStates, MonotonicClock, Stage};
use crate::boundary::Boundary;
use crate::bus::{ConsumerCode, DeliveryOutcome, Link, LinkTable};
use crate::record::tests::{KEY, create_sql, noon, scratch_dir};
use crate::record::tests_call::{TestStamper, ella};
use crate::record::{Authority, Call, CallResult, Consumed, Invocation, Stamper, run_call};
use crate::registry::{FileMigration, FileToMigrate, Registry, frozen, frozen_migrations};

const EPOCH: KeyEpoch = KeyEpoch {
    partition_root_version: 1,
    generation: 0,
};

const TITLE: &[Field] = &[Field {
    name: "title",
    kind: FieldKind::FreeText { max_len: 200 },
    optional: false,
}];

const NOTES: &[Table] = &[Table {
    name: "notes",
    data_types: &[DataType::Meals],
    fields: TITLE,
}];

const TASKS: &[Table] = &[Table {
    name: "tasks",
    data_types: &[DataType::Meals],
    fields: TITLE,
}];

const ADDED: &str = "notes.note.added";

const NOTE_TOPICS: &[Topic] = &[Topic {
    name: ADDED,
    version: 1,
    consumers: &["tasks"],
}];

const TASK_CONSUMERS: &[Consumer] = &[Consumer {
    name: "react",
    topic: ADDED,
}];

/// A module of `tables`, created by one migration, then each of `more`.
fn declare(
    name: &'static str,
    tables: &'static [Table],
    topics: &'static [Topic],
    consumers: &'static [Consumer],
    more: &[&'static str],
) -> &'static ModuleDeclaration {
    let create: String = tables.iter().map(create_sql).collect::<Vec<_>>().join("\n");
    let migrations: Vec<_> = [&*create.leak()]
        .into_iter()
        .chain(more.iter().copied())
        .map(frozen)
        .collect();
    Box::leak(Box::new(ModuleDeclaration {
        name,
        tables,
        fts5_tables: &[],
        migrations: migrations.leak(),
        matrix_sections: &[],
        tools: &[],
        topics,
        consumers,
    }))
}

fn notes() -> &'static ModuleDeclaration {
    declare("notes", NOTES, NOTE_TOPICS, &[], &[])
}

/// The `tasks` module, whose second migration is `second`.
fn tasks(second: &'static str) -> &'static ModuleDeclaration {
    declare("tasks", TASKS, &[], TASK_CONSUMERS, &[second])
}

/// A new file of `module` in `partition` under `directory`, migrated to `version` at most.
fn new_file(
    directory: &Path,
    module: &'static ModuleDeclaration,
    partition: Partition,
    version: usize,
) -> ModuleFile {
    let file = ModuleFile::new(directory, ModuleName::from_static(module.name), partition);
    vilicus_storage::create(&file, &KEY, EPOCH)
        .expect("create")
        .close()
        .expect("close");
    let migrations = frozen_migrations(module).expect("frozen");
    let mut migration = vilicus_storage::open::<Migration>(&file, &KEY).expect("open");
    migration
        .apply_module_migrations(&migrations[..version.min(migrations.len())])
        .expect("migrate");
    migration.close().expect("close");
    file
}

fn module_version(file: &ModuleFile) -> u32 {
    let reader = vilicus_storage::open::<Read>(file, &KEY).expect("open");
    let version = reader.schema_version(MigrationTrack::Module).expect("read");
    reader.close().expect("close");
    version
}

/// Ella adds a note in `file` and emits an event about it; the handle is closed after.
fn add_note(registry: &Registry, file: &ModuleFile, stamper: &mut TestStamper) -> Id {
    let handle = registry.open::<Write>(file, &KEY).expect("open");
    let call = Call {
        principal: Principal::Member,
        source: Source::Member(ella()),
        session: Taint::Trusted,
        consumed: Consumed::NOTHING,
        authority: Authority::OwnAction { member: ella() },
        read: Vec::new(),
        implicit_inputs: Vec::new(),
    };
    let now = stamper.now();
    let invocation = Invocation {
        call_id: CallId::from(Id::new_v7(now, stamper.id_random()).expect("after the epoch")),
        request_hash: None,
        delivery: None,
    };
    let module = registry.module(file.module()).expect("registered");
    let result = run_call(&handle, module, &call, &invocation, stamper, |records| {
        let note = records.insert("notes", &[("title", Value::Text("Pommes".into()))], &[])?;
        records.emit(ADDED, note.id, b"")
    })
    .expect("the call commits");
    handle.close().expect("close");
    match result {
        CallResult::Committed(outcome) => outcome.value,
        other => panic!("{other:?}"),
    }
}

/// A monotonic clock that never moves.
struct Still;

impl MonotonicClock for Still {
    fn now(&self) -> Duration {
        Duration::ZERO
    }
}

/// A link table with nothing to register.
struct NoLinks;

impl LinkTable for NoLinks {
    fn register(&mut self, _: &Link) -> Result<(), vilicus_storage::Error> {
        Ok(())
    }
}

/// What each step of the bring-up saw: each file's state, by module, and, at the re-key, the
/// module version of the `tasks` file, read on a connection of its own (at the delivery the
/// Core holds that file open, and the test reads it afterwards).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    step: &'static str,
    notes: AvailabilityState,
    tasks: AvailabilityState,
    tasks_version: Option<u32>,
}

/// The probes of the bring-up: a re-key of the `notes` file and a consumer, each noting what it
/// saw when it ran.
struct Probe<'a> {
    states: &'a ModuleStates,
    tasks_file: ModuleFile,
    rekey_notes: bool,
    fail_rekey: bool,
    seen: &'a RefCell<Vec<Seen>>,
}

impl Probe<'_> {
    fn note(&self, step: &'static str) {
        let state = |module| {
            self.states
                .state(&ModuleName::from_static(module), Partition::Household)
        };
        self.seen.borrow_mut().push(Seen {
            step,
            notes: state("notes"),
            tasks: state("tasks"),
            tasks_version: Some(module_version(&self.tasks_file)),
        });
    }
}

impl Rekey for Probe<'_> {
    fn pending(&mut self, file: &ModuleFile) -> bool {
        self.rekey_notes && file.module().as_str() == "notes"
    }

    fn rekey(&mut self, _: &ModuleFile) -> Result<(), vilicus_storage::Error> {
        self.note("re-key");
        if self.fail_rekey {
            Err(vilicus_storage::Error::WrongKey)
        } else {
            Ok(())
        }
    }
}

/// Consumer code that notes what it saw, then writes a task.
struct Consumers<'a> {
    probe: &'a Probe<'a>,
}

impl ConsumerCode for Consumers<'_> {
    fn consume(
        &mut self,
        module: &'static ModuleDeclaration,
        _: &'static Consumer,
        event: &Event<'_>,
        records: &mut dyn Records,
    ) -> Result<(), WriteError> {
        assert_eq!(module.name, "tasks");
        self.probe.seen.borrow_mut().push(Seen {
            step: "deliver",
            notes: self
                .probe
                .states
                .state(&ModuleName::from_static("notes"), Partition::Household),
            tasks: self
                .probe
                .states
                .state(&ModuleName::from_static("tasks"), Partition::Household),
            tasks_version: None,
        });
        records.insert(
            "tasks",
            &[("title", Value::Text("after".into()))],
            &[event.record],
        )?;
        Ok(())
    }
}

fn targets<'a>(files: &'a [ModuleFile]) -> Vec<FileToMigrate<'a>> {
    files
        .iter()
        .map(|file| FileToMigrate {
            file,
            key: &KEY,
            verified_backup: None,
        })
        .collect()
}

fn boundary(states: &ModuleStates) -> Boundary<'_> {
    Boundary {
        states,
        clock: &Still,
        budget: HANDLER_TIME_BUDGET,
    }
}

/// The partition with a `notes` file holding one pending event and a `tasks` file one migration
/// behind; unlocked, not brought up.
struct Partitioned {
    registry: Registry,
    files: Vec<ModuleFile>,
    event: Id,
    stamper: TestStamper,
}

fn partitioned(label: &str, second: &'static str) -> Partitioned {
    let directory = scratch_dir(label);
    let notes = notes();
    let tasks = tasks(second);
    let registry = Registry::new(vec![notes, tasks].leak()).expect("a valid registry");
    let notes_file = new_file(&directory, notes, Partition::Household, usize::MAX);
    let tasks_file = new_file(&directory, tasks, Partition::Household, 1);
    let mut stamper = TestStamper::at(noon());
    let event = add_note(&registry, &notes_file, &mut stamper);
    Partitioned {
        registry,
        files: vec![notes_file, tasks_file],
        event,
        stamper,
    }
}

/// Runs the bring-up of `partitioned` with `probe`, delivering through it.
fn run(
    partitioned: &mut Partitioned,
    states: &ModuleStates,
    probe: &Probe<'_>,
) -> (PartitionFiles, BringUpReport) {
    let targets = targets(&partitioned.files);
    let seen = probe.seen;
    let mut rekey = Probe {
        states: probe.states,
        tasks_file: probe.tasks_file.clone(),
        rekey_notes: probe.rekey_notes,
        fail_rekey: probe.fail_rekey,
        seen,
    };
    let mut consumers = Consumers { probe };
    bring_up(
        &partitioned.registry,
        &boundary(states),
        Partition::Household,
        &targets,
        &mut rekey,
        Delivery {
            code: &mut consumers,
            links: &mut NoLinks,
            stamper: &mut partitioned.stamper,
        },
    )
    .expect("a bring-up")
}

fn outcome<'a>(report: &'a BringUpReport, module: &str) -> &'a FileOutcome {
    &report
        .files
        .iter()
        .find(|(name, _)| name.as_str() == module)
        .expect("an outcome")
        .1
}

fn state(states: &ModuleStates, module: &'static str) -> AvailabilityState {
    states.state(&ModuleName::from_static(module), Partition::Household)
}

/// AC3: unlock reports the partition usable at once, every file `opening` and answering
/// `retryable`, before any file is touched; the bring-up then re-keys a file while the others are
/// still opening and before any migration, migrates the file behind, opens both, and only once
/// both are ready delivers the event, which reaches the migrated consumer.
#[test]
fn a_partition_is_usable_at_once_and_its_files_are_re_keyed_migrated_then_delivered() {
    let mut partitioned = partitioned("order", "UPDATE tasks SET title = title;");
    let states = ModuleStates::new();
    states.unlock_partition(&partitioned.registry, Partition::Household);
    for module in ["notes", "tasks"] {
        assert_eq!(state(&states, module), AvailabilityState::Opening);
        assert_eq!(
            states
                .check(&ModuleName::from_static(module), Partition::Household)
                .map_err(|refused| vilicus_types::ClientFacingError::retry_class(&refused)),
            Err(RetryClass::Retryable)
        );
    }
    assert_eq!(
        module_version(&partitioned.files[1]),
        1,
        "nothing touched yet"
    );
    let seen = RefCell::new(Vec::new());
    let probe = Probe {
        states: &states,
        tasks_file: partitioned.files[1].clone(),
        rekey_notes: true,
        fail_rekey: false,
        seen: &seen,
    };
    let (open, report) = run(&mut partitioned, &states, &probe);
    assert_eq!(
        seen.into_inner(),
        [
            Seen {
                step: "re-key",
                notes: AvailabilityState::ReKeying,
                tasks: AvailabilityState::Opening,
                tasks_version: Some(1),
            },
            Seen {
                step: "deliver",
                notes: AvailabilityState::Ready,
                tasks: AvailabilityState::Ready,
                tasks_version: None,
            },
        ],
        "re-key, then migration, then delivery"
    );
    assert!(matches!(outcome(&report, "notes"), FileOutcome::Ready));
    assert!(matches!(outcome(&report, "tasks"), FileOutcome::Ready));
    assert!(report.alerts.is_empty(), "{:?}", report.alerts);
    let tasks = open
        .handle(&ModuleName::from_static("tasks"))
        .expect("open");
    assert_eq!(
        tasks.schema_version(MigrationTrack::Module).expect("read"),
        2
    );
    let delivered = &report.deliveries[0];
    assert_eq!(delivered.0.as_str(), "notes");
    let delivered = delivered.1.as_ref().expect("a delivery pass");
    assert_eq!(delivered.closed, [partitioned.event]);
    assert_eq!(
        tasks
            .query_values("SELECT id FROM tasks", &[])
            .expect("read")
            .len(),
        1
    );
    for module in ["notes", "tasks"] {
        assert_eq!(state(&states, module), AvailabilityState::Ready);
    }
    open.close().expect("close");
}

/// A file whose migration fails stops `failed migration` with its alert, and the events due to
/// its consumer stay; the other file serves. After a restart, a new bring-up under the same code
/// holds it without an alert or a migration.
#[test]
fn a_failed_migration_stops_its_file_and_is_held_after_a_restart() {
    let mut partitioned = partitioned("failed", "UPDATE tasks SET nothing = 1;");
    let states = ModuleStates::new();
    states.unlock_partition(&partitioned.registry, Partition::Household);
    let seen = RefCell::new(Vec::new());
    let probe = Probe {
        states: &states,
        tasks_file: partitioned.files[1].clone(),
        rekey_notes: false,
        fail_rekey: false,
        seen: &seen,
    };
    let (open, report) = run(&mut partitioned, &states, &probe);
    assert!(matches!(
        outcome(&report, "tasks"),
        FileOutcome::Migration(migration) if matches!(**migration, FileMigration::Failed { .. })
    ));
    assert_eq!(
        report.alerts,
        [InstanceAdminAlert::MigrationFailed {
            module: ModuleName::from_static("tasks"),
            partition: Partition::Household,
            file_name: "tasks.household.db".into(),
            track: MigrationTrack::Module,
            version: 2,
        }]
    );
    assert_eq!(state(&states, "tasks"), AvailabilityState::FailedMigration);
    assert_eq!(state(&states, "notes"), AvailabilityState::Ready);
    let delivered = report.deliveries[0].1.as_ref().expect("a delivery pass");
    assert!(matches!(
        delivered.deliveries[0].outcome,
        DeliveryOutcome::NotReady {
            state: AvailabilityState::FailedMigration
        }
    ));
    assert!(seen.borrow().is_empty(), "no consumer code ran");
    open.close().expect("close");

    let restarted = ModuleStates::new();
    restarted.unlock_partition(&partitioned.registry, Partition::Household);
    let probe = Probe {
        states: &restarted,
        tasks_file: partitioned.files[1].clone(),
        rekey_notes: false,
        fail_rekey: false,
        seen: &seen,
    };
    let (open, report) = run(&mut partitioned, &restarted, &probe);
    assert!(matches!(
        outcome(&report, "tasks"),
        FileOutcome::Migration(migration) if matches!(**migration, FileMigration::StillFailed { .. })
    ));
    assert!(
        report.alerts.is_empty(),
        "alerted once: {:?}",
        report.alerts
    );
    assert_eq!(
        restarted.state(&ModuleName::from_static("tasks"), Partition::Household),
        AvailabilityState::FailedMigration
    );
    assert_eq!(module_version(&partitioned.files[1]), 1);
    open.close().expect("close");
}

/// A re-key that fails leaves its file `re-keying`, retryable, untouched by migration; the other
/// file proceeds.
#[test]
fn a_failed_re_key_leaves_its_file_re_keying() {
    let mut partitioned = partitioned("rekey", "UPDATE tasks SET title = title;");
    let states = ModuleStates::new();
    states.unlock_partition(&partitioned.registry, Partition::Household);
    let seen = RefCell::new(Vec::new());
    let probe = Probe {
        states: &states,
        tasks_file: partitioned.files[1].clone(),
        rekey_notes: true,
        fail_rekey: true,
        seen: &seen,
    };
    let (open, report) = run(&mut partitioned, &states, &probe);
    assert!(matches!(
        outcome(&report, "notes"),
        FileOutcome::RekeyFailed(vilicus_storage::Error::WrongKey)
    ));
    assert_eq!(state(&states, "notes"), AvailabilityState::ReKeying);
    assert_eq!(state(&states, "tasks"), AvailabilityState::Ready);
    assert!(open.handle(&ModuleName::from_static("notes")).is_none());
    assert!(
        report
            .deliveries
            .iter()
            .all(|(module, _)| module.as_str() == "tasks")
    );
    open.close().expect("close");
}

/// A file newer than the code stops `newer than code` with its alert.
#[test]
fn a_file_newer_than_the_code_stops_newer_than_code() {
    let directory = scratch_dir("newer");
    let later = tasks("UPDATE tasks SET title = title;");
    let earlier = declare("tasks", TASKS, &[], &[], &[]);
    let registry = Registry::new(vec![earlier].leak()).expect("a valid registry");
    let file = new_file(&directory, later, Partition::Household, usize::MAX);
    let states = ModuleStates::new();
    states.unlock_partition(&registry, Partition::Household);
    let files = [file];
    let targets = targets(&files);
    let mut stamper = TestStamper::at(noon());
    let (open, report) = bring_up(
        &registry,
        &boundary(&states),
        Partition::Household,
        &targets,
        &mut NothingToRekey,
        Delivery {
            code: &mut NoConsumers,
            links: &mut NoLinks,
            stamper: &mut stamper,
        },
    )
    .expect("a bring-up");
    assert!(matches!(
        outcome(&report, "tasks"),
        FileOutcome::Migration(migration) if matches!(**migration, FileMigration::NewerThanCode { .. })
    ));
    assert!(matches!(
        report.alerts.as_slice(),
        [InstanceAdminAlert::NewerThanCode {
            found: 2,
            latest: 1,
            ..
        }]
    ));
    assert_eq!(state(&states, "tasks"), AvailabilityState::NewerThanCode);
    open.close().expect("close");
}

/// Consumer code that is never called.
struct NoConsumers;

impl ConsumerCode for NoConsumers {
    fn consume(
        &mut self,
        _: &'static ModuleDeclaration,
        _: &'static Consumer,
        _: &Event<'_>,
        _: &mut dyn Records,
    ) -> Result<(), WriteError> {
        panic!("no consumer runs");
    }
}

/// A file that needs more free space than its directory has does not migrate: it is `failed
/// migration` with an alert naming both sizes, not held, while a current file serves.
#[test]
fn a_file_without_the_space_to_migrate_is_not_served_and_not_held() {
    let mut partitioned = partitioned("space", "UPDATE tasks SET title = title;");
    let states = ModuleStates::new();
    states.unlock_partition(&partitioned.registry, Partition::Household);
    let targets = targets(&partitioned.files);
    let (open, report) = bring_up_with_space(
        &partitioned.registry,
        &boundary(&states),
        Partition::Household,
        &targets,
        &mut NothingToRekey,
        Delivery {
            code: &mut NoConsumers,
            links: &mut NoLinks,
            stamper: &mut partitioned.stamper,
        },
        &|_| Ok(0),
    )
    .expect("a bring-up");
    assert!(matches!(
        outcome(&report, "tasks"),
        FileOutcome::MigrationNotStarted(_)
    ));
    assert!(matches!(outcome(&report, "notes"), FileOutcome::Ready));
    assert!(matches!(
        report.alerts.as_slice(),
        [InstanceAdminAlert::NoSpaceToMigrate {
            available: 0,
            required,
            ..
        }] if *required > 0
    ));
    assert_eq!(state(&states, "tasks"), AvailabilityState::FailedMigration);
    assert_eq!(
        vilicus_storage::maintenance::failed_migration_mark(&partitioned.files[1]).expect("read"),
        None,
        "the host's state is not held"
    );
    open.close().expect("close");
}

/// A call of module code still running on a file (one that began before the partition was
/// locked) keeps the bring-up from migrating it: the file keeps its state, with an alert, and is
/// not touched.
#[test]
fn a_file_with_a_call_still_running_is_not_migrated() {
    let mut partitioned = partitioned("busy", "UPDATE tasks SET title = title;");
    let states = ModuleStates::new();
    let tasks = ModuleName::from_static("tasks");
    states
        .set_stage(&tasks, Partition::Household, Stage::Ready)
        .expect("no call runs");
    let ticket = states
        .begin_call(&tasks, Partition::Household, Duration::from_secs(5))
        .expect("ready");
    states.lock_partition(Partition::Household);
    states.unlock_partition(&partitioned.registry, Partition::Household);
    let targets = targets(&partitioned.files);
    let (open, report) = bring_up(
        &partitioned.registry,
        &boundary(&states),
        Partition::Household,
        &targets,
        &mut NothingToRekey,
        Delivery {
            code: &mut NoConsumers,
            links: &mut NoLinks,
            stamper: &mut partitioned.stamper,
        },
    )
    .expect("a bring-up");
    assert!(matches!(
        outcome(&report, "tasks"),
        FileOutcome::CallsInFlight(_)
    ));
    assert_eq!(
        report.alerts,
        [InstanceAdminAlert::FileNotServed {
            module: tasks.clone(),
            partition: Partition::Household,
            file_name: "tasks.household.db".into(),
        }]
    );
    assert_eq!(state(&states, "tasks"), AvailabilityState::Opening);
    assert_eq!(module_version(&partitioned.files[1]), 1);
    states.end_call(ticket);
    open.close().expect("close");
}

/// A bring-up takes the files of its partition and of registered modules only, or touches none.
#[test]
fn a_bring_up_takes_registered_files_of_its_partition_only() {
    let partitioned = partitioned("refused", "UPDATE tasks SET title = title;");
    let states = ModuleStates::new();
    let mut stamper = TestStamper::at(noon());
    let elsewhere = ModuleFile::new(
        partitioned.files[0].directory(),
        ModuleName::from_static("notes"),
        Partition::Member(ella()),
    );
    let unknown = ModuleFile::new(
        partitioned.files[0].directory(),
        ModuleName::from_static("meals"),
        Partition::Household,
    );
    for (file, error) in [
        (
            &elsewhere,
            BringUpError::OtherPartition(ModuleName::from_static("notes")),
        ),
        (
            &unknown,
            BringUpError::UnregisteredModule(ModuleName::from_static("meals")),
        ),
    ] {
        let given = [FileToMigrate {
            file,
            key: &KEY,
            verified_backup: None,
        }];
        let refused = bring_up(
            &partitioned.registry,
            &boundary(&states),
            Partition::Household,
            &given,
            &mut NothingToRekey,
            Delivery {
                code: &mut NoConsumers,
                links: &mut NoLinks,
                stamper: &mut stamper,
            },
        );
        assert_eq!(refused.map(drop).expect_err("refused"), error);
    }
}

/// The handles a bring-up opened are those it returns, closed on demand.
#[test]
fn the_ready_files_are_held_and_closed() {
    let mut partitioned = partitioned("held", "UPDATE tasks SET title = title;");
    let states = ModuleStates::new();
    states.unlock_partition(&partitioned.registry, Partition::Household);
    let targets = targets(&partitioned.files);
    let (open, report): (PartitionFiles, BringUpReport) = bring_up(
        &partitioned.registry,
        &boundary(&states),
        Partition::Household,
        &targets,
        &mut NothingToRekey,
        Delivery {
            code: &mut WriteTasks,
            links: &mut NoLinks,
            stamper: &mut partitioned.stamper,
        },
    )
    .expect("a bring-up");
    assert_eq!(open.partition(), Partition::Household);
    assert!(open.handle(&ModuleName::from_static("notes")).is_some());
    assert!(open.handle(&ModuleName::from_static("tasks")).is_some());
    assert_eq!(report.deliveries.len(), 2);
    assert!(format!("{open:?}").contains("tasks.household.db"));
    open.close().expect("close");
    for file in &partitioned.files {
        assert!(!file.wal_path().exists(), "{}", file.file_name());
    }
}

/// Consumer code that writes a task for each event.
struct WriteTasks;

impl ConsumerCode for WriteTasks {
    fn consume(
        &mut self,
        _: &'static ModuleDeclaration,
        _: &'static Consumer,
        event: &Event<'_>,
        records: &mut dyn Records,
    ) -> Result<(), WriteError> {
        records.insert(
            "tasks",
            &[("title", Value::Text("after".into()))],
            &[event.record],
        )?;
        Ok(())
    }
}
