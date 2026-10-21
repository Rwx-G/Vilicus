//! Story 3.8: the Core stamps an event's emitter and payload version and refuses a claim of
//! another emitter, the topic's access list decides its consumers, and consumers receive every
//! earlier version (AC1); a change and its event commit in one transaction and are delivered
//! after a crash once the files open again (AC2); delivery waits for the migrations, runs in
//! commit order per source file and consumer, and a second delivery produces no second effect
//! (AC3); five failures move an event to the dead letters with an alert and later events proceed
//! (AC4); a link is registered after the commit, in the partition that owns the data (AC5); and a
//! consumer's write is an `Event` call of the emitting call's id, author and inputs' taint, at
//! most tier 1, within its partition (AC6).
//!
//! Story 3.9: an event to a consumer in any state but `ready` stays without a failed attempt
//! (AC2), and is dead-lettered past the retention behind a lasting state (D150); a consumer that
//! panics or overruns its budget faults its module (AC4, AC5); the bound consumers of the handler
//! table are what the bus runs.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use vilicus_module_api::{
    Consumer, ConsumerHandler, DataType, Event, Field, FieldKind, ModuleCode, ModuleDeclaration,
    Records, Structured, Table, Topic, Value, WriteError,
};
use vilicus_storage::{
    DeliveryState, Handle, KeyEpoch, Migration, ModuleFile, OutboxState, Partition, SqlValue, Write,
};
use vilicus_types::{
    AvailabilityState, CallId, HANDLER_TIME_BUDGET, Id, ModuleName, OUTBOX_RETENTION, Principal,
    Source, Taint, UtcMillis,
};

use super::{
    ConsumerCode, ConsumerFiles, DeliveryError, DeliveryOutcome, DeliveryReport, FailureCause,
    Link, LinkOutcome, LinkTable, MAX_DELIVERY_ATTEMPTS, deliver_outbox, purge_expired_outbox,
};
use crate::alert::InstanceAdminAlert;
use crate::availability::{Fault, ModuleStates, MonotonicClock, Stage};
use crate::boundary::Boundary;
use crate::handlers::Handlers;
use crate::record::tests::{KEY, create_sql, noon, raw_connection, raw_rows, scratch_dir};
use crate::record::tests_call::{TestStamper, ella, member_id, noe};
use crate::record::{
    Authority, Call, CallResult, Consumed, Invocation, RecordError, RecordProvenance, Stamper,
    decode_inputs, run_call,
};
use crate::registry::{Registry, frozen, frozen_migrations};

const EPOCH: KeyEpoch = KeyEpoch {
    partition_root_version: 1,
    generation: 0,
};

const TITLE: &[Field] = &[
    Field {
        name: "title",
        kind: FieldKind::FreeText { max_len: 400 },
        optional: false,
    },
    Field {
        name: "status",
        kind: FieldKind::Structured(Structured::Enumeration(&["open", "done"])),
        optional: true,
    },
];

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

const PLANS: &[Table] = &[Table {
    name: "plans",
    data_types: &[DataType::Meals],
    fields: TITLE,
}];

const ADDED: &str = "notes.note.added";
const REMOVED: &str = "notes.note.removed";

const NOTE_TOPICS: &[Topic] = &[
    Topic {
        name: ADDED,
        version: 2,
        consumers: &["tasks", "meals"],
    },
    Topic {
        name: REMOVED,
        version: 1,
        consumers: &["tasks"],
    },
];

const NOTE_TOPICS_V1: &[Topic] = &[
    Topic {
        name: ADDED,
        version: 1,
        consumers: &["tasks", "meals"],
    },
    Topic {
        name: REMOVED,
        version: 1,
        consumers: &["tasks"],
    },
];

const TASK_CONSUMERS: &[Consumer] = &[
    Consumer {
        name: "react",
        topic: ADDED,
    },
    Consumer {
        name: "forget",
        topic: REMOVED,
    },
];

const MEAL_CONSUMERS: &[Consumer] = &[Consumer {
    name: "plan",
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

fn tasks() -> &'static ModuleDeclaration {
    declare("tasks", TASKS, &[], TASK_CONSUMERS, &[])
}

fn meals() -> &'static ModuleDeclaration {
    declare("meals", PLANS, &[], MEAL_CONSUMERS, &[])
}

fn registry(modules: Vec<&'static ModuleDeclaration>) -> Registry {
    Registry::new(modules.leak()).expect("a valid registry")
}

/// The module files of `modules` in `partition`, created under `directory` and migrated, opened
/// as the Core opens them.
fn partition_files(
    directory: &Path,
    partition: Partition,
    registry: &Registry,
) -> Vec<Handle<Write>> {
    registry
        .modules()
        .iter()
        .map(|&module| {
            let file = new_file(directory, module, partition, usize::MAX);
            registry.open::<Write>(&file, &KEY).expect("open")
        })
        .collect()
}

/// A new file of `module` in `partition`, migrated to `version` at most.
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

/// The files of one partition as the Core holds them: every handle, and the availability state
/// of each file, ready but for the modules locked.
struct Files {
    handles: Vec<Handle<Write>>,
    states: ModuleStates,
}

impl Files {
    fn new(handles: Vec<Handle<Write>>, locked: Vec<&'static str>) -> Self {
        Self::on_clock(handles, locked, ModuleStates::new())
    }

    /// The files of `handles`, their states held by `states`, ready but for the modules locked.
    fn on_clock(
        handles: Vec<Handle<Write>>,
        locked: Vec<&'static str>,
        states: ModuleStates,
    ) -> Self {
        for handle in &handles {
            if !locked.contains(&handle.file().module().as_str()) {
                states
                    .set_stage(
                        handle.file().module(),
                        handle.file().partition(),
                        Stage::Ready,
                    )
                    .expect("no call runs");
            }
        }
        Self { handles, states }
    }

    /// The boundary the files' calls run in.
    fn boundary(&self) -> Boundary<'_> {
        Boundary {
            states: &self.states,
            budget: HANDLER_TIME_BUDGET,
        }
    }

    fn of(&self, module: &str) -> &Handle<Write> {
        self.handles
            .iter()
            .find(|handle| handle.file().module().as_str() == module)
            .expect("a file of the module")
    }
}

impl ConsumerFiles for Files {
    fn open(&self, module: &ModuleName) -> Option<&Handle<Write>> {
        self.handles
            .iter()
            .find(|handle| handle.file().module() == module)
    }
}

/// Consumer code that inserts one record derived from the event, unless told to fail, panic,
/// request an effect or emit.
#[derive(Default)]
struct Code {
    /// Failures left for a consumer and an event.
    failures: HashMap<(String, Id), u32>,
    /// Fail by panicking rather than by returning an error.
    panics: bool,
    /// Write nothing.
    silent: bool,
    /// Request an outbound effect.
    effect: bool,
    /// Emit an event about the record written.
    emits: bool,
    /// Each delivery the code saw: the consumer, the event, its version, its emitter.
    seen: Vec<(String, Id, u32, String)>,
    /// A clock each delivery moves past the handler time budget.
    slow: Option<std::sync::Arc<Ticking>>,
}

impl ConsumerCode for Code {
    fn consume(
        &mut self,
        module: &'static ModuleDeclaration,
        consumer: &'static Consumer,
        event: &Event<'_>,
        records: &mut dyn Records,
    ) -> Result<(), WriteError> {
        let name = format!("{}.{}", module.name, consumer.name);
        self.seen.push((
            name.clone(),
            event.id,
            event.version,
            event.emitter.to_owned(),
        ));
        if let Some(left) = self.failures.get_mut(&(name, event.id))
            && *left > 0
        {
            *left -= 1;
            assert!(!self.panics, "the consumer fails");
            return Err(WriteError::Failed);
        }
        if let Some(clock) = &self.slow {
            clock.advance(HANDLER_TIME_BUDGET + Duration::from_millis(1));
        }
        if self.effect {
            records.request_effect("notify", b"key", b"")?;
        }
        if self.silent {
            return Ok(());
        }
        let written = records.insert(
            module.tables[0].name,
            &[("title", Value::Text(format!("after {}", event.topic)))],
            &[event.record],
        )?;
        if self.emits {
            records.emit(ADDED, written.id, b"")?;
        }
        Ok(())
    }
}

/// A link table that keeps what it registers and checks, at each registration, that the request
/// is committed in its source file: read through a connection of its own, which sees committed
/// rows only.
struct Links {
    source: ModuleFile,
    registered: Vec<Link>,
}

impl LinkTable for Links {
    fn register(&mut self, link: &Link) -> Result<(), vilicus_storage::Error> {
        let committed = raw_rows(
            &raw_connection(&self.source),
            &format!(
                "SELECT state FROM _outbox WHERE id = x'{}'",
                hex(&link.id.to_bytes())
            ),
        );
        assert_eq!(
            committed,
            [vec![SqlValue::Text("pending".into())]],
            "a link is registered after its request committed, never inside its transaction"
        );
        self.registered.push(link.clone());
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn no_links(files: &Files) -> Links {
    Links {
        source: files.of("notes").file().clone(),
        registered: Vec::new(),
    }
}

fn own_action(member: Id) -> Call {
    Call {
        principal: Principal::Member,
        source: Source::Member(member),
        session: Taint::Trusted,
        consumed: Consumed::NOTHING,
        authority: Authority::OwnAction { member },
        read: Vec::new(),
        implicit_inputs: Vec::new(),
    }
}

fn new_call_id(stamper: &mut TestStamper) -> CallId {
    let now = stamper.now();
    Id::new_v7(now, stamper.id_random())
        .expect("after the epoch")
        .into()
}

/// Runs `body` as `call` in `handle`'s file of `module`, under a new call id; returns the id and
/// what the call returned.
fn run<T>(
    handle: &Handle<Write>,
    module: &'static ModuleDeclaration,
    call: &Call,
    stamper: &mut TestStamper,
    body: impl FnOnce(&mut dyn Records) -> Result<T, WriteError>,
) -> (CallId, Result<CallResult<T>, RecordError>) {
    let call_id = new_call_id(stamper);
    let invocation = Invocation {
        call_id,
        request_hash: None,
        delivery: None,
    };
    (
        call_id,
        run_call(handle, module, call, &invocation, stamper, body),
    )
}

fn title(text: &str) -> Vec<(&'static str, Value)> {
    vec![("title", Value::Text(text.into()))]
}

/// Ella adds a note and emits `topic` about it; returns the note, the event and the call id.
fn add_note(
    handle: &Handle<Write>,
    module: &'static ModuleDeclaration,
    call: &Call,
    stamper: &mut TestStamper,
    topic: &str,
) -> (Id, Id, CallId) {
    let (call_id, result) = run(handle, module, call, stamper, |records| {
        let note = records.insert("notes", &title("Pommes"), &[])?;
        let event = records.emit(topic, note.id, b"payload")?;
        Ok((note.id, event))
    });
    match result.expect("the call commits") {
        CallResult::Committed(outcome) => (outcome.value.0, outcome.value.1, call_id),
        _ => panic!("a new call runs"),
    }
}

fn deliver(
    registry: &Registry,
    files: &Files,
    code: &mut Code,
    stamper: &mut TestStamper,
) -> DeliveryReport {
    let mut links = no_links(files);
    let report = deliver_outbox(
        registry,
        files.of("notes"),
        files,
        &files.boundary(),
        code,
        &mut links,
        stamper,
    )
    .expect("a delivery pass");
    assert!(links.registered.is_empty());
    report
}

/// What each delivery of a pass became, by consumer, in order.
fn outcomes(report: &DeliveryReport) -> Vec<(Id, &str, &'static str)> {
    report
        .deliveries
        .iter()
        .map(|delivery| {
            let outcome = match delivery.outcome {
                DeliveryOutcome::Delivered => "delivered",
                DeliveryOutcome::AlreadyConsumed => "already consumed",
                DeliveryOutcome::Failed { .. } => "failed",
                DeliveryOutcome::DeadLettered { .. } => "dead letter",
                DeliveryOutcome::NotReady { .. } => "not ready",
                DeliveryOutcome::Expired { .. } => "expired",
                DeliveryOutcome::Waiting => "waiting",
            };
            (delivery.event, delivery.consumer.as_str(), outcome)
        })
        .collect()
}

fn titles(handle: &Handle<Write>, table: &str) -> usize {
    handle
        .query_values(&format!("SELECT id FROM {table}"), &[])
        .expect("read")
        .len()
}

fn standard(label: &str) -> (Registry, Files, TestStamper) {
    let registry = registry(vec![notes(), tasks(), meals()]);
    let handles = partition_files(&scratch_dir(label), Partition::Household, &registry);
    (
        registry,
        Files::new(handles, Vec::new()),
        TestStamper::at(noon()),
    )
}

// AC1

#[test]
fn the_core_stamps_the_emitter_and_the_version_and_refuses_a_claim_of_another() {
    let (registry, files, mut stamper) = standard("emitter");
    let handle = files.of("notes");
    let (note, event, call_id) =
        add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
    let rows = handle.outbox_events().expect("read");
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!((row.id, row.record, row.call_id), (event, note, call_id));
    assert_eq!(
        (row.topic.as_str(), row.version),
        (ADDED, 2),
        "the version is the declaration's"
    );
    assert_eq!(
        (row.principal, row.author, row.member),
        (Principal::Member, Some(ella()), Some(ella()))
    );

    for (topic, foreign) in [
        ("tasks.task.added", true),
        ("meals.plan.added", true),
        ("notes.note.archived", false),
        ("notes", false),
    ] {
        let (_, result) = run(
            handle,
            notes(),
            &own_action(ella()),
            &mut stamper,
            |records| {
                let note = records.insert("notes", &title("Poires"), &[])?;
                records.emit(topic, note.id, b"")
            },
        );
        assert!(
            match result {
                Err(RecordError::ForeignTopic) => foreign,
                Err(RecordError::UnknownTopic) => !foreign,
                _ => false,
            },
            "{topic}"
        );
    }
    let (_, unchanged) = run(
        handle,
        notes(),
        &own_action(ella()),
        &mut stamper,
        |records| records.emit(ADDED, note, b""),
    );
    assert!(
        matches!(unchanged, Err(RecordError::UnchangedRecord)),
        "an event is about a record its call changed"
    );
    assert_eq!(
        handle.outbox_events().expect("read").len(),
        1,
        "every refused call rolled back"
    );
    assert_eq!(titles(handle, "notes"), 1);

    let mut code = Code::default();
    deliver(&registry, &files, &mut code, &mut stamper);
    assert!(
        code.seen
            .iter()
            .all(|(_, seen, version, emitter)| *seen == event
                && *version == 2
                && emitter == "notes"),
        "{:?}",
        code.seen
    );
}

#[test]
fn an_event_about_a_deleted_record_carries_its_provenance_as_of_the_delete() {
    let (registry, files, mut stamper) = standard("deleted");
    let handle = files.of("notes");
    let (note, _, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
    let (_, removed) = run(
        handle,
        notes(),
        &own_action(ella()),
        &mut stamper,
        |records| {
            records.delete("notes", note)?;
            records.emit(REMOVED, note, b"")
        },
    );
    assert!(matches!(removed, Ok(CallResult::Committed(_))));
    let mut code = Code::default();
    let report = deliver(&registry, &files, &mut code, &mut stamper);
    assert_eq!(report.closed.len(), 2);
    assert_eq!(titles(files.of("tasks"), "tasks"), 2, "react, then forget");
}

#[test]
fn per_topic_access_lists_decide_which_consumers_receive_an_event() {
    let (registry, files, mut stamper) = standard("acl");
    let handle = files.of("notes");
    let (_, added, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
    let (_, removed, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, REMOVED);
    let mut code = Code::default();
    let report = deliver(&registry, &files, &mut code, &mut stamper);
    assert_eq!(
        outcomes(&report),
        [
            (added, "tasks.react", "delivered"),
            (added, "meals.plan", "delivered"),
            (removed, "tasks.forget", "delivered"),
        ]
    );
    assert_eq!(report.closed, [added, removed]);
    assert_eq!(
        titles(files.of("meals"), "plans"),
        1,
        "meals is not on the list of removed"
    );
}

#[test]
fn consumers_receive_every_earlier_payload_version() {
    let before_upgrade = declare("notes", NOTES, NOTE_TOPICS_V1, &[], &[]);
    let (registry, files, mut stamper) = standard("versions");
    let handle = files.of("notes");
    let (_, old, _) = add_note(
        handle,
        before_upgrade,
        &own_action(ella()),
        &mut stamper,
        ADDED,
    );
    let (_, new, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
    let mut code = Code::default();
    let report = deliver(&registry, &files, &mut code, &mut stamper);
    assert_eq!(report.closed, [old, new]);
    let tasks_saw: Vec<(Id, u32)> = code
        .seen
        .iter()
        .filter(|(consumer, ..)| consumer == "tasks.react")
        .map(|(_, event, version, _)| (*event, *version))
        .collect();
    assert_eq!(
        tasks_saw,
        [(old, 1), (new, 2)],
        "a row written before the upgrade is delivered as written, then the newer one"
    );
}

// AC2

#[test]
fn a_change_and_its_event_commit_together_and_are_delivered_after_a_crash() {
    let directory = scratch_dir("crash");
    let registry = registry(vec![notes(), tasks(), meals()]);
    let mut stamper = TestStamper::at(noon());
    let handles = partition_files(&directory, Partition::Household, &registry);
    let notes_file = handles[0].file().clone();
    let handle = &handles[0];
    let (_, rolled_back) = run(
        handle,
        notes(),
        &own_action(ella()),
        &mut stamper,
        |records| {
            let note = records.insert("notes", &title("Pommes"), &[])?;
            records.emit(ADDED, note.id, b"")?;
            Err::<(), _>(WriteError::Failed)
        },
    );
    assert!(rolled_back.is_err());
    assert_eq!(titles(handle, "notes"), 0);
    assert!(
        handle.outbox_events().expect("read").is_empty(),
        "the event went with its change"
    );

    let (note, event, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
    let committed = raw_rows(
        &raw_connection(&notes_file),
        "SELECT count(*) FROM notes UNION ALL SELECT count(*) FROM _outbox WHERE kind = 'event'",
    );
    assert_eq!(
        committed,
        [vec![SqlValue::Integer(1)], vec![SqlValue::Integer(1)]],
        "the change and its row are in the one file"
    );

    let files = Files::new(handles, vec!["tasks", "meals"]);
    let mut code = Code::default();
    let locked = deliver(&registry, &files, &mut code, &mut stamper);
    assert_eq!(
        outcomes(&locked),
        [
            (event, "tasks.react", "not ready"),
            (event, "meals.plan", "not ready")
        ]
    );
    assert!(code.seen.is_empty());
    assert_eq!(
        files
            .of("notes")
            .delivery(event, "tasks.react")
            .expect("read"),
        None,
        "a locked consumer is not a failure"
    );
    drop(files);

    let handles: Vec<Handle<Write>> = registry
        .modules()
        .iter()
        .map(|module| {
            let file = ModuleFile::new(
                &directory,
                ModuleName::from_static(module.name),
                Partition::Household,
            );
            registry.open::<Write>(&file, &KEY).expect("open again")
        })
        .collect();
    let files = Files::new(handles, Vec::new());
    let report = deliver(&registry, &files, &mut code, &mut stamper);
    assert_eq!(report.closed, [event]);
    assert_eq!(titles(files.of("tasks"), "tasks"), 1);
    assert_eq!(titles(files.of("meals"), "plans"), 1);
    let rows = files.of("notes").outbox_events().expect("read");
    assert_eq!(
        (rows[0].record, rows[0].state),
        (note, OutboxState::Delivered)
    );
}

// AC3

#[test]
fn delivery_waits_for_the_migrations_of_the_source_and_the_consumer() {
    let directory = scratch_dir("migrations");
    let notes = declare(
        "notes",
        NOTES,
        NOTE_TOPICS,
        &[],
        &["UPDATE notes SET status = status;"],
    );
    let tasks = declare(
        "tasks",
        TASKS,
        &[],
        TASK_CONSUMERS,
        &["UPDATE tasks SET status = status;"],
    );
    let registry = registry(vec![notes, tasks]);
    let mut stamper = TestStamper::at(noon());
    let notes_file = new_file(&directory, notes, Partition::Household, 1);
    let tasks_file = new_file(&directory, tasks, Partition::Household, 1);
    let source = vilicus_storage::open::<Write>(&notes_file, &KEY).expect("open");
    let (_, event, _) = add_note(&source, notes, &own_action(ella()), &mut stamper, ADDED);
    let files = Files::new(
        vec![vilicus_storage::open::<Write>(&tasks_file, &KEY).expect("open")],
        Vec::new(),
    );
    let mut code = Code::default();
    let mut links = Links {
        source: notes_file.clone(),
        registered: Vec::new(),
    };
    let refused = deliver_outbox(
        &registry,
        &source,
        &files,
        &files.boundary(),
        &mut code,
        &mut links,
        &mut stamper,
    );
    assert!(matches!(
        refused,
        Err(DeliveryError::NotMigrated {
            track: vilicus_storage::MigrationTrack::Module,
            found: 1,
            latest: 2
        })
    ));
    drop(source);
    let migrate = |file: &ModuleFile, module| {
        let mut migration = vilicus_storage::open::<Migration>(file, &KEY).expect("open");
        migration
            .apply_module_migrations(&frozen_migrations(module).expect("frozen"))
            .expect("migrate");
        migration.close().expect("close");
    };
    migrate(&notes_file, notes);
    let source = registry.open::<Write>(&notes_file, &KEY).expect("open");
    let waiting = deliver_outbox(
        &registry,
        &source,
        &files,
        &files.boundary(),
        &mut code,
        &mut links,
        &mut stamper,
    )
    .expect("a pass");
    assert_eq!(outcomes(&waiting), [(event, "tasks.react", "not ready")]);
    drop(files);
    migrate(&tasks_file, tasks);
    let files = Files::new(
        vec![registry.open::<Write>(&tasks_file, &KEY).expect("open")],
        Vec::new(),
    );
    let delivered = deliver_outbox(
        &registry,
        &source,
        &files,
        &files.boundary(),
        &mut code,
        &mut links,
        &mut stamper,
    )
    .expect("a pass");
    assert_eq!(outcomes(&delivered), [(event, "tasks.react", "delivered")]);
}

#[test]
fn events_are_delivered_in_commit_order_per_source_file_and_consumer() {
    let (registry, files, mut stamper) = standard("order");
    let handle = files.of("notes");
    let events: Vec<Id> = (0..3)
        .map(|_| add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED).1)
        .collect();
    let mut code = Code::default();
    code.failures.insert(("tasks.react".into(), events[0]), 1);
    let first = deliver(&registry, &files, &mut code, &mut stamper);
    assert_eq!(
        outcomes(&first),
        [
            (events[0], "tasks.react", "failed"),
            (events[0], "meals.plan", "delivered"),
            (events[1], "tasks.react", "waiting"),
            (events[1], "meals.plan", "delivered"),
            (events[2], "tasks.react", "waiting"),
            (events[2], "meals.plan", "delivered"),
        ],
        "one consumer's failure holds back that consumer only"
    );
    assert!(first.closed.is_empty());
    let second = deliver(&registry, &files, &mut code, &mut stamper);
    assert_eq!(
        outcomes(&second),
        [
            (events[0], "tasks.react", "delivered"),
            (events[1], "tasks.react", "delivered"),
            (events[2], "tasks.react", "delivered"),
        ]
    );
    assert_eq!(second.closed, events);
    let order = |consumer: &str| -> Vec<Id> {
        code.seen
            .iter()
            .filter(|(seen, ..)| seen == consumer)
            .map(|(_, event, ..)| *event)
            .collect()
    };
    assert_eq!(
        order("tasks.react"),
        [events[0], events[0], events[1], events[2]]
    );
    assert_eq!(order("meals.plan"), events);
    assert!(
        deliver(&registry, &files, &mut code, &mut stamper)
            .deliveries
            .is_empty()
    );
}

#[test]
fn a_consumer_processing_an_event_twice_produces_one_effect() {
    for silent in [false, true] {
        let (registry, files, mut stamper) = standard(&format!("twice-{silent}"));
        let handle = files.of("notes");
        let (_, event, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
        let mut code = Code {
            silent,
            ..Code::default()
        };
        let first = deliver(&registry, &files, &mut code, &mut stamper);
        assert_eq!(first.closed, [event]);
        // A crash after the consumers committed and before the source recorded it: the source
        // still holds the event pending, with no delivery recorded.
        raw_connection(handle.file())
            .execute_batch(
                "DELETE FROM _deliveries; UPDATE _outbox SET state = 'pending' WHERE kind = 'event';",
            )
            .expect("forget the deliveries");
        let again = deliver(&registry, &files, &mut code, &mut stamper);
        assert_eq!(
            outcomes(&again),
            [
                (event, "tasks.react", "already consumed"),
                (event, "meals.plan", "already consumed")
            ],
            "silent consumer: {silent}"
        );
        assert_eq!(again.closed, [event]);
        let expected = usize::from(!silent);
        assert_eq!(titles(files.of("tasks"), "tasks"), expected);
        assert_eq!(titles(files.of("meals"), "plans"), expected);
        assert_eq!(
            code.seen.len(),
            2,
            "the second delivery ran no consumer code"
        );
        for module in ["tasks", "meals"] {
            let consumed = raw_rows(
                &raw_connection(files.of(module).file()),
                "SELECT count(*) FROM _consumed",
            );
            assert_eq!(consumed, [vec![SqlValue::Integer(1)]]);
        }
    }
}

// AC4

#[test]
fn a_consumer_failing_an_event_five_times_dead_letters_it_and_later_events_proceed() {
    let (registry, files, mut stamper) = standard("dead");
    let handle = files.of("notes");
    let (_, failing, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
    let (_, later, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
    let mut code = Code::default();
    code.failures
        .insert(("tasks.react".into(), failing), u32::MAX);
    for attempt in 1..MAX_DELIVERY_ATTEMPTS {
        let report = deliver(&registry, &files, &mut code, &mut stamper);
        let tasks: Vec<_> = report
            .deliveries
            .iter()
            .filter(|delivery| delivery.consumer == "tasks.react")
            .collect();
        assert!(
            matches!(
                &tasks[0].outcome,
                DeliveryOutcome::Failed { attempts, cause }
                    if *attempts == attempt
                        && matches!(cause, FailureCause::Refused(RecordError::Aborted(_)))
            ),
            "{:?}",
            tasks[0].outcome
        );
        assert!(matches!(tasks[1].outcome, DeliveryOutcome::Waiting));
        assert!(report.alerts.is_empty());
    }
    let last = deliver(&registry, &files, &mut code, &mut stamper);
    let letters = handle.dead_letters().expect("read");
    assert_eq!(letters.len(), 1);
    let letter = &letters[0];
    assert_eq!(
        (letter.event, letter.consumer.as_str(), letter.attempts),
        (failing, "tasks.react", MAX_DELIVERY_ATTEMPTS)
    );
    assert_eq!(
        outcomes(&last),
        [
            (failing, "tasks.react", "dead letter"),
            (later, "tasks.react", "delivered"),
        ],
        "the later event proceeds in the same pass"
    );
    assert_eq!(
        last.alerts,
        [InstanceAdminAlert::DeadLetter {
            module: ModuleName::from_static("notes"),
            partition: Partition::Household,
            file_name: "notes.household.db".into(),
            dead_letter: letter.id,
            event: failing,
            topic: ADDED.into(),
            consumer: "tasks.react".into(),
        }]
    );
    assert_eq!(
        last.closed,
        [failing, later],
        "a dead letter closes its delivery"
    );
    assert_eq!(
        handle
            .delivery(failing, "tasks.react")
            .expect("read")
            .map(|d| d.state),
        Some(DeliveryState::DeadLetter)
    );
    assert_eq!(
        titles(files.of("tasks"), "tasks"),
        1,
        "the consumer tolerates the gap"
    );
    assert!(
        deliver(&registry, &files, &mut code, &mut stamper)
            .deliveries
            .is_empty()
    );
}

// AC5

#[test]
fn a_link_is_registered_after_the_commit_in_the_partition_that_owns_the_data() {
    let directory = scratch_dir("links");
    let registry = registry(vec![notes(), tasks(), meals()]);
    let mut stamper = TestStamper::at(noon());
    let files = Files::new(
        partition_files(&directory, Partition::Household, &registry),
        Vec::new(),
    );
    let elsewhere = Files::new(
        partition_files(&directory, Partition::Member(ella()), &registry),
        Vec::new(),
    );
    let insert_task = |handle: &Handle<Write>, stamper: &mut TestStamper| {
        let (_, result) = run(handle, tasks(), &own_action(ella()), stamper, |records| {
            records.insert("tasks", &title("Courses"), &[])
        });
        match result.expect("commits") {
            CallResult::Committed(outcome) => outcome.value.id,
            _ => panic!("a new call"),
        }
    };
    let here = insert_task(files.of("tasks"), &mut stamper);
    let there = insert_task(elsewhere.of("tasks"), &mut stamper);
    let source = files.of("notes");
    let request = |target_module: &'static str, target: Id, stamper: &mut TestStamper| {
        run(source, notes(), &own_action(ella()), stamper, |records| {
            let note = records.insert("notes", &title("Pommes"), &[])?;
            records.request_link(note.id, target_module, target)
        })
    };
    let (_, own) = request("notes", here, &mut stamper);
    assert!(matches!(own, Err(RecordError::InvalidLink)));
    let (_, invalid) = request("Tasks", here, &mut stamper);
    assert!(matches!(invalid, Err(RecordError::InvalidLink)));
    let (_, unchanged) = run(
        source,
        notes(),
        &own_action(ella()),
        &mut stamper,
        |records| records.request_link(here, "tasks", here),
    );
    assert!(matches!(unchanged, Err(RecordError::UnchangedRecord)));
    let link_of = |result: Result<CallResult<Id>, RecordError>| match result.expect("commits") {
        CallResult::Committed(outcome) => outcome.value,
        _ => panic!("a new call"),
    };
    let registered = link_of(request("tasks", here, &mut stamper).1);
    let crossing = link_of(request("tasks", there, &mut stamper).1);
    let unregistered = link_of(request("budget", here, &mut stamper).1);
    let waiting = link_of(request("meals", here, &mut stamper).1);
    assert!(
        source.outbox_links().expect("read").len() == 4,
        "the requests committed with their notes; refused calls left none"
    );

    let mut table = Links {
        source: source.file().clone(),
        registered: Vec::new(),
    };
    let locked_meals = Files::new(files.handles, vec!["meals"]);
    let mut code = Code::default();
    let report = deliver_outbox(
        &registry,
        locked_meals.of("notes"),
        &locked_meals,
        &locked_meals.boundary(),
        &mut code,
        &mut table,
        &mut stamper,
    )
    .expect("a pass");
    assert_eq!(
        report.links,
        [
            (registered, LinkOutcome::Registered),
            (crossing, LinkOutcome::Refused),
            (unregistered, LinkOutcome::Refused),
            (waiting, LinkOutcome::TargetNotReady),
        ]
    );
    let note_of_registered = locked_meals
        .of("notes")
        .outbox_links()
        .expect("read")
        .into_iter()
        .find(|link| link.id == registered)
        .expect("the request")
        .record;
    assert_eq!(
        table.registered,
        [Link {
            id: registered,
            partition: Partition::Household,
            module: ModuleName::from_static("notes"),
            record: note_of_registered,
            target_module: ModuleName::from_static("tasks"),
            target: here,
        }],
        "the link of a record of another partition is never registered"
    );
    assert_eq!(
        report.alerts,
        [
            InstanceAdminAlert::link_refused(locked_meals.of("notes").file(), crossing, "tasks"),
            InstanceAdminAlert::link_refused(
                locked_meals.of("notes").file(),
                unregistered,
                "budget"
            ),
        ]
    );
    let states: Vec<(Id, OutboxState)> = locked_meals
        .of("notes")
        .outbox_links()
        .expect("read")
        .into_iter()
        .map(|link| (link.id, link.state))
        .collect();
    assert_eq!(
        states,
        [
            (registered, OutboxState::Delivered),
            (crossing, OutboxState::Refused),
            (unregistered, OutboxState::Refused),
            (waiting, OutboxState::Pending),
        ]
    );
    let unlocked = Files::new(locked_meals.handles, Vec::new());
    let report = deliver_outbox(
        &registry,
        unlocked.of("notes"),
        &unlocked,
        &unlocked.boundary(),
        &mut code,
        &mut table,
        &mut stamper,
    )
    .expect("a pass");
    assert_eq!(
        report.links,
        [(waiting, LinkOutcome::Refused)],
        "a task id is no record of meals"
    );
    assert_eq!(table.registered.len(), 1);
}

// AC6

/// The journal rows of `table`'s file: principal, `source`, call id and the inputs of each.
fn journal(handle: &Handle<Write>) -> Vec<(String, String, Vec<u8>, Vec<u8>)> {
    raw_rows(
        &raw_connection(handle.file()),
        "SELECT principal, source, call_id, inputs FROM _journal ORDER BY seq",
    )
    .into_iter()
    .map(|row| match row.as_slice() {
        [
            SqlValue::Text(principal),
            SqlValue::Text(source),
            SqlValue::Blob(call_id),
            SqlValue::Blob(inputs),
        ] => (
            principal.clone(),
            source.clone(),
            call_id.clone(),
            inputs.clone(),
        ),
        other => panic!("a journal row: {other:?}"),
    })
    .collect()
}

fn stored(handle: &Handle<Write>, table: &str) -> Vec<(String, String, Option<Vec<u8>>)> {
    handle
        .query_values(
            &format!("SELECT taint, text_taint, author FROM {table}"),
            &[],
        )
        .expect("read")
        .into_iter()
        .map(|row| match row.as_slice() {
            [SqlValue::Text(taint), SqlValue::Text(text), author] => (
                taint.clone(),
                text.clone(),
                match author {
                    SqlValue::Blob(bytes) => Some(bytes.clone()),
                    _ => None,
                },
            ),
            other => panic!("a row: {other:?}"),
        })
        .collect()
}

#[test]
fn a_consumers_write_is_an_event_call_of_the_emitting_call_its_author_and_inputs_taint() {
    let (registry, files, mut stamper) = standard("event-call");
    let handle = files.of("notes");
    let (note, event, call_id) =
        add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
    let plugin = Call {
        principal: Principal::Plugin,
        source: Source::Plugin(member_id(40)),
        session: Taint::Trusted,
        consumed: Consumed::NOTHING,
        authority: Authority::Unapproved {
            author: None,
            acting_for: Some(noe()),
        },
        read: Vec::new(),
        implicit_inputs: Vec::new(),
    };
    let (external_note, external_event, _) =
        add_note(handle, notes(), &plugin, &mut stamper, ADDED);
    let mut code = Code::default();
    let report = deliver(&registry, &files, &mut code, &mut stamper);
    assert_eq!(report.closed, [event, external_event]);

    let tasks_file = files.of("tasks");
    let rows = journal(tasks_file);
    assert_eq!(rows.len(), 2);
    let (principal, source, journaled_call, inputs) = &rows[0];
    assert_eq!(principal, "Event");
    assert_eq!(source, &Source::Event(event).to_string());
    assert_eq!(
        journaled_call.as_slice(),
        call_id.to_bytes(),
        "the emitting call's id"
    );
    let inputs = decode_inputs(inputs).expect("decode");
    assert_eq!(inputs.len(), 1);
    assert_eq!(
        (inputs[0].id, inputs[0].implicit),
        (note, true),
        "the emitting record"
    );
    assert_eq!(inputs[0].taint, "trusted");
    let external_inputs = decode_inputs(&rows[1].3).expect("decode");
    assert_eq!(
        (external_inputs[0].id, external_inputs[0].taint.as_str()),
        (external_note, "external")
    );
    assert_eq!(
        stored(tasks_file, "tasks"),
        [
            (
                "trusted".into(),
                "trusted".into(),
                Some(ella().to_bytes().to_vec())
            ),
            ("external".into(), "external".into(), None),
        ],
        "the emitting call's author, and the most restrictive taint of the inputs"
    );

    add_note(handle, notes(), &own_action(noe()), &mut stamper, ADDED);
    deliver(&registry, &files, &mut code, &mut stamper);
    assert_eq!(
        stored(tasks_file, "tasks")[2],
        (
            "trusted".into(),
            "trusted".into(),
            Some(noe().to_bytes().to_vec())
        ),
        "a consumer acts for the emitting call's member, who sees their own record trusted"
    );
}

#[test]
fn a_consumer_requests_no_effect_and_emits_no_event() {
    for (effect, emits) in [(true, false), (false, true)] {
        let (registry, files, mut stamper) = standard(&format!("tier-{effect}"));
        let handle = files.of("notes");
        let (_, event, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
        let mut code = Code {
            effect,
            emits,
            ..Code::default()
        };
        let report = deliver(&registry, &files, &mut code, &mut stamper);
        for delivery in &report.deliveries {
            assert!(
                matches!(
                    &delivery.outcome,
                    DeliveryOutcome::Failed {
                        cause: FailureCause::Refused(RecordError::NotInConsumer),
                        ..
                    }
                ),
                "{event}: {:?}",
                delivery.outcome
            );
        }
        for module in ["tasks", "meals"] {
            let file = files.of(module);
            assert!(
                file.effects_in_state(vilicus_storage::EffectState::Pending)
                    .expect("read")
                    .is_empty()
            );
            assert!(file.outbox_events().expect("read").is_empty());
        }
    }
}

#[test]
fn no_event_is_delivered_outside_its_source_partition() {
    let directory = scratch_dir("partitions");
    let registry = registry(vec![notes(), tasks(), meals()]);
    let mut stamper = TestStamper::at(noon());
    let household = Files::new(
        partition_files(&directory, Partition::Household, &registry),
        Vec::new(),
    );
    let personal = Files::new(
        partition_files(&directory, Partition::Member(ella()), &registry),
        Vec::new(),
    );
    let (_, household_event, _) = add_note(
        household.of("notes"),
        notes(),
        &own_action(ella()),
        &mut stamper,
        ADDED,
    );
    let (_, personal_event, _) = add_note(
        personal.of("notes"),
        notes(),
        &own_action(ella()),
        &mut stamper,
        ADDED,
    );

    /// Files that offer the consumers of another partition.
    struct Mixed<'a> {
        source: &'a Files,
        consumers: &'a Files,
    }
    impl ConsumerFiles for Mixed<'_> {
        fn open(&self, module: &ModuleName) -> Option<&Handle<Write>> {
            if module.as_str() == "notes" {
                self.source.open(module)
            } else {
                self.consumers.open(module)
            }
        }
    }
    let mut code = Code::default();
    let mut links = no_links(&household);
    let mixed = Mixed {
        source: &household,
        consumers: &personal,
    };
    let crossing = deliver_outbox(
        &registry,
        household.of("notes"),
        &mixed,
        &household.boundary(),
        &mut code,
        &mut links,
        &mut stamper,
    );
    assert!(matches!(
        crossing,
        Err(DeliveryError::CrossPartition { module }) if module.as_str() == "tasks"
    ));
    assert!(code.seen.is_empty());
    assert_eq!(titles(personal.of("tasks"), "tasks"), 0);

    /// Files that offer another module's file for every consumer.
    struct Wrong<'a>(&'a Files);
    impl ConsumerFiles for Wrong<'_> {
        fn open(&self, _: &ModuleName) -> Option<&Handle<Write>> {
            Some(self.0.of("meals"))
        }
    }
    let wrong = deliver_outbox(
        &registry,
        household.of("notes"),
        &Wrong(&household),
        &household.boundary(),
        &mut code,
        &mut links,
        &mut stamper,
    );
    assert!(matches!(
        wrong,
        Err(DeliveryError::WrongModule { module }) if module.as_str() == "tasks"
    ));

    let report = deliver(&registry, &household, &mut code, &mut stamper);
    assert_eq!(report.closed, [household_event]);
    assert_eq!(titles(household.of("tasks"), "tasks"), 1);
    assert_eq!(
        titles(personal.of("tasks"), "tasks"),
        0,
        "nothing reached the other partition"
    );
    assert_eq!(
        personal
            .of("notes")
            .pending_outbox(0, 100)
            .expect("read")
            .len(),
        1,
        "{personal_event} waits for its own partition's pass"
    );
    let report = deliver_outbox(
        &registry,
        personal.of("notes"),
        &personal,
        &personal.boundary(),
        &mut code,
        &mut no_links(&personal),
        &mut stamper,
    )
    .expect("a pass");
    assert_eq!(report.closed, [personal_event]);
    assert_eq!(titles(personal.of("tasks"), "tasks"), 1);
    assert_eq!(titles(household.of("tasks"), "tasks"), 1);
}

// The outbox's retention (AD-26).

#[test]
fn the_outbox_keeps_a_delivered_event_for_its_retention_period() {
    let (registry, files, mut stamper) = standard("retention");
    let handle = files.of("notes");
    let (_, event, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
    deliver(&registry, &files, &mut Code::default(), &mut stamper);
    let day = 24 * 60 * 60 * 1000;
    let at = |days: i64| UtcMillis::from_millis(noon().as_millis() + days * day).expect("in range");
    assert_eq!(
        purge_expired_outbox(handle, at(29)).expect("purge").deleted,
        0
    );
    let ids = |handle: &Handle<Write>| -> Vec<Id> {
        handle
            .outbox_events()
            .expect("read")
            .into_iter()
            .map(|event| event.id)
            .collect()
    };
    assert_eq!(ids(handle), [event]);
    let purge = purge_expired_outbox(handle, at(31)).expect("purge");
    assert_eq!(purge.deleted, 3, "the event and its two deliveries");
    assert!(ids(handle).is_empty());
}

/// An event's snapshot of its record holds the record's data types and none of its free text.
#[test]
fn an_events_snapshot_holds_the_records_data_types() {
    let (_, files, mut stamper) = standard("snapshot");
    let handle = files.of("notes");
    add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
    let row = &handle.outbox_events().expect("read")[0];
    let snapshot: RecordProvenance =
        crate::record::decode_provenance(&row.provenance).expect("decode");
    assert_eq!(snapshot.data_types, [DataType::Meals]);
    assert!(
        snapshot.free_text.is_empty(),
        "no free text leaves the record"
    );
}

/// An event whose row does not decode, in any column the delivery reads, fails each delivery
/// without running the consumer and ends in the dead letters: it never stops the pass, nor hides
/// the events after it, which would block the partition's outbox.
#[test]
fn a_malformed_event_fails_its_deliveries_rather_than_block_the_outbox() {
    for damage in [
        "provenance = x'00'",
        "version = NULL",
        "call_id = x'00'",
        "principal = 'Nobody'",
        "record_id = NULL",
        "author = x'01'",
        "created_at = -9000000000000000000",
    ] {
        let (registry, files, mut stamper) = standard("malformed");
        let handle = files.of("notes");
        let (_, broken, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
        let (_, sound, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
        raw_connection(handle.file())
            .execute_batch(&format!(
                "UPDATE _outbox SET {damage} WHERE id = x'{}'",
                hex(&broken.to_bytes())
            ))
            .unwrap_or_else(|error| panic!("{damage}: {error}"));
        let mut code = Code::default();
        let first = deliver(&registry, &files, &mut code, &mut stamper);
        let broken_outcomes: Vec<_> = first
            .deliveries
            .iter()
            .filter(|delivery| delivery.event == broken)
            .collect();
        assert_eq!(broken_outcomes.len(), 2, "{damage}");
        assert!(
            broken_outcomes.iter().all(|delivery| matches!(
                delivery.outcome,
                DeliveryOutcome::Failed {
                    cause: FailureCause::Malformed,
                    attempts: 1
                }
            )),
            "{damage}: {broken_outcomes:?}"
        );
        for _ in 1..MAX_DELIVERY_ATTEMPTS {
            deliver(&registry, &files, &mut code, &mut stamper);
        }
        assert_eq!(
            handle.dead_letters().expect("read").len(),
            2,
            "{damage}: one per consumer"
        );
        assert!(
            handle.pending_outbox(0, 100).expect("read").is_empty(),
            "{damage}"
        );
        assert!(
            code.seen.iter().all(|(_, event, ..)| *event == sound),
            "{damage}: no consumer code ran on the damaged event"
        );
        assert_eq!(titles(files.of("tasks"), "tasks"), 1, "{damage}");
    }
}

/// A row of the outbox whose id does not decode cannot have its deliveries recorded: it is
/// refused at once with an alert, and the rows after it are delivered.
#[test]
fn a_row_no_id_names_is_refused_and_the_rows_after_it_proceed() {
    let (registry, files, mut stamper) = standard("no-id");
    let handle = files.of("notes");
    let (_, broken, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
    let (_, sound, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
    let seq = handle.outbox_events().expect("read")[0].seq;
    raw_connection(handle.file())
        .execute_batch(&format!(
            "UPDATE _outbox SET id = x'00' WHERE id = x'{}'",
            hex(&broken.to_bytes())
        ))
        .expect("damage the id");
    let report = deliver(&registry, &files, &mut Code::default(), &mut stamper);
    assert_eq!(report.closed, [sound]);
    assert_eq!(
        report.alerts,
        [InstanceAdminAlert::malformed_outbox_row(handle.file(), seq)]
    );
    assert!(handle.pending_outbox(0, 100).expect("read").is_empty());
}

/// A pass reads the outbox a page at a time and delivers every page, in commit order.
#[test]
fn a_pass_delivers_an_outbox_longer_than_a_page() {
    let (registry, files, mut stamper) = standard("pages");
    let handle = files.of("notes");
    let count = usize::try_from(super::OUTBOX_PAGE).expect("small") + 3;
    let (call_id, result) = run(
        handle,
        notes(),
        &own_action(ella()),
        &mut stamper,
        |records| {
            let mut events = Vec::new();
            for _ in 0..count {
                let note = records.insert("notes", &title("Pommes"), &[])?;
                events.push(records.emit(ADDED, note.id, b"")?);
            }
            Ok(events)
        },
    );
    let _ = call_id;
    let events = match result.expect("commits") {
        CallResult::Committed(outcome) => outcome.value,
        _ => panic!("a new call"),
    };
    let mut code = Code {
        silent: true,
        ..Code::default()
    };
    let report = deliver(&registry, &files, &mut code, &mut stamper);
    assert_eq!(report.closed, events);
    let tasks_order: Vec<Id> = code
        .seen
        .iter()
        .filter(|(consumer, ..)| consumer == "tasks.react")
        .map(|(_, event, ..)| *event)
        .collect();
    assert_eq!(tasks_order, events);
}

/// A payload longer than the bound is refused, and the call with it.
#[test]
fn an_event_payload_longer_than_the_bound_is_refused() {
    let (_, files, mut stamper) = standard("payload");
    let handle = files.of("notes");
    for (length, accepted) in [
        (vilicus_module_api::EVENT_PAYLOAD_MAX_LEN, true),
        (vilicus_module_api::EVENT_PAYLOAD_MAX_LEN + 1, false),
    ] {
        let payload = vec![0x5a; length];
        let (_, result) = run(
            handle,
            notes(),
            &own_action(ella()),
            &mut stamper,
            |records| {
                let note = records.insert("notes", &title("Pommes"), &[])?;
                records.emit(ADDED, note.id, &payload)
            },
        );
        assert_eq!(
            matches!(result, Ok(CallResult::Committed(_))),
            accepted,
            "{length}"
        );
        if !accepted {
            assert!(matches!(result, Err(RecordError::PayloadTooLong)));
        }
    }
    assert_eq!(handle.outbox_events().expect("read").len(), 1);
    assert_eq!(titles(handle, "notes"), 1);
}

/// An event about a record carries the taint of its emitting call as well as the record's: a
/// plugin deleting a trusted note emits an event whose consumers' writes are `external` (D20),
/// though the note it is about was `trusted`.
#[test]
fn an_event_carries_the_taint_of_its_emitting_call() {
    let (registry, files, mut stamper) = standard("emitting-taint");
    let handle = files.of("notes");
    let (note, _, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
    let plugin = Call {
        principal: Principal::Plugin,
        source: Source::Plugin(member_id(40)),
        session: Taint::Trusted,
        consumed: Consumed::NOTHING,
        authority: Authority::Unapproved {
            author: None,
            acting_for: Some(ella()),
        },
        read: Vec::new(),
        implicit_inputs: Vec::new(),
    };
    let (_, removed) = run(handle, notes(), &plugin, &mut stamper, |records| {
        records.delete("notes", note)?;
        records.emit(REMOVED, note, b"")
    });
    assert!(matches!(removed, Ok(CallResult::Committed(_))));
    deliver(&registry, &files, &mut Code::default(), &mut stamper);
    let tasks_file = files.of("tasks");
    assert_eq!(
        stored(tasks_file, "tasks")
            .into_iter()
            .map(|(taint, ..)| taint)
            .collect::<Vec<_>>(),
        ["trusted", "external"],
        "Ella's note, then the plugin's deletion of it"
    );
}

/// An AI task that read health data and deletes a note emits an event whose snapshot holds the
/// data types the session consumed, as every write of the task holds them (AD-7, D103).
#[test]
fn an_event_of_an_ai_session_holds_the_data_types_it_consumed() {
    let (_, files, mut stamper) = standard("consumed-types");
    let handle = files.of("notes");
    let (note, _, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
    let task = Call {
        principal: Principal::AiTask,
        source: Source::AiTask(member_id(41)),
        session: Taint::Trusted,
        consumed: Consumed {
            data_types: vec![DataType::Health],
            taint: vilicus_types::EffectiveTaint::Trusted,
        },
        authority: Authority::Unapproved {
            author: Some(ella()),
            acting_for: Some(ella()),
        },
        read: Vec::new(),
        implicit_inputs: Vec::new(),
    };
    let (_, removed) = run(handle, notes(), &task, &mut stamper, |records| {
        records.delete("notes", note)?;
        records.emit(REMOVED, note, b"")
    });
    assert!(
        matches!(removed, Ok(CallResult::Committed(_))),
        "{removed:?}"
    );
    let row = handle
        .outbox_events()
        .expect("read")
        .pop()
        .expect("the event");
    let snapshot = crate::record::decode_provenance(&row.provenance).expect("decode");
    assert_eq!(snapshot.data_types, [DataType::Health, DataType::Meals]);
}

/// A link table that fails, an unavailable `core.<partition>.db`, keeps the request pending and
/// stops nothing: the events of the file are delivered in the same pass.
#[test]
fn a_failing_link_table_keeps_the_request_and_the_pass_goes_on() {
    struct Unavailable;
    impl LinkTable for Unavailable {
        fn register(&mut self, _: &Link) -> Result<(), vilicus_storage::Error> {
            Err(vilicus_storage::Error::OutboxRowNotFound)
        }
    }
    let (registry, files, mut stamper) = standard("link-table");
    let task = {
        let (_, result) = run(
            files.of("tasks"),
            tasks(),
            &own_action(ella()),
            &mut stamper,
            |records| records.insert("tasks", &title("Courses"), &[]),
        );
        match result.expect("commits") {
            CallResult::Committed(outcome) => outcome.value.id,
            _ => panic!("a new call"),
        }
    };
    let handle = files.of("notes");
    let (_, link) = run(
        handle,
        notes(),
        &own_action(ella()),
        &mut stamper,
        |records| {
            let note = records.insert("notes", &title("Pommes"), &[])?;
            records.request_link(note.id, "tasks", task)
        },
    );
    let link = match link.expect("commits") {
        CallResult::Committed(outcome) => outcome.value,
        _ => panic!("a new call"),
    };
    let (_, event, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
    let report = deliver_outbox(
        &registry,
        handle,
        &files,
        &files.boundary(),
        &mut Code::default(),
        &mut Unavailable,
        &mut stamper,
    )
    .expect("the pass goes on");
    assert_eq!(report.links, [(link, LinkOutcome::TableUnavailable)]);
    assert_eq!(report.closed, [event]);
    assert!(report.alerts.is_empty());
    assert_eq!(
        handle.outbox_links().expect("read")[0].state,
        OutboxState::Pending
    );
    let mut table = no_links(&files);
    let mut code = Code::default();
    let later = deliver_outbox(
        &registry,
        handle,
        &files,
        &files.boundary(),
        &mut code,
        &mut table,
        &mut stamper,
    )
    .expect("a pass");
    assert_eq!(later.links, [(link, LinkOutcome::Registered)]);
    assert_eq!(table.registered.len(), 1);
}

/// A link whose linking record was deleted before the pass is refused: a link never outlives the
/// record it starts from.
#[test]
fn a_link_from_a_record_deleted_before_the_pass_is_refused() {
    let (registry, files, mut stamper) = standard("link-deleted");
    let task = {
        let (_, result) = run(
            files.of("tasks"),
            tasks(),
            &own_action(ella()),
            &mut stamper,
            |records| records.insert("tasks", &title("Courses"), &[]),
        );
        match result.expect("commits") {
            CallResult::Committed(outcome) => outcome.value.id,
            _ => panic!("a new call"),
        }
    };
    let handle = files.of("notes");
    let (_, requested) = run(
        handle,
        notes(),
        &own_action(ella()),
        &mut stamper,
        |records| {
            let note = records.insert("notes", &title("Pommes"), &[])?;
            let link = records.request_link(note.id, "tasks", task)?;
            Ok((note.id, link))
        },
    );
    let (note, link) = match requested.expect("commits") {
        CallResult::Committed(outcome) => outcome.value,
        _ => panic!("a new call"),
    };
    let (_, deleted) = run(
        handle,
        notes(),
        &own_action(ella()),
        &mut stamper,
        |records| records.delete("notes", note),
    );
    assert!(matches!(deleted, Ok(CallResult::Committed(_))));
    let mut table = no_links(&files);
    let report = deliver_outbox(
        &registry,
        handle,
        &files,
        &files.boundary(),
        &mut Code::default(),
        &mut table,
        &mut stamper,
    )
    .expect("a pass");
    assert_eq!(report.links, [(link, LinkOutcome::Refused)]);
    assert!(table.registered.is_empty());
    assert_eq!(
        report.alerts,
        [InstanceAdminAlert::link_refused(
            handle.file(),
            link,
            "tasks"
        )]
    );
}

/// A panic of the Core while it runs the consumer's call, outside the consumer's code, is not
/// a failed delivery: it unwinds out of the pass to the boundary of AD-9, the consumer's call
/// rolled back and no attempt recorded.
#[test]
fn a_panic_of_the_core_is_not_counted_as_a_consumers_failure() {
    /// A clock that fails on its first reading inside a consumer's call.
    struct Failing {
        inner: TestStamper,
        readings: u32,
        fail_at: u32,
    }
    impl Stamper for Failing {
        fn now(&mut self) -> UtcMillis {
            self.readings += 1;
            assert!(self.readings != self.fail_at, "the Core fails");
            self.inner.now()
        }
        fn id_random(&mut self) -> [u8; 10] {
            self.inner.id_random()
        }
    }
    let (registry, files, mut stamper) = standard("core-panic");
    let handle = files.of("notes");
    let (_, event, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
    let mut failing = Failing {
        inner: stamper,
        readings: 0,
        fail_at: 1,
    };
    let mut code = Code::default();
    let mut links = no_links(&files);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        deliver_outbox(
            &registry,
            handle,
            &files,
            &files.boundary(),
            &mut code,
            &mut links,
            &mut failing,
        )
    }));
    assert!(unwound.is_err(), "the Core's panic unwinds out of the pass");
    assert!(code.seen.is_empty());
    assert_eq!(handle.delivery(event, "tasks.react").expect("read"), None);
    assert_eq!(titles(files.of("tasks"), "tasks"), 0);
}

/// A module may consume its own topic when its access list names it: the consumer's call runs
/// on the source file itself.
#[test]
fn a_module_consumes_its_own_topic() {
    const OWN_TOPICS: &[Topic] = &[Topic {
        name: ADDED,
        version: 1,
        consumers: &["notes"],
    }];
    const OWN_CONSUMERS: &[Consumer] = &[Consumer {
        name: "echo",
        topic: ADDED,
    }];
    let own = declare("notes", NOTES, OWN_TOPICS, OWN_CONSUMERS, &[]);
    let registry = registry(vec![own]);
    let files = Files::new(
        partition_files(&scratch_dir("own-topic"), Partition::Household, &registry),
        Vec::new(),
    );
    let mut stamper = TestStamper::at(noon());
    let handle = files.of("notes");
    let (_, event, call_id) = add_note(handle, own, &own_action(ella()), &mut stamper, ADDED);
    let report = deliver(&registry, &files, &mut Code::default(), &mut stamper);
    assert_eq!(outcomes(&report), [(event, "notes.echo", "delivered")]);
    assert_eq!(report.closed, [event]);
    assert_eq!(
        titles(handle, "notes"),
        2,
        "the note and the consumer's own"
    );
    let rows = journal(handle);
    assert_eq!(
        (rows[1].0.as_str(), rows[1].2.as_slice()),
        ("Event", &call_id.to_bytes()[..])
    );
}

/// A rule's call, with its name-based call id (AD-39), and an AI task's call emit events whose
/// consumers' calls carry that call id and the author the emitting call names.
#[test]
fn a_rule_and_an_ai_task_emit_events() {
    let (registry, files, mut stamper) = standard("rule-and-task");
    let handle = files.of("notes");
    let definition = RecordProvenance {
        id: member_id(50),
        labels: vilicus_types::RecordLabels::TRUSTED,
        author: Some(ella()),
        data_types: vec![DataType::Meals],
        free_text: Vec::new(),
    };
    let rule = Call {
        principal: Principal::Rule,
        source: Source::Rule(member_id(51)),
        session: Taint::Trusted,
        consumed: Consumed::NOTHING,
        authority: Authority::Unapproved {
            author: Some(ella()),
            acting_for: Some(ella()),
        },
        read: Vec::new(),
        implicit_inputs: vec![definition],
    };
    let mut name_based = [0x6b; 16];
    name_based[6] = 0x58;
    name_based[8] = 0x9c;
    let rule_call = CallId::from_bytes(name_based).expect("a version 5 id");
    let emitted = run_call(
        handle,
        notes(),
        &rule,
        &Invocation {
            call_id: rule_call,
            request_hash: None,
            delivery: None,
        },
        &mut stamper,
        |records| {
            let note = records.insert("notes", &title("Volets"), &[])?;
            records.emit(ADDED, note.id, b"")
        },
    );
    let rule_event = match emitted.expect("commits") {
        CallResult::Committed(outcome) => outcome.value,
        _ => panic!("a new call"),
    };
    let task = Call {
        principal: Principal::AiTask,
        source: Source::AiTask(member_id(52)),
        session: Taint::External,
        consumed: Consumed {
            data_types: vec![DataType::Meals],
            taint: vilicus_types::EffectiveTaint::External,
        },
        authority: Authority::Unapproved {
            author: Some(noe()),
            acting_for: Some(noe()),
        },
        read: Vec::new(),
        implicit_inputs: Vec::new(),
    };
    let (_, recipe) = run(
        handle,
        notes(),
        &own_action(noe()),
        &mut stamper,
        |records| records.insert("notes", &title("Recette"), &[]),
    );
    let recipe = match recipe.expect("commits") {
        CallResult::Committed(outcome) => outcome.value.id,
        _ => panic!("a new call"),
    };
    let (task_call, written) = run(handle, notes(), &task, &mut stamper, |records| {
        let note = records.insert("notes", &title("Menu"), &[recipe])?;
        records.emit(ADDED, note.id, b"")
    });
    let task_event = match written.expect("commits") {
        CallResult::Committed(outcome) => outcome.value,
        _ => panic!("a new call"),
    };
    let report = deliver(&registry, &files, &mut Code::default(), &mut stamper);
    assert_eq!(report.closed, [rule_event, task_event]);
    let rows = journal(files.of("tasks"));
    assert_eq!(rows[0].1, Source::Event(rule_event).to_string());
    assert_eq!(rows[0].2.as_slice(), &rule_call.to_bytes()[..]);
    assert_eq!(rows[1].2.as_slice(), &task_call.to_bytes()[..]);
    assert_eq!(
        stored(files.of("tasks"), "tasks"),
        [
            (
                "trusted".into(),
                "trusted".into(),
                Some(ella().to_bytes().to_vec())
            ),
            (
                "external".into(),
                "external".into(),
                Some(noe().to_bytes().to_vec())
            ),
        ],
        "the rule's validating adult; the task's member, from a tainted session"
    );
}

// Story 3.9: delivery reads the availability states, consumers run inside the boundary of AD-9,
// and an event behind a consumer in a lasting state is dead-lettered past the retention (D150).

/// A monotonic clock a consumer's code moves, shared with the boundary of the pass.
#[derive(Default)]
struct Ticking {
    millis: AtomicU64,
}

impl Ticking {
    fn advance(&self, by: Duration) {
        let millis = u64::try_from(by.as_millis()).expect("a short time");
        self.millis.fetch_add(millis, Ordering::SeqCst);
    }
}

impl MonotonicClock for Ticking {
    fn now(&self) -> Duration {
        Duration::from_millis(self.millis.load(Ordering::SeqCst))
    }
}

/// Puts `module`'s file of `files` in `state`, through the transitions the Core makes.
fn put(files: &Files, module: &'static str, state: AvailabilityState) {
    let name = ModuleName::from_static(module);
    let partition = files.of(module).file().partition();
    let stage = |stage| {
        files
            .states
            .set_stage(&name, partition, stage)
            .expect("no call runs");
    };
    match state {
        AvailabilityState::Locked => stage(Stage::Locked),
        AvailabilityState::Opening => stage(Stage::Opening),
        AvailabilityState::ReKeying => stage(Stage::ReKeying),
        AvailabilityState::Migrating => stage(Stage::Migrating),
        AvailabilityState::Ready => stage(Stage::Ready),
        AvailabilityState::FailedMigration => stage(Stage::FailedMigration),
        AvailabilityState::NewerThanCode => stage(Stage::NewerThanCode),
        AvailabilityState::Faulted => {
            files.states.mark_faulted(&name, partition, Fault::Panicked);
        }
        AvailabilityState::Deactivated => files.states.deactivate(&name, partition),
    }
}

/// The state each delivery of `consumer` in `report` was not ready in, or how it ended.
fn states_of(report: &DeliveryReport, consumer: &str) -> Vec<(Id, String)> {
    report
        .deliveries
        .iter()
        .filter(|delivery| delivery.consumer == consumer)
        .map(|delivery| {
            let outcome = match &delivery.outcome {
                DeliveryOutcome::NotReady { state } => format!("not ready: {state}"),
                DeliveryOutcome::Expired { state, .. } => format!("expired: {state}"),
                DeliveryOutcome::Failed { attempts, cause } => {
                    format!("failed {attempts}: {cause:?}")
                }
                DeliveryOutcome::Delivered => "delivered".to_owned(),
                DeliveryOutcome::AlreadyConsumed => "already consumed".to_owned(),
                DeliveryOutcome::DeadLettered { .. } => "dead letter".to_owned(),
                DeliveryOutcome::Waiting => "waiting".to_owned(),
            };
            (delivery.event, outcome)
        })
        .collect()
}

fn not_ready_states() -> impl Iterator<Item = AvailabilityState> {
    AvailabilityState::ALL
        .iter()
        .copied()
        .filter(|state| *state != AvailabilityState::Ready)
}

/// AC2: for every state but `ready`, as the availability states report it, an event due to the
/// consumer stays in the source outbox: its code does not run, no attempt is recorded, the event
/// stays pending, and the other consumers are delivered; once the file is ready it is delivered.
#[test]
fn an_event_to_a_consumer_that_is_not_ready_stays_without_a_failed_attempt() {
    for state in not_ready_states() {
        let (registry, files, mut stamper) = standard(&format!("not-ready-{state}"));
        put(&files, "tasks", state);
        let handle = files.of("notes");
        let (_, event, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
        let mut code = Code::default();
        let report = deliver(&registry, &files, &mut code, &mut stamper);
        assert_eq!(
            states_of(&report, "tasks.react"),
            [(event, format!("not ready: {state}"))]
        );
        assert_eq!(
            states_of(&report, "meals.plan"),
            [(event, "delivered".to_owned())]
        );
        assert!(report.alerts.is_empty(), "{state}");
        assert!(report.closed.is_empty(), "{state}");
        assert_eq!(handle.delivery(event, "tasks.react").expect("read"), None);
        assert!(
            code.seen
                .iter()
                .all(|(consumer, ..)| consumer != "tasks.react")
        );
        assert_eq!(titles(files.of("tasks"), "tasks"), 0);
        let ready = Files::new(files.handles, Vec::new());
        let report = deliver(&registry, &ready, &mut code, &mut stamper);
        assert_eq!(
            states_of(&report, "tasks.react"),
            [(event, "delivered".to_owned())],
            "{state}"
        );
        assert_eq!(report.closed, [event]);
    }
}

/// D150: an event still pending past the outbox's retention for a consumer in a lasting state is
/// moved to that consumer's dead letters, without an attempt and with an alert, and the
/// consumer's later events are not held back by it; behind a state that is not lasting, or within
/// the retention, it stays.
#[test]
fn an_event_outliving_the_retention_behind_a_lasting_state_is_dead_lettered() {
    let retention = i64::try_from(OUTBOX_RETENTION.as_millis()).expect("in range");
    for state in not_ready_states() {
        let (registry, files, mut stamper) = standard(&format!("expired-{state}"));
        put(&files, "tasks", state);
        let handle = files.of("notes");
        let (_, old, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
        stamper.later(retention);
        let (_, young, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
        let mut code = Code::default();
        let within = deliver(&registry, &files, &mut code, &mut stamper);
        assert_eq!(
            states_of(&within, "tasks.react"),
            [
                (old, format!("not ready: {state}")),
                (young, "waiting".to_owned())
            ],
            "{state}: an event exactly as old as the retention stays"
        );
        stamper.later(1);
        let past = deliver(&registry, &files, &mut code, &mut stamper);
        let letters = handle.dead_letters().expect("read");
        if state.is_lasting() {
            assert_eq!(
                states_of(&past, "tasks.react"),
                [
                    (old, format!("expired: {state}")),
                    (young, format!("not ready: {state}"))
                ],
                "{state}"
            );
            assert_eq!(letters.len(), 1, "{state}");
            assert_eq!(
                (
                    letters[0].event,
                    letters[0].consumer.as_str(),
                    letters[0].attempts
                ),
                (old, "tasks.react", 0)
            );
            assert_eq!(
                past.alerts,
                [InstanceAdminAlert::EventExpired {
                    module: ModuleName::from_static("notes"),
                    partition: Partition::Household,
                    file_name: "notes.household.db".into(),
                    dead_letter: letters[0].id,
                    event: old,
                    topic: ADDED.into(),
                    consumer: "tasks.react".into(),
                    state,
                }]
            );
            assert_eq!(
                past.closed,
                [old],
                "{state}: every consumer is done with it"
            );
        } else {
            assert_eq!(
                states_of(&past, "tasks.react"),
                [
                    (old, format!("not ready: {state}")),
                    (young, "waiting".to_owned())
                ],
                "{state}: a state on its way to serving keeps its events"
            );
            assert!(letters.is_empty(), "{state}");
            assert!(past.alerts.is_empty(), "{state}");
            assert!(past.closed.is_empty(), "{state}");
        }
    }
}

/// AC4 for a consumer: its panic is caught, its call rolled back, its module faulted for the
/// partition with an alert, the attempt counted; its later events then wait for it as for a
/// consumer that is not ready, without a further attempt, while the other consumers go on.
#[test]
fn a_panicking_consumer_faults_its_module_and_its_events_wait() {
    let (registry, files, mut stamper) = standard("consumer-panic");
    let handle = files.of("notes");
    let (_, first, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
    let (_, second, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
    let mut code = Code {
        panics: true,
        ..Code::default()
    };
    code.failures
        .insert(("tasks.react".into(), first), u32::MAX);
    let report = deliver(&registry, &files, &mut code, &mut stamper);
    assert_eq!(
        states_of(&report, "tasks.react"),
        [
            (first, "failed 1: Panicked".to_owned()),
            (second, "waiting".to_owned())
        ]
    );
    assert_eq!(
        states_of(&report, "meals.plan"),
        [
            (first, "delivered".to_owned()),
            (second, "delivered".to_owned())
        ]
    );
    assert_eq!(
        report.alerts,
        [InstanceAdminAlert::ModuleFaulted {
            module: ModuleName::from_static("tasks"),
            partition: Partition::Household,
            file_name: "tasks.household.db".into(),
            fault: Fault::Panicked,
        }]
    );
    assert_eq!(titles(files.of("tasks"), "tasks"), 0, "rolled back");
    assert_eq!(
        files
            .states
            .state(&ModuleName::from_static("tasks"), Partition::Household),
        AvailabilityState::Faulted
    );
    let seen = code.seen.len();
    let next = deliver(&registry, &files, &mut code, &mut stamper);
    assert_eq!(
        states_of(&next, "tasks.react"),
        [
            (first, "not ready: faulted".to_owned()),
            (second, "waiting".to_owned())
        ]
    );
    assert!(next.alerts.is_empty(), "the module faulted once");
    assert_eq!(code.seen.len(), seen, "no further call reaches the module");
    assert_eq!(
        handle
            .delivery(first, "tasks.react")
            .expect("read")
            .map(|delivery| delivery.attempts),
        Some(1)
    );
}

/// AC5 for a consumer: one that runs past the handler time budget is rolled back, its module
/// faulted for the partition with an alert, and it receives no further event there.
#[test]
fn a_consumer_running_past_its_budget_faults_its_module() {
    let (registry, files, mut stamper) = standard("consumer-overrun");
    let handle = files.of("notes");
    let (_, first, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
    let (_, second, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
    let clock = std::sync::Arc::new(Ticking::default());
    let mut code = Code {
        slow: Some(std::sync::Arc::clone(&clock)),
        ..Code::default()
    };
    let files = Files::on_clock(
        files.handles,
        Vec::new(),
        ModuleStates::with_clock(
            std::sync::Arc::clone(&clock) as std::sync::Arc<dyn MonotonicClock>
        ),
    );
    let handle = files.of("notes");
    let boundary = files.boundary();
    let mut links = no_links(&files);
    let report = deliver_outbox(
        &registry,
        handle,
        &files,
        &boundary,
        &mut code,
        &mut links,
        &mut stamper,
    )
    .expect("a delivery pass");
    assert_eq!(
        states_of(&report, "tasks.react"),
        [
            (first, "failed 1: TimeBudget".to_owned()),
            (second, "waiting".to_owned())
        ]
    );
    assert_eq!(
        states_of(&report, "meals.plan")[0].1,
        "failed 1: TimeBudget",
        "the meals consumer overran too"
    );
    assert!(report.alerts.contains(&InstanceAdminAlert::ModuleFaulted {
        module: ModuleName::from_static("tasks"),
        partition: Partition::Household,
        file_name: "tasks.household.db".into(),
        fault: Fault::TimeBudget,
    }));
    assert_eq!(titles(files.of("tasks"), "tasks"), 0, "rolled back");
    let next = deliver(&registry, &files, &mut code, &mut stamper);
    assert_eq!(
        states_of(&next, "tasks.react"),
        [
            (first, "not ready: faulted".to_owned()),
            (second, "waiting".to_owned())
        ]
    );
}

/// The bound consumers of the handler table are what the bus runs: a consumer's function writes
/// through the consumer's call, and a bound function that panics faults its module.
#[test]
fn the_handler_table_runs_the_bound_consumers() {
    fn react(event: &Event<'_>, records: &mut dyn Records) -> Result<(), WriteError> {
        records.insert(
            "tasks",
            &[("title", Value::Text(format!("after {}", event.topic)))],
            &[event.record],
        )?;
        Ok(())
    }
    fn forget(_: &Event<'_>, _: &mut dyn Records) -> Result<(), WriteError> {
        Ok(())
    }
    fn plan(_: &Event<'_>, _: &mut dyn Records) -> Result<(), WriteError> {
        panic!("the meals consumer fails");
    }
    const TASKS_CODE: ModuleCode = ModuleCode {
        module: "tasks",
        tools: &[],
        undo_handlers: &[],
        consumers: &[
            ConsumerHandler {
                consumer: "react",
                consume: react,
            },
            ConsumerHandler {
                consumer: "forget",
                consume: forget,
            },
        ],
    };
    const MEALS_CODE: ModuleCode = ModuleCode {
        module: "meals",
        tools: &[],
        undo_handlers: &[],
        consumers: &[ConsumerHandler {
            consumer: "plan",
            consume: plan,
        }],
    };
    let (registry, files, mut stamper) = standard("bound");
    let mut handlers =
        Handlers::new(registry, &[&TASKS_CODE, &MEALS_CODE]).expect("the code binds");
    let handle = files.of("notes");
    let (_, event, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
    let mut links = no_links(&files);
    let report = deliver_outbox(
        &registry,
        handle,
        &files,
        &files.boundary(),
        &mut handlers,
        &mut links,
        &mut stamper,
    )
    .expect("a delivery pass");
    assert_eq!(
        states_of(&report, "tasks.react"),
        [(event, "delivered".to_owned())]
    );
    assert_eq!(
        states_of(&report, "meals.plan"),
        [(event, "failed 1: Panicked".to_owned())]
    );
    assert_eq!(titles(files.of("tasks"), "tasks"), 1);
    assert_eq!(
        files
            .states
            .state(&ModuleName::from_static("meals"), Partition::Household),
        AvailabilityState::Faulted
    );
}
