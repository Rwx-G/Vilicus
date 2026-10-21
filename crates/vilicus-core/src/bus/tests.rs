//! Story 3.8: the Core stamps an event's emitter and payload version and refuses a claim of
//! another emitter, the topic's access list decides its consumers, and consumers receive every
//! earlier version (AC1); a change and its event commit in one transaction and are delivered
//! after a crash once the files open again (AC2); delivery waits for the migrations, runs in
//! commit order per source file and consumer, and a second delivery produces no second effect
//! (AC3); five failures move an event to the dead letters with an alert and later events proceed
//! (AC4); a link is registered after the commit, in the partition that owns the data (AC5); and a
//! consumer's write is an `Event` call of the emitting call's id, author and inputs' taint, at
//! most tier 1, within its partition (AC6).

use std::collections::HashMap;
use std::path::Path;

use vilicus_module_api::{
    Consumer, DataType, Event, Field, FieldKind, ModuleDeclaration, Records, Structured, Table,
    Topic, Value, WriteError,
};
use vilicus_storage::{
    DeliveryState, Handle, KeyEpoch, Migration, ModuleFile, OutboxState, Partition, SqlValue, Write,
};
use vilicus_types::{CallId, Id, ModuleName, Principal, Source, Taint, UtcMillis};

use super::{
    ConsumerCode, ConsumerFiles, DeliveryError, DeliveryOutcome, DeliveryReport, FailureCause,
    Link, LinkOutcome, LinkTable, MAX_DELIVERY_ATTEMPTS, deliver_outbox, purge_expired_outbox,
};
use crate::alert::InstanceAdminAlert;
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

/// The files of one partition as the Core holds them: every handle, some modules locked.
struct Files {
    handles: Vec<Handle<Write>>,
    locked: Vec<&'static str>,
}

impl Files {
    fn of(&self, module: &str) -> &Handle<Write> {
        self.handles
            .iter()
            .find(|handle| handle.file().module().as_str() == module)
            .expect("a file of the module")
    }
}

impl ConsumerFiles for Files {
    fn ready(&self, module: &ModuleName) -> Option<&Handle<Write>> {
        if self.locked.contains(&module.as_str()) {
            return None;
        }
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
                DeliveryOutcome::NotReady => "not ready",
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
        Files {
            handles,
            locked: Vec::new(),
        },
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

    let files = Files {
        handles,
        locked: vec!["tasks", "meals"],
    };
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
    let files = Files {
        handles,
        locked: Vec::new(),
    };
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
    let files = Files {
        handles: vec![vilicus_storage::open::<Write>(&tasks_file, &KEY).expect("open")],
        locked: Vec::new(),
    };
    let mut code = Code::default();
    let mut links = Links {
        source: notes_file.clone(),
        registered: Vec::new(),
    };
    let refused = deliver_outbox(
        &registry,
        &source,
        &files,
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
        &mut code,
        &mut links,
        &mut stamper,
    )
    .expect("a pass");
    assert_eq!(outcomes(&waiting), [(event, "tasks.react", "not ready")]);
    drop(files);
    migrate(&tasks_file, tasks);
    let files = Files {
        handles: vec![registry.open::<Write>(&tasks_file, &KEY).expect("open")],
        locked: Vec::new(),
    };
    let delivered = deliver_outbox(
        &registry,
        &source,
        &files,
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
    for panics in [false, true] {
        let (registry, files, mut stamper) = standard(&format!("dead-{panics}"));
        let handle = files.of("notes");
        let (_, failing, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
        let (_, later, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
        let mut code = Code {
            panics,
            ..Code::default()
        };
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
                            && matches!(
                                (cause, panics),
                                (FailureCause::Panicked, true)
                                    | (FailureCause::Refused(RecordError::Aborted(_)), false)
                            )
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
}

// AC5

#[test]
fn a_link_is_registered_after_the_commit_in_the_partition_that_owns_the_data() {
    let directory = scratch_dir("links");
    let registry = registry(vec![notes(), tasks(), meals()]);
    let mut stamper = TestStamper::at(noon());
    let files = Files {
        handles: partition_files(&directory, Partition::Household, &registry),
        locked: Vec::new(),
    };
    let elsewhere = Files {
        handles: partition_files(&directory, Partition::Member(ella()), &registry),
        locked: Vec::new(),
    };
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
    let locked_meals = Files {
        handles: files.handles,
        locked: vec!["meals"],
    };
    let mut code = Code::default();
    let report = deliver_outbox(
        &registry,
        locked_meals.of("notes"),
        &locked_meals,
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
    let unlocked = Files {
        handles: locked_meals.handles,
        locked: Vec::new(),
    };
    let report = deliver_outbox(
        &registry,
        unlocked.of("notes"),
        &unlocked,
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
    let household = Files {
        handles: partition_files(&directory, Partition::Household, &registry),
        locked: Vec::new(),
    };
    let personal = Files {
        handles: partition_files(&directory, Partition::Member(ella()), &registry),
        locked: Vec::new(),
    };
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
        fn ready(&self, module: &ModuleName) -> Option<&Handle<Write>> {
            if module.as_str() == "notes" {
                self.source.ready(module)
            } else {
                self.consumers.ready(module)
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
        fn ready(&self, _: &ModuleName) -> Option<&Handle<Write>> {
            Some(self.0.of("meals"))
        }
    }
    let wrong = deliver_outbox(
        &registry,
        household.of("notes"),
        &Wrong(&household),
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
        personal.of("notes").pending_outbox().expect("read").len(),
        1,
        "{personal_event} waits for its own partition's pass"
    );
    let report = deliver_outbox(
        &registry,
        personal.of("notes"),
        &personal,
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

/// An event whose stored provenance does not decode fails each delivery like a refusal and ends
/// in the dead letters: it never stops the pass, which would block the partition's outbox.
#[test]
fn a_malformed_event_fails_its_deliveries_rather_than_block_the_outbox() {
    let (registry, files, mut stamper) = standard("malformed");
    let handle = files.of("notes");
    let (_, broken, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
    let (_, sound, _) = add_note(handle, notes(), &own_action(ella()), &mut stamper, ADDED);
    raw_connection(handle.file())
        .execute_batch(&format!(
            "UPDATE _outbox SET provenance = x'00' WHERE id = x'{}'",
            hex(&broken.to_bytes())
        ))
        .expect("damage the event");
    let mut code = Code::default();
    let first = deliver(&registry, &files, &mut code, &mut stamper);
    assert!(
        first
            .deliveries
            .iter()
            .all(|delivery| delivery.event != broken
                || matches!(
                    delivery.outcome,
                    DeliveryOutcome::Failed {
                        cause: FailureCause::Refused(RecordError::InvalidEvent),
                        ..
                    }
                )),
        "{:?}",
        first.deliveries
    );
    for _ in 1..MAX_DELIVERY_ATTEMPTS {
        deliver(&registry, &files, &mut code, &mut stamper);
    }
    assert_eq!(
        handle.dead_letters().expect("read").len(),
        2,
        "one per consumer"
    );
    assert!(handle.pending_outbox().expect("read").is_empty());
    assert!(
        code.seen.iter().all(|(_, event, ..)| *event == sound),
        "no consumer code ran on the damaged event"
    );
    assert_eq!(titles(files.of("tasks"), "tasks"), 1);
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
