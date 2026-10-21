//! Story 3.9: every state but `ready` answers a typed call with `module_unavailable` and the retry
//! class of AD-54 (AC1); a tool handler or an undo handler that panics is caught, its call rolled
//! back and its module faulted for the partition, with a typed instance admin alert (AC4); a
//! call past its time budget faults its module and no further call reaches it there, whether the
//! call returns late or the supervisor expires it while it runs (AC5); and a module faulted in one
//! partition leaves the other modules and partitions serving (AC6). A panic of the Core is never
//! taken for the module's.

use std::cell::RefCell;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use vilicus_module_api::{
    Confirmation, DataType, ExceptionClass, Field, FieldKind, MatrixRow, ModuleCode,
    ModuleDeclaration, Records, Table, Tier, Tool, ToolCall, ToolHandler, UndoCall, UndoHandler,
    Value, WriteError,
};
use vilicus_storage::{Handle, KeyEpoch, Migration, ModuleFile, Partition, SqlValue, Write};
use vilicus_types::{
    AvailabilityState, CallId, ClientFacingError, Id, ModuleName, Principal, RetryClass, Source,
    Taint, UtcMillis,
};

use super::{Boundary, HandlerError, in_module_code};
use crate::alert::InstanceAdminAlert;
use crate::availability::{Fault, ModuleStates, MonotonicClock, Stage, StageRefused};
use crate::handlers::{Handlers, HandlersError};
use crate::record::tests::{KEY, create_sql, noon, raw_connection, raw_rows, scratch_dir};
use crate::record::tests_call::{TestStamper, ella};
use crate::record::{Authority, Call, CallResult, Consumed, Invocation, Stamper};
use crate::registry::{Registry, frozen, frozen_migrations};

const EPOCH: KeyEpoch = KeyEpoch {
    partition_root_version: 1,
    generation: 0,
};

const BUDGET: Duration = Duration::from_secs(5);

/// A monotonic clock that moves only when a test moves it; shared between threads.
#[derive(Default)]
struct TestClock {
    millis: AtomicU64,
}

impl TestClock {
    fn advance(&self, by: Duration) {
        let millis = u64::try_from(by.as_millis()).expect("a short time");
        self.millis.fetch_add(millis, Ordering::SeqCst);
    }
}

impl MonotonicClock for TestClock {
    fn now(&self) -> Duration {
        Duration::from_millis(self.millis.load(Ordering::SeqCst))
    }
}

const TITLE: &[Field] = &[Field {
    name: "title",
    kind: FieldKind::FreeText { max_len: 200 },
    optional: false,
}];

const TASKS: &[Table] = &[Table {
    name: "tasks",
    data_types: &[DataType::Meals],
    fields: TITLE,
}];

const NOTES: &[Table] = &[Table {
    name: "notes",
    data_types: &[DataType::Meals],
    fields: TITLE,
}];

/// A tier 1 write, undone by the Core's journal.
const ADD_TASK: Tool = Tool {
    name: "add_task",
    arguments: TITLE,
    tier: Tier::ReversibleWrite,
    network_effect: false,
    exception_class: None,
    confirmation: Confirmation::None,
    crosses_partitions: false,
    undo_handler: None,
    matrix_row: MatrixRow {
        section: "2",
        action: "Create or edit a task",
    },
};

/// A tool whose function writes, then panics.
const CRASH: Tool = Tool {
    name: "crash",
    ..ADD_TASK
};

/// A tool with an outbound effect and an undo handler, whose function panics.
const PREPARE_CART: Tool = Tool {
    name: "prepare_cart",
    arguments: &[],
    tier: Tier::ReversibleWrite,
    network_effect: true,
    exception_class: Some(ExceptionClass::ReversibleExternalState),
    confirmation: Confirmation::Light,
    crosses_partitions: false,
    undo_handler: Some("empty_cart"),
    matrix_row: MatrixRow {
        section: "2",
        action: "Prepare a cart",
    },
};

fn add_task(call: &ToolCall<'_>, records: &mut dyn Records) -> Result<(), WriteError> {
    let title = call.argument("title").cloned().unwrap_or(Value::Null);
    records.insert("tasks", &[("title", title)], &[])?;
    Ok(())
}

fn crash(call: &ToolCall<'_>, records: &mut dyn Records) -> Result<(), WriteError> {
    add_task(call, records)?;
    panic!("the module's code fails");
}

fn prepare_cart(_: &ToolCall<'_>, records: &mut dyn Records) -> Result<(), WriteError> {
    records.request_effect("cart_add", b"apples", b"")?;
    Ok(())
}

fn empty_cart(_: &UndoCall<'_>, records: &mut dyn Records) -> Result<(), WriteError> {
    records.insert("tasks", &[("title", Value::Text("undone".into()))], &[])?;
    panic!("the undo handler fails");
}

const TASK_CODE: ModuleCode = ModuleCode {
    module: "tasks",
    tools: &[
        ToolHandler {
            tool: "add_task",
            run: add_task,
        },
        ToolHandler {
            tool: "crash",
            run: crash,
        },
        ToolHandler {
            tool: "prepare_cart",
            run: prepare_cart,
        },
    ],
    undo_handlers: &[UndoHandler {
        name: "empty_cart",
        undo: empty_cart,
    }],
    consumers: &[],
};

fn declare(
    name: &'static str,
    tables: &'static [Table],
    tools: &'static [Tool],
) -> &'static ModuleDeclaration {
    let create: String = tables.iter().map(create_sql).collect::<Vec<_>>().join("\n");
    Box::leak(Box::new(ModuleDeclaration {
        name,
        tables,
        fts5_tables: &[],
        migrations: vec![frozen(create.leak())].leak(),
        matrix_sections: if tools.is_empty() { &[] } else { &["2"] },
        tools,
        topics: &[],
        consumers: &[],
    }))
}

fn tasks() -> &'static ModuleDeclaration {
    declare("tasks", TASKS, &[ADD_TASK, CRASH, PREPARE_CART])
}

fn notes() -> &'static ModuleDeclaration {
    declare("notes", NOTES, &[])
}

fn registry() -> Registry {
    Registry::new(vec![tasks(), notes()].leak()).expect("a valid registry")
}

fn handlers(registry: Registry) -> Handlers {
    Handlers::new(registry, &[&TASK_CODE]).expect("the code binds")
}

/// A migrated file of `module` in `partition` under `directory`, opened as the Core opens it.
fn open_file(
    registry: &Registry,
    directory: &Path,
    module: &'static ModuleDeclaration,
    partition: Partition,
) -> Handle<Write> {
    let file = ModuleFile::new(directory, ModuleName::from_static(module.name), partition);
    vilicus_storage::create(&file, &KEY, EPOCH)
        .expect("create")
        .close()
        .expect("close");
    let mut migration = vilicus_storage::open::<Migration>(&file, &KEY).expect("open");
    migration
        .apply_module_migrations(&frozen_migrations(module).expect("frozen"))
        .expect("migrate");
    migration.close().expect("close");
    registry.open::<Write>(&file, &KEY).expect("open")
}

fn ready(states: &ModuleStates, handle: &Handle<Write>) {
    states
        .set_stage(
            states.generation(handle.file().partition()),
            handle.file().module(),
            Stage::Ready,
        )
        .expect("no call runs");
}

fn own_action() -> Call {
    Call {
        principal: Principal::Member,
        source: Source::Member(ella()),
        session: Taint::Trusted,
        consumed: Consumed::NOTHING,
        authority: Authority::OwnAction { member: ella() },
        read: Vec::new(),
        implicit_inputs: Vec::new(),
    }
}

fn invocation(stamper: &mut TestStamper) -> Invocation {
    let now = stamper.now();
    let id = Id::new_v7(now, stamper.id_random()).expect("after the epoch");
    Invocation {
        call_id: CallId::from(id),
        request_hash: None,
        delivery: None,
    }
}

fn rows(handle: &Handle<Write>, sql: &str) -> usize {
    handle.query_values(sql, &[]).expect("read").len()
}

/// The journal rows of `handle`'s file, read on a connection of its own: module SQL reads no
/// Core table.
fn journal_rows(handle: &Handle<Write>) -> usize {
    raw_rows(&raw_connection(handle.file()), "SELECT seq FROM _journal").len()
}

fn title(text: &str) -> Vec<(&'static str, Value)> {
    vec![("title", Value::Text(text.into()))]
}

/// The partition, the modules and their files of one test.
struct Fixture {
    registry: Registry,
    handlers: Handlers,
    states: ModuleStates,
    clock: Arc<TestClock>,
    stamper: RefCell<TestStamper>,
    tasks: Handle<Write>,
    notes: Handle<Write>,
    ellas_tasks: Handle<Write>,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let registry = registry();
        let directory = scratch_dir(label);
        let tasks = open_file(
            &registry,
            &directory,
            registry.modules()[0],
            Partition::Household,
        );
        let notes = open_file(
            &registry,
            &directory,
            registry.modules()[1],
            Partition::Household,
        );
        let ellas_tasks = open_file(
            &registry,
            &directory,
            registry.modules()[0],
            Partition::Member(ella()),
        );
        let clock = Arc::new(TestClock::default());
        let states = ModuleStates::with_clock(Arc::clone(&clock) as Arc<dyn MonotonicClock>);
        for handle in [&tasks, &notes, &ellas_tasks] {
            ready(&states, handle);
        }
        Self {
            handlers: handlers(registry),
            registry,
            states,
            clock,
            stamper: RefCell::new(TestStamper::at(noon())),
            tasks,
            notes,
            ellas_tasks,
        }
    }

    fn boundary(&self) -> Boundary<'_> {
        Boundary {
            states: &self.states,
            budget: BUDGET,
        }
    }

    fn invocation(&self) -> Invocation {
        invocation(&mut self.stamper.borrow_mut())
    }

    fn call_tool(
        &self,
        handle: &Handle<Write>,
        tool: &str,
        arguments: &[(&str, Value)],
    ) -> Result<CallResult<()>, HandlerError> {
        let invocation = self.invocation();
        self.handlers.call_tool(
            &self.boundary(),
            handle,
            tool,
            arguments,
            &own_action(),
            &invocation,
            &mut *self.stamper.borrow_mut(),
        )
    }
}

/// Puts `module`'s file in `partition` in `state`, through the transitions the Core makes.
fn put(states: &ModuleStates, module: &ModuleName, partition: Partition, state: AvailabilityState) {
    let stage = |stage| {
        states
            .set_stage(states.generation(partition), module, stage)
            .expect("no call runs")
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
            stage(Stage::Ready);
            states.mark_faulted(module, partition, Fault::Panicked);
        }
        AvailabilityState::Deactivated => {
            stage(Stage::Ready);
            states.deactivate(module, partition);
        }
    }
}

/// AD-54's table, the independent statement the answers are checked against.
const AD_54_RETRY: [(AvailabilityState, Option<RetryClass>); 9] = [
    (AvailabilityState::Locked, Some(RetryClass::Retryable)),
    (AvailabilityState::Opening, Some(RetryClass::Retryable)),
    (AvailabilityState::ReKeying, Some(RetryClass::Retryable)),
    (AvailabilityState::Migrating, Some(RetryClass::Retryable)),
    (AvailabilityState::Ready, None),
    (
        AvailabilityState::FailedMigration,
        Some(RetryClass::NotRetryable),
    ),
    (AvailabilityState::Faulted, Some(RetryClass::NotRetryable)),
    (
        AvailabilityState::Deactivated,
        Some(RetryClass::NotRetryable),
    ),
    (
        AvailabilityState::NewerThanCode,
        Some(RetryClass::NotRetryable),
    ),
];

// AC1

/// Every state is reported, and every state but `ready` answers a typed call with
/// `module_unavailable` and the retry class of AD-54, before any of the module's code runs; the
/// gate and the boundary agree.
#[test]
fn every_state_but_ready_answers_module_unavailable_with_its_retry_class() {
    assert_eq!(AD_54_RETRY.len(), AvailabilityState::ALL.len());
    for (state, retry_class) in AD_54_RETRY {
        let fixture = Fixture::new("states");
        let name = fixture.tasks.file().module().clone();
        put(&fixture.states, &name, Partition::Household, state);
        assert_eq!(fixture.states.state(&name, Partition::Household), state);
        let gate = fixture.states.check(&name, Partition::Household);
        let tasks = &fixture.tasks;
        let called = fixture.call_tool(tasks, "add_task", &title("Pommes"));
        match retry_class {
            None => {
                assert_eq!(gate, Ok(()));
                assert!(matches!(called, Ok(CallResult::Committed(_))), "{state}");
                assert_eq!(rows(tasks, "SELECT id FROM tasks"), 1);
            }
            Some(retry_class) => {
                let refused = gate.expect_err("not ready");
                assert_eq!(refused.state(), state);
                let sent = refused.to_client_error();
                assert_eq!(sent.code.as_str(), "module_unavailable");
                assert_eq!(sent.message_key.as_str(), "error.module_unavailable");
                assert_eq!(sent.retry_class, retry_class, "{state}");
                match called {
                    Err(HandlerError::Unavailable(unavailable)) => {
                        assert_eq!(unavailable, refused);
                    }
                    other => panic!("{state}: {other:?}"),
                }
                assert_eq!(rows(tasks, "SELECT id FROM tasks"), 0, "{state}");
                assert_eq!(journal_rows(tasks), 0, "{state}");
            }
        }
    }
}

/// A file the Core never heard of is `locked`: unknown files never serve.
#[test]
fn a_file_the_core_does_not_know_is_locked() {
    let states = ModuleStates::new();
    let name = ModuleName::from_static("tasks");
    assert_eq!(
        states.state(&name, Partition::Home),
        AvailabilityState::Locked
    );
    assert_eq!(
        states
            .check(&name, Partition::Home)
            .map_err(|refused| refused.retry_class()),
        Err(RetryClass::Retryable)
    );
}

// AC4

/// A tool handler that writes, then panics: the panic is caught, the call rolled back, the module
/// faulted for the partition with an alert, the thread's mark restored, and no further call
/// reaches the module there.
#[test]
fn a_panicking_tool_handler_is_caught_rolled_back_and_faults_its_module() {
    let fixture = Fixture::new("tool-panic");
    let tasks = &fixture.tasks;
    let crashed = fixture.call_tool(tasks, "crash", &title("Pommes"));
    let Err(HandlerError::Faulted {
        fault: Fault::Panicked,
        alert: Some(alert),
    }) = crashed
    else {
        panic!("{crashed:?}");
    };
    assert_eq!(
        *alert,
        InstanceAdminAlert::ModuleFaulted {
            module: ModuleName::from_static("tasks"),
            partition: Partition::Household,
            file_name: "tasks.household.db".to_owned(),
            fault: Fault::Panicked,
        }
    );
    assert!(!in_module_code(), "the mark is restored after the panic");
    assert_eq!(rows(tasks, "SELECT id FROM tasks"), 0, "rolled back");
    assert_eq!(journal_rows(tasks), 0);
    assert_eq!(
        fixture
            .states
            .state(tasks.file().module(), Partition::Household),
        AvailabilityState::Faulted
    );
    let next = fixture.call_tool(tasks, "add_task", &title("Poires"));
    let Err(HandlerError::Unavailable(refused)) = next else {
        panic!("{next:?}");
    };
    assert_eq!(refused.retry_class(), RetryClass::NotRetryable);
    assert_eq!(rows(tasks, "SELECT id FROM tasks"), 0);
    assert!(
        tasks.execute_batch("BEGIN IMMEDIATE; ROLLBACK;").is_ok(),
        "the handle holds no open transaction"
    );
}

/// An undo handler that panics is caught like a tool handler: its writes rolled back, its module
/// faulted, an alert returned.
#[test]
fn a_panicking_undo_handler_is_caught_rolled_back_and_faults_its_module() {
    let fixture = Fixture::new("undo-panic");
    let tasks = &fixture.tasks;
    let prepared = fixture.call_tool(tasks, "prepare_cart", &[]);
    let Ok(CallResult::Committed(outcome)) = prepared else {
        panic!("{prepared:?}");
    };
    let effect = &outcome.effects[0];
    let effects = [vilicus_module_api::UndoneEffect {
        id: effect.id,
        effect: &effect.effect,
        idempotency_key: &effect.idempotency_key,
        payload: b"",
    }];
    let undo = UndoCall::new("prepare_cart", CallId::from(effect.id), &effects);
    let invocation = fixture.invocation();
    let undone = fixture.handlers.call_undo(
        &fixture.boundary(),
        tasks,
        &undo,
        &own_action(),
        &invocation,
        &mut *fixture.stamper.borrow_mut(),
    );
    let Err(HandlerError::Faulted {
        fault: Fault::Panicked,
        alert: Some(alert),
    }) = undone
    else {
        panic!("{undone:?}");
    };
    assert!(matches!(*alert, InstanceAdminAlert::ModuleFaulted { .. }));
    assert_eq!(rows(tasks, "SELECT id FROM tasks"), 0, "rolled back");
    assert_eq!(
        fixture
            .states
            .state(tasks.file().module(), Partition::Household),
        AvailabilityState::Faulted
    );
    assert!(matches!(
        fixture.handlers.call_undo(
            &fixture.boundary(),
            tasks,
            &UndoCall::new("add_task", CallId::from(effect.id), &[]),
            &own_action(),
            &invocation,
            &mut *fixture.stamper.borrow_mut(),
        ),
        Err(HandlerError::UnknownHandler)
    ));
}

/// The thread is marked while the module's code runs and unmarked inside the Core's record port
/// it calls, so the Core's panic hook can tell the two apart (D131).
#[test]
fn the_thread_is_marked_in_the_modules_code_only() {
    /// A clock that notes, at each reading, whether the thread is marked.
    struct Watching {
        inner: TestStamper,
        marks: Vec<bool>,
    }
    impl Stamper for Watching {
        fn now(&mut self) -> UtcMillis {
            self.marks.push(in_module_code());
            self.inner.now()
        }
        fn id_random(&mut self) -> [u8; 10] {
            self.inner.id_random()
        }
    }
    let fixture = Fixture::new("mark");
    let module = fixture.registry.modules()[0];
    let invocation = fixture.invocation();
    let mut watching = Watching {
        inner: TestStamper::at(noon()),
        marks: Vec::new(),
    };
    let mut in_body = None;
    assert!(!in_module_code());
    let committed = fixture.boundary().run(
        &fixture.tasks,
        module,
        &own_action(),
        &invocation,
        &mut watching,
        |records| {
            in_body = Some(in_module_code());
            records.insert("tasks", &title("Pommes"), &[])?;
            Ok(())
        },
    );
    assert!(matches!(committed, Ok(CallResult::Committed(_))));
    assert_eq!(in_body, Some(true));
    assert!(!watching.marks.is_empty());
    assert!(
        watching.marks.iter().all(|marked| !marked),
        "the Core's own code runs unmarked: {:?}",
        watching.marks
    );
    assert!(!in_module_code());
}

/// A panic of the Core, inside the record port the module's code calls or before that code runs,
/// unwinds out of the boundary: the call rolled back, the module not faulted, its call ended.
#[test]
fn a_panic_of_the_core_is_never_taken_for_the_modules() {
    /// A clock that fails at one of its readings.
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
    let fixture = Fixture::new("core-panic");
    let module = fixture.registry.modules()[0];
    for fail_at in [1, 2] {
        let invocation = fixture.invocation();
        let mut failing = Failing {
            inner: TestStamper::at(noon()),
            readings: 0,
            fail_at,
        };
        let boundary = fixture.boundary();
        let tasks = &fixture.tasks;
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            boundary.run(
                tasks,
                module,
                &own_action(),
                &invocation,
                &mut failing,
                |records| {
                    records.insert("tasks", &title("Pommes"), &[])?;
                    Ok(())
                },
            )
        }));
        assert!(
            unwound.is_err(),
            "reading {fail_at}: the Core's panic unwinds on"
        );
        assert!(!in_module_code());
        assert_eq!(rows(&fixture.tasks, "SELECT id FROM tasks"), 0);
        assert_eq!(
            fixture
                .states
                .state(fixture.tasks.file().module(), Partition::Household),
            AvailabilityState::Ready,
            "reading {fail_at}: the module is not faulted"
        );
    }
    let tasks = &fixture.tasks;
    assert!(
        matches!(
            fixture.call_tool(tasks, "add_task", &title("Pommes")),
            Ok(CallResult::Committed(_))
        ),
        "the call ended, and the file serves"
    );
}

/// A call names a tool of the module of its file; a tool of another module, an unknown tool or
/// a file of a module with no code is refused before anything runs.
#[test]
fn a_call_names_a_bound_handler_of_its_files_module() {
    let fixture = Fixture::new("names");
    let tasks = &fixture.tasks;
    assert!(matches!(
        fixture.call_tool(tasks, "unknown", &[]),
        Err(HandlerError::UnknownHandler)
    ));
    let notes = &fixture.notes;
    assert!(matches!(
        fixture.call_tool(notes, "add_task", &title("Pommes")),
        Err(HandlerError::UnknownHandler)
    ));
    let invocation = fixture.invocation();
    let wrong = fixture.boundary().run(
        notes,
        fixture.registry.modules()[0],
        &own_action(),
        &invocation,
        &mut *fixture.stamper.borrow_mut(),
        |_| Ok(()),
    );
    assert!(matches!(wrong, Err(HandlerError::WrongFile)));
    assert_eq!(rows(tasks, "SELECT id FROM tasks"), 0);
}

/// The code of a registry binds whole or not at all.
#[test]
fn the_handler_table_binds_every_registered_module_or_none() {
    let registry = registry();
    assert!(Handlers::new(registry, &[&TASK_CODE]).is_ok());
    assert_eq!(
        Handlers::new(registry, &[]).map(drop),
        Err(HandlersError::MissingCode { module: "tasks" })
    );
    assert_eq!(
        Handlers::new(registry, &[&TASK_CODE, &TASK_CODE]).map(drop),
        Err(HandlersError::DuplicateCode { module: "tasks" })
    );
    const MEALS_CODE: ModuleCode = ModuleCode {
        module: "meals",
        tools: &[],
        undo_handlers: &[],
        consumers: &[],
    };
    assert_eq!(
        Handlers::new(registry, &[&TASK_CODE, &MEALS_CODE]).map(drop),
        Err(HandlersError::UnregisteredModule { module: "meals" })
    );
    const NO_UNDO: ModuleCode = ModuleCode {
        undo_handlers: &[],
        ..TASK_CODE
    };
    let refused = Handlers::new(registry, &[&NO_UNDO]).map(drop);
    assert_eq!(
        refused,
        Err(HandlersError::Binding {
            module: "tasks",
            error: vilicus_module_api::BindingError::MissingUndoHandler { name: "empty_cart" },
        })
    );
    let error = refused.expect_err("refused");
    assert_eq!(
        error.to_string(),
        "module tasks: an undo handler a tool names has no function: empty_cart"
    );
    assert_eq!(
        Handlers::new(registry, &[&TASK_CODE])
            .expect("binds")
            .code("notes")
            .map(|code| code.module),
        None,
        "a module with nothing to bind needs no code"
    );
}

// AC5

/// A call that returns after its deadline is rolled back and faults its module; a call that
/// returns at its deadline commits.
#[test]
fn a_call_returning_past_its_budget_is_rolled_back_and_faults_its_module() {
    let fixture = Fixture::new("overrun");
    let module = fixture.registry.modules()[0];
    let invocation_at_budget = fixture.invocation();
    let on_time = fixture.boundary().run(
        &fixture.tasks,
        module,
        &own_action(),
        &invocation_at_budget,
        &mut *fixture.stamper.borrow_mut(),
        |records| {
            records.insert("tasks", &title("Pommes"), &[])?;
            fixture.clock.advance(BUDGET);
            Ok(())
        },
    );
    assert!(
        matches!(on_time, Ok(CallResult::Committed(_))),
        "{on_time:?}"
    );
    let invocation_late = fixture.invocation();
    let late = fixture.boundary().run(
        &fixture.tasks,
        module,
        &own_action(),
        &invocation_late,
        &mut *fixture.stamper.borrow_mut(),
        |records| {
            records.insert("tasks", &title("Poires"), &[])?;
            fixture.clock.advance(BUDGET + Duration::from_millis(1));
            Ok(())
        },
    );
    let Err(HandlerError::Faulted {
        fault: Fault::TimeBudget,
        alert: Some(alert),
    }) = late
    else {
        panic!("{late:?}");
    };
    assert!(matches!(
        *alert,
        InstanceAdminAlert::ModuleFaulted {
            fault: Fault::TimeBudget,
            ..
        }
    ));
    assert_eq!(
        rows(&fixture.tasks, "SELECT id FROM tasks"),
        1,
        "the late call rolled back"
    );
    let next_invocation = fixture.invocation();
    let mut ran = false;
    let next = fixture.boundary().run(
        &fixture.tasks,
        module,
        &own_action(),
        &next_invocation,
        &mut *fixture.stamper.borrow_mut(),
        |_| {
            ran = true;
            Ok(())
        },
    );
    assert!(matches!(next, Err(HandlerError::Unavailable(_))));
    assert!(!ran, "no further call reaches the module");
}

/// The supervisor expires a call while it runs, on another thread: the module is faulted at
/// once, no other call starts on the file, and the call, when its code returns, is rolled back
/// without a second alert. The threads meet on channels, never on a timer.
#[test]
fn a_call_still_running_past_its_deadline_is_expired_by_the_supervisor() {
    let fixture = Fixture::new("expire");
    let Fixture {
        registry,
        states,
        clock,
        tasks,
        ..
    } = fixture;
    let module = registry.modules()[0];
    let name = tasks.file().module().clone();
    let (started, wait_started) = mpsc::channel::<()>();
    let (release, wait_release) = mpsc::channel::<()>();
    let boundary = Boundary {
        states: &states,
        budget: BUDGET,
    };
    let mut stamper = TestStamper::at(noon());
    let invocation = invocation(&mut stamper);
    std::thread::scope(|scope| {
        let handler = scope.spawn(move || {
            let result = boundary.run(
                &tasks,
                module,
                &own_action(),
                &invocation,
                &mut stamper,
                |records| {
                    records.insert("tasks", &title("Pommes"), &[])?;
                    started.send(()).expect("the test waits");
                    wait_release.recv().expect("the test releases");
                    Ok(())
                },
            );
            (result, rows(&tasks, "SELECT id FROM tasks"))
        });
        wait_started.recv().expect("the call started");
        assert!(states.expire_overdue().is_empty(), "within its budget");
        clock.advance(BUDGET + Duration::from_millis(1));
        let alerts = states.expire_overdue();
        assert_eq!(
            alerts,
            [InstanceAdminAlert::ModuleFaulted {
                module: name.clone(),
                partition: Partition::Household,
                file_name: "tasks.household.db".to_owned(),
                fault: Fault::TimeBudget,
            }]
        );
        assert!(states.expire_overdue().is_empty(), "alerted once");
        assert_eq!(
            states.state(&name, Partition::Household),
            AvailabilityState::Faulted
        );
        assert!(
            states.begin_call(&name, Partition::Household).is_err(),
            "no other call starts on the file"
        );
        release.send(()).expect("the call waits");
        let (result, stored) = handler.join().expect("the handler thread ends");
        assert!(
            matches!(
                result,
                Err(HandlerError::Faulted {
                    fault: Fault::TimeBudget,
                    alert: None,
                })
            ),
            "{result:?}"
        );
        assert_eq!(stored, 0, "the expired call rolled back");
    });
}

/// A file is put to migrating, or re-keying, only when no call of module code runs on it: the
/// Core's writer of the file is held for the whole run (D149).
#[test]
fn a_file_is_not_migrated_while_a_call_runs_on_it() {
    let fixture = Fixture::new("writer");
    let module = fixture.registry.modules()[0];
    let name = fixture.tasks.file().module().clone();
    let invocation = fixture.invocation();
    let states = &fixture.states;
    let mut refused = None;
    let committed = fixture.boundary().run(
        &fixture.tasks,
        module,
        &own_action(),
        &invocation,
        &mut *fixture.stamper.borrow_mut(),
        |_| {
            refused = Some((
                states.set_stage(
                    states.generation(Partition::Household),
                    &name,
                    Stage::Migrating,
                ),
                states.set_stage(
                    states.generation(Partition::Household),
                    &name,
                    Stage::ReKeying,
                ),
            ));
            Ok(())
        },
    );
    assert!(matches!(committed, Ok(CallResult::Committed(_))));
    assert_eq!(
        refused,
        Some((
            Err(StageRefused::CallsInFlight { calls: 1 }),
            Err(StageRefused::CallsInFlight { calls: 1 })
        ))
    );
    assert_eq!(
        states.set_stage(
            states.generation(Partition::Household),
            &name,
            Stage::Migrating
        ),
        Ok(()),
        "once the call ended"
    );
}

// AC6

/// A module faulted in one partition: its file in another partition and the other modules of
/// the partition keep serving, and locking and unlocking the partition does not clear the fault.
#[test]
fn a_module_faulted_in_one_partition_leaves_the_others_serving() {
    let fixture = Fixture::new("isolation");
    let tasks = &fixture.tasks;
    let ellas = &fixture.ellas_tasks;
    assert!(matches!(
        fixture.call_tool(tasks, "crash", &title("Pommes")),
        Err(HandlerError::Faulted { .. })
    ));
    assert!(matches!(
        fixture.call_tool(ellas, "add_task", &title("Pommes")),
        Ok(CallResult::Committed(_))
    ));
    assert_eq!(rows(ellas, "SELECT id FROM tasks"), 1);
    let module = fixture.registry.modules()[1];
    let invocation = fixture.invocation();
    let noted = fixture.boundary().run(
        &fixture.notes,
        module,
        &own_action(),
        &invocation,
        &mut *fixture.stamper.borrow_mut(),
        |records| {
            records.insert("notes", &title("Pommes"), &[])?;
            Ok(())
        },
    );
    assert!(matches!(noted, Ok(CallResult::Committed(_))));
    assert_eq!(rows(&fixture.notes, "SELECT id FROM notes"), 1);
    let tasks_name = ModuleName::from_static("tasks");
    let notes_name = ModuleName::from_static("notes");
    assert_eq!(
        [
            fixture.states.state(&tasks_name, Partition::Household),
            fixture.states.state(&tasks_name, Partition::Member(ella())),
            fixture.states.state(&notes_name, Partition::Household),
        ],
        [
            AvailabilityState::Faulted,
            AvailabilityState::Ready,
            AvailabilityState::Ready
        ]
    );
    fixture.states.lock_partition(Partition::Household);
    fixture
        .states
        .unlock_partition(&fixture.registry, Partition::Household);
    for handle in [tasks, &fixture.notes] {
        ready(&fixture.states, handle);
    }
    assert_eq!(
        fixture.states.state(&tasks_name, Partition::Household),
        AvailabilityState::Faulted,
        "a fault lasts as long as the Core"
    );
    assert_eq!(
        fixture.states.state(&notes_name, Partition::Household),
        AvailabilityState::Ready
    );
    let raw: Vec<Vec<SqlValue>> = tasks
        .query_values("SELECT id FROM tasks", &[])
        .expect("read");
    assert!(raw.is_empty());
}

// Story 3.9 review.

/// Where the last `Bomb` was dropped: 1 in module code, 2 in the Core's.
static BOMB_DROPPED_IN: AtomicU64 = AtomicU64::new(0);

/// A panic payload whose drop panics again.
struct Bomb;

impl Drop for Bomb {
    fn drop(&mut self) {
        BOMB_DROPPED_IN.store(if in_module_code() { 1 } else { 2 }, Ordering::SeqCst);
        panic!("the payload's drop panics");
    }
}

/// Review item 1: a module that panics with a payload whose drop panics in turn is caught like any
/// panic: the payload is dropped as module code, nothing unwinds out of the boundary, the call is
/// rolled back and the module faulted with its alert.
#[test]
fn a_panic_payload_whose_drop_panics_stays_inside_the_boundary() {
    let fixture = Fixture::new("payload-bomb");
    let module = fixture.registry.modules()[0];
    let invocation = fixture.invocation();
    let boundary = fixture.boundary();
    let tasks = &fixture.tasks;
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        boundary.run(
            tasks,
            module,
            &own_action(),
            &invocation,
            &mut *fixture.stamper.borrow_mut(),
            |records| -> Result<(), WriteError> {
                records.insert("tasks", &title("Pommes"), &[])?;
                std::panic::panic_any(Bomb)
            },
        )
    }));
    let Ok(result) = unwound else {
        panic!("the module's panic unwound out of the boundary");
    };
    assert!(
        matches!(
            result,
            Err(HandlerError::Faulted {
                fault: Fault::Panicked,
                alert: Some(_),
            })
        ),
        "{result:?}"
    );
    assert_eq!(
        BOMB_DROPPED_IN.load(Ordering::SeqCst),
        1,
        "dropped as module code"
    );
    assert!(!in_module_code());
    assert_eq!(rows(tasks, "SELECT id FROM tasks"), 0, "rolled back");
    assert_eq!(
        fixture
            .states
            .state(tasks.file().module(), Partition::Household),
        AvailabilityState::Faulted
    );
}

/// Review item 4: a panic of the Core in the record port that the module's code catches and goes
/// on from is still the Core's: the call is rolled back, whatever the module wrote after it, the
/// panic unwinds out of the boundary, and the module is not faulted.
#[test]
fn a_panic_of_the_core_the_module_catches_still_rolls_the_call_back() {
    /// A clock that fails at its second reading, the first write's.
    struct Failing {
        inner: TestStamper,
        readings: u32,
    }
    impl Stamper for Failing {
        fn now(&mut self) -> UtcMillis {
            self.readings += 1;
            assert!(self.readings != 2, "the Core fails");
            self.inner.now()
        }
        fn id_random(&mut self) -> [u8; 10] {
            self.inner.id_random()
        }
    }
    let fixture = Fixture::new("core-panic-caught");
    let module = fixture.registry.modules()[0];
    let invocation = fixture.invocation();
    let boundary = fixture.boundary();
    let tasks = &fixture.tasks;
    let mut failing = Failing {
        inner: TestStamper::at(noon()),
        readings: 0,
    };
    let mut caught = false;
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        boundary.run(
            tasks,
            module,
            &own_action(),
            &invocation,
            &mut failing,
            |records| {
                caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    records.insert("tasks", &title("Pommes"), &[])
                }))
                .is_err();
                records.insert("tasks", &title("Poires"), &[])?;
                Ok(())
            },
        )
    }));
    assert!(caught, "the module's code caught the Core's panic");
    assert!(
        unwound.is_err(),
        "the Core's panic unwinds out of the boundary"
    );
    assert_eq!(rows(tasks, "SELECT id FROM tasks"), 0, "rolled back");
    assert_eq!(
        fixture
            .states
            .state(tasks.file().module(), Partition::Household),
        AvailabilityState::Ready
    );
}

/// Review item 3: the Core's own work before the module's code (the write lock, the call's
/// deduplication, the call's start time) is not charged to the module: a Core that takes longer
/// than the whole budget before the code starts faults nothing.
#[test]
fn the_cores_time_before_the_modules_code_is_not_charged_to_it() {
    /// A clock that, at its first reading, before the module's code, moves the monotonic clock
    /// past the budget.
    struct Slow<'a> {
        inner: TestStamper,
        clock: &'a TestClock,
        readings: u32,
    }
    impl Stamper for Slow<'_> {
        fn now(&mut self) -> UtcMillis {
            self.readings += 1;
            if self.readings == 1 {
                self.clock.advance(BUDGET + Duration::from_millis(1));
            }
            self.inner.now()
        }
        fn id_random(&mut self) -> [u8; 10] {
            self.inner.id_random()
        }
    }
    let fixture = Fixture::new("slow-core");
    let module = fixture.registry.modules()[0];
    let invocation = fixture.invocation();
    let mut slow = Slow {
        inner: TestStamper::at(noon()),
        clock: &fixture.clock,
        readings: 0,
    };
    let mut ran = false;
    let result = fixture.boundary().run(
        &fixture.tasks,
        module,
        &own_action(),
        &invocation,
        &mut slow,
        |_| {
            ran = true;
            Ok(())
        },
    );
    assert!(ran);
    assert!(
        slow.readings >= 1,
        "the Core read its clock before the code"
    );
    assert!(matches!(result, Ok(CallResult::Committed(_))), "{result:?}");
    assert_eq!(
        fixture
            .states
            .state(fixture.tasks.file().module(), Partition::Household),
        AvailabilityState::Ready
    );
}
