//! Story 3.10: the reference module exercises the module contract end to end in the testbed, on
//! files the Core creates, unlocks and brings up through its own paths (AC3): two migrations in
//! sequence, a typed write with its journal, an event and its consumers, an effect intent and the
//! undo handler that compensates it, each asserted; and the testbed's second module reads the
//! reference module's records only through its typed API, within its partition scope, while no
//! handle on the reference module's file is ever obtained (AC5).

use vilicus_core::boundary::HandlerError;
use vilicus_core::bus::DeliveryOutcome;
use vilicus_core::handlers::Handlers;
use vilicus_core::record::{Call, CallResult, Invocation, RecordError, decode_inputs};
use vilicus_core::registry::Registry;
use vilicus_core::startup::{BringUpReport, FileOutcome};
use vilicus_core::testing::{
    CORE_SCHEMA_VERSION, CallKey, DeliveryState, EffectState, MigrationTrack, OutboxState,
    Partition, SqlValue,
};
use vilicus_mod_reference::{
    ITEM_ADDED, ITEM_ADDED_VERSION, ITEM_CATEGORY, ITEMS, MIGRATIONS, NAME, PUBLISH_ITEM,
    REFERENCE, REFERENCE_CODE, TALLIES, WITHDRAW_ITEM,
};
use vilicus_module_api::{
    ModuleDeclaration, ReadRecord, Rev, Table, UndoCall, UndoneEffect, Value, WriteError,
};
use vilicus_types::{Id, ModuleName, Principal, Source};

use crate::reader::{READER, READER_CODE};
use crate::registry::{HANDLERS, REGISTRY};
use crate::support::{House, ella, key, noe, own_action, text};

/// The reference module's items as its first migration makes them: without the note the second
/// adds, last.
const ITEMS_AT_1: Table = Table {
    fields: ITEMS.fields.split_at(ITEMS.fields.len() - 1).0,
    ..ITEMS
};

/// The reference module at its first release: its first migration only.
const REFERENCE_AT_1: ModuleDeclaration = ModuleDeclaration {
    tables: &[ITEMS_AT_1, TALLIES],
    migrations: MIGRATIONS.split_at(1).0,
    ..REFERENCE
};

const REGISTRY_AT_1: Registry = match Registry::new(&[&REFERENCE_AT_1, &READER]) {
    Ok(registry) => registry,
    Err(error) => panic!("{}", error.rule()),
};

const HANDLERS_AT_1: Handlers = match Handlers::new(REGISTRY_AT_1, &[&REFERENCE_CODE, &READER_CODE])
{
    Ok(handlers) => handlers,
    Err(error) => panic!("{}", error.rule()),
};

fn reference() -> ModuleName {
    ModuleName::from_static(NAME)
}

fn reader() -> ModuleName {
    ModuleName::from_static(crate::reader::NAME)
}

fn ellas() -> Partition {
    Partition::Member(ella())
}

fn noes() -> Partition {
    Partition::Member(noe())
}

fn item(title: &str, quantity: i64) -> Vec<(&'static str, Value)> {
    vec![
        ("title", text(title)),
        ("quantity", Value::Integer(quantity)),
    ]
}

/// What a call of a tool of the reference module made: the call, its invocation and its result.
struct Called {
    call: Call,
    invocation: Invocation,
    result: Result<CallResult<()>, HandlerError>,
}

impl Called {
    fn committed(&self) -> &vilicus_core::record::CallOutcome<()> {
        match &self.result {
            Ok(CallResult::Committed(outcome)) => outcome,
            other => panic!("{other:?}"),
        }
    }

    fn key(&self) -> CallKey<'_> {
        key(&self.call, &self.invocation)
    }
}

/// Calls the reference module's tool `tool` in `partition` with `arguments`, as `member`'s own
/// action, through `handlers` and the boundary of AD-9.
fn call_tool(
    house: &House,
    partition: Partition,
    registry: &Registry,
    handlers: Handlers,
    tool: &str,
    arguments: &[(&str, Value)],
    member: Id,
) -> Called {
    let call = own_action(member);
    let invocation = house.invocation();
    let handle = house
        .files(partition)
        .and_then(|files| files.handle(&reference()))
        .expect("an open file");
    let result = house.with_boundary(partition, registry, |boundary| {
        handlers.call_tool(
            boundary,
            handle,
            tool,
            arguments,
            &call,
            &invocation,
            &mut *house.stamper(),
        )
    });
    Called {
        call,
        invocation,
        result,
    }
}

fn add_item(house: &House, partition: Partition, title: &str, quantity: i64) -> Called {
    call_tool(
        house,
        partition,
        &REGISTRY,
        HANDLERS,
        "add_item",
        &item(title, quantity),
        ella(),
    )
}

fn every_file_is_ready(report: &BringUpReport) {
    assert_eq!(report.files.len(), REGISTRY.modules().len());
    for (module, outcome) in &report.files {
        assert!(
            matches!(outcome, FileOutcome::Ready),
            "{module}: {outcome:?}"
        );
    }
}

fn rows(house: &House, module: &ModuleName, partition: Partition, sql: &str) -> Vec<Vec<SqlValue>> {
    house
        .files(partition)
        .and_then(|files| files.handle(module))
        .expect("an open file")
        .query_values(sql, &[])
        .expect("read")
}

fn blob(id: Id) -> SqlValue {
    SqlValue::Blob(id.to_bytes().to_vec())
}

/// AC3 (FR-23, AD-23, D149): the reference module's two migrations run in sequence through the
/// migration runner, each on a copy swapped in at a partition's unlock: the first when the file is
/// new, the second at the unlock after its release, which keeps the record written in between and
/// adds the note field and the journal kind; each run records the frozen hash of what it ran, the
/// second keeps the file at version 1 as its cold copy, and the event written at version 1 is
/// delivered only once the file is migrated (AD-29).
#[test]
fn the_two_migrations_run_in_sequence_through_the_runner() {
    let mut house = House::new("migrations", &REGISTRY, &[Partition::Household]);
    let report = house.unlock(Partition::Household, &REGISTRY_AT_1, HANDLERS_AT_1);
    every_file_is_ready(&report);
    let version = |house: &House| {
        let handle = house
            .files(Partition::Household)
            .and_then(|files| files.handle(&reference()))
            .expect("an open file");
        (
            handle.schema_version(MigrationTrack::Module).expect("read"),
            handle
                .migration_hashes(MigrationTrack::Module)
                .expect("read"),
        )
    };
    assert_eq!(version(&house), (1, vec![MIGRATIONS[0].sha256]));
    let columns = rows(
        &house,
        &reference(),
        Partition::Household,
        "SELECT name FROM pragma_table_info('items')",
    );
    assert!(!columns.contains(&vec![SqlValue::Text("note".into())]));

    let added = call_tool(
        &house,
        Partition::Household,
        &REGISTRY_AT_1,
        HANDLERS_AT_1,
        "add_item",
        &item("Pommes", 3),
        ella(),
    );
    let item = added.committed().changes[0].id;
    house.lock(Partition::Household);

    let report = house.unlock(Partition::Household, &REGISTRY, HANDLERS);
    every_file_is_ready(&report);
    assert_eq!(
        version(&house),
        (
            2,
            MIGRATIONS
                .iter()
                .map(|migration| migration.sha256)
                .collect()
        )
    );
    let mut cold_copy = house
        .file(NAME, Partition::Household)
        .path()
        .into_os_string();
    cold_copy.push(format!(".pre-{CORE_SCHEMA_VERSION}.1"));
    assert!(std::path::Path::new(&cold_copy).is_file(), "{cold_copy:?}");
    assert_eq!(
        rows(
            &house,
            &reference(),
            Partition::Household,
            "SELECT id, title, quantity, note FROM items"
        ),
        [vec![
            blob(item),
            SqlValue::Text("Pommes".into()),
            SqlValue::Integer(3),
            SqlValue::Null
        ]]
    );
    assert!(
        rows(
            &house,
            &reference(),
            Partition::Household,
            "SELECT id FROM entries"
        )
        .is_empty(),
        "the journal kind the second migration adds"
    );
    let (_, delivered) = report
        .deliveries
        .iter()
        .find(|(module, _)| *module == reference())
        .expect("the reference file's outbox was delivered");
    let delivered = delivered.as_ref().expect("the pass ran");
    let consumers: Vec<(&str, bool)> = delivered
        .deliveries
        .iter()
        .map(|delivery| {
            (
                delivery.consumer.as_str(),
                matches!(delivery.outcome, DeliveryOutcome::Delivered),
            )
        })
        .collect();
    assert_eq!(
        consumers,
        [("reference.tally_item", true), ("reader.copy_item", true)]
    );
}

/// AC3 (AD-9, AD-26, AD-28, AD-29): a call of the reference module's tier 1 tool writes its item
/// through the typed record API, the Core stamping its envelope and journaling it in the call's
/// transaction, and in the same transaction emits its event and writes its effect intent, which
/// waits in the outbox for the Core to perform it after the commit.
#[test]
fn a_tool_call_writes_through_the_journal_and_emits_its_event_and_effect_intent() {
    let mut house = House::new("tool", &REGISTRY, &[Partition::Household]);
    every_file_is_ready(&house.unlock(Partition::Household, &REGISTRY, HANDLERS));
    let arguments = [
        ("title", text("Pommes")),
        ("quantity", Value::Integer(3)),
        ("due", text("2026-10-30")),
    ];
    let added = call_tool(
        &house,
        Partition::Household,
        &REGISTRY,
        HANDLERS,
        "add_item",
        &arguments,
        ella(),
    );
    let outcome = added.committed();
    assert_eq!(outcome.changes.len(), 1);
    let change = &outcome.changes[0];
    assert_eq!(
        (change.table.as_str(), change.before, change.after),
        ("items", None, Some(Rev::FIRST))
    );
    let item = change.id;
    let mut business_key = b"Pommes\0".to_vec();
    business_key.extend_from_slice(&3_i64.to_be_bytes());
    assert_eq!(outcome.effects.len(), 1);
    assert_eq!(outcome.effects[0].effect, PUBLISH_ITEM);
    assert_eq!(outcome.effects[0].idempotency_key, business_key);

    assert_eq!(
        rows(
            &house,
            &reference(),
            Partition::Household,
            "SELECT title, status, quantity, due, category, note, source, taint, text_taint, \
             data_types, author, rev FROM items"
        ),
        [vec![
            SqlValue::Text("Pommes".into()),
            SqlValue::Text("open".into()),
            SqlValue::Integer(3),
            SqlValue::Text("2026-10-30".into()),
            SqlValue::Null,
            SqlValue::Null,
            SqlValue::Text(Source::Member(ella()).to_string()),
            SqlValue::Text("trusted".into()),
            SqlValue::Text("trusted".into()),
            SqlValue::Text("household_other".into()),
            blob(ella()),
            SqlValue::Integer(1),
        ]]
    );
    let handle = house
        .files(Partition::Household)
        .and_then(|files| files.handle(&reference()))
        .expect("an open file");
    let journal = handle
        .journaled_call(&added.key())
        .expect("read the journal");
    assert_eq!(journal.len(), 1);
    let row = &journal[0];
    assert_eq!(
        (
            row.table.as_str(),
            row.record,
            row.rev_before,
            row.rev_after,
            row.member
        ),
        ("items", item, None, Some(Rev::FIRST), Some(ella()))
    );
    assert!(row.image_before.is_none() && row.image_after.is_some());
    assert!(decode_inputs(&row.inputs).expect("decode").is_empty());

    let effects = handle
        .effects_of_call(&added.key())
        .expect("read the outbox");
    assert_eq!(effects.len(), 1);
    assert_eq!(
        (
            effects[0].effect.as_str(),
            effects[0].state,
            effects[0].payload.as_slice()
        ),
        (
            PUBLISH_ITEM,
            EffectState::Pending,
            item.to_bytes().as_slice()
        )
    );
    let events = handle.outbox_events().expect("read the outbox");
    assert_eq!(events.len(), 1);
    assert_eq!(
        (
            events[0].topic.as_str(),
            events[0].version,
            events[0].record,
            events[0].call_id,
            events[0].payload.as_slice(),
            events[0].state
        ),
        (
            ITEM_ADDED,
            ITEM_ADDED_VERSION,
            item,
            added.invocation.call_id,
            3_i64.to_be_bytes().as_slice(),
            OutboxState::Pending
        )
    );
}

/// AC3 and AC5 (AD-10, AD-27, AD-5): the item's event reaches the reference module's own consumer
/// and the second module's, each in a call of its own with principal `Event`, journaled in its
/// file with the item as an implicit input and recorded in `_consumed`; the second module's
/// consumer reads the item through the reference module's typed API, its copy deriving from it.
/// A second pass delivers nothing.
#[test]
fn the_event_reaches_both_consumers_whose_calls_are_journaled() {
    let mut house = House::new("event", &REGISTRY, &[Partition::Household]);
    every_file_is_ready(&house.unlock(Partition::Household, &REGISTRY, HANDLERS));
    let added = add_item(&house, Partition::Household, "Pommes", 3);
    let item = added.committed().changes[0].id;
    let source = house
        .files(Partition::Household)
        .and_then(|files| files.handle(&reference()))
        .expect("an open file");
    let event = source.outbox_events().expect("read")[0].id;

    let report = house.deliver(NAME, Partition::Household, &REGISTRY, HANDLERS);
    let outcomes: Vec<(&str, bool)> = report
        .deliveries
        .iter()
        .map(|delivery| {
            (
                delivery.consumer.as_str(),
                matches!(delivery.outcome, DeliveryOutcome::Delivered),
            )
        })
        .collect();
    assert_eq!(
        outcomes,
        [("reference.tally_item", true), ("reader.copy_item", true)]
    );
    assert_eq!(report.closed, [event]);
    assert!(report.alerts.is_empty(), "{:?}", report.alerts);

    let consumer_call = Call {
        principal: Principal::Event,
        source: Source::Event(event),
        ..own_action(ella())
    };
    for (module, table, consumer, fields) in [
        (reference(), "tallies", "tally_item", "item, quantity"),
        (reader(), "copies", "copy_item", "item, quantity, title"),
    ] {
        let handle = house
            .files(Partition::Household)
            .and_then(|files| files.handle(&module))
            .expect("an open file");
        assert!(
            handle.is_consumed(event, consumer).expect("read"),
            "{consumer}"
        );
        assert_eq!(
            source
                .delivery(event, &format!("{module}.{consumer}"))
                .expect("read")
                .map(|row| row.state),
            Some(DeliveryState::Delivered)
        );
        let journal = handle
            .journaled_call(&key(&consumer_call, &added.invocation))
            .expect("read the journal");
        assert_eq!(journal.len(), 1, "{consumer}");
        assert_eq!(journal[0].table, table);
        let inputs = decode_inputs(&journal[0].inputs).expect("decode");
        assert_eq!(inputs.len(), 1, "{consumer}: the event's record, once");
        assert_eq!((inputs[0].id, inputs[0].implicit), (item, true));
        assert_eq!(inputs[0].text_taint, "trusted");
        let stored = rows(
            &house,
            &module,
            Partition::Household,
            &format!("SELECT {fields}, taint, source FROM {table}"),
        );
        let mut expected = vec![blob(item), SqlValue::Integer(3)];
        if table == "copies" {
            expected.push(SqlValue::Text("Pommes".into()));
        }
        expected.push(SqlValue::Text("trusted".into()));
        expected.push(SqlValue::Text(Source::Event(event).to_string()));
        assert_eq!(stored, [expected], "{consumer}");
    }

    let again = house.deliver(NAME, Partition::Household, &REGISTRY, HANDLERS);
    assert!(again.deliveries.is_empty() && again.closed.is_empty());
}

/// AC3 (I13, AD-26, AD-28): the reference module's undo handler, called through the handler table
/// for a call of its tier 1 tool, receives the effects that call requested and compensates each
/// with an effect intent of its own, keyed by the effect it undoes.
#[test]
fn the_undo_handler_compensates_the_effects_of_the_call_it_undoes() {
    let mut house = House::new("undo", &REGISTRY, &[Partition::Household]);
    every_file_is_ready(&house.unlock(Partition::Household, &REGISTRY, HANDLERS));
    let added = add_item(&house, Partition::Household, "Pommes", 3);
    let handle = house
        .files(Partition::Household)
        .and_then(|files| files.handle(&reference()))
        .expect("an open file");
    let published = handle.effects_of_call(&added.key()).expect("read");
    let undone: Vec<UndoneEffect<'_>> = published
        .iter()
        .map(|effect| UndoneEffect {
            id: effect.id,
            effect: &effect.effect,
            idempotency_key: &effect.idempotency_key,
            payload: &effect.payload,
        })
        .collect();
    let undo = UndoCall::new("add_item", added.invocation.call_id, &undone);
    let call = own_action(ella());
    let invocation = house.invocation();
    let result = house.with_boundary(Partition::Household, &REGISTRY, |boundary| {
        HANDLERS.call_undo(
            boundary,
            handle,
            &undo,
            &call,
            &invocation,
            &mut *house.stamper(),
        )
    });
    let Ok(CallResult::Committed(outcome)) = result else {
        panic!("{result:?}");
    };
    assert!(outcome.changes.is_empty());
    assert_eq!(outcome.effects.len(), 1);
    assert_eq!(outcome.effects[0].effect, WITHDRAW_ITEM);
    assert_eq!(
        outcome.effects[0].idempotency_key,
        published[0].id.to_bytes()
    );
    let pending: Vec<(String, Vec<u8>)> = handle
        .effects_in_state(EffectState::Pending)
        .expect("read")
        .into_iter()
        .map(|effect| (effect.effect, effect.payload))
        .collect();
    assert_eq!(
        pending,
        [
            (PUBLISH_ITEM.to_owned(), published[0].payload.clone()),
            (WITHDRAW_ITEM.to_owned(), published[0].payload.clone()),
        ]
    );
}

/// AC2 (FR-22): the tier 0 tool runs through the handler table and writes nothing, so it leaves
/// no journal row and no outbox row; a call that writes nothing runs again when repeated.
#[test]
fn the_tier_0_tool_runs_and_writes_nothing() {
    let mut house = House::new("read-tool", &REGISTRY, &[Partition::Household]);
    every_file_is_ready(&house.unlock(Partition::Household, &REGISTRY, HANDLERS));
    let listed = call_tool(
        &house,
        Partition::Household,
        &REGISTRY,
        HANDLERS,
        "list_items",
        &[("status", text("open"))],
        ella(),
    );
    let outcome = listed.committed();
    assert!(outcome.changes.is_empty() && outcome.effects.is_empty());
    let handle = house
        .files(Partition::Household)
        .and_then(|files| files.handle(&reference()))
        .expect("an open file");
    assert!(
        handle
            .journaled_call(&listed.key())
            .expect("read")
            .is_empty()
    );
    assert!(handle.outbox_events().expect("read").is_empty());
}

/// AC1 (FR-58, D98, D104): a write of the reference module holds every value to its declaration:
/// a label no adult confirmed in the file, or a quantity outside its bounds, refuses the whole
/// call, and nothing of it is stored.
#[test]
fn a_value_outside_its_declaration_or_an_unconfirmed_label_refuses_the_call() {
    let mut house = House::new("refused", &REGISTRY, &[Partition::Household]);
    every_file_is_ready(&house.unlock(Partition::Household, &REGISTRY, HANDLERS));
    let mut labelled = item("Pommes", 3);
    labelled.push(("category", text("Courses")));
    let called = call_tool(
        &house,
        Partition::Household,
        &REGISTRY,
        HANDLERS,
        "add_item",
        &labelled,
        ella(),
    );
    assert!(
        matches!(
            called.result,
            Err(HandlerError::Refused(RecordError::UnconfirmedLabel {
                table: "items",
                column: "category",
                vocabulary: ITEM_CATEGORY,
            }))
        ),
        "{:?}",
        called.result
    );
    let called = add_item(&house, Partition::Household, "Pommes", 1001);
    assert!(
        matches!(
            called.result,
            Err(HandlerError::Refused(RecordError::Invalid {
                table: "items",
                column: "quantity",
                ..
            }))
        ),
        "{:?}",
        called.result
    );
    assert!(
        rows(
            &house,
            &reference(),
            Partition::Household,
            "SELECT id FROM items"
        )
        .is_empty()
    );
    let handle = house
        .files(Partition::Household)
        .and_then(|files| files.handle(&reference()))
        .expect("an open file");
    assert!(handle.outbox_events().expect("read").is_empty());
}

/// Runs `body` as the second module's code in a call of its file in `partition`, as `member`'s
/// own action, through the boundary of AD-9.
fn as_reader<T>(
    house: &House,
    partition: Partition,
    member: Id,
    body: impl FnOnce(&mut dyn vilicus_module_api::Records) -> Result<T, WriteError>,
) -> Result<CallResult<T>, HandlerError> {
    let handle = house
        .files(partition)
        .and_then(|files| files.handle(&reader()))
        .expect("an open file");
    let invocation = house.invocation();
    house.with_boundary(partition, &REGISTRY, |boundary| {
        boundary.run(
            handle,
            &READER,
            &own_action(member),
            &invocation,
            &mut *house.stamper(),
            body,
        )
    })
}

/// AC5 (AD-5, FR-19, I6): the second module reads the reference module's items only through its
/// query, which returns the fields it names and nothing of the envelope; a call in Ella's partition
/// reads her items and the household's, never Noé's, and a household call never reads hers.
#[test]
fn the_second_module_reads_reference_items_through_the_typed_api_within_its_scope() {
    let mut house = House::new("scope", &REGISTRY, &[Partition::Household, ellas(), noes()]);
    for partition in [Partition::Household, ellas(), noes()] {
        every_file_is_ready(&house.unlock(partition, &REGISTRY, HANDLERS));
    }
    let id = |house: &House, partition, title| {
        add_item(house, partition, title, 3).committed().changes[0].id
    };
    let household = id(&house, Partition::Household, "Pommes");
    let hers = id(&house, ellas(), "Poires");
    let his = id(&house, noes(), "Prunes");

    let read = |partition, item| match as_reader(&house, partition, ella(), |records| {
        records.read(NAME, "item", item)
    }) {
        Ok(CallResult::Committed(outcome)) => Ok(outcome.value),
        Err(HandlerError::Refused(error)) => Err(error),
        other => panic!("{other:?}"),
    };
    for (item, title) in [(household, "Pommes"), (hers, "Poires")] {
        assert_eq!(
            read(ellas(), item).expect("in Ella's scope"),
            ReadRecord {
                id: item,
                fields: vec![
                    ("title", text(title)),
                    ("status", text("open")),
                    ("quantity", Value::Integer(3)),
                ],
            }
        );
    }
    for (partition, item) in [(ellas(), his), (Partition::Household, hers)] {
        assert!(
            matches!(
                read(partition, item),
                Err(RecordError::RecordNotFound { table: "items" })
            ),
            "{partition}"
        );
    }
}

/// AC5 (I6, AD-5): no module obtains a handle on the reference module's file. The second module's
/// code holds the record port of its call only; its own connections, write and read, refuse to
/// attach the reference module's file; and the reference module's query is served to the modules
/// its access list names only, the reference module itself not among them.
#[test]
fn no_handle_on_the_reference_modules_file_is_obtained() {
    let mut house = House::new("handle", &REGISTRY, &[Partition::Household]);
    every_file_is_ready(&house.unlock(Partition::Household, &REGISTRY, HANDLERS));
    let item = add_item(&house, Partition::Household, "Pommes", 3)
        .committed()
        .changes[0]
        .id;
    let path = house.file(NAME, Partition::Household).path();
    let attach = format!("ATTACH DATABASE '{}' AS reference", path.display());
    let files = house.files(Partition::Household).expect("unlocked");
    let writer = files.handle(&reader()).expect("an open file");
    let refused = writer
        .execute_batch(&attach)
        .expect_err("ATTACH is refused");
    assert!(refused.is_refusal(), "{refused}");
    let reader_handle = vilicus_core::api::ApiFiles::reader(files, &reader(), Partition::Household)
        .expect("an open read handle");
    let refused = reader_handle
        .execute_batch(&attach)
        .expect_err("ATTACH is refused");
    assert!(refused.is_refusal(), "{refused}");

    let called = call_tool(
        &house,
        Partition::Household,
        &REGISTRY,
        HANDLERS,
        "list_items",
        &[],
        ella(),
    );
    assert!(called.result.is_ok());
    let handle = files.handle(&reference()).expect("an open file");
    let invocation = house.invocation();
    let own = house.with_boundary(Partition::Household, &REGISTRY, |boundary| {
        boundary.run(
            handle,
            &REFERENCE,
            &own_action(ella()),
            &invocation,
            &mut *house.stamper(),
            |records| records.read(NAME, "item", item),
        )
    });
    assert!(
        matches!(
            own,
            Err(HandlerError::Refused(RecordError::QueryNotAllowed {
                query: "item"
            }))
        ),
        "{own:?}"
    );
}
