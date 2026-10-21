//! The release gate of AD-9 that needs a module (D102): a panicking reference handler leaves the
//! unlocked members unlocked, and the other files and partitions serving.
//!
//! Until the unlock path of the Core process exists (Stories 4.3, 5.1), a partition is unlocked
//! here as the Core marks it once its keys are derived (`ModuleStates::unlock_partition`) and
//! brought up through the Core's own bring-up; the gate's run against the `vilicus-testbed`
//! executable in the Debian VM, with a member's real unlock, is Story 14.1's (AC3).

use vilicus_core::availability::Fault;
use vilicus_core::boundary::HandlerError;
use vilicus_core::handlers::Handlers;
use vilicus_core::record::{CallOutcome, CallResult};
use vilicus_core::testing::Partition;
use vilicus_mod_reference::{NAME, REFERENCE_CODE};
use vilicus_module_api::{ModuleCode, Records, ToolCall, ToolHandler, Value, WriteError};
use vilicus_types::{AvailabilityState, ClientFacingError, ModuleName, RetryClass};

use crate::reader::READER_CODE;
use crate::registry::{HANDLERS, REGISTRY};
use crate::support::{House, ella, noe, own_action, text};

/// The reference module's `add_item`, made to panic once it wrote: the handler of a module whose
/// code has a defect.
fn add_item_then_panic(call: &ToolCall<'_>, records: &mut dyn Records) -> Result<(), WriteError> {
    let fields: Vec<(&str, Value)> = call
        .arguments()
        .iter()
        .map(|(name, value)| (*name, value.clone()))
        .chain([("status", text("open"))])
        .collect();
    records.insert("items", &fields, &[])?;
    panic!("a defect of the reference module");
}

/// The reference module's code with its tier 1 tool panicking, bound to the same declaration.
const PANICKING_REFERENCE_CODE: ModuleCode = ModuleCode {
    tools: &[
        REFERENCE_CODE.tools[0],
        ToolHandler {
            tool: "add_item",
            run: add_item_then_panic,
        },
    ],
    ..REFERENCE_CODE
};

const PANICKING: Handlers =
    match Handlers::new(REGISTRY, &[&PANICKING_REFERENCE_CODE, &READER_CODE]) {
        Ok(handlers) => handlers,
        Err(error) => panic!("{}", error.rule()),
    };

fn reference() -> ModuleName {
    ModuleName::from_static(NAME)
}

/// Calls `add_item` of the reference module in `partition` through `handlers`, as Ella's own
/// action, for an item of `title`.
fn add_item(
    house: &House,
    partition: Partition,
    handlers: Handlers,
    title: &str,
) -> Result<CallResult<()>, HandlerError> {
    let handle = house
        .files(partition)
        .and_then(|files| files.handle(&reference()))
        .expect("an open file");
    let invocation = house.invocation();
    house.with_boundary(partition, &REGISTRY, |boundary| {
        handlers.call_tool(
            boundary,
            handle,
            "add_item",
            &[("title", text(title)), ("quantity", Value::Integer(3))],
            &own_action(ella()),
            &invocation,
            &mut *house.stamper(),
        )
    })
}

fn committed<T: std::fmt::Debug>(result: Result<CallResult<T>, HandlerError>) -> CallOutcome<T> {
    match result {
        Ok(CallResult::Committed(outcome)) => outcome,
        other => panic!("{other:?}"),
    }
}

/// AD-9, AC6 of Story 3.9, Story 14.1 AC3: Ella, Noé and the household are unlocked; the
/// reference module's handler panics in Ella's partition. The panic is caught at the boundary,
/// its call rolled back and the module faulted there with an alert; every partition stays
/// unlocked, under the generation of its unlock; the second module keeps serving in Ella's
/// partition, reading through the typed API, and the reference module keeps serving in the
/// household's and Noé's, while in Ella's it receives no further call.
#[test]
fn a_panicking_reference_handler_leaves_unlocked_members_unlocked() {
    let ellas = Partition::Member(ella());
    let noes = Partition::Member(noe());
    let partitions = [Partition::Household, ellas, noes];
    let mut house = House::new("panic-gate", &REGISTRY, &partitions);
    for partition in partitions {
        house.unlock(partition, &REGISTRY, HANDLERS);
    }
    let item = committed(add_item(&house, Partition::Household, HANDLERS, "Pommes")).changes[0].id;

    let panicked = add_item(&house, ellas, PANICKING, "Poires");
    let Err(HandlerError::Faulted {
        fault: Fault::Panicked,
        alert: Some(_),
    }) = panicked
    else {
        panic!("{panicked:?}");
    };
    assert!(
        house
            .files(ellas)
            .and_then(|files| files.handle(&reference()))
            .expect("an open file")
            .query_values("SELECT id FROM items", &[])
            .expect("read")
            .is_empty(),
        "the call was rolled back"
    );

    for partition in partitions {
        assert!(
            house.states.is_current(house.generation(partition)),
            "{partition} is still unlocked"
        );
    }
    assert_eq!(
        house.states.state(&reference(), ellas),
        AvailabilityState::Faulted
    );
    assert_eq!(
        house.states.state(&reference(), Partition::Household),
        AvailabilityState::Ready
    );
    let reader = ModuleName::from_static(crate::reader::NAME);
    for partition in partitions {
        assert_eq!(
            house.states.state(&reader, partition),
            AvailabilityState::Ready
        );
    }

    let handle = house
        .files(ellas)
        .and_then(|files| files.handle(&reader))
        .expect("an open file");
    let invocation = house.invocation();
    let read = house.with_boundary(ellas, &REGISTRY, |boundary| {
        boundary.run(
            handle,
            &crate::reader::READER,
            &own_action(ella()),
            &invocation,
            &mut *house.stamper(),
            |records| {
                let item = records.read(NAME, "item", item)?;
                records.insert(
                    "copies",
                    &[
                        ("item", Value::Blob(item.id.to_bytes().to_vec())),
                        ("title", text("Pommes")),
                        ("quantity", Value::Integer(3)),
                    ],
                    &[],
                )
            },
        )
    });
    committed(read);

    for partition in [Partition::Household, noes] {
        committed(add_item(&house, partition, HANDLERS, "Prunes"));
    }
    match add_item(&house, ellas, HANDLERS, "Poires") {
        Err(HandlerError::Unavailable(unavailable)) => {
            assert_eq!(unavailable.state(), AvailabilityState::Faulted);
            assert_eq!(unavailable.retry_class(), RetryClass::NotRetryable);
        }
        other => panic!("{other:?}"),
    }
}
