//! Story 3.10, AC5 (AD-5, I6): a module reads another module's record only through the query that
//! module declares, served by the Core: the query's access list names the caller, the file read is
//! ready, its partition is in the caller's scope, and the record read counts as an input of every
//! later write of the call.

use std::cell::RefCell;
use std::path::Path;
use std::time::Duration;

use vilicus_module_api::{
    DataType, Field, FieldKind, ModuleDeclaration, Query, ReadRecord, Records, Structured, Table,
    Value, WriteError,
};
use vilicus_storage::{CallKey, Handle, KeyEpoch, Migration, ModuleFile, Partition, Read, Write};
use vilicus_types::{AvailabilityState, CallId, Id, ModuleName, Principal, Source, Taint};

use super::{ApiFiles, Apis, read_scope};
use crate::availability::{ModuleStates, Stage};
use crate::boundary::{Boundary, HandlerError};
use crate::record::tests::{KEY, create_sql, noon, scratch_dir};
use crate::record::tests_call::{TestStamper, ella, noe};
use crate::record::{
    Authority, Call, CallResult, Consumed, Invocation, RecordError, Stamper, decode_inputs,
    run_call,
};
use crate::registry::{Registry, frozen};

const EPOCH: KeyEpoch = KeyEpoch {
    partition_root_version: 1,
    generation: 0,
};

const ITEMS: Table = Table {
    name: "items",
    data_types: &[DataType::ShoppingList],
    fields: &[
        Field {
            name: "label",
            kind: FieldKind::FreeText { max_len: 200 },
            optional: false,
        },
        Field {
            name: "quantity",
            kind: FieldKind::Structured(Structured::Integer { min: 0, max: 99 }),
            optional: false,
        },
    ],
    elevation_exempt: false,
};

const NOTES: Table = Table {
    name: "notes",
    data_types: &[DataType::ShoppingList],
    fields: &[Field {
        name: "title",
        kind: FieldKind::FreeText { max_len: 200 },
        optional: false,
    }],
    elevation_exempt: false,
};

/// `shop` offers one query, of its items' label alone, to `notes`; `stock` is not in its list.
const ITEM_QUERY: Query = Query {
    name: "item",
    table: "items",
    fields: &["label"],
    callers: &["notes"],
};

fn module(
    name: &'static str,
    table: &'static Table,
    queries: &'static [Query],
) -> &'static ModuleDeclaration {
    Box::leak(Box::new(ModuleDeclaration {
        name,
        tables: std::slice::from_ref(table),
        fts5_tables: &[],
        migrations: vec![frozen(create_sql(table).leak())].leak(),
        matrix_sections: &[],
        tools: &[],
        topics: &[],
        consumers: &[],
        queries,
    }))
}

fn registry() -> Registry {
    Registry::new(
        vec![
            module("shop", &ITEMS, std::slice::from_ref(&ITEM_QUERY)),
            module("notes", &NOTES, &[]),
            module("stock", &NOTES, &[]),
        ]
        .leak(),
    )
    .expect("a valid registry")
}

/// A migrated file of `module` in `partition` under `directory`.
fn new_file(
    directory: &Path,
    module: &'static ModuleDeclaration,
    partition: Partition,
) -> ModuleFile {
    let file = ModuleFile::new(directory, ModuleName::from_static(module.name), partition);
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

/// The read handles of a test, and every file a read asked them for.
struct Readers {
    handles: Vec<Handle<Read>>,
    asked: RefCell<Vec<(String, Partition)>>,
}

impl ApiFiles for Readers {
    fn reader(&self, module: &ModuleName, partition: Partition) -> Option<&Handle<Read>> {
        self.asked
            .borrow_mut()
            .push((module.as_str().to_owned(), partition));
        self.handles.iter().find(|handle| {
            handle.file().module() == module && handle.file().partition() == partition
        })
    }
}

/// Ella's partition, the household's and Noé's: a `shop` file in each, each holding one item a
/// plugin wrote (so `external`), a `notes` file in Ella's partition and the household's, and a
/// `stock` file in the household, every file ready.
struct Fixture {
    registry: Registry,
    states: ModuleStates,
    readers: Readers,
    writers: Vec<Handle<Write>>,
    /// The item of each partition: Ella's, the household's, Noé's.
    items: [Id; 3],
    stamper: RefCell<TestStamper>,
}

#[allow(
    non_snake_case,
    reason = "the partitions read as names in the tables of the tests"
)]
fn ELLA() -> Partition {
    Partition::Member(ella())
}

#[allow(
    non_snake_case,
    reason = "the partitions read as names in the tables of the tests"
)]
fn NOE() -> Partition {
    Partition::Member(noe())
}

impl Fixture {
    fn new(label: &str) -> Self {
        let registry = registry();
        let directory = scratch_dir(label);
        let states = ModuleStates::new();
        let mut stamper = TestStamper::at(noon());
        let mut writers = Vec::new();
        let mut handles = Vec::new();
        let mut items = Vec::new();
        let files = [
            ("shop", ELLA()),
            ("shop", Partition::Household),
            ("shop", NOE()),
            ("notes", ELLA()),
            ("notes", Partition::Household),
            ("stock", Partition::Household),
        ];
        for (name, partition) in files {
            let declaration = registry
                .module(&ModuleName::from_static(name))
                .expect("registered");
            let file = new_file(&directory, declaration, partition);
            let writer = registry.open::<Write>(&file, &KEY).expect("open");
            if name == "shop" {
                items.push(plugin_item(declaration, &writer, partition, &mut stamper));
            }
            handles.push(registry.open::<Read>(&file, &KEY).expect("open"));
            states
                .set_stage(states.generation(partition), file.module(), Stage::Ready)
                .expect("no call runs");
            writers.push(writer);
        }
        Self {
            registry,
            states,
            readers: Readers {
                handles,
                asked: RefCell::new(Vec::new()),
            },
            writers,
            items: items.try_into().expect("three items"),
            stamper: RefCell::new(stamper),
        }
    }

    fn writer(&self, module: &str, partition: Partition) -> &Handle<Write> {
        self.writers
            .iter()
            .find(|handle| {
                handle.file().module().as_str() == module && handle.file().partition() == partition
            })
            .expect("a file of the fixture")
    }

    fn boundary(&self) -> Boundary<'_> {
        Boundary {
            states: &self.states,
            budget: Duration::from_secs(5),
            apis: Some(Apis {
                registry: self.registry,
                files: &self.readers,
            }),
        }
    }

    fn invocation(&self) -> Invocation {
        let mut stamper = self.stamper.borrow_mut();
        let now = stamper.now();
        let id = Id::new_v7(now, stamper.id_random()).expect("after the epoch");
        Invocation {
            call_id: CallId::from(id),
            request_hash: None,
            delivery: None,
        }
    }

    /// Runs `body` as a call of `module` on its file in `partition`, made by a rule an adult
    /// validated: no member made or approved it, so each of its writes derives from its inputs.
    fn rule_call<T>(
        &self,
        module: &str,
        partition: Partition,
        invocation: &Invocation,
        body: impl FnOnce(&mut dyn Records) -> Result<T, WriteError>,
    ) -> Result<CallResult<T>, HandlerError> {
        let handle = self.writer(module, partition);
        let declaration = self
            .registry
            .module(handle.file().module())
            .expect("registered");
        self.boundary().run(
            handle,
            declaration,
            &rule(),
            invocation,
            &mut *self.stamper.borrow_mut(),
            body,
        )
    }

    fn asked(&self) -> Vec<(String, Partition)> {
        self.readers.asked.take()
    }
}

fn rule_id() -> Id {
    Id::from_bytes([
        0x01, 0x92, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0x2a,
    ])
    .expect("a v7 id")
}

fn rule() -> Call {
    Call {
        principal: Principal::Rule,
        source: Source::Rule(rule_id()),
        session: Taint::Trusted,
        consumed: Consumed::NOTHING,
        authority: Authority::Unapproved {
            author: Some(ella()),
            acting_for: None,
        },
        read: Vec::new(),
        implicit_inputs: Vec::new(),
    }
}

/// Inserts an item a plugin delivered into the `shop` file of `writer`: stored `external`.
fn plugin_item(
    shop: &'static ModuleDeclaration,
    writer: &Handle<Write>,
    partition: Partition,
    stamper: &mut TestStamper,
) -> Id {
    let call = Call {
        principal: Principal::Plugin,
        source: Source::Plugin(rule_id()),
        session: Taint::Trusted,
        consumed: Consumed::NOTHING,
        authority: Authority::Unapproved {
            author: None,
            acting_for: None,
        },
        read: Vec::new(),
        implicit_inputs: Vec::new(),
    };
    let now = stamper.now();
    let invocation = Invocation {
        call_id: CallId::from(Id::new_v7(now, stamper.id_random()).expect("after the epoch")),
        request_hash: None,
        delivery: None,
    };
    let label = format!("Pommes de {partition}");
    match run_call(writer, shop, &call, &invocation, stamper, |records| {
        records.insert(
            "items",
            &[
                ("label", Value::Text(label)),
                ("quantity", Value::Integer(3)),
            ],
            &[],
        )
    }) {
        Ok(CallResult::Committed(outcome)) => outcome.value.id,
        other => panic!("{other:?}"),
    }
}

fn text(value: &str) -> Value {
    Value::Text(value.into())
}

#[test]
fn the_scope_of_a_call_is_its_partition_then_the_household_for_a_member() {
    assert_eq!(read_scope(ELLA()), [ELLA(), Partition::Household]);
    assert_eq!(read_scope(Partition::Household), [Partition::Household]);
    assert_eq!(read_scope(Partition::Home), [Partition::Home]);
}

/// AC5 (AD-5, AD-7): `notes` reads the household's item through `shop`'s query and writes a note
/// from it without naming it: the read returns the field the query names, nothing else, and the
/// note derives from the item anyway, `external` as the item, the read journaled as an implicit
/// input. Without the read the same write has no input and is refused.
#[test]
fn a_read_through_a_query_returns_its_fields_and_every_later_write_derives_from_it() {
    let fixture = Fixture::new("api-read");
    let item = fixture.items[1];
    let invocation = fixture.invocation();
    let result = fixture.rule_call("notes", Partition::Household, &invocation, |records| {
        let read = records.read("shop", "item", item)?;
        let Some(Value::Text(label)) = read.field("label").cloned() else {
            panic!("{read:?}");
        };
        records.insert("notes", &[("title", Value::Text(label))], &[])?;
        Ok(read)
    });
    let CallResult::Committed(outcome) = result.expect("the call commits") else {
        panic!("not committed");
    };
    assert_eq!(
        outcome.value,
        ReadRecord {
            id: item,
            fields: vec![("label", text("Pommes de household"))],
        }
    );
    assert!(outcome.value.field("quantity").is_none());
    assert_eq!(fixture.asked(), [("shop".to_owned(), Partition::Household)]);
    let note = &outcome.changes[0];
    assert_eq!(note.inputs, [item]);
    let notes = fixture.writer("notes", Partition::Household);
    let stored = notes
        .query_values(
            "SELECT taint, text_taint, data_types, title FROM notes",
            &[],
        )
        .expect("read");
    assert_eq!(
        format!("{stored:?}"),
        r#"[[Text("external"), Text("external"), Text("shopping_list"), Text("Pommes de household")]]"#
    );
    let source = rule().source;
    let journal = notes
        .journaled_call(&CallKey {
            principal: Principal::Rule,
            source: &source,
            call_id: invocation.call_id,
        })
        .expect("read the journal");
    let inputs = decode_inputs(&journal[0].inputs).expect("decode");
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].id, item);
    assert!(inputs[0].implicit, "the read counts as an implicit input");
    assert_eq!(inputs[0].text_taint, "external");

    let unread = fixture.rule_call(
        "notes",
        Partition::Household,
        &fixture.invocation(),
        |records| records.insert("notes", &[("title", text("Pommes"))], &[]),
    );
    assert!(
        matches!(
            unread,
            Err(HandlerError::Refused(RecordError::MissingInputs {
                table: "notes"
            }))
        ),
        "{unread:?}"
    );
}

/// AC5 (AD-5): a query no module offers, and a caller its access list does not name, are refused,
/// and the refusal ends the call like a refused write: nothing of it is stored.
#[test]
fn a_read_is_refused_unless_the_module_offers_the_query_to_the_caller() {
    let fixture = Fixture::new("api-refused");
    let item = fixture.items[1];
    for (module, caller, query, expected) in [
        ("shop", "notes", "items", WriteError::UnknownQuery),
        ("absent", "notes", "item", WriteError::UnknownQuery),
        ("shop", "stock", "item", WriteError::QueryNotAllowed),
    ] {
        let mut seen = None;
        let result = fixture.rule_call(
            caller,
            Partition::Household,
            &fixture.invocation(),
            |records| {
                let refused = records.read(module, query, item).map(|_| ());
                let later = records.insert("notes", &[("title", text("après"))], &[]);
                seen = Some((refused, later.map(|_| ())));
                Ok(())
            },
        );
        assert_eq!(
            seen,
            Some((Err(expected), Err(WriteError::CallRefused))),
            "{module}.{query} by {caller}"
        );
        match (expected, result) {
            (WriteError::UnknownQuery, Err(HandlerError::Refused(RecordError::UnknownQuery)))
            | (
                WriteError::QueryNotAllowed,
                Err(HandlerError::Refused(RecordError::QueryNotAllowed { query: "item" })),
            ) => {}
            (_, other) => panic!("{module}.{query} by {caller}: {other:?}"),
        }
        let rows = fixture
            .writer(caller, Partition::Household)
            .query_values("SELECT id FROM notes", &[])
            .expect("read");
        assert!(rows.is_empty());
    }
    assert!(
        fixture.asked().is_empty(),
        "no file is asked for a refused query"
    );
}

/// AC5 (AD-5, FR-19): a call reads in its own partition, then in the household's when it is a
/// member's, and nowhere else: the Core never asks for a file outside that scope, so a record of
/// another member's partition, or a member's record from the household, is not found.
#[test]
fn a_read_searches_the_callers_partition_then_the_household_and_nothing_else() {
    let fixture = Fixture::new("api-scope");
    let [ellas, household, noes] = fixture.items;
    let read = |partition: Partition, item: Id| {
        let result = fixture.rule_call("notes", partition, &fixture.invocation(), |records| {
            records.read("shop", "item", item)
        });
        (result, fixture.asked())
    };
    let (result, asked) = read(ELLA(), ellas);
    assert!(matches!(result, Ok(CallResult::Committed(_))), "{result:?}");
    assert_eq!(asked, [("shop".to_owned(), ELLA())]);
    let (result, asked) = read(ELLA(), household);
    assert!(matches!(result, Ok(CallResult::Committed(_))), "{result:?}");
    assert_eq!(
        asked,
        [
            ("shop".to_owned(), ELLA()),
            ("shop".to_owned(), Partition::Household)
        ]
    );
    for (partition, item, scope) in [
        (ELLA(), noes, vec![ELLA(), Partition::Household]),
        (Partition::Household, ellas, vec![Partition::Household]),
        (Partition::Household, noes, vec![Partition::Household]),
    ] {
        let (result, asked) = read(partition, item);
        assert!(
            matches!(
                result,
                Err(HandlerError::Refused(RecordError::RecordNotFound {
                    table: "items"
                }))
            ),
            "{partition}: {result:?}"
        );
        let expected: Vec<_> = scope
            .into_iter()
            .map(|partition| ("shop".to_owned(), partition))
            .collect();
        assert_eq!(asked, expected, "{partition}");
        assert!(asked.iter().all(|(_, asked)| *asked != NOE()));
    }
}

/// AC5 (AD-54): a file in scope that is not ready answers `module_unavailable` with its state's
/// retry class before any read; a file the states report ready whose read connection the Core
/// does not hold answers `opening`.
#[test]
fn a_read_of_a_file_that_is_not_ready_is_module_unavailable() {
    let fixture = Fixture::new("api-unavailable");
    let household = fixture.items[1];
    let shop = ModuleName::from_static("shop");
    fixture.states.deactivate(&shop, Partition::Household);
    let result = fixture.rule_call(
        "notes",
        Partition::Household,
        &fixture.invocation(),
        |records| records.read("shop", "item", household),
    );
    match result {
        Err(HandlerError::Refused(RecordError::Unavailable(unavailable))) => {
            assert_eq!(unavailable.state(), AvailabilityState::Deactivated);
            assert_eq!(unavailable.partition(), Partition::Household);
        }
        other => panic!("{other:?}"),
    }
    assert!(fixture.asked().is_empty(), "no connection is asked for");
    fixture.states.activate(&shop, Partition::Household);

    let mut fixture = fixture;
    fixture
        .readers
        .handles
        .retain(|handle| handle.file().partition() != Partition::Household);
    let result = fixture.rule_call(
        "notes",
        Partition::Household,
        &fixture.invocation(),
        |records| records.read("shop", "item", household),
    );
    match result {
        Err(HandlerError::Refused(RecordError::Unavailable(unavailable))) => {
            assert_eq!(unavailable.state(), AvailabilityState::Opening);
        }
        other => panic!("{other:?}"),
    }
}

/// A call run outside the boundary serves no typed API, and a boundary without one neither: every
/// read is refused.
#[test]
fn a_call_without_typed_apis_refuses_every_read() {
    let fixture = Fixture::new("api-none");
    let item = fixture.items[1];
    let notes = fixture.writer("notes", Partition::Household);
    let declaration = fixture
        .registry
        .module(notes.file().module())
        .expect("registered");
    let invocation = fixture.invocation();
    let result = run_call(
        notes,
        declaration,
        &rule(),
        &invocation,
        &mut *fixture.stamper.borrow_mut(),
        |records| records.read("shop", "item", item),
    );
    assert!(
        matches!(result, Err(RecordError::UnknownQuery)),
        "{result:?}"
    );
    let boundary = Boundary {
        apis: None,
        ..fixture.boundary()
    };
    let result = boundary.run(
        notes,
        declaration,
        &rule(),
        &fixture.invocation(),
        &mut *fixture.stamper.borrow_mut(),
        |records| records.read("shop", "item", item),
    );
    assert!(
        matches!(
            result,
            Err(HandlerError::Refused(RecordError::UnknownQuery))
        ),
        "{result:?}"
    );
}
