//! Story 3.10, AC5 (AD-5, I6): a module reads another module's record only through the query that
//! module declares, served by the Core: the query's access list names the caller, the file read is
//! ready, its partition is in the caller's scope, the read keeps the file from being migrated, and
//! the record read counts as an input of every later write, event and journal row of the call.

use std::cell::RefCell;
use std::path::Path;
use std::time::Duration;

use vilicus_module_api::{
    Consumer, DataType, Field, FieldKind, ModuleDeclaration, Query, ReadRecord, Records,
    Structured, Table, Topic, Value, WriteError,
};
use vilicus_storage::{CallKey, Handle, KeyEpoch, Migration, ModuleFile, Partition, Read, Write};
use vilicus_types::{
    AvailabilityState, CallId, Id, ModuleName, Principal, RecordLabels, Source, Taint,
};

use super::{ApiFiles, Apis, read_scope};
use crate::availability::{ModuleStates, Stage, StageRefused};
use crate::boundary::{Boundary, HandlerError};
use crate::record::tests::{KEY, create_sql, noon, scratch_dir};
use crate::record::tests_call::{TestStamper, ella, noe};
use crate::record::{
    Authority, Call, CallResult, Consumed, Invocation, RecordError, RecordProvenance, Stamper,
    decode_inputs, run_call,
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

/// The `shop` diary: entries of the journal data type, which the provider policy keeps local.
const DIARY: Table = Table {
    name: "diary",
    data_types: &[DataType::Journal],
    fields: &[Field {
        name: "body",
        kind: FieldKind::FreeText { max_len: 200 },
        optional: false,
    }],
    elevation_exempt: false,
};

/// `shop` offers its items' label alone to `notes` and `stock`, and its diary entries to `notes`
/// only.
const QUERIES: &[Query] = &[
    Query {
        name: "item",
        table: "items",
        fields: &["label"],
        callers: &["notes", "stock"],
    },
    Query {
        name: "entry",
        table: "diary",
        fields: &["body"],
        callers: &["notes"],
    },
];

const NOTE_ADDED: &str = "notes.note.added";

const NOTE_TOPICS: &[Topic] = &[Topic {
    name: NOTE_ADDED,
    version: 1,
    consumers: &["stock"],
}];

const STOCK_CONSUMERS: &[Consumer] = &[Consumer {
    name: "count",
    topic: NOTE_ADDED,
}];

fn module(
    name: &'static str,
    tables: &'static [Table],
    topics: &'static [Topic],
    consumers: &'static [Consumer],
    queries: &'static [Query],
) -> &'static ModuleDeclaration {
    let create: Vec<String> = tables.iter().map(create_sql).collect();
    Box::leak(Box::new(ModuleDeclaration {
        name,
        tables,
        fts5_tables: &[],
        migrations: vec![frozen(create.join("\n").leak())].leak(),
        matrix_sections: &[],
        tools: &[],
        topics,
        consumers,
        queries,
    }))
}

fn registry() -> Registry {
    Registry::new(
        vec![
            module("shop", &[ITEMS, DIARY], &[], &[], QUERIES),
            module("notes", &[NOTES], NOTE_TOPICS, &[], &[]),
            module("stock", &[NOTES], &[], STOCK_CONSUMERS, &[]),
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
    /// The household's diary entry, of the journal data type.
    entry: Id,
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
        let mut entry = None;
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
                if partition == Partition::Household {
                    entry = Some(plugin_write(
                        declaration,
                        &writer,
                        &mut stamper,
                        |records| records.insert("diary", &[("body", text("Une journée"))], &[]),
                    ));
                }
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
            entry: entry.expect("the household's entry"),
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
    let label = format!("Pommes de {partition}");
    plugin_write(shop, writer, stamper, |records| {
        records.insert(
            "items",
            &[
                ("label", Value::Text(label)),
                ("quantity", Value::Integer(3)),
            ],
            &[],
        )
    })
}

/// Runs `insert` as a call of a plugin on the `shop` file of `writer`, so what it inserts is
/// stored `external`, and returns the id it inserted.
fn plugin_write(
    shop: &'static ModuleDeclaration,
    writer: &Handle<Write>,
    stamper: &mut TestStamper,
    insert: impl FnOnce(&mut dyn Records) -> Result<vilicus_module_api::Written, WriteError>,
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
    match run_call(writer, shop, &call, &invocation, stamper, insert) {
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
        ("shop", "stock", "entry", WriteError::QueryNotAllowed),
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
                Err(HandlerError::Refused(RecordError::QueryNotAllowed { query: "entry" })),
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

/// AC5 (AD-54): a file in scope that is not ready is never read; a record it may hold answers
/// `module_unavailable` with its state's retry class, while a record of another file of the scope
/// is served; a file the states report ready whose read connection the Core does not hold answers
/// `opening`.
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

    let [ellas, _, _] = fixture.items;
    fixture.states.deactivate(&shop, ELLA());
    let read = |item| {
        fixture.rule_call("notes", ELLA(), &fixture.invocation(), |records| {
            records.read("shop", "item", item)
        })
    };
    assert!(
        matches!(read(household), Ok(CallResult::Committed(_))),
        "a record of the household's file, the scope's file that serves"
    );
    match read(ellas) {
        Err(HandlerError::Refused(RecordError::Unavailable(unavailable))) => {
            assert_eq!(unavailable.state(), AvailabilityState::Deactivated);
            assert_eq!(unavailable.partition(), ELLA());
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        fixture.asked(),
        [
            ("shop".to_owned(), Partition::Household),
            ("shop".to_owned(), Partition::Household)
        ],
        "the file that is not ready is never asked for"
    );
    fixture.states.activate(&shop, ELLA());

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

/// Read connections that answer every request with the `shop` file of Ella's partition.
struct Misplaced<'a> {
    ellas: &'a Handle<Read>,
}

impl ApiFiles for Misplaced<'_> {
    fn reader(&self, _: &ModuleName, _: Partition) -> Option<&Handle<Read>> {
        Some(self.ellas)
    }
}

/// AD-5, FR-19: the Core reads only the file of the module and partition it asked for. A
/// household call reading Ella's item through connections that answer with her file never reads
/// it: the connection of another file counts as a file that is not open.
#[test]
fn a_connection_of_another_file_is_never_read() {
    let fixture = Fixture::new("api-misplaced");
    let ellas = fixture
        .readers
        .handles
        .iter()
        .find(|handle| {
            handle.file().module().as_str() == "shop" && handle.file().partition() == ELLA()
        })
        .expect("Ella's shop file");
    let misplaced = Misplaced { ellas };
    let boundary = Boundary {
        apis: Some(Apis {
            registry: fixture.registry,
            files: &misplaced,
        }),
        ..fixture.boundary()
    };
    let notes = fixture.writer("notes", Partition::Household);
    let declaration = fixture
        .registry
        .module(notes.file().module())
        .expect("registered");
    let hers = fixture.items[0];
    let result = boundary.run(
        notes,
        declaration,
        &rule(),
        &fixture.invocation(),
        &mut *fixture.stamper.borrow_mut(),
        |records| records.read("shop", "item", hers),
    );
    match result {
        Err(HandlerError::Refused(RecordError::Unavailable(unavailable))) => {
            assert_eq!(unavailable.state(), AvailabilityState::Opening);
            assert_eq!(unavailable.partition(), Partition::Household);
        }
        other => panic!("{other:?}"),
    }
}

/// AD-7, D151: a record a call carries as a snapshot and also reads through a typed API counts as
/// both combined, the most restrictive of the two: a `trusted` snapshot, by Ella, of an item stored
/// `external` never lowers the note derived from it for her.
#[test]
fn a_read_of_a_snapshot_the_call_carries_never_lowers_it() {
    let fixture = Fixture::new("api-snapshot");
    let item = fixture.items[1];
    let call = Call {
        implicit_inputs: vec![RecordProvenance {
            id: item,
            labels: RecordLabels::TRUSTED,
            author: Some(ella()),
            data_types: vec![DataType::ShoppingList],
            free_text: Vec::new(),
        }],
        authority: Authority::Unapproved {
            author: Some(ella()),
            acting_for: Some(ella()),
        },
        ..rule()
    };
    let notes = fixture.writer("notes", Partition::Household);
    let declaration = fixture
        .registry
        .module(notes.file().module())
        .expect("registered");
    let read_first = |read: bool| {
        let result = fixture.boundary().run(
            notes,
            declaration,
            &call,
            &fixture.invocation(),
            &mut *fixture.stamper.borrow_mut(),
            |records| {
                if read {
                    records.read("shop", "item", item)?;
                }
                records.insert("notes", &[("title", text("Pommes"))], &[])
            },
        );
        let Ok(CallResult::Committed(outcome)) = result else {
            panic!("{result:?}");
        };
        let stored = notes
            .query_values(
                "SELECT taint FROM notes WHERE id = ?1",
                &[vilicus_storage::SqlValue::Blob(
                    outcome.value.id.to_bytes().to_vec(),
                )],
            )
            .expect("read");
        format!("{stored:?}")
    };
    assert_eq!(read_first(false), r#"[[Text("trusted")]]"#);
    assert_eq!(read_first(true), r#"[[Text("external")]]"#);
}

// Story 3.10 review: what a read leaves on the events, journal rows and deliveries of the call,
// and the file it keeps from being migrated.

/// A record read before the call, `trusted` and of no author: what the rule's writes name.
fn read_before(id: Id) -> RecordProvenance {
    RecordProvenance {
        id,
        labels: RecordLabels::TRUSTED,
        author: None,
        data_types: vec![DataType::ShoppingList],
        free_text: Vec::new(),
    }
}

fn earlier() -> Id {
    Id::from_bytes([
        0x01, 0x92, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0x2b,
    ])
    .expect("a v7 id")
}

/// Runs `body` as a rule's call on the household's `notes` file, the call carrying a `trusted`
/// record read before it, and returns the provenance of the one event the file then holds.
fn emitted_after(
    fixture: &Fixture,
    body: impl FnOnce(&mut dyn Records) -> Result<(), WriteError>,
) -> crate::record::JournaledInput {
    let call = Call {
        read: vec![read_before(earlier())],
        ..rule()
    };
    let handle = fixture.writer("notes", Partition::Household);
    let declaration = fixture
        .registry
        .module(handle.file().module())
        .expect("registered");
    let result = fixture.boundary().run(
        handle,
        declaration,
        &call,
        &fixture.invocation(),
        &mut *fixture.stamper.borrow_mut(),
        body,
    );
    assert!(matches!(result, Ok(CallResult::Committed(_))), "{result:?}");
    let events = handle.outbox_events().expect("read the outbox");
    assert_eq!(events.len(), 1);
    let mut provenance = decode_inputs(&events[0].provenance).expect("decode");
    assert_eq!(provenance.len(), 1);
    provenance.remove(0)
}

/// Review item 1 (AD-7, AD-27, D152), the reviewer's probe: a call writes a `trusted` note, then
/// reads an `external` item through the typed API, then emits an event about the note whose
/// payload is the item's label. The event carries what the call read: `external`.
#[test]
fn an_event_emitted_after_a_read_carries_what_the_call_read() {
    let fixture = Fixture::new("api-event-taint");
    let item = fixture.items[1];
    let provenance = emitted_after(&fixture, |records| {
        let note = records.insert("notes", &[("title", text("Pommes"))], &[earlier()])?;
        let read = records.read("shop", "item", item)?;
        let Some(Value::Text(label)) = read.field("label").cloned() else {
            panic!("{read:?}");
        };
        records.emit(NOTE_ADDED, note.id, label.as_bytes())?;
        Ok(())
    });
    let stored = fixture
        .writer("notes", Partition::Household)
        .query_values("SELECT taint FROM notes", &[])
        .expect("read");
    assert_eq!(format!("{stored:?}"), r#"[[Text("trusted")]]"#);
    assert_eq!(
        (provenance.taint.as_str(), provenance.text_taint.as_str()),
        ("external", "external")
    );
    assert_eq!(provenance.data_types, "shopping_list");
}

/// Review item 1 (D103, D152): an event emitted after the call read a record of a local-only
/// data type keeps that data type, so a consumer's write and the provider policy see it.
#[test]
fn an_event_keeps_the_data_types_of_a_record_the_call_read() {
    let fixture = Fixture::new("api-event-types");
    let entry = fixture.entry;
    let provenance = emitted_after(&fixture, |records| {
        let note = records.insert("notes", &[("title", text("Pommes"))], &[earlier()])?;
        let read = records.read("shop", "entry", entry)?;
        let Some(Value::Text(body)) = read.field("body").cloned() else {
            panic!("{read:?}");
        };
        records.emit(NOTE_ADDED, note.id, body.as_bytes())?;
        Ok(())
    });
    assert_eq!(provenance.data_types, "journal,shopping_list");
    assert_eq!(provenance.taint, "external");
}

/// Review item 4 (AD-26, D151): a delete journals the call's implicit inputs as its insert and
/// update do, each combined with the call's fresher read of it: a `trusted` snapshot of an item
/// the call also read, stored `external`, is journaled `external` on both rows.
#[test]
fn a_delete_journals_its_inputs_combined_with_the_reads_of_the_call() {
    let fixture = Fixture::new("api-delete");
    let item = fixture.items[1];
    let call = Call {
        implicit_inputs: vec![RecordProvenance {
            id: item,
            author: Some(ella()),
            ..read_before(item)
        }],
        authority: Authority::Unapproved {
            author: Some(ella()),
            acting_for: Some(ella()),
        },
        ..rule()
    };
    let handle = fixture.writer("notes", Partition::Household);
    let declaration = fixture
        .registry
        .module(handle.file().module())
        .expect("registered");
    let invocation = fixture.invocation();
    let result = fixture.boundary().run(
        handle,
        declaration,
        &call,
        &invocation,
        &mut *fixture.stamper.borrow_mut(),
        |records| {
            records.read("shop", "item", item)?;
            let note = records.insert("notes", &[("title", text("Pommes"))], &[])?;
            records.delete("notes", note.id)
        },
    );
    assert!(matches!(result, Ok(CallResult::Committed(_))), "{result:?}");
    let journal = handle
        .journaled_call(&CallKey {
            principal: call.principal,
            source: &call.source,
            call_id: invocation.call_id,
        })
        .expect("read the journal");
    assert_eq!(journal.len(), 2);
    assert!(
        journal[1].rev_after.is_none(),
        "the second row is the delete"
    );
    for row in &journal {
        let inputs = decode_inputs(&row.inputs).expect("decode");
        assert_eq!(inputs.len(), 1);
        assert_eq!((inputs[0].id, inputs[0].implicit), (item, true));
        assert_eq!(
            (inputs[0].taint.as_str(), inputs[0].text_taint.as_str()),
            ("external", "external"),
            "rev after {:?}",
            row.rev_after
        );
    }
}

/// The fixture's read connections, which, when a read asks for the household's `shop` file, try
/// to put that file to `migrating` as a bring-up would, and note whether the states let them.
struct MigratingDuringRead<'a> {
    readers: &'a Readers,
    states: &'a ModuleStates,
    tried: RefCell<Vec<Result<(), StageRefused>>>,
}

impl ApiFiles for MigratingDuringRead<'_> {
    fn reader(&self, module: &ModuleName, partition: Partition) -> Option<&Handle<Read>> {
        if module.as_str() == "shop" && partition == Partition::Household {
            let tried =
                self.states
                    .set_stage(self.states.generation(partition), module, Stage::Migrating);
            self.tried.borrow_mut().push(tried);
        }
        self.readers.reader(module, partition)
    }
}

/// Review item 3 (D149, D151): a read is registered as a call on the file it reads for as long as
/// it lasts, so the file cannot be put to re-keying or migrating meanwhile; once the read ended,
/// it can.
#[test]
fn a_read_keeps_the_file_it_reads_from_being_migrated() {
    let fixture = Fixture::new("api-in-flight");
    let item = fixture.items[1];
    let migrating = MigratingDuringRead {
        readers: &fixture.readers,
        states: &fixture.states,
        tried: RefCell::new(Vec::new()),
    };
    let boundary = Boundary {
        apis: Some(Apis {
            registry: fixture.registry,
            files: &migrating,
        }),
        ..fixture.boundary()
    };
    let notes = fixture.writer("notes", Partition::Household);
    let declaration = fixture
        .registry
        .module(notes.file().module())
        .expect("registered");
    let result = boundary.run(
        notes,
        declaration,
        &rule(),
        &fixture.invocation(),
        &mut *fixture.stamper.borrow_mut(),
        |records| records.read("shop", "item", item),
    );
    assert!(matches!(result, Ok(CallResult::Committed(_))), "{result:?}");
    assert_eq!(
        migrating.tried.take(),
        [Err(StageRefused::CallsInFlight { calls: 1 })]
    );
    let shop = ModuleName::from_static("shop");
    let generation = fixture.states.generation(Partition::Household);
    for stage in [Stage::ReKeying, Stage::Migrating] {
        assert_eq!(fixture.states.set_stage(generation, &shop, stage), Ok(()));
        fixture
            .states
            .set_stage(generation, &shop, Stage::Ready)
            .expect("the writer is released");
    }
}
