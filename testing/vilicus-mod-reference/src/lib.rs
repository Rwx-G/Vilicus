//! The Vilicus reference module: a module that exists to exercise the module contract of
//! `vilicus-module-api` in tests (FR-22).
//!
//! It is never packaged. It is linked only into `vilicus-testbed`, and the crate graph check
//! keeps it out of the shipped binary's dependency closure (`doc/prd.md` FR-109, D102;
//! `doc/architecture-spine.md` AD-3); `ci/check_workspace.py` holds its normal dependencies to
//! the module port alone (AD-9). It uses every part of the contract:
//!
//! - its record kinds, each with the full envelope and its data types: [`ITEMS`] (free text and
//!   structured fields with their maximum lengths and value sets, a reviewed vocabulary, and a
//!   field a later migration adds), [`TALLIES`] (structured fields only, declared exempt from
//!   elevation) and [`ENTRIES`] (a journal kind, a data type the provider policy keeps local);
//! - two migrations, each with its frozen hash, the second adding a field and a table;
//! - a tier 0 tool and a tier 1 tool with an outbound effect under its exception class, an undo
//!   handler and the capability matrix rows of a testbed-only fixture (`doc/capability-matrix.md`
//!   has no row of this module);
//! - a topic, consumed by its own consumer and by the testbed's second module, and the query of
//!   its typed API that module reads its items through (AD-5).
//!
//! Its code, [`REFERENCE_CODE`], is bound to [`REFERENCE`] by name and checked in this crate's
//! build, as every module's is.

#![forbid(unsafe_code)]

use vilicus_module_api::{
    Confirmation, Consumer, ConsumerHandler, DataType, Event, ExceptionClass, Field, FieldKind,
    MatrixRow, Migration, ModuleCode, ModuleDeclaration, Query, Records, Structured, Table, Tier,
    Tool, ToolCall, ToolHandler, Topic, UndoCall, UndoHandler, Value, WriteError, sha256_hex,
};

/// The module's name, which names its files.
pub const NAME: &str = "reference";

/// The topic the module emits when a call adds an item.
pub const ITEM_ADDED: &str = "reference.item.added";

/// The version of [`ITEM_ADDED`]'s payload: the item's quantity, as 8 big-endian bytes.
pub const ITEM_ADDED_VERSION: u32 = 1;

/// The effect [`add_item`](REFERENCE_CODE) requests: the item published outside the instance,
/// with no effect a third party sees (`reversible_external_state`).
pub const PUBLISH_ITEM: &str = "publish_item";

/// The effect the undo handler requests for each effect of the call it undoes.
pub const WITHDRAW_ITEM: &str = "withdraw_item";

/// The reviewed vocabulary of an item's category.
pub const ITEM_CATEGORY: &str = "item_category";

/// The capability matrix section the module claims, in the testbed's fixture.
pub const MATRIX_SECTION: &str = "2";

const QUANTITY: Structured = Structured::Integer { min: 0, max: 1000 };

const ITEM_FIELDS: &[Field] = &[
    Field {
        name: "title",
        kind: FieldKind::FreeText { max_len: 200 },
        optional: false,
    },
    Field {
        name: "status",
        kind: FieldKind::Structured(Structured::Enumeration(&["open", "done"])),
        optional: false,
    },
    Field {
        name: "quantity",
        kind: FieldKind::Structured(QUANTITY),
        optional: false,
    },
    Field {
        name: "due",
        kind: FieldKind::Structured(Structured::Date),
        optional: true,
    },
    Field {
        name: "category",
        kind: FieldKind::Structured(Structured::ReviewedVocabulary(ITEM_CATEGORY)),
        optional: true,
    },
    Field {
        name: "note",
        kind: FieldKind::FreeText { max_len: 2000 },
        optional: true,
    },
];

/// The household's items: free text and structured fields, a reviewed vocabulary, and a note the
/// second migration adds, optional and last.
pub const ITEMS: Table = Table {
    name: "items",
    data_types: &[DataType::HouseholdOther],
    fields: ITEM_FIELDS,
    elevation_exempt: false,
};

/// How many of an item were counted, written by the module's consumer: structured fields only, a
/// low-risk record kind exempt from elevation (D104).
pub const TALLIES: Table = Table {
    name: "tallies",
    data_types: &[DataType::HouseholdOther],
    fields: &[
        Field {
            name: "item",
            kind: FieldKind::Structured(Structured::Uuid),
            optional: false,
        },
        Field {
            name: "quantity",
            kind: FieldKind::Structured(QUANTITY),
            optional: false,
        },
    ],
    elevation_exempt: true,
};

/// Journal entries, a data type the provider policy keeps local; the second migration adds it.
pub const ENTRIES: Table = Table {
    name: "entries",
    data_types: &[DataType::Journal],
    fields: &[
        Field {
            name: "day",
            kind: FieldKind::Structured(Structured::Date),
            optional: false,
        },
        Field {
            name: "body",
            kind: FieldKind::FreeText { max_len: 4000 },
            optional: false,
        },
    ],
    elevation_exempt: false,
};

/// The module's migrations, in order, each with its frozen hash.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        sql: "CREATE TABLE items (\
        id BLOB NOT NULL PRIMARY KEY, \
        source TEXT NOT NULL, \
        taint TEXT NOT NULL, \
        text_taint TEXT NOT NULL, \
        data_types TEXT NOT NULL, \
        author BLOB, \
        created_at INTEGER NOT NULL, \
        updated_at INTEGER NOT NULL, \
        rev INTEGER NOT NULL, \
        title TEXT NOT NULL, \
        status TEXT NOT NULL, \
        quantity INTEGER NOT NULL, \
        due TEXT, \
        category TEXT) STRICT;\n\
        CREATE TABLE tallies (\
        id BLOB NOT NULL PRIMARY KEY, \
        source TEXT NOT NULL, \
        taint TEXT NOT NULL, \
        text_taint TEXT NOT NULL, \
        data_types TEXT NOT NULL, \
        author BLOB, \
        created_at INTEGER NOT NULL, \
        updated_at INTEGER NOT NULL, \
        rev INTEGER NOT NULL, \
        item BLOB NOT NULL, \
        quantity INTEGER NOT NULL) STRICT;",
        sha256: sha256_hex("444ea91fe06202cb54cd6cafd85ca4d0bfac55c5f5a05dda422d7d568182c265"),
    },
    Migration {
        sql: "ALTER TABLE items ADD COLUMN note TEXT;\n\
        CREATE TABLE entries (\
        id BLOB NOT NULL PRIMARY KEY, \
        source TEXT NOT NULL, \
        taint TEXT NOT NULL, \
        text_taint TEXT NOT NULL, \
        data_types TEXT NOT NULL, \
        author BLOB, \
        created_at INTEGER NOT NULL, \
        updated_at INTEGER NOT NULL, \
        rev INTEGER NOT NULL, \
        day TEXT NOT NULL, \
        body TEXT NOT NULL) STRICT;",
        sha256: sha256_hex("2b1a0b3811ae64afb50a148318469fc3e0ccc779dba20da8e5ac00435d63be8f"),
    },
];

/// The arguments of [`ADD_ITEM`]: an item's fields, its status aside.
const ADD_ITEM_ARGUMENTS: &[Field] = &[
    ITEM_FIELDS[0],
    ITEM_FIELDS[2],
    ITEM_FIELDS[3],
    ITEM_FIELDS[4],
];

/// Lists the items, a tier 0 read.
pub const LIST_ITEMS: Tool = Tool {
    name: "list_items",
    arguments: &[Field {
        name: "status",
        kind: ITEM_FIELDS[1].kind,
        optional: true,
    }],
    tier: Tier::Read,
    network_effect: false,
    exception_class: None,
    confirmation: Confirmation::None,
    crosses_partitions: false,
    undo_handler: None,
    matrix_row: MatrixRow {
        section: MATRIX_SECTION,
        action: "List reference items",
    },
};

/// Adds an item and publishes it outside the instance: a tier 1 write with an outbound effect
/// under its exception class, so it requires a light confirmation and names its undo handler
/// (I13, AD-48).
pub const ADD_ITEM: Tool = Tool {
    name: "add_item",
    arguments: ADD_ITEM_ARGUMENTS,
    tier: Tier::ReversibleWrite,
    network_effect: true,
    exception_class: Some(ExceptionClass::ReversibleExternalState),
    confirmation: Confirmation::Light,
    crosses_partitions: false,
    undo_handler: Some(WITHDRAW_ITEM),
    matrix_row: MatrixRow {
        section: MATRIX_SECTION,
        action: "Add a reference item",
    },
};

/// The module's declaration.
pub const REFERENCE: ModuleDeclaration = ModuleDeclaration {
    name: NAME,
    tables: &[ITEMS, TALLIES, ENTRIES],
    fts5_tables: &[],
    migrations: MIGRATIONS,
    matrix_sections: &[MATRIX_SECTION],
    tools: &[LIST_ITEMS, ADD_ITEM],
    topics: &[Topic {
        name: ITEM_ADDED,
        version: ITEM_ADDED_VERSION,
        consumers: &[NAME, "reader"],
    }],
    consumers: &[Consumer {
        name: "tally_item",
        topic: ITEM_ADDED,
    }],
    queries: &[Query {
        name: "item",
        table: "items",
        fields: &["title", "status", "quantity"],
        callers: &["reader"],
    }],
};

const _: () = REFERENCE.assert_valid();

/// The module's code, bound by name to [`REFERENCE`].
pub const REFERENCE_CODE: ModuleCode = ModuleCode {
    module: NAME,
    tools: &[
        ToolHandler {
            tool: LIST_ITEMS.name,
            run: list_items,
        },
        ToolHandler {
            tool: ADD_ITEM.name,
            run: add_item,
        },
    ],
    undo_handlers: &[UndoHandler {
        name: WITHDRAW_ITEM,
        undo: withdraw_item,
    }],
    consumers: &[ConsumerHandler {
        consumer: "tally_item",
        consume: tally_item,
    }],
};

const _: () = REFERENCE_CODE.assert_bound(&REFERENCE);

/// A read: it writes nothing. Its output comes with the module read handle (Story 10.3).
fn list_items(_: &ToolCall<'_>, _: &mut dyn Records) -> Result<(), WriteError> {
    Ok(())
}

/// Inserts the item the arguments give, open, emits [`ITEM_ADDED`] about it, and requests its
/// publication under a key derived from its title and quantity, so the same item asked twice is
/// one effect (AD-28).
fn add_item(call: &ToolCall<'_>, records: &mut dyn Records) -> Result<(), WriteError> {
    let mut fields: Vec<(&str, Value)> = vec![("status", Value::Text("open".into()))];
    fields.extend(
        call.arguments()
            .iter()
            .map(|(name, value)| (*name, value.clone())),
    );
    let item = records.insert(ITEMS.name, &fields, &[])?;
    let (Some(Value::Text(title)), Some(Value::Integer(quantity))) =
        (call.argument("title"), call.argument("quantity"))
    else {
        return Err(WriteError::Failed);
    };
    records.emit(ITEM_ADDED, item.id, &quantity.to_be_bytes())?;
    let mut key = title.as_bytes().to_vec();
    key.push(0);
    key.extend_from_slice(&quantity.to_be_bytes());
    records.request_effect(PUBLISH_ITEM, &key, &item.id.to_bytes())?;
    Ok(())
}

/// Requests the withdrawal of each item the undone call published, keyed by the effect it undoes.
fn withdraw_item(undo: &UndoCall<'_>, records: &mut dyn Records) -> Result<(), WriteError> {
    for effect in undo.effects() {
        records.request_effect(WITHDRAW_ITEM, &effect.id.to_bytes(), effect.payload)?;
    }
    Ok(())
}

/// Counts the item an [`ITEM_ADDED`] event is about, from the quantity its payload carries; a
/// payload of another form is refused, which fails the delivery.
fn tally_item(event: &Event<'_>, records: &mut dyn Records) -> Result<(), WriteError> {
    let quantity = <[u8; 8]>::try_from(event.payload)
        .map(i64::from_be_bytes)
        .map_err(|_| WriteError::Failed)?;
    records.insert(
        TALLIES.name,
        &[
            ("item", Value::Blob(event.record.to_bytes().to_vec())),
            ("quantity", Value::Integer(quantity)),
        ],
        &[],
    )?;
    Ok(())
}
