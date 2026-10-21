//! The testbed's second module, `reader` (Story 3.10, AC5): it reads the reference module's
//! items only through that module's typed API, which the Core serves (AD-5, I6).
//!
//! It is written against the module port alone, as a module crate is: its code receives the record
//! port of its call and nothing else, so no handle, path or table of the reference module's file
//! is within its reach. Its consumer reacts to each item the reference module adds, reads the item
//! through the reference module's query and keeps a copy of what it read.

use vilicus_mod_reference::ITEM_ADDED;
use vilicus_module_api::{
    Consumer, ConsumerHandler, DataType, Event, Field, FieldKind, Migration, ModuleCode,
    ModuleDeclaration, Records, Structured, Table, Value, WriteError, sha256_hex,
};

/// The module's name.
pub(crate) const NAME: &str = "reader";

/// The copies of the reference items the module read.
pub(crate) const COPIES: Table = Table {
    name: "copies",
    data_types: &[DataType::HouseholdOther],
    fields: &[
        Field {
            name: "item",
            kind: FieldKind::Structured(Structured::Uuid),
            optional: false,
        },
        Field {
            name: "title",
            kind: FieldKind::FreeText { max_len: 200 },
            optional: false,
        },
        Field {
            name: "quantity",
            kind: FieldKind::Structured(Structured::Integer { min: 0, max: 1000 }),
            optional: false,
        },
    ],
    elevation_exempt: false,
};

/// The module's declaration: a table, a consumer of the reference module's topic, no tool.
pub(crate) const READER: ModuleDeclaration = ModuleDeclaration {
    name: NAME,
    tables: &[COPIES],
    fts5_tables: &[],
    migrations: &[Migration {
        sql: "CREATE TABLE copies (\
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
        title TEXT NOT NULL, \
        quantity INTEGER NOT NULL) STRICT;",
        sha256: sha256_hex("f3b4c76fb651749ef4a11d7ee098c7e286988a9624895cfb9829aa0be8cae9bf"),
    }],
    matrix_sections: &[],
    tools: &[],
    topics: &[],
    consumers: &[Consumer {
        name: "copy_item",
        topic: ITEM_ADDED,
    }],
    queries: &[],
};

const _: () = READER.assert_valid();

/// The module's code, bound by name to [`READER`].
pub(crate) const READER_CODE: ModuleCode = ModuleCode {
    module: NAME,
    tools: &[],
    undo_handlers: &[],
    consumers: &[ConsumerHandler {
        consumer: "copy_item",
        consume: copy_item,
    }],
};

const _: () = READER_CODE.assert_bound(&READER);

/// Reads the item the event is about through the reference module's query, and keeps a copy of
/// its title and quantity. The copy names no input: the Core counts the item read, and the
/// event's record, as its inputs (AD-7).
fn copy_item(event: &Event<'_>, records: &mut dyn Records) -> Result<(), WriteError> {
    let item = records.read(vilicus_mod_reference::NAME, "item", event.record)?;
    let (Some(title), Some(quantity)) = (item.field("title"), item.field("quantity")) else {
        return Err(WriteError::Failed);
    };
    records.insert(
        COPIES.name,
        &[
            ("item", Value::Blob(item.id.to_bytes().to_vec())),
            ("title", title.clone()),
            ("quantity", quantity.clone()),
        ],
        &[],
    )?;
    Ok(())
}
