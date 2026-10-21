//! The module port of Vilicus: what a module declares (schema and migrations, record types,
//! tools, event topics, undo handlers) and the scoped handles it receives from the Core.
//!
//! Modules depend on this crate and never on the Core's internals, and it exports no key type
//! (`doc/architecture-spine.md`, AD-3 and AD-9).
//!
//! A module declares itself in one [`ModuleDeclaration`], a `const` item: its [`Table`]s, each
//! holding one record kind with the data types its fields may hold and its [`Field`]s, structured
//! or free text; its [`Fts5Table`]s; its [`Migration`]s, each with its frozen hash; its
//! [`Tool`]s, each with its tier,
//! network effect, exception class, [`Confirmation`] and capability [`MatrixRow`], and the
//! capability matrix sections it implements; the event [`Topic`]s it emits, each with its payload
//! version and the modules allowed to consume it, and its [`Consumer`]s. Every table also carries
//! the record [`ENVELOPE`],
//! which the Core stamps. [`ModuleDeclaration::assert_valid`] applies the rules of the contract at
//! build time, and the Core's registry applies them again, then compares the declaration with the
//! schema the migrations produce and the tools with `doc/capability-matrix.md`.
//!
//! A module writes its records only through the typed record API, [`Records`] (AD-9): insert,
//! update by id with the expected [`Rev`], delete by id. It gives field values and the ids of
//! the records a write is derived from; the Core stamps the envelope and computes `taint`,
//! `text_taint` and `data_types` (AD-6, AD-7). A write gives each field a [`Value`], which [`Field::check_value`]
//! holds to the field's declaration (FR-58, D98): the Core runs it on every write, and checks in
//! the write transaction that a reviewed-vocabulary label is one an adult confirmed (D104).

mod check;
mod declaration;
mod event;
mod records;
mod tool;
mod value;

pub use check::{
    CORE_MATRIX_SECTION, DeclarationError, FREE_TEXT_MAX_LEN, FTS5_RESERVED_COLUMNS,
    IDENTIFIER_MAX_LEN, IdentifierKind, MATRIX_SECTION_MAX_LEN, ROWID_NAMES, is_identifier,
    is_matrix_section,
};
pub use declaration::{
    ENVELOPE, EnvelopeColumn, FTS5_SHADOW_SUFFIXES, Field, FieldKind, Fts5Content, Fts5Table,
    Fts5Tokenizer, Migration, ModuleDeclaration, SqlType, Structured, Table,
};
pub use event::{Consumer, Event, Topic, is_topic, topic_module};
pub use records::{Records, WriteError, Written};
pub use tool::{Confirmation, MatrixRow, Tool};
pub use value::{Value, ValueError, check_vocabulary_label, is_free_text_character};
pub use vilicus_types::{
    DataType, ExceptionClass, Id, Rev, Tier, VOCABULARY_LABEL_MAX_LEN, VOCABULARY_LABEL_SEPARATORS,
    is_vocabulary_label, is_vocabulary_label_letter, sha256_hex,
};

#[cfg(test)]
mod tests;
