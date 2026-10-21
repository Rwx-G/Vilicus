//! The module port of Vilicus: what a module declares (schema and migrations, record types,
//! tools, event topics, undo handlers) and the scoped handles it receives from the Core.
//!
//! Modules depend on this crate and never on the Core's internals, and it exports no key type
//! (`doc/architecture-spine.md`, AD-3 and AD-9).
//!
//! A module declares its file in one [`ModuleDeclaration`], a `const` item: its [`Table`]s, each
//! holding one record kind with the data types its fields may hold and its [`Field`]s, structured
//! or free text; its [`Fts5Table`]s; its [`Migration`]s. Every table also carries the record
//! [`ENVELOPE`], which the Core stamps. [`ModuleDeclaration::assert_valid`] applies the rules of
//! the contract at build time, and the Core's registry applies them again, then compares the
//! declaration with the schema the migrations produce.

mod check;
mod declaration;

pub use check::{DeclarationError, IDENTIFIER_MAX_LEN, IdentifierKind, is_identifier};
pub use declaration::{
    ENVELOPE, EnvelopeColumn, FTS5_SHADOW_SUFFIXES, Field, FieldKind, Fts5Content, Fts5Table,
    Fts5Tokenizer, Migration, ModuleDeclaration, SqlType, Structured, Table,
};
pub use vilicus_types::DataType;

#[cfg(test)]
mod tests;
