//! The module port of Vilicus: what a module declares (schema and migrations, record types,
//! tools, event topics, undo handlers) and the scoped handles it receives from the Core.
//!
//! Modules depend on this crate and never on the Core's internals, and it exports no key type
//! (`doc/architecture-spine.md`, AD-3 and AD-9).
//!
//! A module declares itself in one [`ModuleDeclaration`], a `const` item: its [`Table`]s, each
//! holding one record kind with the data types its fields may hold and its [`Field`]s, structured
//! or free text; its [`Fts5Table`]s; its [`Migration`]s; its [`Tool`]s, each with its tier,
//! network effect, exception class, [`Confirmation`] and capability [`MatrixRow`], and the
//! capability matrix sections it implements. Every table also carries the record [`ENVELOPE`],
//! which the Core stamps. [`ModuleDeclaration::assert_valid`] applies the rules of the contract at
//! build time, and the Core's registry applies them again, then compares the declaration with the
//! schema the migrations produce and the tools with `doc/capability-matrix.md`.

mod check;
mod declaration;
mod tool;

pub use check::{
    DeclarationError, FTS5_RESERVED_COLUMNS, IDENTIFIER_MAX_LEN, IdentifierKind,
    MATRIX_SECTION_MAX_LEN, ROWID_NAMES, is_identifier, is_matrix_section,
};
pub use declaration::{
    ENVELOPE, EnvelopeColumn, FTS5_SHADOW_SUFFIXES, Field, FieldKind, Fts5Content, Fts5Table,
    Fts5Tokenizer, Migration, ModuleDeclaration, SqlType, Structured, Table,
};
pub use tool::{Confirmation, MatrixRow, Tool};
pub use vilicus_types::{DataType, ExceptionClass, Tier};

#[cfg(test)]
mod tests;
