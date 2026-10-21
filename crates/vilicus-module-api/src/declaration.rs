//! What a module declares about its file: its tables, each one record kind with its data types and
//! its fields, its FTS5 tables and its migrations (AD-6, AD-9, D98, D103, D104, D127).
//!
//! Every declaration is plain `'static` data built in a `const` item, so the set of tables,
//! fields, value sets and data types is fixed when the binary is built; nothing in this crate
//! builds or extends one at run time.

use vilicus_types::DataType;

/// The SQL type a column is declared with in the module's migrations; the registry compares it
/// with `PRAGMA table_xinfo` of the migrated file, ignoring ASCII case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SqlType {
    /// `INTEGER`.
    Integer,
    /// `TEXT`.
    Text,
    /// `BLOB`.
    Blob,
}

impl SqlType {
    /// The type as written in a `CREATE TABLE` statement.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Integer => "INTEGER",
            Self::Text => "TEXT",
            Self::Blob => "BLOB",
        }
    }
}

/// A column of the record envelope (AD-6), which the Core stamps on every write; a module never
/// writes it and never declares a field of the same name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EnvelopeColumn {
    /// The column name.
    pub name: &'static str,
    /// Its SQL type.
    pub sql_type: SqlType,
    /// True when the column is `NOT NULL`.
    pub not_null: bool,
    /// True for the primary key, the record `id`.
    pub primary_key: bool,
}

const fn envelope(
    name: &'static str,
    sql_type: SqlType,
    not_null: bool,
    primary_key: bool,
) -> EnvelopeColumn {
    EnvelopeColumn {
        name,
        sql_type,
        not_null,
        primary_key,
    }
}

/// The record envelope every module table carries, in the order of AD-6. Ids are 16-byte UUIDv7
/// blobs and times UTC integer milliseconds (spine conventions); `author` is empty for the
/// principals the conventions name, so it may be `NULL`. How `source` and `data_types` are
/// written in their `TEXT` columns is the typed record API's (Story 3.5).
pub const ENVELOPE: &[EnvelopeColumn] = &[
    envelope("id", SqlType::Blob, true, true),
    envelope("source", SqlType::Text, true, false),
    envelope("taint", SqlType::Text, true, false),
    envelope("data_types", SqlType::Text, true, false),
    envelope("author", SqlType::Blob, false, false),
    envelope("created_at", SqlType::Integer, true, false),
    envelope("updated_at", SqlType::Integer, true, false),
    envelope("rev", SqlType::Integer, true, false),
];

/// A structured value set, fixed at build time (D104): a field whose values cannot carry free
/// text, so reading it does not taint a session (D70).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Structured {
    /// A compiled enumeration: one of the listed names, each an identifier
    /// ([`IDENTIFIER_MAX_LEN`](crate::IDENTIFIER_MAX_LEN) characters at most, lowercase ASCII
    /// letters, digits and underscores, starting with a letter). Stored as `TEXT`.
    Enumeration(&'static [&'static str]),
    /// An integer in `min..=max`. Stored as `INTEGER`.
    Integer {
        /// The smallest value accepted.
        min: i64,
        /// The largest value accepted.
        max: i64,
    },
    /// A calendar date. Stored as `TEXT`.
    Date,
    /// An instant, in UTC integer milliseconds (spine conventions, Time). Stored as `INTEGER`.
    Timestamp,
    /// An opaque UUIDv7, the 16-byte form of the spine conventions. Stored as `BLOB`.
    Uuid,
    /// A reviewed vocabulary, by name: only labels an adult confirmed are accepted (D104,
    /// Story 3.4). Stored as `TEXT`.
    ReviewedVocabulary(&'static str),
}

/// Whether a field is structured or free text (FR-58).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FieldKind {
    /// A value from a set fixed at build time.
    Structured(Structured),
    /// Free text, at most `max_len` characters; anything a run-time vocabulary holds is free text
    /// unless it is a reviewed vocabulary (D104). Stored as `TEXT`.
    FreeText {
        /// The maximum length, in characters; 0 is refused.
        max_len: u32,
    },
}

impl FieldKind {
    /// The SQL type the field is stored as.
    pub const fn sql_type(self) -> SqlType {
        match self {
            Self::Structured(Structured::Integer { .. } | Structured::Timestamp) => {
                SqlType::Integer
            }
            Self::Structured(Structured::Uuid) => SqlType::Blob,
            Self::Structured(
                Structured::Enumeration(_) | Structured::Date | Structured::ReviewedVocabulary(_),
            )
            | Self::FreeText { .. } => SqlType::Text,
        }
    }
}

/// A field of a table: a column beside the envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Field {
    /// The column name, an identifier.
    pub name: &'static str,
    /// Structured or free text.
    pub kind: FieldKind,
    /// True when the field may be absent (`NULL`); otherwise the column is `NOT NULL`.
    pub optional: bool,
}

/// A module table, which holds one record kind: the envelope, then the declared fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Table {
    /// The table name, an identifier.
    pub name: &'static str,
    /// The data types the record kind's fields may hold (FR-68, D103); at least one.
    pub data_types: &'static [DataType],
    /// The fields beside the envelope.
    pub fields: &'static [Field],
}

/// A built-in FTS5 tokenizer, the allowlist of D127.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Fts5Tokenizer {
    /// `unicode61`, FTS5's default.
    Unicode61,
    /// `ascii`.
    Ascii,
    /// `porter`.
    Porter,
    /// `trigram`.
    Trigram,
}

impl Fts5Tokenizer {
    /// Every tokenizer of the allowlist.
    pub const ALL: &'static [Self] = &[Self::Unicode61, Self::Ascii, Self::Porter, Self::Trigram];

    /// The tokenizer's name in a `tokenize=` option.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unicode61 => "unicode61",
            Self::Ascii => "ascii",
            Self::Porter => "porter",
            Self::Trigram => "trigram",
        }
    }
}

/// Where an FTS5 table's indexed text lives (D127): never a copy of its own, so the text stays in
/// an enveloped table, with its provenance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Fts5Content {
    /// `content=''`: a contentless index.
    Contentless,
    /// `content='<table>'`: an external-content index over a table of the same module.
    Table(&'static str),
}

/// An FTS5 table of the module (D127). Its migration creates it with exactly these arguments and
/// sets its `secure-delete` option to 1 (D132), which the registry checks in the migrated file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Fts5Table {
    /// The table name, an identifier.
    pub name: &'static str,
    /// The indexed columns, in order; with [`Fts5Content::Table`], fields of that table.
    pub columns: &'static [&'static str],
    /// The tokenizer.
    pub tokenizer: Fts5Tokenizer,
    /// Where the indexed text lives.
    pub content: Fts5Content,
}

/// The suffixes FTS5 gives its shadow tables, `<table>_<suffix>`; no module table may take one.
pub const FTS5_SHADOW_SUFFIXES: &[&str] = &["config", "content", "data", "docsize", "idx"];

/// One migration of the module's track (AD-23), declarative SQL embedded in the binary. Its
/// version is its position in [`ModuleDeclaration::migrations`], from 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Migration {
    /// The SQL, run by the Core's migration runner under the migration policy.
    pub sql: &'static str,
}

/// Everything a module declares about its file. A module crate exposes one as a `const` item and
/// checks it there with [`ModuleDeclaration::assert_valid`], so a declaration the registry would
/// refuse fails that crate's build.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ModuleDeclaration {
    /// The module name (`vilicus_types::ModuleName` grammar), which names its files.
    pub name: &'static str,
    /// The module's tables.
    pub tables: &'static [Table],
    /// The module's FTS5 tables.
    pub fts5_tables: &'static [Fts5Table],
    /// The module's migrations, in order: the first is version 1.
    pub migrations: &'static [Migration],
}

impl ModuleDeclaration {
    /// The schema version the module's last migration brings a file to.
    pub const fn latest_version(&self) -> u32 {
        // A declaration's migrations are a static list written out in a module crate; no build
        // holds 2^32 of them.
        self.migrations.len() as u32
    }

    /// The table named `name`.
    pub fn table(&self, name: &str) -> Option<&'static Table> {
        self.tables.iter().find(|table| table.name == name)
    }

    /// The FTS5 table named `name`.
    pub fn fts5_table(&self, name: &str) -> Option<&'static Fts5Table> {
        self.fts5_tables.iter().find(|table| table.name == name)
    }
}
