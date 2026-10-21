//! The rules a module declaration must meet before the registry accepts it (FR-18, FR-22, FR-58,
//! FR-68, AD-6, AD-9, D98, D103, D104, D127), as `const` functions: a module checks its own
//! declaration in a `const` item, where a refusal stops the build, and the Core's registry runs
//! the same check on every module it is built from.
//!
//! What the migrated file actually holds (the envelope columns, the field columns, the FTS5
//! arguments and `secure-delete`) is the registry's comparison with the file, in `vilicus-core`.

use core::fmt;

use vilicus_types::ModuleName;

use crate::declaration::{
    ENVELOPE, FTS5_SHADOW_SUFFIXES, Field, FieldKind, Fts5Content, Fts5Table, ModuleDeclaration,
    Structured, Table,
};

/// Longest identifier accepted for a table, a field, an FTS5 table or column, an enumeration
/// value or a vocabulary name.
pub const IDENTIFIER_MAX_LEN: usize = 64;

/// Names SQLite gives the rowid of a table that has no column of that name: a field of one of
/// these names would take the place of the rowid in every statement that names it. `_rowid_` is
/// outside the identifier grammar already.
pub const ROWID_NAMES: &[&str] = &["rowid", "oid", "_rowid_"];

/// Column names an FTS5 table keeps for itself (`rank`, its rowid); an FTS5 table's own name is
/// one too, the hidden column that takes its special commands.
pub const FTS5_RESERVED_COLUMNS: &[&str] = &["rank", "rowid"];

/// What an identifier names, for the error that refuses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IdentifierKind {
    /// A table.
    Table,
    /// A field of a table.
    Field,
    /// An FTS5 table.
    Fts5Table,
    /// A column of an FTS5 table.
    Fts5Column,
    /// A value of a compiled enumeration.
    EnumerationValue,
    /// The name of a reviewed vocabulary.
    Vocabulary,
}

impl IdentifierKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Table => "table",
            Self::Field => "field",
            Self::Fts5Table => "FTS5 table",
            Self::Fts5Column => "FTS5 column",
            Self::EnumerationValue => "enumeration value",
            Self::Vocabulary => "vocabulary name",
        }
    }
}

/// Why a module declaration is refused. Each variant names the table and the item at fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DeclarationError {
    /// The module name is outside the grammar of `vilicus_types::ModuleName`.
    InvalidModuleName {
        /// The name refused.
        module: &'static str,
    },
    /// An identifier is outside the grammar: a lowercase ASCII letter, then lowercase ASCII
    /// letters, digits and underscores, at most [`IDENTIFIER_MAX_LEN`] of them, and not
    /// SQLite's reserved `sqlite_` prefix.
    InvalidIdentifier {
        /// What the identifier names.
        kind: IdentifierKind,
        /// The identifier refused.
        name: &'static str,
    },
    /// Two tables or FTS5 tables of the module share a name, or a table takes the name of an
    /// FTS5 table's shadow table.
    DuplicateTable {
        /// The name used twice.
        table: &'static str,
    },
    /// Two fields of a table share a name.
    DuplicateField {
        /// The table.
        table: &'static str,
        /// The name used twice.
        field: &'static str,
    },
    /// A field takes the name of an envelope column, which only the Core writes (AD-6).
    EnvelopeName {
        /// The table.
        table: &'static str,
        /// The field.
        field: &'static str,
    },
    /// A record kind declares no data type (FR-68, I36).
    NoDataType {
        /// The table.
        table: &'static str,
    },
    /// A record kind declares a data type twice.
    DuplicateDataType {
        /// The table.
        table: &'static str,
        /// The data type's name.
        data_type: &'static str,
    },
    /// A free-text field has no maximum length (FR-58).
    FreeTextWithoutMaxLength {
        /// The table.
        table: &'static str,
        /// The field.
        field: &'static str,
    },
    /// A compiled enumeration lists no value, so its value set is not fixed (D104).
    EmptyEnumeration {
        /// The table.
        table: &'static str,
        /// The field.
        field: &'static str,
    },
    /// A compiled enumeration lists a value twice.
    DuplicateEnumerationValue {
        /// The table.
        table: &'static str,
        /// The field.
        field: &'static str,
        /// The value listed twice.
        value: &'static str,
    },
    /// A bounded integer whose minimum is above its maximum admits no value.
    EmptyIntegerRange {
        /// The table.
        table: &'static str,
        /// The field.
        field: &'static str,
    },
    /// An FTS5 table indexes no column.
    Fts5WithoutColumn {
        /// The FTS5 table.
        table: &'static str,
    },
    /// An FTS5 table lists a column twice.
    DuplicateFts5Column {
        /// The FTS5 table.
        table: &'static str,
        /// The column listed twice.
        column: &'static str,
    },
    /// An FTS5 table's `content=` names no table of the module (D127).
    Fts5ContentOutsideModule {
        /// The FTS5 table.
        table: &'static str,
        /// The table named.
        content: &'static str,
    },
    /// An external-content FTS5 table indexes a column its content table does not declare.
    Fts5ColumnNotInContent {
        /// The FTS5 table.
        table: &'static str,
        /// The column.
        column: &'static str,
    },
    /// A field takes a name of the rowid, or an FTS5 column a name FTS5 keeps for itself.
    ReservedName {
        /// The table or FTS5 table.
        table: &'static str,
        /// The name.
        name: &'static str,
    },
    /// A migration holds no SQL.
    EmptyMigration {
        /// Its version.
        version: usize,
    },
}

impl DeclarationError {
    /// The rule broken, without the names: the message a `const` check stops the build with.
    pub const fn rule(self) -> &'static str {
        match self {
            Self::InvalidModuleName { .. } => "the module name is outside the module name grammar",
            Self::InvalidIdentifier { .. } => "an identifier is outside the identifier grammar",
            Self::DuplicateTable { .. } => "two tables share a name",
            Self::DuplicateField { .. } => "two fields of a table share a name",
            Self::EnvelopeName { .. } => "a field takes the name of an envelope column",
            Self::NoDataType { .. } => "a record kind declares no data type",
            Self::DuplicateDataType { .. } => "a record kind declares a data type twice",
            Self::FreeTextWithoutMaxLength { .. } => "a free-text field has no maximum length",
            Self::EmptyEnumeration { .. } => "a compiled enumeration lists no value",
            Self::DuplicateEnumerationValue { .. } => "an enumeration lists a value twice",
            Self::EmptyIntegerRange { .. } => "a bounded integer admits no value",
            Self::Fts5WithoutColumn { .. } => "an FTS5 table indexes no column",
            Self::DuplicateFts5Column { .. } => "an FTS5 table lists a column twice",
            Self::Fts5ContentOutsideModule { .. } => {
                "an FTS5 table's content names no table of the module"
            }
            Self::Fts5ColumnNotInContent { .. } => {
                "an FTS5 column is not a field of its content table"
            }
            Self::ReservedName { .. } => "a column takes a name SQLite or FTS5 keeps for itself",
            Self::EmptyMigration { .. } => "a migration holds no SQL",
        }
    }
}

impl fmt::Display for DeclarationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.rule())?;
        match *self {
            Self::InvalidModuleName { module } => write!(formatter, ": {module:?}"),
            Self::InvalidIdentifier { kind, name } => {
                write!(formatter, ": {} {name:?}", kind.as_str())
            }
            Self::DuplicateTable { table }
            | Self::NoDataType { table }
            | Self::Fts5WithoutColumn { table } => write!(formatter, ": {table}"),
            Self::DuplicateField { table, field }
            | Self::EnvelopeName { table, field }
            | Self::FreeTextWithoutMaxLength { table, field }
            | Self::EmptyEnumeration { table, field }
            | Self::EmptyIntegerRange { table, field } => write!(formatter, ": {table}.{field}"),
            Self::DuplicateDataType { table, data_type } => {
                write!(formatter, ": {table} ({data_type})")
            }
            Self::DuplicateEnumerationValue {
                table,
                field,
                value,
            } => write!(formatter, ": {table}.{field} ({value})"),
            Self::DuplicateFts5Column { table, column }
            | Self::Fts5ColumnNotInContent { table, column } => {
                write!(formatter, ": {table}.{column}")
            }
            Self::Fts5ContentOutsideModule { table, content } => {
                write!(formatter, ": {table} (content {content})")
            }
            Self::ReservedName { table, name } => write!(formatter, ": {table}.{name}"),
            Self::EmptyMigration { version } => write!(formatter, ": version {version}"),
        }
    }
}

impl std::error::Error for DeclarationError {}

/// Turns a failed check into an early return of its error.
macro_rules! check {
    ($result:expr) => {
        if let Err(error) = $result {
            return Err(error);
        }
    };
}

impl ModuleDeclaration {
    /// Checks the declaration against the rules of the module contract; the first rule broken is
    /// returned. `const`, so it runs at build time in a `const` item.
    pub const fn validate(&self) -> Result<(), DeclarationError> {
        if !ModuleName::is_valid(self.name) {
            return Err(DeclarationError::InvalidModuleName { module: self.name });
        }
        let mut index = 0;
        while index < self.tables.len() {
            check!(validate_table(&self.tables[index]));
            index += 1;
        }
        check!(validate_table_names(self));
        index = 0;
        while index < self.fts5_tables.len() {
            check!(validate_fts5(self, &self.fts5_tables[index]));
            index += 1;
        }
        index = 0;
        while index < self.migrations.len() {
            if self.migrations[index].sql.is_empty() {
                return Err(DeclarationError::EmptyMigration { version: index + 1 });
            }
            index += 1;
        }
        Ok(())
    }

    /// [`validate`](Self::validate), stopping the build with the broken rule when it is called in
    /// a `const` item:
    ///
    /// ```
    /// use vilicus_module_api::{DataType, Field, FieldKind, Migration, ModuleDeclaration, Table};
    ///
    /// pub const MODULE: ModuleDeclaration = ModuleDeclaration {
    ///     name: "notes",
    ///     tables: &[Table {
    ///         name: "notes",
    ///         data_types: &[DataType::PersonalOther],
    ///         fields: &[Field {
    ///             name: "body",
    ///             kind: FieldKind::FreeText { max_len: 2000 },
    ///             optional: false,
    ///         }],
    ///     }],
    ///     fts5_tables: &[],
    ///     migrations: &[Migration {
    ///         sql: "CREATE TABLE notes (id BLOB NOT NULL PRIMARY KEY, body TEXT NOT NULL) STRICT;",
    ///     }],
    /// };
    /// const _: () = MODULE.assert_valid();
    /// ```
    ///
    /// A record kind without a data type does not build (FR-68):
    ///
    /// ```compile_fail,E0080
    /// use vilicus_module_api::{Migration, ModuleDeclaration, Table};
    ///
    /// const MODULE: ModuleDeclaration = ModuleDeclaration {
    ///     name: "notes",
    ///     tables: &[Table { name: "notes", data_types: &[], fields: &[] }],
    ///     fts5_tables: &[],
    ///     migrations: &[Migration { sql: "CREATE TABLE notes (id BLOB) STRICT;" }],
    /// };
    /// const _: () = MODULE.assert_valid();
    /// ```
    ///
    /// Nor does a data type outside the closed set of `vilicus-types` (D103):
    ///
    /// ```compile_fail,E0599
    /// use vilicus_module_api::{DataType, Table};
    ///
    /// const NOTES: Table = Table { name: "notes", data_types: &[DataType::Pets], fields: &[] };
    /// ```
    ///
    /// # Panics
    ///
    /// When the declaration breaks a rule; in a `const` item that is a build error.
    pub const fn assert_valid(&self) {
        if let Err(error) = self.validate() {
            panic!("{}", error.rule());
        }
    }
}

const fn validate_table(table: &Table) -> Result<(), DeclarationError> {
    check!(identifier(IdentifierKind::Table, table.name));
    if table.data_types.is_empty() {
        return Err(DeclarationError::NoDataType { table: table.name });
    }
    let mut index = 0;
    while index < table.data_types.len() {
        let mut other = index + 1;
        while other < table.data_types.len() {
            if table.data_types[index] as usize == table.data_types[other] as usize {
                return Err(DeclarationError::DuplicateDataType {
                    table: table.name,
                    data_type: table.data_types[index].as_str(),
                });
            }
            other += 1;
        }
        index += 1;
    }
    index = 0;
    while index < table.fields.len() {
        let field = &table.fields[index];
        check!(validate_field(table.name, field));
        let mut other = index + 1;
        while other < table.fields.len() {
            if same(field.name, table.fields[other].name) {
                return Err(DeclarationError::DuplicateField {
                    table: table.name,
                    field: field.name,
                });
            }
            other += 1;
        }
        index += 1;
    }
    Ok(())
}

const fn validate_field(table: &'static str, field: &Field) -> Result<(), DeclarationError> {
    check!(identifier(IdentifierKind::Field, field.name));
    if listed(ROWID_NAMES, field.name) {
        return Err(DeclarationError::ReservedName {
            table,
            name: field.name,
        });
    }
    let mut index = 0;
    while index < ENVELOPE.len() {
        if same(field.name, ENVELOPE[index].name) {
            return Err(DeclarationError::EnvelopeName {
                table,
                field: field.name,
            });
        }
        index += 1;
    }
    match field.kind {
        FieldKind::FreeText { max_len: 0 } => Err(DeclarationError::FreeTextWithoutMaxLength {
            table,
            field: field.name,
        }),
        FieldKind::FreeText { .. }
        | FieldKind::Structured(Structured::Date | Structured::Timestamp | Structured::Uuid) => {
            Ok(())
        }
        FieldKind::Structured(Structured::Integer { min, max }) => {
            if min > max {
                Err(DeclarationError::EmptyIntegerRange {
                    table,
                    field: field.name,
                })
            } else {
                Ok(())
            }
        }
        FieldKind::Structured(Structured::ReviewedVocabulary(name)) => {
            identifier(IdentifierKind::Vocabulary, name)
        }
        FieldKind::Structured(Structured::Enumeration(values)) => {
            validate_enumeration(table, field.name, values)
        }
    }
}

const fn validate_enumeration(
    table: &'static str,
    field: &'static str,
    values: &'static [&'static str],
) -> Result<(), DeclarationError> {
    if values.is_empty() {
        return Err(DeclarationError::EmptyEnumeration { table, field });
    }
    let mut index = 0;
    while index < values.len() {
        check!(identifier(IdentifierKind::EnumerationValue, values[index]));
        let mut other = index + 1;
        while other < values.len() {
            if same(values[index], values[other]) {
                return Err(DeclarationError::DuplicateEnumerationValue {
                    table,
                    field,
                    value: values[index],
                });
            }
            other += 1;
        }
        index += 1;
    }
    Ok(())
}

const fn validate_fts5(
    module: &ModuleDeclaration,
    fts5: &Fts5Table,
) -> Result<(), DeclarationError> {
    check!(identifier(IdentifierKind::Fts5Table, fts5.name));
    if fts5.columns.is_empty() {
        return Err(DeclarationError::Fts5WithoutColumn { table: fts5.name });
    }
    let content = match fts5.content {
        Fts5Content::Contentless => None,
        Fts5Content::Table(name) => match find_table(module, name) {
            Some(table) => Some(table),
            None => {
                return Err(DeclarationError::Fts5ContentOutsideModule {
                    table: fts5.name,
                    content: name,
                });
            }
        },
    };
    let mut index = 0;
    while index < fts5.columns.len() {
        let column = fts5.columns[index];
        check!(identifier(IdentifierKind::Fts5Column, column));
        if listed(FTS5_RESERVED_COLUMNS, column) || same(column, fts5.name) {
            return Err(DeclarationError::ReservedName {
                table: fts5.name,
                name: column,
            });
        }
        let mut other = index + 1;
        while other < fts5.columns.len() {
            if same(column, fts5.columns[other]) {
                return Err(DeclarationError::DuplicateFts5Column {
                    table: fts5.name,
                    column,
                });
            }
            other += 1;
        }
        if let Some(table) = content
            && !has_field(table, column)
        {
            return Err(DeclarationError::Fts5ColumnNotInContent {
                table: fts5.name,
                column,
            });
        }
        index += 1;
    }
    Ok(())
}

/// Tables and FTS5 tables share one namespace, which also holds each FTS5 table's shadow tables.
const fn validate_table_names(module: &ModuleDeclaration) -> Result<(), DeclarationError> {
    let mut index = 0;
    while index < module.tables.len() {
        let name = module.tables[index].name;
        let mut other = index + 1;
        while other < module.tables.len() {
            if same(name, module.tables[other].name) {
                return Err(DeclarationError::DuplicateTable { table: name });
            }
            other += 1;
        }
        let mut fts5 = 0;
        while fts5 < module.fts5_tables.len() {
            let fts5_name = module.fts5_tables[fts5].name;
            if same(name, fts5_name) || is_shadow_of(name, fts5_name) {
                return Err(DeclarationError::DuplicateTable { table: name });
            }
            fts5 += 1;
        }
        index += 1;
    }
    index = 0;
    while index < module.fts5_tables.len() {
        let name = module.fts5_tables[index].name;
        let mut other = 0;
        while other < module.fts5_tables.len() {
            let other_name = module.fts5_tables[other].name;
            if (other > index && same(name, other_name))
                || (other != index && is_shadow_of(name, other_name))
            {
                return Err(DeclarationError::DuplicateTable { table: name });
            }
            other += 1;
        }
        index += 1;
    }
    Ok(())
}

/// True when `name` is `<fts5>_<suffix>` for a shadow table suffix of FTS5.
const fn is_shadow_of(name: &str, fts5: &str) -> bool {
    let name = name.as_bytes();
    let fts5 = fts5.as_bytes();
    if name.len() <= fts5.len() + 1 || name[fts5.len()] != b'_' {
        return false;
    }
    let mut index = 0;
    while index < fts5.len() {
        if name[index] != fts5[index] {
            return false;
        }
        index += 1;
    }
    let (_, suffix) = name.split_at(fts5.len() + 1);
    let mut known = 0;
    while known < FTS5_SHADOW_SUFFIXES.len() {
        if same_bytes(suffix, FTS5_SHADOW_SUFFIXES[known].as_bytes()) {
            return true;
        }
        known += 1;
    }
    false
}

const fn find_table(module: &ModuleDeclaration, name: &str) -> Option<&'static Table> {
    let mut index = 0;
    while index < module.tables.len() {
        if same(module.tables[index].name, name) {
            return Some(&module.tables[index]);
        }
        index += 1;
    }
    None
}

const fn has_field(table: &Table, name: &str) -> bool {
    let mut index = 0;
    while index < table.fields.len() {
        if same(table.fields[index].name, name) {
            return true;
        }
        index += 1;
    }
    false
}

/// The identifier grammar of [`DeclarationError::InvalidIdentifier`].
const fn identifier(kind: IdentifierKind, name: &'static str) -> Result<(), DeclarationError> {
    if is_identifier(name) {
        Ok(())
    } else {
        Err(DeclarationError::InvalidIdentifier { kind, name })
    }
}

/// True for a lowercase ASCII letter followed by lowercase ASCII letters, digits and underscores,
/// at most [`IDENTIFIER_MAX_LEN`] in all, outside SQLite's reserved `sqlite_` prefix. The grammar
/// holds no space, quote or dot, so an identifier needs no quoting and carries no sentence.
pub const fn is_identifier(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > IDENTIFIER_MAX_LEN || !bytes[0].is_ascii_lowercase() {
        return false;
    }
    let mut index = 1;
    while index < bytes.len() {
        let byte = bytes[index];
        if !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_') {
            return false;
        }
        index += 1;
    }
    let reserved = b"sqlite_";
    !(bytes.len() >= reserved.len() && same_bytes(bytes.split_at(reserved.len()).0, reserved))
}

const fn listed(list: &[&str], name: &str) -> bool {
    let mut index = 0;
    while index < list.len() {
        if same(list[index], name) {
            return true;
        }
        index += 1;
    }
    false
}

const fn same(left: &str, right: &str) -> bool {
    same_bytes(left.as_bytes(), right.as_bytes())
}

const fn same_bytes(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}
