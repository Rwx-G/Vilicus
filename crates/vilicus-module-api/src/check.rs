//! The rules a module declaration must meet before the registry accepts it (FR-18, FR-21, FR-22,
//! FR-24, FR-58, FR-60, FR-68, AD-6, AD-8, AD-9, AD-29, AD-48, I13, I18, D20, D46, D98, D103,
//! D104, D127), as `const`
//! functions: a module checks its own declaration in a `const` item, where a refusal stops the
//! build, and the Core's registry runs the same check on every module it is built from.
//!
//! What the migrated file actually holds (the envelope columns, the field columns, the FTS5
//! arguments and `secure-delete`) is the registry's comparison with the file, and whether each
//! tool's row exists in `doc/capability-matrix.md` with the same tier and confirmation is the
//! registry's comparison with the matrix, both in `vilicus-core`.

use core::fmt;

use vilicus_types::{ExceptionClass, ModuleName, Tier};

use crate::declaration::{
    ENVELOPE, FTS5_SHADOW_SUFFIXES, Field, FieldKind, Fts5Content, Fts5Table, ModuleDeclaration,
    Structured, Table,
};
use crate::event::{Consumer, Topic, is_topic};
use crate::tool::{Confirmation, Tool};

/// Longest identifier accepted for a table, a field, an FTS5 table or column, an enumeration
/// value or a vocabulary name.
pub const IDENTIFIER_MAX_LEN: usize = 64;

/// Longest maximum length a free-text field may declare, in characters: 1 Mi characters, far above
/// any note or draft the modules hold, and low enough that the write path fuzz test can write one
/// character past any declared maximum.
pub const FREE_TEXT_MAX_LEN: u32 = 1 << 20;

/// Names SQLite gives the rowid of a table that has no column of that name: a field of one of
/// these names would take the place of the rowid in every statement that names it. `_rowid_` is
/// outside the identifier grammar already.
pub const ROWID_NAMES: &[&str] = &["rowid", "oid", "_rowid_"];

/// Column names an FTS5 table keeps for itself (`rank`, its rowid); an FTS5 table's own name is
/// one too, the hidden column that takes its special commands.
pub const FTS5_RESERVED_COLUMNS: &[&str] = &["rank", "rowid"];

/// The capability matrix section of the Core and its administration (`doc/capability-matrix.md`,
/// section 1), which no module may claim.
pub const CORE_MATRIX_SECTION: &str = "1";

/// Longest capability matrix section number accepted.
pub const MATRIX_SECTION_MAX_LEN: usize = 8;

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
    /// A tool.
    Tool,
    /// The undo handler a tool names.
    UndoHandler,
    /// A consumer of events.
    Consumer,
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
            Self::Tool => "tool",
            Self::UndoHandler => "undo handler",
            Self::Consumer => "consumer",
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
    /// Two fields of a table, or two arguments of a tool, share a name.
    DuplicateField {
        /// The table, or the tool for an argument.
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
    /// A free-text field declares a maximum length above [`FREE_TEXT_MAX_LEN`].
    FreeTextTooLong {
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
    /// A capability matrix section the module claims is not a section number: ASCII digits, the
    /// first not 0, then lowercase ASCII letters, at most [`MATRIX_SECTION_MAX_LEN`] in all
    /// (`2`, `10a`).
    InvalidMatrixSection {
        /// The section refused.
        section: &'static str,
    },
    /// The module claims the Core's capability matrix section, [`CORE_MATRIX_SECTION`]: its rows
    /// are the Core's own actions, never a module's.
    CoreMatrixSection {
        /// The section.
        section: &'static str,
    },
    /// The module claims a capability matrix section twice.
    DuplicateMatrixSection {
        /// The section claimed twice.
        section: &'static str,
    },
    /// Two tools of the module share a name.
    DuplicateTool {
        /// The name used twice.
        tool: &'static str,
    },
    /// A tool is tier H: a human-only action is a Core operation outside the tool registry, never
    /// a tool (I18, AD-8).
    HumanOnlyTool {
        /// The tool.
        tool: &'static str,
    },
    /// A tool is tier 2, and no tier 2 action is registered before the native app exists (D46,
    /// FR-60).
    Tier2BeforeNativeApp {
        /// The tool.
        tool: &'static str,
    },
    /// A tool moves or copies a record across partitions, which is tier 2 and so unregistered
    /// before the native app exists (FR-21, D46).
    CrossPartitionTool {
        /// The tool.
        tool: &'static str,
    },
    /// A tool that changes state outside the instance is below tier 2 without an exception class
    /// (I13).
    NetworkEffectBelowTier2 {
        /// The tool.
        tool: &'static str,
    },
    /// A tool that declares an exception class is not tier 1 (AD-48).
    ExceptionClassOutsideTier1 {
        /// The tool.
        tool: &'static str,
    },
    /// A tool declares an exception class but no network effect: a class only ever excuses a
    /// change of state outside the instance from tier 2 (I13).
    ExceptionClassWithoutNetworkEffect {
        /// The tool.
        tool: &'static str,
    },
    /// A `reversible_external_state` or `own_account_delivery` tool does not require light
    /// confirmation (I13, AD-48).
    ExceptionClassWithoutLightConfirmation {
        /// The tool.
        tool: &'static str,
        /// The class's name.
        class: &'static str,
    },
    /// A tool that declares an exception class names no undo handler (I13).
    ExceptionClassWithoutUndoHandler {
        /// The tool.
        tool: &'static str,
    },
    /// A tool outside tier 1 requires light confirmation, which approves a tier 1 request only
    /// (`doc/capability-matrix.md`, Legend).
    LightConfirmationOutsideTier1 {
        /// The tool.
        tool: &'static str,
    },
    /// A tier 0 tool names an undo handler: a read changes nothing to undo.
    UndoHandlerOnRead {
        /// The tool.
        tool: &'static str,
    },
    /// A tool's matrix row is in a section the module does not claim.
    MatrixRowOutsideModuleSections {
        /// The tool.
        tool: &'static str,
        /// The row's section.
        section: &'static str,
    },
    /// A tool's matrix row has no Action text a matrix cell can hold: empty, with white space at
    /// either end, or with a `|` or a control character.
    InvalidMatrixAction {
        /// The tool.
        tool: &'static str,
    },
    /// A topic name is outside the grammar `<module>.<entity>.<past_verb>`, or a consumer names
    /// such a topic.
    InvalidTopic {
        /// The topic.
        topic: &'static str,
    },
    /// A module declares a topic of another module: the Core stamps the real emitter, so a
    /// module emits its own topics only (D20).
    ForeignTopic {
        /// The topic.
        topic: &'static str,
    },
    /// A topic declares payload version 0; versions start at 1 (AD-29).
    TopicWithoutVersion {
        /// The topic.
        topic: &'static str,
    },
    /// Two topics of the module share a name.
    DuplicateTopic {
        /// The topic.
        topic: &'static str,
    },
    /// A topic's access list names something other than a module name, or a module twice.
    InvalidTopicConsumer {
        /// The topic.
        topic: &'static str,
        /// The entry refused.
        module: &'static str,
    },
    /// Two consumers of the module share a name.
    DuplicateConsumer {
        /// The consumer.
        consumer: &'static str,
    },
    /// Two consumers of the module consume one topic: a module has one consumer per topic, so
    /// each delivery to the module is one call.
    TwoConsumersOfOneTopic {
        /// The topic.
        topic: &'static str,
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
            Self::FreeTextTooLong { .. } => "a free-text field declares too long a maximum length",
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
            Self::InvalidMatrixSection { .. } => {
                "a capability matrix section is not a section number"
            }
            Self::DuplicateMatrixSection { .. } => "a capability matrix section is claimed twice",
            Self::CoreMatrixSection { .. } => {
                "a module claims the Core's capability matrix section"
            }
            Self::DuplicateTool { .. } => "two tools share a name",
            Self::HumanOnlyTool { .. } => "a tool is tier H, which is never a tool",
            Self::Tier2BeforeNativeApp { .. } => {
                "a tool is tier 2, unregistered before the native app"
            }
            Self::CrossPartitionTool { .. } => {
                "a tool crosses partitions, tier 2 and unregistered before the native app"
            }
            Self::NetworkEffectBelowTier2 { .. } => {
                "a tool with an outbound effect is below tier 2 without an exception class"
            }
            Self::ExceptionClassOutsideTier1 { .. } => {
                "a tool with an exception class is not tier 1"
            }
            Self::ExceptionClassWithoutNetworkEffect { .. } => {
                "a tool declares an exception class without a network effect"
            }
            Self::ExceptionClassWithoutLightConfirmation { .. } => {
                "a tool of this exception class does not require light confirmation"
            }
            Self::ExceptionClassWithoutUndoHandler { .. } => {
                "a tool with an exception class names no undo handler"
            }
            Self::LightConfirmationOutsideTier1 { .. } => {
                "a tool outside tier 1 requires light confirmation"
            }
            Self::UndoHandlerOnRead { .. } => "a tier 0 tool names an undo handler",
            Self::MatrixRowOutsideModuleSections { .. } => {
                "a tool's matrix row is in a section its module does not claim"
            }
            Self::InvalidMatrixAction { .. } => "a tool's matrix row has no valid action text",
            Self::InvalidTopic { .. } => {
                "a topic is outside the <module>.<entity>.<past_verb> grammar"
            }
            Self::ForeignTopic { .. } => "a module declares a topic of another module",
            Self::TopicWithoutVersion { .. } => "a topic declares payload version 0",
            Self::DuplicateTopic { .. } => "two topics share a name",
            Self::InvalidTopicConsumer { .. } => {
                "a topic's access list names something other than a module, or a module twice"
            }
            Self::DuplicateConsumer { .. } => "two consumers share a name",
            Self::TwoConsumersOfOneTopic { .. } => "two consumers of a module consume one topic",
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
            | Self::FreeTextTooLong { table, field }
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
            Self::InvalidMatrixSection { section }
            | Self::DuplicateMatrixSection { section }
            | Self::CoreMatrixSection { section } => {
                write!(formatter, ": {section:?}")
            }
            Self::DuplicateTool { tool }
            | Self::HumanOnlyTool { tool }
            | Self::Tier2BeforeNativeApp { tool }
            | Self::CrossPartitionTool { tool }
            | Self::NetworkEffectBelowTier2 { tool }
            | Self::ExceptionClassOutsideTier1 { tool }
            | Self::ExceptionClassWithoutNetworkEffect { tool }
            | Self::ExceptionClassWithoutUndoHandler { tool }
            | Self::LightConfirmationOutsideTier1 { tool }
            | Self::UndoHandlerOnRead { tool }
            | Self::InvalidMatrixAction { tool } => write!(formatter, ": {tool}"),
            Self::ExceptionClassWithoutLightConfirmation { tool, class } => {
                write!(formatter, ": {tool} ({class})")
            }
            Self::MatrixRowOutsideModuleSections { tool, section } => {
                write!(formatter, ": {tool} (section {section})")
            }
            Self::InvalidTopic { topic }
            | Self::ForeignTopic { topic }
            | Self::TopicWithoutVersion { topic }
            | Self::DuplicateTopic { topic }
            | Self::TwoConsumersOfOneTopic { topic } => write!(formatter, ": {topic:?}"),
            Self::InvalidTopicConsumer { topic, module } => {
                write!(formatter, ": {topic} ({module:?})")
            }
            Self::DuplicateConsumer { consumer } => write!(formatter, ": {consumer}"),
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
        check!(validate_matrix_sections(self.matrix_sections));
        index = 0;
        while index < self.tools.len() {
            let tool = &self.tools[index];
            check!(validate_tool(self, tool));
            let mut other = index + 1;
            while other < self.tools.len() {
                if same(tool.name, self.tools[other].name) {
                    return Err(DeclarationError::DuplicateTool { tool: tool.name });
                }
                other += 1;
            }
            index += 1;
        }
        index = 0;
        while index < self.topics.len() {
            check!(validate_topic(self, index));
            index += 1;
        }
        index = 0;
        while index < self.consumers.len() {
            check!(validate_consumer(self.consumers, index));
            index += 1;
        }
        Ok(())
    }

    /// [`validate`](Self::validate), stopping the build with the broken rule when it is called in
    /// a `const` item:
    ///
    /// ```
    /// use vilicus_module_api::{
    ///     Confirmation, DataType, Field, FieldKind, MatrixRow, Migration, ModuleDeclaration,
    ///     Table, Tier, Tool, sha256_hex,
    /// };
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
    ///         sql: "CREATE TABLE notes (id BLOB NOT NULL PRIMARY KEY, \
    ///               body TEXT NOT NULL) STRICT;",
    ///         sha256: sha256_hex("bd3ae7e55c50de674128958bd6bdb1da23a2c490ad40895aeccdac1da6575bc7"),
    ///     }],
    ///     matrix_sections: &["7"],
    ///     topics: &[],
    ///     consumers: &[],
    ///     tools: &[Tool {
    ///         name: "create_note",
    ///         arguments: &[Field {
    ///             name: "body",
    ///             kind: FieldKind::FreeText { max_len: 2000 },
    ///             optional: false,
    ///         }],
    ///         tier: Tier::ReversibleWrite,
    ///         network_effect: false,
    ///         exception_class: None,
    ///         confirmation: Confirmation::None,
    ///         crosses_partitions: false,
    ///         undo_handler: None,
    ///         matrix_row: MatrixRow { section: "7", action: "Create or edit a page" },
    ///     }],
    /// };
    /// const _: () = MODULE.assert_valid();
    /// ```
    ///
    /// A record kind without a data type does not build (FR-68):
    ///
    /// ```compile_fail,E0080
    /// use vilicus_module_api::{Migration, ModuleDeclaration, Table, sha256_hex};
    ///
    /// const MODULE: ModuleDeclaration = ModuleDeclaration {
    ///     name: "notes",
    ///     tables: &[Table { name: "notes", data_types: &[], fields: &[] }],
    ///     fts5_tables: &[],
    ///     migrations: &[Migration {
    ///         sql: "CREATE TABLE notes (id BLOB) STRICT;",
    ///         sha256: sha256_hex("504c31b0d64a5a28102bc23da76c8128190f99fec66184760eb62fd388c051a6"),
    ///     }],
    ///     matrix_sections: &[],
    ///     topics: &[],
    ///     consumers: &[],
    ///     tools: &[],
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
    /// A tool that does not declare its network effect does not build (I13):
    ///
    /// ```compile_fail,E0063
    /// use vilicus_module_api::{Confirmation, MatrixRow, Tier, Tool};
    ///
    /// const READ: Tool = Tool {
    ///     name: "read_notes",
    ///     arguments: &[],
    ///     tier: Tier::Read,
    ///     exception_class: None,
    ///     confirmation: Confirmation::None,
    ///     crosses_partitions: false,
    ///     undo_handler: None,
    ///     matrix_row: MatrixRow { section: "7", action: "Read pages and procedures" },
    /// };
    /// ```
    ///
    /// Nor does an exception class outside the closed set of I13 (AD-48):
    ///
    /// ```compile_fail,E0599
    /// use vilicus_module_api::ExceptionClass;
    ///
    /// const CLASS: Option<ExceptionClass> = Some(ExceptionClass::SystemNotification);
    /// ```
    ///
    /// Nor does a tier H tool (I18), or a tier 2 tool before the native app (D46, FR-60):
    ///
    /// ```compile_fail,E0080
    /// use vilicus_module_api::{Confirmation, MatrixRow, ModuleDeclaration, Tier, Tool};
    ///
    /// const MODULE: ModuleDeclaration = ModuleDeclaration {
    ///     name: "plugins",
    ///     tables: &[],
    ///     fts5_tables: &[],
    ///     migrations: &[],
    ///     matrix_sections: &["10"],
    ///     topics: &[],
    ///     consumers: &[],
    ///     tools: &[Tool {
    ///         name: "install_plugin",
    ///         arguments: &[],
    ///         tier: Tier::HumanOnly,
    ///         network_effect: false,
    ///         exception_class: None,
    ///         confirmation: Confirmation::None,
    ///         crosses_partitions: false,
    ///         undo_handler: None,
    ///         matrix_row: MatrixRow { section: "10", action: "Install or enable a plugin" },
    ///     }],
    /// };
    /// const _: () = MODULE.assert_valid();
    /// ```
    ///
    /// ```compile_fail,E0080
    /// use vilicus_module_api::{Confirmation, MatrixRow, ModuleDeclaration, Tier, Tool};
    ///
    /// const MODULE: ModuleDeclaration = ModuleDeclaration {
    ///     name: "tasks",
    ///     tables: &[],
    ///     fts5_tables: &[],
    ///     migrations: &[],
    ///     matrix_sections: &["2"],
    ///     topics: &[],
    ///     consumers: &[],
    ///     tools: &[Tool {
    ///         name: "purge_tasks",
    ///         arguments: &[],
    ///         tier: Tier::Irreversible,
    ///         network_effect: false,
    ///         exception_class: None,
    ///         confirmation: Confirmation::None,
    ///         crosses_partitions: false,
    ///         undo_handler: None,
    ///         matrix_row: MatrixRow { section: "2", action: "Purge deleted tasks" },
    ///     }],
    /// };
    /// const _: () = MODULE.assert_valid();
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
        FieldKind::FreeText { max_len } if max_len > FREE_TEXT_MAX_LEN => {
            Err(DeclarationError::FreeTextTooLong {
                table,
                field: field.name,
            })
        }
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

const fn validate_matrix_sections(sections: &[&'static str]) -> Result<(), DeclarationError> {
    let mut index = 0;
    while index < sections.len() {
        let section = sections[index];
        if !is_matrix_section(section) {
            return Err(DeclarationError::InvalidMatrixSection { section });
        }
        if same(section, CORE_MATRIX_SECTION) {
            return Err(DeclarationError::CoreMatrixSection { section });
        }
        let mut other = index + 1;
        while other < sections.len() {
            if same(section, sections[other]) {
                return Err(DeclarationError::DuplicateMatrixSection { section });
            }
            other += 1;
        }
        index += 1;
    }
    Ok(())
}

/// The rules of a tool: its schema, then I18, FR-21, AD-48, I13 and D46 on its tier, partition
/// effect, network effect, exception class, confirmation and undo handler, then its matrix row.
const fn validate_tool(module: &ModuleDeclaration, tool: &Tool) -> Result<(), DeclarationError> {
    let name = tool.name;
    check!(identifier(IdentifierKind::Tool, name));
    let mut index = 0;
    while index < tool.arguments.len() {
        let argument = &tool.arguments[index];
        check!(validate_field(name, argument));
        let mut other = index + 1;
        while other < tool.arguments.len() {
            if same(argument.name, tool.arguments[other].name) {
                return Err(DeclarationError::DuplicateField {
                    table: name,
                    field: argument.name,
                });
            }
            other += 1;
        }
        index += 1;
    }
    if matches!(tool.tier, Tier::HumanOnly) {
        return Err(DeclarationError::HumanOnlyTool { tool: name });
    }
    if tool.crosses_partitions {
        return Err(DeclarationError::CrossPartitionTool { tool: name });
    }
    match tool.exception_class {
        Some(class) => {
            if !matches!(tool.tier, Tier::ReversibleWrite) {
                return Err(DeclarationError::ExceptionClassOutsideTier1 { tool: name });
            }
            if !tool.network_effect {
                return Err(DeclarationError::ExceptionClassWithoutNetworkEffect { tool: name });
            }
            if matches!(
                class,
                ExceptionClass::ReversibleExternalState | ExceptionClass::OwnAccountDelivery
            ) && !matches!(tool.confirmation, Confirmation::Light)
            {
                return Err(DeclarationError::ExceptionClassWithoutLightConfirmation {
                    tool: name,
                    class: class.as_str(),
                });
            }
            if tool.undo_handler.is_none() {
                return Err(DeclarationError::ExceptionClassWithoutUndoHandler { tool: name });
            }
        }
        None => {
            if tool.network_effect && !matches!(tool.tier, Tier::Irreversible) {
                return Err(DeclarationError::NetworkEffectBelowTier2 { tool: name });
            }
        }
    }
    if matches!(tool.tier, Tier::Irreversible) {
        return Err(DeclarationError::Tier2BeforeNativeApp { tool: name });
    }
    if matches!(tool.confirmation, Confirmation::Light)
        && !matches!(tool.tier, Tier::ReversibleWrite)
    {
        return Err(DeclarationError::LightConfirmationOutsideTier1 { tool: name });
    }
    if let Some(handler) = tool.undo_handler {
        if matches!(tool.tier, Tier::Read) {
            return Err(DeclarationError::UndoHandlerOnRead { tool: name });
        }
        check!(identifier(IdentifierKind::UndoHandler, handler));
    }
    if !listed(module.matrix_sections, tool.matrix_row.section) {
        return Err(DeclarationError::MatrixRowOutsideModuleSections {
            tool: name,
            section: tool.matrix_row.section,
        });
    }
    if !is_matrix_action(tool.matrix_row.action) {
        return Err(DeclarationError::InvalidMatrixAction { tool: name });
    }
    Ok(())
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

/// The rules of the topic at `index` of `module`: its name in the topic grammar and of the
/// module, a version from 1, unique in the module, and an access list of distinct module names.
const fn validate_topic(module: &ModuleDeclaration, index: usize) -> Result<(), DeclarationError> {
    let topic: &Topic = &module.topics[index];
    let name = topic.name;
    if !is_topic(name) {
        return Err(DeclarationError::InvalidTopic { topic: name });
    }
    let prefix = module.name.as_bytes();
    if name.len() <= prefix.len()
        || name.as_bytes()[prefix.len()] != b'.'
        || !same_bytes(name.as_bytes().split_at(prefix.len()).0, prefix)
    {
        return Err(DeclarationError::ForeignTopic { topic: name });
    }
    if topic.version == 0 {
        return Err(DeclarationError::TopicWithoutVersion { topic: name });
    }
    let mut other = index + 1;
    while other < module.topics.len() {
        if same(name, module.topics[other].name) {
            return Err(DeclarationError::DuplicateTopic { topic: name });
        }
        other += 1;
    }
    let mut entry = 0;
    while entry < topic.consumers.len() {
        let consumer = topic.consumers[entry];
        let mut later = entry + 1;
        let mut repeated = false;
        while later < topic.consumers.len() {
            repeated = repeated || same(consumer, topic.consumers[later]);
            later += 1;
        }
        if repeated || !ModuleName::is_valid(consumer) {
            return Err(DeclarationError::InvalidTopicConsumer {
                topic: name,
                module: consumer,
            });
        }
        entry += 1;
    }
    Ok(())
}

/// The rules of the consumer at `index` of `consumers`: an identifier, unique, of a topic in
/// the topic grammar that no other consumer of the module consumes.
const fn validate_consumer(consumers: &[Consumer], index: usize) -> Result<(), DeclarationError> {
    let consumer = &consumers[index];
    check!(identifier(IdentifierKind::Consumer, consumer.name));
    if !is_topic(consumer.topic) {
        return Err(DeclarationError::InvalidTopic {
            topic: consumer.topic,
        });
    }
    let mut other = index + 1;
    while other < consumers.len() {
        if same(consumer.name, consumers[other].name) {
            return Err(DeclarationError::DuplicateConsumer {
                consumer: consumer.name,
            });
        }
        if same(consumer.topic, consumers[other].topic) {
            return Err(DeclarationError::TwoConsumersOfOneTopic {
                topic: consumer.topic,
            });
        }
        other += 1;
    }
    Ok(())
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

/// True for a capability matrix section number as its heading writes it: ASCII digits, the first
/// not 0, then lowercase ASCII letters, at most [`MATRIX_SECTION_MAX_LEN`] in all (`2`, `10a`).
pub const fn is_matrix_section(section: &str) -> bool {
    let bytes = section.as_bytes();
    if bytes.is_empty() || bytes.len() > MATRIX_SECTION_MAX_LEN || !matches!(bytes[0], b'1'..=b'9')
    {
        return false;
    }
    let mut index = 1;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    while index < bytes.len() && bytes[index].is_ascii_lowercase() {
        index += 1;
    }
    index == bytes.len()
}

/// True for text a matrix Action cell can hold as it is read back: not empty, no white space at
/// either end, no `|` and no control character.
const fn is_matrix_action(action: &str) -> bool {
    let bytes = action.as_bytes();
    if bytes.is_empty()
        || bytes[0].is_ascii_whitespace()
        || bytes[bytes.len() - 1].is_ascii_whitespace()
    {
        return false;
    }
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'|' || bytes[index].is_ascii_control() {
            return false;
        }
        index += 1;
    }
    true
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

pub(crate) const fn same(left: &str, right: &str) -> bool {
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
