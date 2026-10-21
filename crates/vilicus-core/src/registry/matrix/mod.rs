//! The capability matrix check (FR-22, AD-9, I13, I18, D46): `doc/capability-matrix.md` read back
//! into its rows, and the registry's tool table compared with them in both directions.
//!
//! A tool names its row by section number and Action cell ([`MatrixRow`]); a module claims the
//! sections it implements. The check fails on a tool whose row is absent, is not a tool's row
//! (tier H, `n/a`, tier 2 before the native app, or a cell that names no single tier), has an
//! unsettled exception class, or gives another tier, confirmation, exception class or network
//! effect than the tool declares; and on a row of a claimed section that a tool could implement
//! but none does, or that the check cannot assign. Several tools may implement one row; each is
//! compared with it. The matrix is the design's statement of every action
//! (`doc/capability-matrix.md`, section 12); a binary checks its registry against it in a test,
//! and the testbed against its own fixture.
//!
//! The reader accepts only the plain table forms the matrix uses: anything it does not recognise
//! in a table of actions, or in a numbered section, is a refusal, never a guess.

#[cfg(test)]
mod tests;

use core::fmt;

use vilicus_module_api::{
    Confirmation, ExceptionClass, MatrixRow, ModuleDeclaration, Tier, Tool, is_matrix_section,
};

use super::Registry;

/// The header of a table of actions: its first column, the one a tool's
/// [`MatrixRow::action`] names.
const ACTION_COLUMN: &str = "Action";
/// The column holding a row's tier.
const TIER_COLUMN: &str = "Tier";
/// The column holding a row's confirmation.
const CONFIRMATION_COLUMN: &str = "Confirmation";
/// The column holding a row's exception class.
const EXCEPTION_CLASS_COLUMN: &str = "Exception class";
/// The Exception class cell of a row with no class.
const NO_CLASS: &str = "none";
/// The Exception class cell of a row whose class the design has not settled.
const UNSETTLED_CLASS: &str = "unsettled";

/// `doc/capability-matrix.md`, or a fixture in its format, read back: its numbered sections and
/// the rows of their tables of actions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityMatrix {
    sections: Vec<MatrixSection>,
}

/// A numbered section of the matrix (`## 10a. Home automation`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatrixSection {
    /// The number before the period: `10a`.
    pub number: String,
    /// The title after it: `Home automation`.
    pub title: String,
    /// True when the section holds a table of actions; a module can claim only such a section.
    pub has_actions: bool,
    /// The rows of its tables of actions, in order.
    pub rows: Vec<MatrixEntry>,
}

/// A row of a table of actions, with the cells the check reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatrixEntry {
    /// The Action cell.
    pub action: String,
    /// The Tier cell, as written.
    pub tier: String,
    /// The Confirmation cell, as written.
    pub confirmation: String,
    /// The Exception class cell, as read.
    pub class: RowClass,
    /// The line of the row in the document, from 1.
    pub line: usize,
}

/// How the check reads a row's Tier cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowTier {
    /// `0` or `1`: a tier a tool of this milestone can have.
    Registrable(Tier),
    /// `2`, marked or not (`2 (D46)`, `2 (D69)`): no tool before the native app (D46, FR-60).
    Irreversible,
    /// `H`: a human-only action, never a tool (I18, AD-8).
    HumanOnly,
    /// `n/a`: a Core operation, or not an action of Vilicus, never a tool.
    NotApplicable,
    /// A cell that names no single tier, such as `0 or 1` or `1; H when ...`: no tool can claim
    /// the row until it is split into rows of one tier each.
    NotOneTier,
}

/// A row's Exception class cell: `none`, a member of the closed set of I13, or `unsettled`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowClass {
    /// `none`: the row's tool declares no class, so it changes no state outside the instance
    /// below tier 2.
    None,
    /// The row's tool declares this class, and with it a network effect.
    Class(ExceptionClass),
    /// `unsettled`: the design has not settled the row's class, so no tool can implement it.
    Unsettled,
}

impl RowClass {
    /// Reads an Exception class cell; `None` for any other text.
    fn read(cell: &str) -> Option<Self> {
        match cell {
            NO_CLASS => Some(Self::None),
            UNSETTLED_CLASS => Some(Self::Unsettled),
            _ => ExceptionClass::ALL
                .iter()
                .copied()
                .find(|class| class.as_str() == cell)
                .map(Self::Class),
        }
    }
}

impl fmt::Display for RowClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => formatter.write_str(NO_CLASS),
            Self::Class(class) => formatter.write_str(class.as_str()),
            Self::Unsettled => formatter.write_str(UNSETTLED_CLASS),
        }
    }
}

impl MatrixEntry {
    /// The row's tier, as the check reads its Tier cell.
    pub fn row_tier(&self) -> RowTier {
        match self.tier.as_str() {
            "0" => RowTier::Registrable(Tier::Read),
            "1" => RowTier::Registrable(Tier::ReversibleWrite),
            "H" => RowTier::HumanOnly,
            "n/a" => RowTier::NotApplicable,
            tier if tier == "2" || is_decision_marked_tier_2(tier) => RowTier::Irreversible,
            _ => RowTier::NotOneTier,
        }
    }

    /// The confirmation the row requires of a tool, from the first term of its Confirmation
    /// cell (`light, in the app` reads as light); `None` when that term is not a tool's
    /// confirmation (`signed`, `step-up`, `spoken`, `provider policy`, `light to grant`).
    pub fn tool_confirmation(&self) -> Option<Confirmation> {
        tool_confirmation(&self.confirmation)
    }
}

fn tool_confirmation(cell: &str) -> Option<Confirmation> {
    let first = cell.split([',', ';']).next().unwrap_or_default();
    let first = first
        .split_once(" (")
        .map_or(first, |(term, _)| term)
        .trim();
    Confirmation::ALL
        .iter()
        .copied()
        .find(|confirmation| confirmation.as_str() == first)
}

/// `2 (D<digits>)`: a tier 2 row marked with the decision that keeps it unregistered.
fn is_decision_marked_tier_2(tier: &str) -> bool {
    tier.strip_prefix("2 (D")
        .and_then(|rest| rest.strip_suffix(')'))
        .is_some_and(|digits| {
            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
        })
}

/// Why the matrix cannot be read. Each variant names the line, from 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MatrixError {
    /// A table row does not start and end with `|`.
    MalformedRow {
        /// The line.
        line: usize,
    },
    /// The line after a table header is not its separator row, or there is none: a lone table
    /// row reads as a header.
    MissingSeparator {
        /// The line.
        line: usize,
    },
    /// A separator row has another number of cells than its header.
    SeparatorCellCount {
        /// The line.
        line: usize,
    },
    /// A table row in a numbered section does not start at the line's first character.
    IndentedTableRow {
        /// The line.
        line: usize,
    },
    /// A table-like line sits in a fenced code block of a numbered section.
    TableInFence {
        /// The line.
        line: usize,
    },
    /// A table has a `Tier` column but its first column is not exactly `Action`.
    MisplacedActionColumn {
        /// The line of its header.
        line: usize,
    },
    /// A table of actions sits outside a numbered section.
    TableOutsideSection {
        /// The line of its header.
        line: usize,
    },
    /// A table of actions has no column of this name.
    MissingColumn {
        /// The line of its header.
        line: usize,
        /// The column.
        column: &'static str,
    },
    /// A row has another number of cells than its header.
    CellCount {
        /// The line.
        line: usize,
    },
    /// A row's Action cell is empty.
    EmptyAction {
        /// The line.
        line: usize,
    },
    /// A row's Exception class cell is not `none`, `unsettled` or a member of the closed set.
    UnknownExceptionClass {
        /// The line.
        line: usize,
        /// The cell.
        value: String,
    },
    /// A row with an exception class is not tier 1 (AD-48).
    ExceptionClassOutsideTier1 {
        /// The line.
        line: usize,
    },
    /// A `reversible_external_state` or `own_account_delivery` row does not require light
    /// confirmation (I13, AD-48).
    ExceptionClassWithoutLightConfirmation {
        /// The line.
        line: usize,
    },
    /// Two rows of a section share an Action cell, so a tool's row would be ambiguous.
    DuplicateAction {
        /// The line of the second row.
        line: usize,
        /// The section.
        section: String,
        /// The Action cell.
        action: String,
    },
    /// Two sections share a number.
    DuplicateSection {
        /// The line of the second heading.
        line: usize,
        /// The number.
        section: String,
    },
}

impl fmt::Display for MatrixError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedRow { line } => {
                write!(
                    formatter,
                    "line {line}: a table row does not start and end with |"
                )
            }
            Self::MissingSeparator { line } => {
                write!(
                    formatter,
                    "line {line}: a table header has no separator row"
                )
            }
            Self::SeparatorCellCount { line } => write!(
                formatter,
                "line {line}: a separator row has another number of cells than its header"
            ),
            Self::IndentedTableRow { line } => {
                write!(
                    formatter,
                    "line {line}: a table row of a section is indented"
                )
            }
            Self::TableInFence { line } => write!(
                formatter,
                "line {line}: a table row of a section is in a fenced code block"
            ),
            Self::MisplacedActionColumn { line } => write!(
                formatter,
                "line {line}: a table with a Tier column does not start with the Action column"
            ),
            Self::TableOutsideSection { line } => write!(
                formatter,
                "line {line}: a table of actions is outside a numbered section"
            ),
            Self::MissingColumn { line, column } => write!(
                formatter,
                "line {line}: a table of actions has no {column} column"
            ),
            Self::CellCount { line } => write!(
                formatter,
                "line {line}: a row has another number of cells than its header"
            ),
            Self::EmptyAction { line } => write!(formatter, "line {line}: an Action cell is empty"),
            Self::UnknownExceptionClass { line, value } => {
                write!(formatter, "line {line}: unknown exception class {value:?}")
            }
            Self::ExceptionClassOutsideTier1 { line } => write!(
                formatter,
                "line {line}: a row with an exception class is not tier 1"
            ),
            Self::ExceptionClassWithoutLightConfirmation { line } => write!(
                formatter,
                "line {line}: a row of this exception class does not require light confirmation"
            ),
            Self::DuplicateAction {
                line,
                section,
                action,
            } => write!(
                formatter,
                "line {line}: section {section} has two rows {action:?}"
            ),
            Self::DuplicateSection { line, section } => {
                write!(
                    formatter,
                    "line {line}: two sections are numbered {section}"
                )
            }
        }
    }
}

impl std::error::Error for MatrixError {}

/// The table being read.
enum Table {
    /// Not in a table.
    None,
    /// After a header, before its separator; `Some` holds the columns of a table of actions.
    Header(usize, Option<Columns>),
    /// In the body of a table; `Some` for a table of actions.
    Body(Option<Columns>),
}

/// The section a table of actions belongs to, and where it keeps the cells the check reads.
#[derive(Clone, Copy)]
struct Columns {
    section: usize,
    count: usize,
    tier: usize,
    confirmation: usize,
    class: usize,
}

impl CapabilityMatrix {
    /// Reads `text`, in the format of `doc/capability-matrix.md`: each `## <number>. <title>`
    /// heading opens a section, and each table whose first header cell is `Action` is a table of
    /// actions, which must have `Tier`, `Confirmation` and `Exception class` columns. Other
    /// headings and other tables are not read, but every table needs its separator row. In a
    /// numbered section, an indented table row and a table row in a fenced code block are refused
    /// rather than skipped.
    pub fn parse(text: &str) -> Result<Self, MatrixError> {
        let mut sections: Vec<MatrixSection> = Vec::new();
        let mut current: Option<usize> = None;
        let mut table = Table::None;
        let mut fenced = false;
        let mut last_line = 0;
        for (index, line) in text.lines().enumerate() {
            let line_number = index + 1;
            last_line = line_number;
            if matches!(table, Table::Header(..)) && !line.starts_with('|') {
                return Err(MatrixError::MissingSeparator { line: line_number });
            }
            let trimmed = line.trim_start();
            if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
                fenced = !fenced;
                table = Table::None;
                continue;
            }
            if fenced {
                if current.is_some() && trimmed.starts_with('|') {
                    return Err(MatrixError::TableInFence { line: line_number });
                }
                continue;
            }
            if let Some(heading) = line.strip_prefix("## ") {
                table = Table::None;
                current = None;
                if let Some((number, title)) = numbered_heading(heading) {
                    if sections.iter().any(|section| section.number == number) {
                        return Err(MatrixError::DuplicateSection {
                            line: line_number,
                            section: number.to_owned(),
                        });
                    }
                    sections.push(MatrixSection {
                        number: number.to_owned(),
                        title: title.to_owned(),
                        has_actions: false,
                        rows: Vec::new(),
                    });
                    current = Some(sections.len() - 1);
                }
                continue;
            }
            if !line.starts_with('|') {
                if current.is_some() && trimmed.starts_with('|') {
                    return Err(MatrixError::IndentedTableRow { line: line_number });
                }
                table = Table::None;
                continue;
            }
            let cells = cells(line).ok_or(MatrixError::MalformedRow { line: line_number })?;
            table = match table {
                Table::None => {
                    let columns = header(&cells, current, line_number)?;
                    if let Some(columns) = columns {
                        sections[columns.section].has_actions = true;
                    }
                    Table::Header(cells.len(), columns)
                }
                Table::Header(count, columns) => {
                    if !is_separator(&cells) {
                        return Err(MatrixError::MissingSeparator { line: line_number });
                    }
                    if cells.len() != count {
                        return Err(MatrixError::SeparatorCellCount { line: line_number });
                    }
                    Table::Body(columns)
                }
                Table::Body(None) => Table::Body(None),
                Table::Body(Some(columns)) => {
                    let section = &mut sections[columns.section];
                    let row = entry(section, &cells, columns, line_number)?;
                    section.rows.push(row);
                    Table::Body(Some(columns))
                }
            };
        }
        if matches!(table, Table::Header(..)) {
            return Err(MatrixError::MissingSeparator {
                line: last_line + 1,
            });
        }
        Ok(Self { sections })
    }

    /// The numbered sections, in order.
    pub fn sections(&self) -> &[MatrixSection] {
        &self.sections
    }

    /// The section numbered `number`.
    pub fn section(&self, number: &str) -> Option<&MatrixSection> {
        self.sections
            .iter()
            .find(|section| section.number == number)
    }

    /// The row a tool names.
    pub fn row(&self, row: &MatrixRow) -> Option<&MatrixEntry> {
        self.section(row.section)?
            .rows
            .iter()
            .find(|entry| entry.action == row.action)
    }

    /// Every difference between the registry's tool table and the matrix, in both directions:
    /// empty when they agree.
    pub fn differences(&self, registry: &Registry) -> Vec<MatrixDifference> {
        let mut differences = Vec::new();
        for module in registry.modules() {
            for &section in module.matrix_sections {
                if !self.section(section).is_some_and(|found| found.has_actions) {
                    differences.push(MatrixDifference::SectionMissing {
                        module: module.name,
                        section,
                    });
                }
            }
        }
        for tool in registry.tools() {
            self.tool_differences(&tool, &mut differences);
        }
        for module in registry.modules() {
            self.row_differences(module, &mut differences);
        }
        differences
    }

    /// Every difference a tool makes with its row.
    fn tool_differences(
        &self,
        registered: &RegisteredTool,
        differences: &mut Vec<MatrixDifference>,
    ) {
        let tool = registered.tool;
        let name = registered.qualified_name();
        let row = tool.matrix_row;
        let Some(entry) = self.row(&row) else {
            differences.push(MatrixDifference::ToolWithoutRow { tool: name, row });
            return;
        };
        let RowTier::Registrable(tier) = entry.row_tier() else {
            differences.push(MatrixDifference::RowNotATool {
                tool: name,
                row,
                tier: entry.tier.clone(),
            });
            return;
        };
        if tier != tool.tier {
            differences.push(MatrixDifference::TierMismatch {
                tool: name.clone(),
                row,
                matrix: entry.tier.clone(),
                declared: tool.tier,
            });
        }
        if entry.tool_confirmation() != Some(tool.confirmation) {
            differences.push(MatrixDifference::ConfirmationMismatch {
                tool: name.clone(),
                row,
                matrix: entry.confirmation.clone(),
                declared: tool.confirmation,
            });
        }
        let expected = match entry.class {
            RowClass::Unsettled => {
                differences.push(MatrixDifference::ToolOnUnsettledRow { tool: name, row });
                return;
            }
            RowClass::None => None,
            RowClass::Class(class) => Some(class),
        };
        if tool.exception_class != expected {
            differences.push(MatrixDifference::ExceptionClassMismatch {
                tool: name.clone(),
                row,
                matrix: entry.class,
                declared: tool.exception_class,
            });
        }
        if tool.network_effect != expected.is_some() {
            differences.push(MatrixDifference::NetworkEffectMismatch {
                tool: name,
                row,
                matrix: entry.class,
                declared: tool.network_effect,
            });
        }
    }

    /// The rows of the module's sections that a tool could implement but none of its tools does,
    /// and the rows the check cannot assign: no single tier, or an unsettled class.
    fn row_differences(
        &self,
        module: &'static ModuleDeclaration,
        differences: &mut Vec<MatrixDifference>,
    ) {
        for &number in module.matrix_sections {
            let Some(section) = self.section(number) else {
                continue;
            };
            for entry in &section.rows {
                match (entry.row_tier(), entry.class) {
                    (RowTier::Registrable(_), RowClass::Unsettled) => {
                        differences.push(MatrixDifference::RowWithUnsettledClass {
                            module: module.name,
                            section: number,
                            action: entry.action.clone(),
                        });
                    }
                    (RowTier::Registrable(_), _) => {
                        let implemented = module.tools.iter().any(|tool| {
                            tool.matrix_row.section == number
                                && tool.matrix_row.action == entry.action
                        });
                        if !implemented {
                            differences.push(MatrixDifference::RowWithoutTool {
                                module: module.name,
                                section: number,
                                action: entry.action.clone(),
                            });
                        }
                    }
                    (RowTier::NotOneTier, _) => {
                        differences.push(MatrixDifference::RowWithoutOneTier {
                            module: module.name,
                            section: number,
                            action: entry.action.clone(),
                            tier: entry.tier.clone(),
                        });
                    }
                    (RowTier::Irreversible | RowTier::HumanOnly | RowTier::NotApplicable, _) => {}
                }
            }
        }
    }

    /// The check of a binary or a testbed: `Ok` when the registry's tool table and the matrix
    /// agree, otherwise every difference.
    pub fn check(text: &str, registry: &Registry) -> Result<(), MatrixCheckError> {
        let matrix = Self::parse(text).map_err(MatrixCheckError::Unreadable)?;
        let differences = matrix.differences(registry);
        if differences.is_empty() {
            Ok(())
        } else {
            Err(MatrixCheckError::Differences(differences))
        }
    }
}

/// `<number>. <title>`, the heading of a numbered section; a closing sequence of `#` preceded
/// by a space is not part of the title.
fn numbered_heading(heading: &str) -> Option<(&str, &str)> {
    let (number, title) = heading.split_once(". ")?;
    let title = title.trim_end();
    let unclosed = title.trim_end_matches('#');
    let title = if unclosed.len() < title.len() && unclosed.ends_with(' ') {
        unclosed.trim_end()
    } else {
        title
    };
    (is_matrix_section(number) && !title.is_empty()).then_some((number, title))
}

/// The cells of a table row, trimmed; `None` unless the row starts and ends with `|`.
fn cells(line: &str) -> Option<Vec<&str>> {
    let inner = line.trim_end().strip_prefix('|')?.strip_suffix('|')?;
    Some(inner.split('|').map(str::trim).collect())
}

/// True for a separator row: every cell dashes, with optional alignment colons.
fn is_separator(cells: &[&str]) -> bool {
    cells.iter().all(|cell| {
        let dashes = cell.trim_start_matches(':').trim_end_matches(':');
        !dashes.is_empty() && dashes.bytes().all(|byte| byte == b'-')
    })
}

/// The columns of a table of actions, `None` for another table.
fn header(
    cells: &[&str],
    section: Option<usize>,
    line: usize,
) -> Result<Option<Columns>, MatrixError> {
    if cells.first() != Some(&ACTION_COLUMN) {
        if cells.contains(&TIER_COLUMN) {
            return Err(MatrixError::MisplacedActionColumn { line });
        }
        return Ok(None);
    }
    let section = section.ok_or(MatrixError::TableOutsideSection { line })?;
    let column = |name: &'static str| {
        cells
            .iter()
            .position(|cell| *cell == name)
            .ok_or(MatrixError::MissingColumn { line, column: name })
    };
    Ok(Some(Columns {
        section,
        count: cells.len(),
        tier: column(TIER_COLUMN)?,
        confirmation: column(CONFIRMATION_COLUMN)?,
        class: column(EXCEPTION_CLASS_COLUMN)?,
    }))
}

/// A row of a table of actions in `section`, its exception class held to AD-48.
fn entry(
    section: &MatrixSection,
    cells: &[&str],
    columns: Columns,
    line: usize,
) -> Result<MatrixEntry, MatrixError> {
    if cells.len() != columns.count {
        return Err(MatrixError::CellCount { line });
    }
    let action = cells[0];
    if action.is_empty() {
        return Err(MatrixError::EmptyAction { line });
    }
    if section.rows.iter().any(|row| row.action == action) {
        return Err(MatrixError::DuplicateAction {
            line,
            section: section.number.clone(),
            action: action.to_owned(),
        });
    }
    let class_cell = cells[columns.class];
    let class = RowClass::read(class_cell).ok_or_else(|| MatrixError::UnknownExceptionClass {
        line,
        value: class_cell.to_owned(),
    })?;
    let tier = cells[columns.tier];
    let confirmation = cells[columns.confirmation];
    if let RowClass::Class(class) = class {
        if tier != Tier::ReversibleWrite.as_str() {
            return Err(MatrixError::ExceptionClassOutsideTier1 { line });
        }
        if matches!(
            class,
            ExceptionClass::ReversibleExternalState | ExceptionClass::OwnAccountDelivery
        ) && tool_confirmation(confirmation) != Some(Confirmation::Light)
        {
            return Err(MatrixError::ExceptionClassWithoutLightConfirmation { line });
        }
    }
    Ok(MatrixEntry {
        action: action.to_owned(),
        tier: tier.to_owned(),
        confirmation: confirmation.to_owned(),
        class,
        line,
    })
}

/// A tool of the registry's tool table, with its module.
#[derive(Clone, Copy, Debug)]
pub struct RegisteredTool {
    /// The module that declares it.
    pub module: &'static ModuleDeclaration,
    /// The tool.
    pub tool: &'static Tool,
}

impl RegisteredTool {
    /// `<module>.<tool>`, the name the Core gives the tool.
    pub fn qualified_name(&self) -> String {
        format!("{}.{}", self.module.name, self.tool.name)
    }
}

/// A difference between the registry's tool table and the matrix; each names the tool or the
/// module, and the row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MatrixDifference {
    /// A module claims a section the matrix does not have, or one without a table of actions.
    SectionMissing {
        /// The module.
        module: &'static str,
        /// The section.
        section: &'static str,
    },
    /// A tool's row is not in the matrix.
    ToolWithoutRow {
        /// The tool, `<module>.<tool>`.
        tool: String,
        /// The row it names.
        row: MatrixRow,
    },
    /// A tool's row is not one a tool can implement: tier H, `n/a`, tier 2, or no single tier.
    RowNotATool {
        /// The tool, `<module>.<tool>`.
        tool: String,
        /// The row it names.
        row: MatrixRow,
        /// The row's Tier cell.
        tier: String,
    },
    /// A tool's row has an unsettled exception class.
    ToolOnUnsettledRow {
        /// The tool, `<module>.<tool>`.
        tool: String,
        /// The row it names.
        row: MatrixRow,
    },
    /// A tool's tier is not its row's.
    TierMismatch {
        /// The tool, `<module>.<tool>`.
        tool: String,
        /// The row it names.
        row: MatrixRow,
        /// The row's Tier cell.
        matrix: String,
        /// The tool's tier.
        declared: Tier,
    },
    /// A tool's confirmation is not its row's.
    ConfirmationMismatch {
        /// The tool, `<module>.<tool>`.
        tool: String,
        /// The row it names.
        row: MatrixRow,
        /// The row's Confirmation cell.
        matrix: String,
        /// The tool's confirmation.
        declared: Confirmation,
    },
    /// A tool's exception class is not its row's.
    ExceptionClassMismatch {
        /// The tool, `<module>.<tool>`.
        tool: String,
        /// The row it names.
        row: MatrixRow,
        /// The row's class.
        matrix: RowClass,
        /// The tool's class.
        declared: Option<ExceptionClass>,
    },
    /// A tool's network effect is not the one its row's class implies: a class, and only a
    /// class, comes with a network effect below tier 2.
    NetworkEffectMismatch {
        /// The tool, `<module>.<tool>`.
        tool: String,
        /// The row it names.
        row: MatrixRow,
        /// The row's class.
        matrix: RowClass,
        /// The tool's network effect.
        declared: bool,
    },
    /// A row of a module's section that a tool could implement has no tool.
    RowWithoutTool {
        /// The module.
        module: &'static str,
        /// The section.
        section: &'static str,
        /// The row's Action cell.
        action: String,
    },
    /// A row of a module's section names no single tier, so the check cannot tell whether it
    /// needs a tool.
    RowWithoutOneTier {
        /// The module.
        module: &'static str,
        /// The section.
        section: &'static str,
        /// The row's Action cell.
        action: String,
        /// The row's Tier cell.
        tier: String,
    },
    /// A row of a module's section has an unsettled exception class, so no tool can implement it.
    RowWithUnsettledClass {
        /// The module.
        module: &'static str,
        /// The section.
        section: &'static str,
        /// The row's Action cell.
        action: String,
    },
}

impl fmt::Display for MatrixDifference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SectionMissing { module, section } => write!(
                formatter,
                "module {module} claims section {section}, which the matrix does not have as a \
                 section of actions"
            ),
            Self::ToolWithoutRow { tool, row } => write!(
                formatter,
                "tool {tool} has no matrix row: section {} has no row {:?}",
                row.section, row.action
            ),
            Self::RowNotATool { tool, row, tier } => write!(
                formatter,
                "tool {tool} names row {:?} of section {}, which is tier {tier:?}, not a tool's",
                row.action, row.section
            ),
            Self::ToolOnUnsettledRow { tool, row } => write!(
                formatter,
                "tool {tool} names row {:?} of section {}, whose exception class is unsettled",
                row.action, row.section
            ),
            Self::TierMismatch {
                tool,
                row,
                matrix,
                declared,
            } => write!(
                formatter,
                "tool {tool} is tier {declared}, its row {:?} of section {} tier {matrix:?}",
                row.action, row.section
            ),
            Self::ConfirmationMismatch {
                tool,
                row,
                matrix,
                declared,
            } => write!(
                formatter,
                "tool {tool} requires confirmation {}, its row {:?} of section {} {matrix:?}",
                declared.as_str(),
                row.action,
                row.section
            ),
            Self::ExceptionClassMismatch {
                tool,
                row,
                matrix,
                declared,
            } => write!(
                formatter,
                "tool {tool} declares exception class {}, its row {:?} of section {} {matrix}",
                declared.map_or(NO_CLASS, ExceptionClass::as_str),
                row.action,
                row.section
            ),
            Self::NetworkEffectMismatch {
                tool,
                row,
                matrix,
                declared,
            } => write!(
                formatter,
                "tool {tool} declares network effect {declared}, its row {:?} of section {} has \
                 exception class {matrix}",
                row.action, row.section
            ),
            Self::RowWithoutTool {
                module,
                section,
                action,
            } => write!(
                formatter,
                "matrix row {action:?} of section {section}, claimed by module {module}, has no \
                 tool"
            ),
            Self::RowWithoutOneTier {
                module,
                section,
                action,
                tier,
            } => write!(
                formatter,
                "matrix row {action:?} of section {section}, claimed by module {module}, names no \
                 single tier: {tier:?}"
            ),
            Self::RowWithUnsettledClass {
                module,
                section,
                action,
            } => write!(
                formatter,
                "matrix row {action:?} of section {section}, claimed by module {module}, has an \
                 unsettled exception class"
            ),
        }
    }
}

/// Why a registry fails the capability matrix check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MatrixCheckError {
    /// The matrix cannot be read.
    Unreadable(MatrixError),
    /// The registry and the matrix differ.
    Differences(Vec<MatrixDifference>),
}

impl fmt::Display for MatrixCheckError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable(error) => {
                write!(formatter, "the capability matrix is unreadable: {error}")
            }
            Self::Differences(differences) => {
                write!(
                    formatter,
                    "the tool table and the capability matrix differ:"
                )?;
                for difference in differences {
                    write!(formatter, "\n- {difference}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for MatrixCheckError {}
