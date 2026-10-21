//! The capability matrix check (FR-22, AD-9, I13, I18, D46): `doc/capability-matrix.md` read back
//! into its rows, and the registry's tool table compared with them in both directions.
//!
//! A tool names its row by section number and Action cell ([`MatrixRow`]); a module claims the
//! sections it implements. The check fails on a tool whose row is absent, is not a tool's row
//! (tier H, `n/a`, tier 2 before the native app, or a cell that names no single tier), or gives
//! another tier or confirmation than the tool declares; and on a row of a claimed section that a
//! tool could implement but none does. The matrix is the design's statement of every action
//! (`doc/capability-matrix.md`, section 12); a binary checks its registry against it in a test,
//! and the testbed against its own fixture.
//!
//! The reader accepts only the plain table forms the matrix uses: anything it does not recognise
//! in a table of actions is a refusal, never a guess.

#[cfg(test)]
mod tests;

use core::fmt;

use vilicus_module_api::{
    Confirmation, MatrixRow, ModuleDeclaration, Tier, Tool, is_matrix_section,
};

use super::Registry;

/// The header of a table of actions: its first column, the one a tool's
/// [`MatrixRow::action`] names.
const ACTION_COLUMN: &str = "Action";
/// The column holding a row's tier.
const TIER_COLUMN: &str = "Tier";
/// The column holding a row's confirmation.
const CONFIRMATION_COLUMN: &str = "Confirmation";

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
        let first = self
            .confirmation
            .split([',', ';'])
            .next()
            .unwrap_or_default();
        let first = first
            .split_once(" (")
            .map_or(first, |(term, _)| term)
            .trim();
        Confirmation::ALL
            .iter()
            .copied()
            .find(|confirmation| confirmation.as_str() == first)
    }
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
    /// The line after a table header is not its separator row.
    MissingSeparator {
        /// The line.
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
    Header(Option<Columns>),
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
}

impl CapabilityMatrix {
    /// Reads `text`, in the format of `doc/capability-matrix.md`: each `## <number>. <title>`
    /// heading opens a section, and each table whose first header cell is `Action` is a table of
    /// actions, which must have `Tier` and `Confirmation` columns. Other headings and other
    /// tables are not read.
    pub fn parse(text: &str) -> Result<Self, MatrixError> {
        let mut sections: Vec<MatrixSection> = Vec::new();
        let mut current: Option<usize> = None;
        let mut table = Table::None;
        for (index, line) in text.lines().enumerate() {
            let line_number = index + 1;
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
                        rows: Vec::new(),
                    });
                    current = Some(sections.len() - 1);
                }
                continue;
            }
            if !line.starts_with('|') {
                table = Table::None;
                continue;
            }
            let cells = cells(line).ok_or(MatrixError::MalformedRow { line: line_number })?;
            table = match table {
                Table::None => Table::Header(header(&cells, current, line_number)?),
                Table::Header(columns) => {
                    if !is_separator(&cells) {
                        return Err(MatrixError::MissingSeparator { line: line_number });
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
                if self.section(section).is_none() {
                    differences.push(MatrixDifference::SectionMissing {
                        module: module.name,
                        section,
                    });
                }
            }
        }
        for tool in registry.tools() {
            if let Some(difference) = self.tool_difference(&tool) {
                differences.push(difference);
            }
        }
        for module in registry.modules() {
            self.row_differences(module, &mut differences);
        }
        differences
    }

    /// The difference a tool makes with its row, if any.
    fn tool_difference(&self, registered: &RegisteredTool) -> Option<MatrixDifference> {
        let tool = registered.tool;
        let Some(entry) = self.row(&tool.matrix_row) else {
            return Some(MatrixDifference::ToolWithoutRow {
                tool: registered.qualified_name(),
                row: tool.matrix_row,
            });
        };
        let RowTier::Registrable(tier) = entry.row_tier() else {
            return Some(MatrixDifference::RowNotATool {
                tool: registered.qualified_name(),
                row: tool.matrix_row,
                tier: entry.tier.clone(),
            });
        };
        if tier != tool.tier {
            return Some(MatrixDifference::TierMismatch {
                tool: registered.qualified_name(),
                row: tool.matrix_row,
                matrix: entry.tier.clone(),
                declared: tool.tier,
            });
        }
        if entry.tool_confirmation() != Some(tool.confirmation) {
            return Some(MatrixDifference::ConfirmationMismatch {
                tool: registered.qualified_name(),
                row: tool.matrix_row,
                matrix: entry.confirmation.clone(),
                declared: tool.confirmation,
            });
        }
        None
    }

    /// The rows of the module's sections that a tool could implement but none of its tools does,
    /// and the rows the check cannot read as one tier.
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
                match entry.row_tier() {
                    RowTier::Registrable(_) => {
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
                    RowTier::NotOneTier => differences.push(MatrixDifference::RowWithoutOneTier {
                        module: module.name,
                        section: number,
                        action: entry.action.clone(),
                        tier: entry.tier.clone(),
                    }),
                    RowTier::Irreversible | RowTier::HumanOnly | RowTier::NotApplicable => {}
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

/// `<number>. <title>`, the heading of a numbered section.
fn numbered_heading(heading: &str) -> Option<(&str, &str)> {
    let (number, title) = heading.split_once(". ")?;
    (is_matrix_section(number) && !title.trim().is_empty()).then_some((number, title.trim()))
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
    }))
}

/// A row of a table of actions in `section`.
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
    Ok(MatrixEntry {
        action: action.to_owned(),
        tier: cells[columns.tier].to_owned(),
        confirmation: cells[columns.confirmation].to_owned(),
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
    /// A module claims a section the matrix does not have.
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
}

impl fmt::Display for MatrixDifference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SectionMissing { module, section } => write!(
                formatter,
                "module {module} claims section {section}, which the matrix does not have"
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
            Self::RowWithoutTool {
                module,
                section,
                action,
            } => write!(
                formatter,
                "matrix row {action:?} of section {section}, claimed by module {module}, has no tool"
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
