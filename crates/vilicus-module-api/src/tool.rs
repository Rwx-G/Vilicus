//! What a module declares about its tools (FR-22, AD-9, I13, AD-48): each tool's name, schema,
//! tier, network effect, exception class, confirmation, partition effect, undo handler and the
//! capability matrix row it implements.
//!
//! Like the rest of a declaration, a tool is plain `'static` data in a `const` item, so the set of
//! tools is fixed when the binary is built. The rules a tool must meet are in `check.rs`; the
//! comparison of every registered tool with `doc/capability-matrix.md` is the registry's, in
//! `vilicus-core`.

use vilicus_types::{ExceptionClass, Tier};

use crate::declaration::Field;

/// The confirmation a tool requires on every call, whatever the session's taint
/// (`doc/capability-matrix.md`, Legend, Confirmation). A tainted session can still make a tier 1
/// call elevated (AD-7); that is the pipeline's, not the declaration's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Confirmation {
    /// No confirmation.
    None,
    /// A light confirmation: one explicit tap in an authenticated session of a paired device,
    /// signed by its device key over the canonical hash of the request (D35, D38). Tier 1 only.
    Light,
}

impl Confirmation {
    /// Every confirmation a tool can require.
    pub const ALL: &'static [Self] = &[Self::None, Self::Light];

    /// The name the capability matrix gives it in its Confirmation column.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Light => "light",
        }
    }
}

/// A row of `doc/capability-matrix.md`, by its section and its Action cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MatrixRow {
    /// The section's number as its heading writes it before the period: `2` for
    /// `## 2. Tasks`, `10a` for `## 10a. Home automation`. One of the module's
    /// [`matrix_sections`](crate::ModuleDeclaration::matrix_sections).
    pub section: &'static str,
    /// The row's Action cell, exactly as the matrix writes it.
    pub action: &'static str,
}

/// A tool of a module: an action a principal calls through the Core pipeline (AD-8, AD-9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Tool {
    /// The tool's name, an identifier unique in its module; the registry names it
    /// `<module>.<name>`.
    pub name: &'static str,
    /// The tool's schema: its arguments, each structured or free text with a maximum length, under
    /// the rules of a table's fields (FR-58).
    pub arguments: &'static [Field],
    /// Its tier, the one its matrix row gives. Tier H never is a tool (I18), and tier 2 is not
    /// registered before the native app exists (D46, FR-60).
    pub tier: Tier,
    /// True when a call has an outbound network effect: anything leaving the instance, a device
    /// command included. Such a tool is tier 2 unless it declares an exception class (I13).
    pub network_effect: bool,
    /// The named exception class of I13 that makes an outbound effect tier 1, at most one
    /// (AD-48).
    pub exception_class: Option<ExceptionClass>,
    /// The confirmation every call requires.
    pub confirmation: Confirmation,
    /// True when a call moves or copies a record from one partition into another, which is tier 2
    /// (FR-21, `doc/architecture.md` section 9.4).
    pub crosses_partitions: bool,
    /// The name of the module's undo handler for this tool, an identifier. The Core's journal
    /// undoes a tier 1 write inside the module's file (Story 10.7); an outbound effect needs the
    /// module's own handler, so every exception-class tool names one (I13). Binding the name to
    /// the handler is the module port's handler table (Story 3.9).
    pub undo_handler: Option<&'static str>,
    /// The capability matrix row the tool implements.
    pub matrix_row: MatrixRow,
}
