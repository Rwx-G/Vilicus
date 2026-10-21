//! The handler table of the binary (AD-9): the code of every registered module, bound by name to
//! its declaration, and the calls of that code through the boundary of AD-9.
//!
//! [`Handlers::new`] is a `const fn` over a [`Registry`] and the [`ModuleCode`] of its modules,
//! so a binary builds its table in a `const` item and a module whose code does not bind stops the
//! build: every tool, every undo handler a tool names and every consumer of every registered module
//! has exactly one function, and no code is bound to a module that is not registered.
//!
//! ```
//! use vilicus_core::handlers::Handlers;
//! use vilicus_core::registry::Registry;
//! use vilicus_module_api::{ModuleCode, ModuleDeclaration};
//!
//! const NOTES: ModuleDeclaration = ModuleDeclaration {
//!     name: "notes",
//!     tables: &[],
//!     fts5_tables: &[],
//!     migrations: &[],
//!     matrix_sections: &[],
//!     tools: &[],
//!     topics: &[],
//!     consumers: &[],
//! };
//! const NOTES_CODE: ModuleCode = ModuleCode {
//!     module: "notes",
//!     tools: &[],
//!     undo_handlers: &[],
//!     consumers: &[],
//! };
//! const REGISTRY: Registry = match Registry::new(&[&NOTES]) {
//!     Ok(registry) => registry,
//!     Err(error) => panic!("{}", error.rule()),
//! };
//! const HANDLERS: Handlers = match Handlers::new(REGISTRY, &[&NOTES_CODE]) {
//!     Ok(handlers) => handlers,
//!     Err(error) => panic!("{}", error.rule()),
//! };
//! assert!(HANDLERS.code("notes").is_some());
//! ```

use core::fmt;

use vilicus_module_api::{
    BindingError, Consumer, Event, ModuleCode, ModuleDeclaration, Records, ToolCall, UndoCall,
    Value, WriteError,
};
use vilicus_storage::{Handle, Write};

use crate::boundary::{Boundary, HandlerError};
use crate::bus::ConsumerCode;
use crate::record::{Call, CallResult, Invocation, Stamper};
use crate::registry::Registry;

/// The code of every module of a registry, each bound to its declaration.
#[derive(Clone, Copy, Debug)]
pub struct Handlers {
    registry: Registry,
    code: &'static [&'static ModuleCode],
}

/// Why the code of a registry's modules does not bind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandlersError {
    /// A module's code does not bind to its declaration.
    Binding {
        /// The module.
        module: &'static str,
        /// The rule broken.
        error: BindingError,
    },
    /// Code is given for a module the registry does not hold.
    UnregisteredModule {
        /// The module the code names.
        module: &'static str,
    },
    /// A registered module that declares a tool or a consumer has no code.
    MissingCode {
        /// The module.
        module: &'static str,
    },
    /// Two codes are given for one module.
    DuplicateCode {
        /// The module.
        module: &'static str,
    },
}

impl HandlersError {
    /// The rule broken, without the names: the message a `const` table stops the build with.
    pub const fn rule(self) -> &'static str {
        match self {
            Self::Binding { error, .. } => error.rule(),
            Self::UnregisteredModule { .. } => "code is given for a module that is not registered",
            Self::MissingCode { .. } => "a module with tools or consumers has no code",
            Self::DuplicateCode { .. } => "two codes are given for one module",
        }
    }
}

impl fmt::Display for HandlersError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Binding { module, error } => write!(formatter, "module {module}: {error}"),
            Self::UnregisteredModule { module }
            | Self::MissingCode { module }
            | Self::DuplicateCode { module } => write!(formatter, "{}: {module}", self.rule()),
        }
    }
}

impl std::error::Error for HandlersError {}

impl Handlers {
    /// The handler table of `registry`'s modules from `code`: each code binds to the declaration
    /// of its module ([`ModuleCode::check`]), each module has at most one code, and a module that
    /// declares a tool or a consumer has one. `const`, so a binary builds its table in a `const`
    /// item and a refusal is a build error.
    pub const fn new(
        registry: Registry,
        code: &'static [&'static ModuleCode],
    ) -> Result<Self, HandlersError> {
        let mut index = 0;
        while index < code.len() {
            let module_code = code[index];
            let Some(declaration) = declaration_of(registry.modules(), module_code.module) else {
                return Err(HandlersError::UnregisteredModule {
                    module: module_code.module,
                });
            };
            if let Err(error) = module_code.check(declaration) {
                return Err(HandlersError::Binding {
                    module: declaration.name,
                    error,
                });
            }
            let mut other = index + 1;
            while other < code.len() {
                if same(module_code.module, code[other].module) {
                    return Err(HandlersError::DuplicateCode {
                        module: module_code.module,
                    });
                }
                other += 1;
            }
            index += 1;
        }
        let modules = registry.modules();
        index = 0;
        while index < modules.len() {
            let module = modules[index];
            let binds_something = !module.tools.is_empty() || !module.consumers.is_empty();
            if binds_something && code_of(code, module.name).is_none() {
                return Err(HandlersError::MissingCode {
                    module: module.name,
                });
            }
            index += 1;
        }
        Ok(Self { registry, code })
    }

    /// The registry the table binds.
    pub const fn registry(&self) -> Registry {
        self.registry
    }

    /// The code of the module `module`.
    pub fn code(&self, module: &str) -> Option<&'static ModuleCode> {
        self.code.iter().copied().find(|code| code.module == module)
    }

    /// The module of `handle`'s file and its code.
    fn module_of(
        &self,
        handle: &Handle<Write>,
    ) -> Result<(&'static ModuleDeclaration, &'static ModuleCode), HandlerError> {
        let name = handle.file().module();
        let module = self
            .registry
            .module(name)
            .ok_or_else(|| HandlerError::UnregisteredModule(name.clone()))?;
        let code = self.code(module.name).ok_or(HandlerError::UnknownHandler)?;
        Ok((module, code))
    }

    /// Calls the tool `tool` of the module of `handle`'s file with `arguments`, which the pipeline
    /// validated against the tool's schema, as `call`, through `boundary` (AD-9): the tool's
    /// function runs in the call's transaction on the file, refused unless the file is ready, and
    /// a panic or an overrun faults the module for the partition.
    #[allow(
        clippy::too_many_arguments,
        reason = "a call of module code is the boundary, the file, the handler, its input and the call"
    )]
    pub fn call_tool(
        &self,
        boundary: &Boundary<'_>,
        handle: &Handle<Write>,
        tool: &str,
        arguments: &[(&str, Value)],
        call: &Call,
        invocation: &Invocation,
        stamper: &mut dyn Stamper,
    ) -> Result<CallResult<()>, HandlerError> {
        let (module, code) = self.module_of(handle)?;
        module.tool(tool).ok_or(HandlerError::UnknownHandler)?;
        let handler = code.tool(tool).ok_or(HandlerError::UnknownHandler)?;
        let input = ToolCall::new(arguments);
        boundary.run(handle, module, call, invocation, stamper, |records| {
            (handler.run)(&input, records)
        })
    }

    /// Calls the undo handler that the tool `undo.tool()` of the module of `handle`'s file names,
    /// as `call`, through `boundary` (AD-9), as [`call_tool`](Self::call_tool) calls a tool.
    pub fn call_undo(
        &self,
        boundary: &Boundary<'_>,
        handle: &Handle<Write>,
        undo: &UndoCall<'_>,
        call: &Call,
        invocation: &Invocation,
        stamper: &mut dyn Stamper,
    ) -> Result<CallResult<()>, HandlerError> {
        let (module, code) = self.module_of(handle)?;
        let name = module
            .tool(undo.tool())
            .and_then(|tool| tool.undo_handler)
            .ok_or(HandlerError::UnknownHandler)?;
        let handler = code
            .undo_handler(name)
            .ok_or(HandlerError::UnknownHandler)?;
        boundary.run(handle, module, call, invocation, stamper, |records| {
            (handler.undo)(undo, records)
        })
    }
}

/// The bound consumers: the bus runs each through the boundary of AD-9.
impl ConsumerCode for Handlers {
    fn consume(
        &mut self,
        module: &'static ModuleDeclaration,
        consumer: &'static Consumer,
        event: &Event<'_>,
        records: &mut dyn Records,
    ) -> Result<(), WriteError> {
        match self
            .code(module.name)
            .and_then(|code| code.consumer(consumer.name))
        {
            Some(handler) => (handler.consume)(event, records),
            None => Err(WriteError::Failed),
        }
    }
}

const fn declaration_of(
    modules: &'static [&'static ModuleDeclaration],
    name: &str,
) -> Option<&'static ModuleDeclaration> {
    let mut index = 0;
    while index < modules.len() {
        if same(modules[index].name, name) {
            return Some(modules[index]);
        }
        index += 1;
    }
    None
}

const fn code_of(code: &'static [&'static ModuleCode], name: &str) -> Option<&'static ModuleCode> {
    let mut index = 0;
    while index < code.len() {
        if same(code[index].module, name) {
            return Some(code[index]);
        }
        index += 1;
    }
    None
}

const fn same(left: &str, right: &str) -> bool {
    let (left, right) = (left.as_bytes(), right.as_bytes());
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
