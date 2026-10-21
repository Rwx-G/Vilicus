//! The module port's handler table (AD-9): the code of a module, bound by name to what its
//! declaration names, so the Core can call a tool, an undo handler or an event consumer.
//!
//! Handlers are synchronous functions the Core runs on the writer thread of the module's file,
//! inside the boundary of AD-9: the call's transaction, `catch_unwind` and the handler time
//! budget. Each receives what it acts on and the record port of the call, [`Records`], and
//! nothing else: no handle, no key, no thread. A module exposes one [`ModuleCode`] as a `const`
//! item beside its [`ModuleDeclaration`]; [`ModuleCode::check`] holds the two together, in the
//! module's build and again when the Core binds the code of every registered module: every tool,
//! every undo handler a tool names and every consumer has exactly one function, and no function is
//! bound to a name the declaration does not hold.
//!
//! ```
//! use vilicus_module_api::{
//!     Consumer, ConsumerHandler, Event, ModuleCode, ModuleDeclaration, Records, WriteError,
//! };
//!
//! fn plan_meals(_event: &Event<'_>, _records: &mut dyn Records) -> Result<(), WriteError> {
//!     Ok(())
//! }
//!
//! const MEALS: ModuleDeclaration = ModuleDeclaration {
//!     name: "meals",
//!     tables: &[],
//!     fts5_tables: &[],
//!     migrations: &[],
//!     matrix_sections: &[],
//!     tools: &[],
//!     topics: &[],
//!     consumers: &[Consumer { name: "plan", topic: "tasks.task.added" }],
//!     queries: &[],
//! };
//! const MEALS_CODE: ModuleCode = ModuleCode {
//!     module: "meals",
//!     tools: &[],
//!     undo_handlers: &[],
//!     consumers: &[ConsumerHandler { consumer: "plan", consume: plan_meals }],
//! };
//! const _: () = MEALS_CODE.assert_bound(&MEALS);
//! ```

use core::fmt;

use vilicus_types::{CallId, Id};

use crate::check::same;
use crate::declaration::ModuleDeclaration;
use crate::event::Event;
use crate::records::{Records, WriteError};
use crate::value::Value;

/// The function of a tool: it acts on the call's arguments through the call's record port.
pub type ToolFn = fn(&ToolCall<'_>, &mut dyn Records) -> Result<(), WriteError>;

/// The function of an undo handler: it undoes, through the record port of a call of its own, what
/// a call of a tool did outside the module's file.
pub type UndoFn = fn(&UndoCall<'_>, &mut dyn Records) -> Result<(), WriteError>;

/// The function of an event consumer: it reacts to one event through the record port of the
/// consumer's call, principal `Event` (AD-27).
pub type ConsumeFn = fn(&Event<'_>, &mut dyn Records) -> Result<(), WriteError>;

/// The function bound to a tool the declaration names.
#[derive(Clone, Copy, Debug)]
pub struct ToolHandler {
    /// The tool's name, as its declaration gives it.
    pub tool: &'static str,
    /// Its function.
    pub run: ToolFn,
}

/// The function bound to an undo handler a tool of the declaration names.
#[derive(Clone, Copy, Debug)]
pub struct UndoHandler {
    /// The undo handler's name, as the tools that name it give it.
    pub name: &'static str,
    /// Its function.
    pub undo: UndoFn,
}

/// The function bound to a consumer the declaration names.
#[derive(Clone, Copy, Debug)]
pub struct ConsumerHandler {
    /// The consumer's name, as its declaration gives it.
    pub consumer: &'static str,
    /// Its function.
    pub consume: ConsumeFn,
}

/// The code of one module: the function of each tool, undo handler and consumer its declaration
/// names, by name.
#[derive(Clone, Copy, Debug)]
pub struct ModuleCode {
    /// The module's name, the one its declaration gives.
    pub module: &'static str,
    /// The function of each tool.
    pub tools: &'static [ToolHandler],
    /// The function of each undo handler the tools name.
    pub undo_handlers: &'static [UndoHandler],
    /// The function of each consumer.
    pub consumers: &'static [ConsumerHandler],
}

/// The arguments of one call of a tool, as the Core gives them to the tool's function once the
/// pipeline validated them against the tool's schema (AD-8, FR-58).
#[derive(Clone, Copy, Debug)]
pub struct ToolCall<'a> {
    arguments: &'a [(&'a str, Value)],
}

impl<'a> ToolCall<'a> {
    /// The call of a tool with `arguments`, each a declared argument's name and its value.
    pub const fn new(arguments: &'a [(&'a str, Value)]) -> Self {
        Self { arguments }
    }

    /// The arguments, each once, in the order the caller gave them.
    pub const fn arguments(&self) -> &'a [(&'a str, Value)] {
        self.arguments
    }

    /// The value of the argument `name`, when the call gives it.
    pub fn argument(&self, name: &str) -> Option<&'a Value> {
        self.arguments
            .iter()
            .find(|(given, _)| *given == name)
            .map(|(_, value)| value)
    }
}

/// An outbound effect a call of a tool requested, as an undo handler receives it: the module
/// cannot read the Core tables that hold it (AD-26, AD-28).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UndoneEffect<'a> {
    /// The effect intent's id.
    pub id: Id,
    /// The effect, as the module named it.
    pub effect: &'a str,
    /// Its business idempotency key.
    pub idempotency_key: &'a [u8],
    /// Its parameters, as the module encoded them.
    pub payload: &'a [u8],
}

/// What an undo handler undoes: one call of one of the module's tools, and the outbound effects
/// that call requested. Undoing the call's writes inside the module's file is the Core's journal
/// (AD-26); the handler compensates what left the file.
#[derive(Clone, Copy, Debug)]
pub struct UndoCall<'a> {
    tool: &'a str,
    call_id: CallId,
    effects: &'a [UndoneEffect<'a>],
}

impl<'a> UndoCall<'a> {
    /// The undo of the call `call_id` of the tool `tool`, which requested `effects`.
    pub const fn new(tool: &'a str, call_id: CallId, effects: &'a [UndoneEffect<'a>]) -> Self {
        Self {
            tool,
            call_id,
            effects,
        }
    }

    /// The tool whose call is undone.
    pub const fn tool(&self) -> &'a str {
        self.tool
    }

    /// The id of the call undone.
    pub const fn call_id(&self) -> CallId {
        self.call_id
    }

    /// The outbound effects that call requested, in order.
    pub const fn effects(&self) -> &'a [UndoneEffect<'a>] {
        self.effects
    }
}

/// Why a module's code does not bind to its declaration. Each variant names the item, a name the
/// declaration or the code holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingError {
    /// The code is another module's.
    OtherModule {
        /// The module the code names.
        module: &'static str,
    },
    /// A declared tool has no function.
    MissingTool {
        /// The tool.
        tool: &'static str,
    },
    /// A function is bound to a tool the declaration does not hold.
    UnknownTool {
        /// The name bound.
        tool: &'static str,
    },
    /// Two functions are bound to one tool.
    DuplicateTool {
        /// The tool.
        tool: &'static str,
    },
    /// An undo handler a tool names has no function.
    MissingUndoHandler {
        /// The undo handler.
        name: &'static str,
    },
    /// A function is bound to an undo handler no tool names.
    UnknownUndoHandler {
        /// The name bound.
        name: &'static str,
    },
    /// Two functions are bound to one undo handler.
    DuplicateUndoHandler {
        /// The undo handler.
        name: &'static str,
    },
    /// A declared consumer has no function.
    MissingConsumer {
        /// The consumer.
        consumer: &'static str,
    },
    /// A function is bound to a consumer the declaration does not hold.
    UnknownConsumer {
        /// The name bound.
        consumer: &'static str,
    },
    /// Two functions are bound to one consumer.
    DuplicateConsumer {
        /// The consumer.
        consumer: &'static str,
    },
}

impl BindingError {
    /// The rule broken, without the names: the message a `const` binding stops the build with.
    pub const fn rule(self) -> &'static str {
        match self {
            Self::OtherModule { .. } => "the code is another module's",
            Self::MissingTool { .. } => "a declared tool has no function",
            Self::UnknownTool { .. } => {
                "a function is bound to a tool the declaration does not hold"
            }
            Self::DuplicateTool { .. } => "two functions are bound to one tool",
            Self::MissingUndoHandler { .. } => "an undo handler a tool names has no function",
            Self::UnknownUndoHandler { .. } => {
                "a function is bound to an undo handler no tool names"
            }
            Self::DuplicateUndoHandler { .. } => "two functions are bound to one undo handler",
            Self::MissingConsumer { .. } => "a declared consumer has no function",
            Self::UnknownConsumer { .. } => {
                "a function is bound to a consumer the declaration does not hold"
            }
            Self::DuplicateConsumer { .. } => "two functions are bound to one consumer",
        }
    }

    /// The item the error names.
    const fn item(self) -> &'static str {
        match self {
            Self::OtherModule { module } => module,
            Self::MissingTool { tool }
            | Self::UnknownTool { tool }
            | Self::DuplicateTool { tool } => tool,
            Self::MissingUndoHandler { name }
            | Self::UnknownUndoHandler { name }
            | Self::DuplicateUndoHandler { name } => name,
            Self::MissingConsumer { consumer }
            | Self::UnknownConsumer { consumer }
            | Self::DuplicateConsumer { consumer } => consumer,
        }
    }
}

impl fmt::Display for BindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.rule(), self.item())
    }
}

impl std::error::Error for BindingError {}

/// Returns early with the error of a check that fails.
macro_rules! bound {
    ($check:expr) => {
        if let Err(error) = $check {
            return Err(error);
        }
    };
}

impl ModuleCode {
    /// Holds the code to `declaration`: the same module; each tool, each undo handler a tool
    /// names and each consumer bound to exactly one function; and no function bound to a name the
    /// declaration does not hold. `const`, so a module checks its own code in its build, and the
    /// Core again when it binds every registered module's.
    pub const fn check(&self, declaration: &ModuleDeclaration) -> Result<(), BindingError> {
        if !same(self.module, declaration.name) {
            return Err(BindingError::OtherModule {
                module: self.module,
            });
        }
        bound!(self.check_tools(declaration));
        bound!(self.check_undo_handlers(declaration));
        self.check_consumers(declaration)
    }

    /// Stops the build of a `const` item when [`check`](Self::check) refuses the code.
    pub const fn assert_bound(&self, declaration: &ModuleDeclaration) {
        if let Err(error) = self.check(declaration) {
            panic!("{}", error.rule());
        }
    }

    /// The function of the tool `name`.
    pub fn tool(&self, name: &str) -> Option<&'static ToolHandler> {
        self.tools.iter().find(|handler| handler.tool == name)
    }

    /// The function of the undo handler `name`.
    pub fn undo_handler(&self, name: &str) -> Option<&'static UndoHandler> {
        self.undo_handlers
            .iter()
            .find(|handler| handler.name == name)
    }

    /// The function of the consumer `name`.
    pub fn consumer(&self, name: &str) -> Option<&'static ConsumerHandler> {
        self.consumers
            .iter()
            .find(|handler| handler.consumer == name)
    }

    const fn check_tools(&self, declaration: &ModuleDeclaration) -> Result<(), BindingError> {
        let mut index = 0;
        while index < declaration.tools.len() {
            let tool = declaration.tools[index].name;
            match count_tools(self.tools, tool) {
                0 => return Err(BindingError::MissingTool { tool }),
                1 => {}
                _ => return Err(BindingError::DuplicateTool { tool }),
            }
            index += 1;
        }
        index = 0;
        while index < self.tools.len() {
            let tool = self.tools[index].tool;
            if !declares_tool(declaration, tool) {
                return Err(BindingError::UnknownTool { tool });
            }
            index += 1;
        }
        Ok(())
    }

    const fn check_undo_handlers(
        &self,
        declaration: &ModuleDeclaration,
    ) -> Result<(), BindingError> {
        let mut index = 0;
        while index < declaration.tools.len() {
            if let Some(name) = declaration.tools[index].undo_handler {
                match count_undo_handlers(self.undo_handlers, name) {
                    0 => return Err(BindingError::MissingUndoHandler { name }),
                    1 => {}
                    _ => return Err(BindingError::DuplicateUndoHandler { name }),
                }
            }
            index += 1;
        }
        index = 0;
        while index < self.undo_handlers.len() {
            let name = self.undo_handlers[index].name;
            if !names_undo_handler(declaration, name) {
                return Err(BindingError::UnknownUndoHandler { name });
            }
            index += 1;
        }
        Ok(())
    }

    const fn check_consumers(&self, declaration: &ModuleDeclaration) -> Result<(), BindingError> {
        let mut index = 0;
        while index < declaration.consumers.len() {
            let consumer = declaration.consumers[index].name;
            match count_consumers(self.consumers, consumer) {
                0 => return Err(BindingError::MissingConsumer { consumer }),
                1 => {}
                _ => return Err(BindingError::DuplicateConsumer { consumer }),
            }
            index += 1;
        }
        index = 0;
        while index < self.consumers.len() {
            let consumer = self.consumers[index].consumer;
            if !declares_consumer(declaration, consumer) {
                return Err(BindingError::UnknownConsumer { consumer });
            }
            index += 1;
        }
        Ok(())
    }
}

const fn count_tools(handlers: &[ToolHandler], tool: &str) -> usize {
    let mut count = 0;
    let mut index = 0;
    while index < handlers.len() {
        if same(handlers[index].tool, tool) {
            count += 1;
        }
        index += 1;
    }
    count
}

const fn count_undo_handlers(handlers: &[UndoHandler], name: &str) -> usize {
    let mut count = 0;
    let mut index = 0;
    while index < handlers.len() {
        if same(handlers[index].name, name) {
            count += 1;
        }
        index += 1;
    }
    count
}

const fn count_consumers(handlers: &[ConsumerHandler], consumer: &str) -> usize {
    let mut count = 0;
    let mut index = 0;
    while index < handlers.len() {
        if same(handlers[index].consumer, consumer) {
            count += 1;
        }
        index += 1;
    }
    count
}

const fn declares_tool(declaration: &ModuleDeclaration, tool: &str) -> bool {
    let mut index = 0;
    while index < declaration.tools.len() {
        if same(declaration.tools[index].name, tool) {
            return true;
        }
        index += 1;
    }
    false
}

const fn names_undo_handler(declaration: &ModuleDeclaration, name: &str) -> bool {
    let mut index = 0;
    while index < declaration.tools.len() {
        if let Some(named) = declaration.tools[index].undo_handler
            && same(named, name)
        {
            return true;
        }
        index += 1;
    }
    false
}

const fn declares_consumer(declaration: &ModuleDeclaration, consumer: &str) -> bool {
    let mut index = 0;
    while index < declaration.consumers.len() {
        if same(declaration.consumers[index].name, consumer) {
            return true;
        }
        index += 1;
    }
    false
}
