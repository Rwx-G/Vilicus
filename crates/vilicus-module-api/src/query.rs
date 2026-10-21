//! A module's typed API (AD-5, I6): the reads it offers other modules, declared as `const` data
//! like the rest of its declaration and served by the Core.
//!
//! A module never opens another module's file. It reads another module's records only through
//! the queries that module declares, with [`Records::read`](crate::Records::read) inside one of
//! its calls; the Core checks that the query's access list names the calling module, that the
//! file it reads is ready, and that its partition is in the caller's scope, then reads the record
//! on a read connection of that file and returns the fields the query names. The Core keeps the
//! record's provenance with the call, so every write the call makes afterwards derives from it,
//! whether the module names it as an input or not (AD-7).
//!
//! A query reads one record of one table by its id and returns the fields it declares, nothing
//! of the envelope: the reading module learns no taint, author or source, which stay the Core's.

use vilicus_types::Id;

use crate::value::Value;

/// A read a module offers other modules: one record of one of its tables, by id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Query {
    /// The query's name, an identifier unique in its module; the Core names it
    /// `<module>.<name>`.
    pub name: &'static str,
    /// The table it reads, one the module declares.
    pub table: &'static str,
    /// The fields of that table it returns, each once, in this order.
    pub fields: &'static [&'static str],
    /// The modules allowed to call it, by name: its access list (AD-5, as a topic's for its
    /// consumers, D20). The module itself is never one: it reads its own file in its call's
    /// transaction.
    pub callers: &'static [&'static str],
}

/// A record another module's query returned to a call: its id and the fields the query names,
/// in the query's order, each as the file holds it.
#[derive(Clone, Debug, PartialEq)]
pub struct ReadRecord {
    /// The record's id.
    pub id: Id,
    /// Each field the query names, with its value.
    pub fields: Vec<(&'static str, Value)>,
}

impl ReadRecord {
    /// The value of the field `name`, when the query returns it.
    pub fn field(&self, name: &str) -> Option<&Value> {
        self.fields
            .iter()
            .find(|(field, _)| *field == name)
            .map(|(_, value)| value)
    }
}
