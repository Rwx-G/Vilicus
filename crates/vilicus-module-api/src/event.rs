//! What a module declares about events (FR-24, AD-9, AD-29, D20): the topics it emits, each with
//! its payload version and the modules allowed to consume it, and its consumers, each of one
//! topic; and the event a consumer receives.
//!
//! A module emits an event about a record its call changed, through
//! [`Records::emit`](crate::Records::emit), in the call's transaction. The Core stamps the real
//! emitter, the module whose call it is, and the payload version its declaration gives the topic;
//! a topic of another module is refused. The Core delivers the event after the call commits, to
//! the consumers of every module the topic's access list names, each in a call of its own with
//! principal `Event` (AD-27). A payload evolves append-only: a new field raises the topic's
//! version, and a consumer accepts every earlier version, since rows written before an upgrade
//! are still delivered after it (AD-29).

use vilicus_types::Id;

/// A topic a module emits: its name, the version of its payload, and its access list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Topic {
    /// The topic's name, `<module>.<entity>.<past_verb>` (spine conventions, Event topics): the
    /// emitting module's name, then two identifiers, such as `meals.plan.updated`.
    pub name: &'static str,
    /// The version of the payload the module emits now, from 1. It only grows: a payload evolves
    /// append-only, and consumers accept every earlier version (AD-29).
    pub version: u32,
    /// The modules whose consumers may receive the topic's events, by name (D20, the access list
    /// per topic). A consumer of a module the list does not name is refused by the registry.
    pub consumers: &'static [&'static str],
}

/// A consumer of a module: the code the Core calls, with principal `Event`, for each event of one
/// topic (AD-27). The Core records each event it consumed in `_consumed` in the transaction of
/// its effect, so a second delivery produces no second effect (AD-10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Consumer {
    /// The consumer's name, an identifier unique in its module.
    pub name: &'static str,
    /// The topic it consumes, declared by another module or by its own, whose access list names
    /// this module. A module has at most one consumer per topic.
    pub topic: &'static str,
}

/// One event as a consumer receives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event<'a> {
    /// The event's id, which the Core stamped.
    pub id: Id,
    /// The topic.
    pub topic: &'a str,
    /// The module that emitted it, stamped by the Core.
    pub emitter: &'a str,
    /// The payload version it was emitted with, any version up to the topic's current one.
    pub version: u32,
    /// The record the event is about, in the emitter's file; a write of the consumer derives
    /// from it whether it names it or not.
    pub record: Id,
    /// The payload, as the emitter encoded it.
    pub payload: &'a [u8],
}

/// The module part of a topic name, `<module>` of `<module>.<entity>.<past_verb>`, when `topic`
/// follows that grammar.
pub fn topic_module(topic: &str) -> Option<&str> {
    if is_topic(topic) {
        topic.split_once('.').map(|(module, _)| module)
    } else {
        None
    }
}

/// True for a topic name `<module>.<entity>.<past_verb>`: a module name, then two identifiers,
/// separated by single dots.
pub const fn is_topic(topic: &str) -> bool {
    let bytes = topic.as_bytes();
    let mut dots = [0; 2];
    let mut found = 0;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'.' {
            if found == 2 {
                return false;
            }
            dots[found] = index;
            found += 1;
        }
        index += 1;
    }
    if found != 2 {
        return false;
    }
    let (module, rest) = bytes.split_at(dots[0]);
    let (entity, verb) = rest.split_at(dots[1] - dots[0]);
    let entity = entity.split_at(1).1;
    let verb = verb.split_at(1).1;
    match (
        core::str::from_utf8(module),
        core::str::from_utf8(entity),
        core::str::from_utf8(verb),
    ) {
        (Ok(module), Ok(entity), Ok(verb)) => {
            vilicus_types::ModuleName::is_valid(module)
                && crate::is_identifier(entity)
                && crate::is_identifier(verb)
        }
        _ => false,
    }
}
