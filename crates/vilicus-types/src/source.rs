//! The `source` vocabulary of the spine conventions: who produced a record.

use core::fmt;
use std::borrow::Cow;

use crate::id::Id;
use crate::name::{MODULE_NAME_MAX_LEN, NameError, is_module_name};

/// Who produced a record, from the closed vocabulary of the spine conventions. Every identifier
/// is an [`Id`]; [`Event`](Source::Event) carries the `call_id` of the call that delivered the
/// event (spine AD-28).
///
/// Serialized externally tagged, the tag being the vocabulary name: `"system"`, or a one-entry map
/// such as `{"member": "<id>"}`. Deserialization accepts only those two forms: `system` as a
/// string and nothing else, every other kind as a map with exactly one entry whose key is the
/// kind's name as a string (an integer index or a byte string is refused).
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// A member.
    Member(Id),
    /// The Core itself.
    System,
    /// A module, by name.
    Module(ModuleName),
    /// A plugin.
    Plugin(Id),
    /// An import.
    Import(Id),
    /// An AI task.
    AiTask(Id),
    /// A run of a scheduled task.
    ScheduledTask(Id),
    /// A playbook.
    Playbook(Id),
    /// An event, by the call id that delivered it.
    Event(Id),
    /// A home rule.
    Rule(Id),
    /// A household display.
    Display(Id),
    /// A device adapter.
    Adapter(Id),
}

closed_set! {
    /// The kind of a [`Source`], the key of its serialized form; it is read as a string only.
    pub enum SourceKind {
        /// `member(id)`.
        Member => "member",
        /// `system`.
        System => "system",
        /// `module(name)`.
        Module => "module",
        /// `plugin(id)`.
        Plugin => "plugin",
        /// `import(id)`.
        Import => "import",
        /// `ai_task(id)`.
        AiTask => "ai_task",
        /// `scheduled_task(id)`.
        ScheduledTask => "scheduled_task",
        /// `playbook(id)`.
        Playbook => "playbook",
        /// `event(call id)`.
        Event => "event",
        /// `rule(id)`.
        Rule => "rule",
        /// `display(id)`.
        Display => "display",
        /// `adapter(id)`.
        Adapter => "adapter",
    }
}

impl<'de> serde::Deserialize<'de> for Source {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SourceVisitor;

        impl<'de> serde::de::Visitor<'de> for SourceVisitor {
            type Value = Source;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .write_str("\"system\" or a one-entry map from a source kind to its payload")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Source, E> {
                let kind: SourceKind = serde::Deserialize::deserialize(
                    serde::de::IntoDeserializer::<E>::into_deserializer(value),
                )?;
                match kind {
                    SourceKind::System => Ok(Source::System),
                    _ => Err(E::invalid_value(
                        serde::de::Unexpected::Str(value),
                        &"\"system\"; any other kind is a map",
                    )),
                }
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Source, A::Error> {
                let kind: SourceKind = map
                    .next_key()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &"one entry"))?;
                let source = match kind {
                    SourceKind::System => {
                        return Err(serde::de::Error::custom(
                            "`system` is the string \"system\", not a map",
                        ));
                    }
                    SourceKind::Member => Source::Member(map.next_value()?),
                    SourceKind::Module => Source::Module(map.next_value()?),
                    SourceKind::Plugin => Source::Plugin(map.next_value()?),
                    SourceKind::Import => Source::Import(map.next_value()?),
                    SourceKind::AiTask => Source::AiTask(map.next_value()?),
                    SourceKind::ScheduledTask => Source::ScheduledTask(map.next_value()?),
                    SourceKind::Playbook => Source::Playbook(map.next_value()?),
                    SourceKind::Event => Source::Event(map.next_value()?),
                    SourceKind::Rule => Source::Rule(map.next_value()?),
                    SourceKind::Display => Source::Display(map.next_value()?),
                    SourceKind::Adapter => Source::Adapter(map.next_value()?),
                };
                if map.next_key::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(serde::de::Error::invalid_length(2, &"one entry"));
                }
                Ok(source)
            }
        }

        deserializer.deserialize_any(SourceVisitor)
    }
}

/// The name of a module, as in the crate name `vilicus-mod-<module>` and the tool prefix
/// `<module>.`: a lowercase ASCII letter, then lowercase ASCII letters and digits, at most
/// [`MAX_LEN`](Self::MAX_LEN) of them.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ModuleName(Cow<'static, str>);

impl ModuleName {
    /// Longest module name accepted, in characters.
    pub const MAX_LEN: usize = MODULE_NAME_MAX_LEN;

    /// True when `name` follows the grammar of a module name. A `const` check, so a declaration
    /// read at build time can report a bad name as a value rather than a panic.
    pub const fn is_valid(name: &str) -> bool {
        is_module_name(name)
    }

    /// A module name known at build time, such as a module's own declaration.
    ///
    /// # Panics
    ///
    /// When `name` is outside the grammar; in a `const` item that is a build error.
    pub const fn from_static(name: &'static str) -> Self {
        assert!(is_module_name(name), "not a valid module name");
        Self(Cow::Borrowed(name))
    }

    /// Reads a module name; a name outside the grammar is refused, never normalized.
    pub fn parse(name: &str) -> Result<Self, NameError> {
        if is_module_name(name) {
            Ok(Self(Cow::Owned(name.to_owned())))
        } else {
            Err(NameError::new("module name"))
        }
    }

    /// The name as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ModuleName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl serde::Serialize for ModuleName {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ModuleName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct NameVisitor;

        impl serde::de::Visitor<'_> for NameVisitor {
            type Value = ModuleName;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a module name")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<ModuleName, E> {
                ModuleName::parse(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(NameVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{from_map, from_single_entry_map, from_str, to_json};

    const ID_TEXT: &str = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f";

    /// The vocabulary name of each kind of source. The match has no wildcard, so a kind added to
    /// [`Source`] does not compile here until it is named; the names are then checked against
    /// [`SPINE_VOCABULARY`] by `source_vocabulary_is_the_spine_conventions`.
    fn vocabulary_name(source: &Source) -> &'static str {
        match source {
            Source::Member(_) => "member",
            Source::System => "system",
            Source::Module(_) => "module",
            Source::Plugin(_) => "plugin",
            Source::Import(_) => "import",
            Source::AiTask(_) => "ai_task",
            Source::ScheduledTask(_) => "scheduled_task",
            Source::Playbook(_) => "playbook",
            Source::Event(_) => "event",
            Source::Rule(_) => "rule",
            Source::Display(_) => "display",
            Source::Adapter(_) => "adapter",
        }
    }

    /// Spine, Consistency Conventions, `source` vocabulary: the independent statement the enum is
    /// checked against.
    const SPINE_VOCABULARY: [&str; 12] = [
        "member",
        "system",
        "module",
        "plugin",
        "import",
        "ai_task",
        "scheduled_task",
        "playbook",
        "event",
        "rule",
        "display",
        "adapter",
    ];

    fn one_of_each() -> Vec<Source> {
        let id = Id::parse(ID_TEXT).expect("valid");
        vec![
            Source::Member(id),
            Source::System,
            Source::Module(ModuleName::from_static("meals")),
            Source::Plugin(id),
            Source::Import(id),
            Source::AiTask(id),
            Source::ScheduledTask(id),
            Source::Playbook(id),
            Source::Event(id),
            Source::Rule(id),
            Source::Display(id),
            Source::Adapter(id),
        ]
    }

    #[test]
    fn source_vocabulary_is_the_spine_conventions() {
        let names: Vec<&str> = one_of_each().iter().map(vocabulary_name).collect();
        assert_eq!(names, SPINE_VOCABULARY);
    }

    #[test]
    fn sources_serialize_under_their_vocabulary_name() {
        for source in one_of_each() {
            let name = vocabulary_name(&source);
            let json = to_json(&source).expect("serializable");
            match &source {
                Source::System => {
                    assert_eq!(json, "\"system\"");
                    assert_eq!(from_str::<Source>(name), Ok(source));
                }
                Source::Module(module) => {
                    assert_eq!(json, format!("{{\"{name}\":\"{module}\"}}"));
                    assert_eq!(
                        from_single_entry_map::<Source>(name, module.as_str()),
                        Ok(source)
                    );
                }
                _ => {
                    assert_eq!(json, format!("{{\"{name}\":\"{ID_TEXT}\"}}"));
                    assert_eq!(from_single_entry_map::<Source>(name, ID_TEXT), Ok(source));
                }
            }
        }
    }

    #[test]
    fn unknown_or_malformed_sources_are_refused() {
        assert!(from_str::<Source>("mail").is_err());
        assert!(
            from_str::<Source>("member").is_err(),
            "a member source needs its id"
        );
        assert!(from_single_entry_map::<Source>("mail", ID_TEXT).is_err());
        assert!(from_single_entry_map::<Source>("Member", ID_TEXT).is_err());
        assert!(from_single_entry_map::<Source>("member", "not-an-id").is_err());
        assert!(from_single_entry_map::<Source>("module", "Meals").is_err());
        assert!(from_single_entry_map::<Source>("module", "vilicus-mod-meals").is_err());
    }

    #[test]
    fn only_the_string_tag_of_a_single_entry_is_accepted() {
        let integer_tag = from_map::<_, _, Source>(vec![(0_u64, ID_TEXT)]);
        assert!(integer_tag.is_err(), "integer variant index accepted");
        let byte_tag = from_map::<_, _, Source>(vec![(b"member".as_slice(), ID_TEXT)]);
        assert!(byte_tag.is_err(), "byte-string tag accepted");
        let second_entry = from_map::<_, _, Source>(vec![("member", ID_TEXT), ("plugin", ID_TEXT)]);
        assert!(second_entry.is_err(), "second entry dropped silently");
        let empty = from_map::<&str, &str, Source>(vec![]);
        assert!(empty.is_err(), "empty map accepted");
    }

    #[test]
    fn system_has_one_encoding() {
        assert_eq!(from_str::<Source>("system"), Ok(Source::System));
        assert!(from_map::<_, _, Source>(vec![("system", ())]).is_err());
        assert!(from_single_entry_map::<Source>("system", "").is_err());
    }

    #[test]
    fn module_names_are_checked() {
        assert_eq!(
            ModuleName::parse("familydocs")
                .map(|name| name.to_string())
                .as_deref(),
            Ok("familydocs")
        );
        assert!(ModuleName::parse("family docs").is_err());
        for name in ["familydocs", "family docs", "Meals", ""] {
            assert_eq!(
                ModuleName::is_valid(name),
                ModuleName::parse(name).is_ok(),
                "{name:?}"
            );
        }
        assert!(from_str::<ModuleName>("meals.plan").is_err());
        assert_eq!(
            to_json(&ModuleName::from_static("home")).as_deref(),
            Ok("\"home\"")
        );
    }

    #[test]
    #[should_panic(expected = "not a valid module name")]
    fn invalid_static_module_name_panics() {
        let _ = ModuleName::from_static("Not A Module");
    }
}
