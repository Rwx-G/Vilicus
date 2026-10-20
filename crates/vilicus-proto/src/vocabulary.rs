//! The shared vocabulary of `vilicus-types` on the wire, mapped by hand through [`crate::wire`].
//!
//! An identifier is its 16-byte stored form as a byte string, a time its UTC milliseconds as an
//! integer, a closed set one of its names as text, an error code or a message key its dotted name
//! as text, and a `source` the name of its kind alone (`system`) or a map of one entry from the
//! kind's name to its payload, the shape `vilicus-types` gives it in serde. Each value is checked
//! by the constructor `vilicus-types` provides, so a malformed one is refused, never repaired.

use dcbor::{CBOR, CBORCase};
use vilicus_types::{
    ClientError, DataType, ErrorCode, ExceptionClass, Id, MessageKey, ModuleName, OperatorSetting,
    Principal, RetryClass, Source, Taint, Tier, UtcMillis,
};

use crate::wire::{self, DecodeError, Fields, Wire};

impl Wire for Id {
    fn to_cbor(&self) -> CBOR {
        CBOR::to_byte_string(self.to_bytes())
    }

    fn from_cbor(value: &CBOR) -> Result<Self, DecodeError> {
        let CBORCase::ByteString(bytes) = value.as_case() else {
            return Err(DecodeError::Expected {
                type_name: "Id",
                expected: "a byte string",
            });
        };
        let bytes: [u8; 16] = bytes.data().try_into().map_err(|_| DecodeError::Invalid {
            type_name: "Id",
            reason: "not 16 bytes",
        })?;
        Self::from_bytes(bytes).map_err(|_| DecodeError::Invalid {
            type_name: "Id",
            reason: "not a UUIDv7",
        })
    }
}

impl Wire for UtcMillis {
    fn to_cbor(&self) -> CBOR {
        self.as_millis().to_cbor()
    }

    fn from_cbor(value: &CBOR) -> Result<Self, DecodeError> {
        Self::from_millis(i64::from_cbor(value)?).map_err(|_| DecodeError::Invalid {
            type_name: "UtcMillis",
            reason: "outside years 0000 to 9999",
        })
    }
}

/// Maps each closed set of `vilicus-types` by its names, through [`wire::closed_name`].
macro_rules! closed_sets {
    ($($name:ident),+ $(,)?) => {
        $(
            impl Wire for $name {
                fn to_cbor(&self) -> CBOR {
                    CBOR::from(self.as_str())
                }

                fn from_cbor(value: &CBOR) -> Result<Self, DecodeError> {
                    wire::closed_name(value, stringify!($name), $name::ALL, $name::as_str)
                }
            }
        )+

        #[cfg(test)]
        /// Every closed set mapped here, each member encoded, for the tests.
        pub(crate) fn closed_set_members() -> Vec<(&'static str, &'static str, CBOR)> {
            let mut members = Vec::new();
            $(
                for member in $name::ALL {
                    members.push((stringify!($name), member.as_str(), member.to_cbor()));
                }
            )+
            members
        }
    };
}

closed_sets!(
    Taint,
    Tier,
    Principal,
    DataType,
    ExceptionClass,
    RetryClass,
    OperatorSetting,
);

/// Maps a dotted name type of `vilicus-types` as its text, checked by its `parse`.
macro_rules! dotted_names {
    ($($name:ident),+ $(,)?) => {
        $(
            impl Wire for $name {
                fn to_cbor(&self) -> CBOR {
                    CBOR::from(self.as_str())
                }

                fn from_cbor(value: &CBOR) -> Result<Self, DecodeError> {
                    $name::parse(&String::from_cbor(value)?).map_err(|_| DecodeError::Invalid {
                        type_name: stringify!($name),
                        reason: "does not follow its name grammar",
                    })
                }
            }
        )+
    };
}

dotted_names!(ErrorCode, MessageKey, ModuleName);

impl Wire for ClientError {
    fn to_cbor(&self) -> CBOR {
        wire::record([
            ("code", self.code.to_cbor()),
            ("message_key", self.message_key.to_cbor()),
            ("retry_class", self.retry_class.to_cbor()),
        ])
    }

    fn from_cbor(value: &CBOR) -> Result<Self, DecodeError> {
        let mut fields = Fields::open(value, "ClientError")?;
        let error = Self {
            code: fields.required("code")?,
            message_key: fields.required("message_key")?,
            retry_class: fields.required("retry_class")?,
        };
        fields.finish()?;
        Ok(error)
    }
}

impl Wire for Source {
    fn to_cbor(&self) -> CBOR {
        let (name, id) = match self {
            Self::System => return CBOR::from("system"),
            Self::Module(module) => return wire::tagged("module", module.to_cbor()),
            Self::Member(id) => ("member", id),
            Self::Plugin(id) => ("plugin", id),
            Self::Import(id) => ("import", id),
            Self::AiTask(id) => ("ai_task", id),
            Self::ScheduledTask(id) => ("scheduled_task", id),
            Self::Playbook(id) => ("playbook", id),
            Self::Event(id) => ("event", id),
            Self::Rule(id) => ("rule", id),
            Self::Display(id) => ("display", id),
            Self::Adapter(id) => ("adapter", id),
        };
        wire::tagged(name, id.to_cbor())
    }

    fn from_cbor(value: &CBOR) -> Result<Self, DecodeError> {
        const TYPE: &str = "Source";
        let read = wire::variant(value, TYPE)?;
        if read.name == "system" {
            read.no_payload(TYPE)?;
            return Ok(Self::System);
        }
        let payload = read.payload(TYPE)?;
        let with_id: fn(Id) -> Self = match read.name {
            "module" => return ModuleName::from_cbor(payload).map(Self::Module),
            "member" => Self::Member,
            "plugin" => Self::Plugin,
            "import" => Self::Import,
            "ai_task" => Self::AiTask,
            "scheduled_task" => Self::ScheduledTask,
            "playbook" => Self::Playbook,
            "event" => Self::Event,
            "rule" => Self::Rule,
            "display" => Self::Display,
            "adapter" => Self::Adapter,
            _ => return Err(read.unknown(TYPE)),
        };
        Id::from_cbor(payload).map(with_id)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use dcbor::Map;
    use vilicus_types::Taint;

    use super::*;
    use crate::profile;
    use crate::wire::{decode, encode};

    /// A valid UUIDv7, the example of RFC 9562 appendix A.6.
    pub(crate) fn sample_id() -> Id {
        Id::parse("017f22e2-79b0-7cc3-98c4-dc0c0c07398f").expect("UUIDv7")
    }

    /// One value of each `source` kind. Rust cannot enumerate the variants of an enum, so the
    /// list is written out; the exhaustive match below it stops compiling when `Source` gains a
    /// kind, next to the list that must gain it too.
    pub(crate) fn every_source_kind() -> Vec<Source> {
        let id = sample_id();
        let sources = vec![
            Source::System,
            Source::Module(ModuleName::from_static("tasks")),
            Source::Member(id),
            Source::Plugin(id),
            Source::Import(id),
            Source::AiTask(id),
            Source::ScheduledTask(id),
            Source::Playbook(id),
            Source::Event(id),
            Source::Rule(id),
            Source::Display(id),
            Source::Adapter(id),
        ];
        for source in &sources {
            match source {
                Source::System
                | Source::Module(_)
                | Source::Member(_)
                | Source::Plugin(_)
                | Source::Import(_)
                | Source::AiTask(_)
                | Source::ScheduledTask(_)
                | Source::Playbook(_)
                | Source::Event(_)
                | Source::Rule(_)
                | Source::Display(_)
                | Source::Adapter(_) => {}
            }
        }
        sources
    }

    #[test]
    fn every_closed_set_member_round_trips_by_name() {
        let members = closed_set_members();
        assert!(!members.is_empty());
        for (type_name, name, value) in members {
            let bytes = profile::encode(&value).expect("names are NFC text");
            assert_eq!(profile::decode(&bytes), Ok(CBOR::from(name)), "{type_name}");
        }
    }

    /// The 2.4 review: serde's derived enums accept an integer variant index. On the wire a closed
    /// set is its name as text and nothing else.
    #[test]
    fn a_closed_set_refuses_an_integer_index_bytes_and_other_names() {
        for index in 0..Taint::ALL.len() as u64 {
            let bytes = encode(&index).expect("integer");
            assert!(matches!(
                decode::<Taint>(&bytes),
                Err(DecodeError::Expected { .. })
            ));
        }
        let bytes = profile::encode(&CBOR::to_byte_string(b"trusted")).expect("bytes");
        assert!(matches!(
            decode::<Taint>(&bytes),
            Err(DecodeError::Expected { .. })
        ));
        for refused in ["member", "Trusted", "trusted "] {
            let bytes = profile::encode(&CBOR::from(refused)).expect("text");
            assert_eq!(
                decode::<Taint>(&bytes),
                Err(DecodeError::UnknownName {
                    type_name: "Taint",
                    name: refused.to_owned()
                })
            );
        }
    }

    #[test]
    fn ids_are_their_stored_uuidv7_bytes() {
        let id = sample_id();
        let bytes = encode(&id).expect("bytes");
        assert_eq!(bytes[0], 0x50, "a 16-byte byte string");
        assert_eq!(decode::<Id>(&bytes), Ok(id));
        let mut not_v7 = id.to_bytes();
        not_v7[6] = 0x40 | (not_v7[6] & 0x0f);
        let bytes = profile::encode(&CBOR::to_byte_string(not_v7)).expect("bytes");
        assert!(matches!(
            decode::<Id>(&bytes),
            Err(DecodeError::Invalid { .. })
        ));
        let bytes = profile::encode(&CBOR::to_byte_string([0u8; 15])).expect("bytes");
        assert!(matches!(
            decode::<Id>(&bytes),
            Err(DecodeError::Invalid { .. })
        ));
        let text = profile::encode(&CBOR::from(id.to_string().as_str())).expect("text");
        assert!(matches!(
            decode::<Id>(&text),
            Err(DecodeError::Expected { .. })
        ));
    }

    #[test]
    fn times_are_milliseconds_within_the_range_of_vilicus_types() {
        for time in [UtcMillis::MIN, UtcMillis::UNIX_EPOCH, UtcMillis::MAX] {
            assert_eq!(decode::<UtcMillis>(&encode(&time).expect("int")), Ok(time));
        }
        let past_max = encode(&(UtcMillis::MAX.as_millis() + 1)).expect("int");
        assert!(matches!(
            decode::<UtcMillis>(&past_max),
            Err(DecodeError::Invalid { .. })
        ));
    }

    #[test]
    fn every_source_kind_round_trips() {
        for source in every_source_kind() {
            let bytes = encode(&source).expect("source");
            assert_eq!(decode::<Source>(&bytes), Ok(source));
        }
    }

    /// The 2.4 review found serde's derived form accepting each of these; the wire refuses them.
    #[test]
    fn source_refuses_index_tags_byte_keys_extra_entries_and_a_payload_on_system() {
        let id = sample_id().to_cbor();
        let mut by_index = Map::new();
        by_index.insert(0u64, id.clone());
        let mut by_bytes = Map::new();
        by_bytes.insert(CBOR::to_byte_string(b"member"), id.clone());
        let two_entries = wire::record([("member", id.clone()), ("plugin", id.clone())]);
        let system_with_payload = wire::tagged("system", CBOR::null());
        let unknown = wire::tagged("mail", id.clone());
        let member_without_payload = CBOR::from("member");
        for refused in [
            CBOR::from(by_index),
            CBOR::from(by_bytes),
            two_entries,
            system_with_payload,
            unknown,
            member_without_payload,
            CBOR::from(Map::new()),
        ] {
            let bytes = profile::encode(&refused).expect("in the profile");
            assert!(decode::<Source>(&bytes).is_err(), "{refused:?}");
        }
    }

    #[test]
    fn client_error_is_closed() {
        let error = ClientError {
            code: ErrorCode::from_static("policy.denied"),
            message_key: MessageKey::from_static("error.policy.denied"),
            retry_class: RetryClass::NotRetryable,
        };
        let bytes = encode(&error).expect("record");
        assert_eq!(decode::<ClientError>(&bytes), Ok(error.clone()));

        let CBORCase::Map(map) = error.to_cbor().into_case() else {
            panic!("a record is a map");
        };
        let mut with_message = map.clone();
        with_message.insert("message", "internal detail");
        let mut by_index = Map::new();
        for (index, (_, value)) in map.iter().enumerate() {
            by_index.insert(index as u64, value.clone());
        }
        let mut missing = Map::new();
        for (key, value) in map.iter().skip(1) {
            missing.insert(key.clone(), value.clone());
        }
        let mut sentence = map.clone();
        sentence.insert("code", "Access was denied");
        for refused in [with_message, by_index, missing, sentence] {
            let bytes = profile::encode(&CBOR::from(refused.clone())).expect("in the profile");
            assert!(decode::<ClientError>(&bytes).is_err(), "{refused:?}");
        }
    }
}
