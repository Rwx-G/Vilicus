//! Closed types on the wire (spine AD-12, AD-13): how a Rust type maps to and from a `dcbor`
//! value, by hand, and the one closed-type check every decoder goes through.
//!
//! A record is a map whose keys are its field names as text: [`Fields`] reads it, refuses a key
//! that is not text, a field the type does not declare and a missing field, and is the only code
//! that reads a record. A closed set is one of its names as text, read by [`closed_name`]: an
//! integer variant index, which serde's derived enums accept (Story 2.4 review), is refused. A
//! choice between variants is a name as text for a variant without payload, or a map with exactly
//! one entry, the variant's name to its payload, read by [`variant`]. Duplicate keys, unsorted
//! keys and bytes after the value are refused earlier, by the profile ([`crate::profile`]).

use core::fmt;

use dcbor::{CBOR, CBORCase, Map};

use crate::profile::{self, Rejection};

/// A type that crosses a socket or is hashed: mapped by hand to and from a `dcbor` value.
pub trait Wire: Sized {
    /// The value this one encodes to. It may still break the profile (non-NFC text, a key equal
    /// to another once normalized); [`encode`] checks it.
    fn to_cbor(&self) -> CBOR;

    /// Reads a value already accepted by the profile, refusing anything the type does not
    /// declare.
    fn from_cbor(value: &CBOR) -> Result<Self, DecodeError>;
}

/// Why a message was refused. Nothing is ignored or repaired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Refused by the canonical profile before the type was looked at.
    Profile(Rejection),
    /// The value has the wrong CBOR kind for the type.
    Expected {
        /// The type being read.
        type_name: &'static str,
        /// What it must be.
        expected: &'static str,
    },
    /// A map key that is not text, such as an integer field index or a byte string.
    KeyNotText {
        /// The type being read.
        type_name: &'static str,
    },
    /// A field the type does not declare.
    UnknownField {
        /// The type being read.
        type_name: &'static str,
        /// The field name received.
        field: String,
    },
    /// A field the type requires and the message lacks.
    MissingField {
        /// The type being read.
        type_name: &'static str,
        /// The field name.
        field: &'static str,
    },
    /// A name outside the closed set or the type's variants.
    UnknownName {
        /// The type being read.
        type_name: &'static str,
        /// The name received.
        name: String,
    },
    /// A choice between variants that is not one name nor a map of exactly one entry.
    NotOneVariant {
        /// The type being read.
        type_name: &'static str,
    },
    /// The value has the right kind but breaks the type's own rule.
    Invalid {
        /// The type being read.
        type_name: &'static str,
        /// The rule it breaks.
        reason: &'static str,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Profile(rejection) => write!(f, "refused by the canonical profile: {rejection}"),
            Self::Expected {
                type_name,
                expected,
            } => write!(f, "{type_name}: expected {expected}"),
            Self::KeyNotText { type_name } => write!(f, "{type_name}: a map key is not text"),
            Self::UnknownField { type_name, field } => {
                write!(f, "{type_name}: undeclared field {field:?}")
            }
            Self::MissingField { type_name, field } => {
                write!(f, "{type_name}: missing field {field:?}")
            }
            Self::UnknownName { type_name, name } => {
                write!(f, "{type_name}: unknown name {name:?}")
            }
            Self::NotOneVariant { type_name } => {
                write!(f, "{type_name}: expected one name or a map of one entry")
            }
            Self::Invalid { type_name, reason } => write!(f, "{type_name}: {reason}"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl From<Rejection> for DecodeError {
    fn from(rejection: Rejection) -> Self {
        Self::Profile(rejection)
    }
}

/// Encodes a value to its canonical bytes, refusing it if the profile does not allow it.
pub fn encode<T: Wire>(value: &T) -> Result<Vec<u8>, Rejection> {
    profile::encode(&value.to_cbor())
}

/// Decodes canonical bytes into a closed type: the profile first, head walk included, then the
/// type's own reading. The number of items is not bounded: bytes read from a socket go through
/// [`decode_with_max_items`], which [`crate::frame::read_message`] calls with the socket kind's
/// bound.
pub fn decode<T: Wire>(bytes: &[u8]) -> Result<T, DecodeError> {
    decode_with_max_items(bytes, usize::MAX)
}

/// [`decode`], refusing more than `max_items` data items in the head walk, before anything is
/// built ([`profile::decode_with_max_items`]).
pub fn decode_with_max_items<T: Wire>(bytes: &[u8], max_items: usize) -> Result<T, DecodeError> {
    T::from_cbor(&profile::decode_with_max_items(bytes, max_items)?)
}

/// Builds a record from its fields, in any order; the encoding sorts them.
///
/// Field names are the type's own constants, so two equal names are a programming error, which
/// the profile check of [`encode`] would not see once `dcbor` has merged them: this panics on one.
pub fn record(fields: impl IntoIterator<Item = (&'static str, CBOR)>) -> CBOR {
    let mut map = Map::new();
    for (name, value) in fields {
        if profile::insert_unique(&mut map, CBOR::from(name), value).is_err() {
            panic!("field {name:?} declared twice");
        }
    }
    map.into()
}

/// The fields of a record being read. Each field is taken once, by name; [`finish`] refuses any
/// field left over, so a field the type does not declare is never ignored.
///
/// [`finish`]: Fields::finish
pub struct Fields<'a> {
    type_name: &'static str,
    entries: Vec<(&'a str, &'a CBOR, bool)>,
}

impl<'a> Fields<'a> {
    /// Opens a record: the value must be a map whose keys are all text.
    pub fn open(value: &'a CBOR, type_name: &'static str) -> Result<Self, DecodeError> {
        let CBORCase::Map(map) = value.as_case() else {
            return Err(DecodeError::Expected {
                type_name,
                expected: "a map",
            });
        };
        let entries = map
            .iter()
            .map(|(key, item)| match key.as_case() {
                CBORCase::Text(name) => Ok((name.as_str(), item, false)),
                _ => Err(DecodeError::KeyNotText { type_name }),
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { type_name, entries })
    }

    /// Takes a field the type requires.
    pub fn required<T: Wire>(&mut self, name: &'static str) -> Result<T, DecodeError> {
        self.optional(name)?.ok_or(DecodeError::MissingField {
            type_name: self.type_name,
            field: name,
        })
    }

    /// Takes a field the type allows to be absent. Absent is the only encoding of "none": a
    /// present field always carries a value.
    pub fn optional<T: Wire>(&mut self, name: &'static str) -> Result<Option<T>, DecodeError> {
        match self.entries.iter_mut().find(|(key, _, _)| *key == name) {
            Some((_, item, taken)) => {
                *taken = true;
                T::from_cbor(item).map(Some)
            }
            None => Ok(None),
        }
    }

    /// Closes the record, refusing any field that was not taken.
    pub fn finish(self) -> Result<(), DecodeError> {
        match self.entries.into_iter().find(|(_, _, taken)| !taken) {
            Some((key, _, _)) => Err(DecodeError::UnknownField {
                type_name: self.type_name,
                field: key.to_owned(),
            }),
            None => Ok(()),
        }
    }
}

/// Reads a member of a closed set by its name, as text only.
pub fn closed_name<T: Copy>(
    value: &CBOR,
    type_name: &'static str,
    members: &[T],
    name_of: impl Fn(T) -> &'static str,
) -> Result<T, DecodeError> {
    let CBORCase::Text(name) = value.as_case() else {
        return Err(DecodeError::Expected {
            type_name,
            expected: "a name as text",
        });
    };
    members
        .iter()
        .copied()
        .find(|member| name_of(*member) == name)
        .ok_or_else(|| DecodeError::UnknownName {
            type_name,
            name: name.clone(),
        })
}

/// A variant as read by [`variant`]: its name and, for a variant with a payload, the payload.
pub struct Variant<'a> {
    /// The variant's name.
    pub name: &'a str,
    /// The payload; `None` when the variant was sent as a name alone.
    pub payload: Option<&'a CBOR>,
}

/// Reads a choice between variants: a name as text, or a map with exactly one entry whose key is
/// the name as text. The caller matches the name and requires a payload, or its absence.
pub fn variant<'a>(value: &'a CBOR, type_name: &'static str) -> Result<Variant<'a>, DecodeError> {
    match value.as_case() {
        CBORCase::Text(name) => Ok(Variant {
            name,
            payload: None,
        }),
        CBORCase::Map(map) => {
            let mut entries = map.iter();
            match (entries.next(), entries.next()) {
                (Some((key, payload)), None) => match key.as_case() {
                    CBORCase::Text(name) => Ok(Variant {
                        name,
                        payload: Some(payload),
                    }),
                    _ => Err(DecodeError::KeyNotText { type_name }),
                },
                _ => Err(DecodeError::NotOneVariant { type_name }),
            }
        }
        _ => Err(DecodeError::NotOneVariant { type_name }),
    }
}

impl Variant<'_> {
    /// The payload of a variant that requires one.
    pub fn payload(&self, type_name: &'static str) -> Result<&CBOR, DecodeError> {
        self.payload.ok_or(DecodeError::Expected {
            type_name,
            expected: "a variant with its payload",
        })
    }

    /// Refuses a payload on a variant that has none: such a variant has one encoding, its name.
    pub fn no_payload(&self, type_name: &'static str) -> Result<(), DecodeError> {
        match self.payload {
            None => Ok(()),
            Some(_) => Err(DecodeError::Invalid {
                type_name,
                reason: "this variant is sent as its name alone",
            }),
        }
    }

    /// The error for a name that is none of the type's variants.
    pub fn unknown(&self, type_name: &'static str) -> DecodeError {
        DecodeError::UnknownName {
            type_name,
            name: self.name.to_owned(),
        }
    }
}

/// A variant with a payload, as [`variant`] reads it.
pub fn tagged(name: &'static str, payload: CBOR) -> CBOR {
    record([(name, payload)])
}

impl Wire for bool {
    fn to_cbor(&self) -> CBOR {
        CBOR::from(*self)
    }

    fn from_cbor(value: &CBOR) -> Result<Self, DecodeError> {
        match value.as_case() {
            CBORCase::Simple(dcbor::Simple::True) => Ok(true),
            CBORCase::Simple(dcbor::Simple::False) => Ok(false),
            _ => Err(DecodeError::Expected {
                type_name: "bool",
                expected: "true or false",
            }),
        }
    }
}

impl Wire for u64 {
    fn to_cbor(&self) -> CBOR {
        CBORCase::Unsigned(*self).into()
    }

    fn from_cbor(value: &CBOR) -> Result<Self, DecodeError> {
        match value.as_case() {
            CBORCase::Unsigned(number) => Ok(*number),
            _ => Err(DecodeError::Expected {
                type_name: "u64",
                expected: "an unsigned integer",
            }),
        }
    }
}

impl Wire for u16 {
    fn to_cbor(&self) -> CBOR {
        u64::from(*self).to_cbor()
    }

    fn from_cbor(value: &CBOR) -> Result<Self, DecodeError> {
        Self::try_from(u64::from_cbor(value)?).map_err(|_| DecodeError::Invalid {
            type_name: "u16",
            reason: "integer above 65535",
        })
    }
}

impl Wire for i64 {
    fn to_cbor(&self) -> CBOR {
        if *self >= 0 {
            CBORCase::Unsigned(self.unsigned_abs()).into()
        } else {
            // CBOR stores a negative integer n as -1 - n.
            CBORCase::Negative(self.unsigned_abs() - 1).into()
        }
    }

    fn from_cbor(value: &CBOR) -> Result<Self, DecodeError> {
        let out_of_range = DecodeError::Invalid {
            type_name: "i64",
            reason: "integer outside the i64 range",
        };
        match value.as_case() {
            CBORCase::Unsigned(number) => Self::try_from(*number).map_err(|_| out_of_range),
            CBORCase::Negative(magnitude) => Self::try_from(*magnitude)
                .map(|magnitude| -1 - magnitude)
                .map_err(|_| out_of_range),
            _ => Err(DecodeError::Expected {
                type_name: "i64",
                expected: "an integer",
            }),
        }
    }
}

impl Wire for String {
    fn to_cbor(&self) -> CBOR {
        CBOR::from(self.as_str())
    }

    fn from_cbor(value: &CBOR) -> Result<Self, DecodeError> {
        match value.as_case() {
            CBORCase::Text(text) => Ok(text.clone()),
            _ => Err(DecodeError::Expected {
                type_name: "text",
                expected: "text",
            }),
        }
    }
}

impl<T: Wire> Wire for Vec<T> {
    fn to_cbor(&self) -> CBOR {
        CBOR::from(self.iter().map(Wire::to_cbor).collect::<Vec<_>>())
    }

    fn from_cbor(value: &CBOR) -> Result<Self, DecodeError> {
        match value.as_case() {
            CBORCase::Array(items) => items.iter().map(T::from_cbor).collect(),
            _ => Err(DecodeError::Expected {
                type_name: "array",
                expected: "an array",
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_map_to_their_cbor_kind_at_the_range_ends() {
        for number in [i64::MIN, -1, 0, 1, i64::MAX] {
            let bytes = encode(&number).expect("in the profile range");
            assert_eq!(decode::<i64>(&bytes), Ok(number));
        }
        assert_eq!(encode(&-1i64), Ok(vec![0x20]));
        assert!(matches!(
            decode::<i64>(&encode(&u64::MAX).expect("u64")),
            Err(DecodeError::Invalid { .. })
        ));
        assert!(matches!(
            decode::<u16>(&encode(&65_536u64).expect("u64")),
            Err(DecodeError::Invalid { .. })
        ));
        assert!(matches!(
            decode::<u64>(&encode(&-1i64).expect("i64")),
            Err(DecodeError::Expected { .. })
        ));
    }

    #[test]
    fn a_record_refuses_non_text_keys_unknown_and_missing_fields() {
        let value = record([("a", 1u64.to_cbor()), ("b", 2u64.to_cbor())]);
        let mut fields = Fields::open(&value, "Sample").expect("map");
        assert_eq!(fields.required::<u64>("a"), Ok(1));
        assert_eq!(
            fields.finish(),
            Err(DecodeError::UnknownField {
                type_name: "Sample",
                field: "b".to_owned()
            })
        );

        let mut fields = Fields::open(&value, "Sample").expect("map");
        assert_eq!(
            fields.required::<u64>("c"),
            Err(DecodeError::MissingField {
                type_name: "Sample",
                field: "c"
            })
        );

        let mut map = Map::new();
        map.insert(0u64, 1u64);
        let value = CBOR::from(map);
        assert_eq!(
            Fields::open(&value, "Sample").err(),
            Some(DecodeError::KeyNotText {
                type_name: "Sample"
            })
        );
    }

    #[test]
    #[should_panic(expected = "declared twice")]
    fn a_record_built_with_a_field_twice_panics() {
        record([("a", 1u64.to_cbor()), ("a", 2u64.to_cbor())]);
    }

    #[test]
    fn a_variant_is_one_name_or_one_entry() {
        let named = CBOR::from("ping");
        assert_eq!(variant(&named, "Sample").expect("name").name, "ping");
        let one = tagged("cancel", 1u64.to_cbor());
        let read = variant(&one, "Sample").expect("one entry");
        assert_eq!(read.name, "cancel");
        assert_eq!(read.payload("Sample"), Ok(&1u64.to_cbor()));
        let two = record([("a", 1u64.to_cbor()), ("b", 2u64.to_cbor())]);
        assert!(matches!(
            variant(&two, "Sample"),
            Err(DecodeError::NotOneVariant { .. })
        ));
        assert!(matches!(
            variant(&CBOR::from(Map::new()), "Sample"),
            Err(DecodeError::NotOneVariant { .. })
        ));
        assert!(matches!(
            variant(&0u64.to_cbor(), "Sample"),
            Err(DecodeError::NotOneVariant { .. })
        ));
        let mut map = Map::new();
        map.insert(CBOR::to_byte_string(b"cancel"), 1u64);
        assert!(matches!(
            variant(&CBOR::from(map), "Sample"),
            Err(DecodeError::KeyNotText { .. })
        ));
    }
}
