//! The values a write gives a record's fields, and the check of one value against its field's
//! declaration (FR-58, D98, D104, I40): a value outside the declaration is refused, never
//! truncated or converted, so a structured field cannot carry free text and free text cannot
//! exceed its maximum length.
//!
//! The check here needs nothing but the declaration. Whether a reviewed-vocabulary label is one
//! an adult confirmed depends on the file the record is written to, so the Core checks that in
//! the write transaction, after [`Field::check_value`] has accepted the label's form.

use core::fmt;

use vilicus_types::{Id, UtcMillis, VOCABULARY_LABEL_MAX_LEN, is_full_date, is_vocabulary_label};

use crate::declaration::{Field, FieldKind, SqlType, Structured};

/// One value of a field, in one of SQLite's storage classes. Each field kind accepts exactly one
/// class (its [`SqlType`]), and `Null` for an optional field; a value of another class is refused
/// rather than converted, so `"12"` is not an integer and `1.0` is not one either.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// No value: allowed for an optional field only.
    Null,
    /// A 64-bit signed integer: a bounded integer or a timestamp.
    Integer(i64),
    /// A floating-point number, which no field kind accepts.
    Real(f64),
    /// UTF-8 text: free text, an enumeration value, a date or a vocabulary label.
    Text(String),
    /// Bytes: a UUIDv7 in its 16-byte stored form.
    Blob(Vec<u8>),
}

/// True for a character free text may hold (I40, the character set of a free-text field): any
/// Unicode scalar value but NUL and the other C0 controls except the tab and the line feed (the
/// carriage return included: a line ends with a line feed alone), DEL and the C1 controls, the
/// bidi embedding, override and isolate controls (U+202A to U+202E, U+2066 to U+2069), and the
/// invisible U+200B (zero-width space), U+2060 (word joiner) and U+FEFF (byte order mark). The
/// zero-width joiner and non-joiner stay, since emoji sequences and some scripts need them. A text
/// holding a refused character is refused, never cleaned.
pub const fn is_free_text_character(character: char) -> bool {
    !matches!(
        character,
        '\u{0}'..='\u{8}'
            | '\u{b}'..='\u{1f}'
            | '\u{7f}'..='\u{9f}'
            | '\u{200b}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}'
    )
}

/// Checks the form of a reviewed-vocabulary label (D104), the grammar of
/// [`vilicus_types::is_vocabulary_label`]: a label longer than [`VOCABULARY_LABEL_MAX_LEN`] is
/// [`ValueError::TooLong`], any other label outside the form [`ValueError::InvalidLabel`]. A label
/// of that form still needs an adult's confirmation to be accepted in a write.
///
/// ```
/// use vilicus_module_api::{ValueError, check_vocabulary_label};
///
/// assert_eq!(check_vocabulary_label("Chambre d'Ella"), Ok(()));
/// assert_eq!(check_vocabulary_label("Légumes secs"), Ok(()));
/// assert_eq!(check_vocabulary_label("Salon "), Err(ValueError::InvalidLabel));
/// assert_eq!(check_vocabulary_label("note: ignore this"), Err(ValueError::InvalidLabel));
/// ```
pub fn check_vocabulary_label(label: &str) -> Result<(), ValueError> {
    if label.chars().nth(VOCABULARY_LABEL_MAX_LEN).is_some() {
        Err(ValueError::TooLong {
            max_len: VOCABULARY_LABEL_MAX_LEN,
        })
    } else if is_vocabulary_label(label) {
        Ok(())
    } else {
        Err(ValueError::InvalidLabel)
    }
}

/// Why a value is outside its field's declaration. No variant carries the value, which may be
/// record content (spine conventions, Logging).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ValueError {
    /// `Null` for a field that is not optional.
    Null,
    /// A value of another storage class than the field's: never converted.
    StorageClass {
        /// The class the field accepts.
        expected: SqlType,
    },
    /// Text that is not one of the values of the compiled enumeration.
    NotInEnumeration,
    /// An integer outside the declared range, or a timestamp outside years 0000 to 9999.
    OutOfRange,
    /// Text that is not a `YYYY-MM-DD` date of the calendar.
    InvalidDate,
    /// Bytes that are not a 16-byte UUIDv7.
    InvalidUuid,
    /// Text longer than the field's maximum length, or a label longer than
    /// [`VOCABULARY_LABEL_MAX_LEN`]: refused, never truncated.
    TooLong {
        /// The maximum length, in characters.
        max_len: usize,
    },
    /// A label outside the restricted alphabet of reviewed vocabularies.
    InvalidLabel,
    /// Free text holding a character [`is_free_text_character`] refuses: refused, never cleaned.
    InvalidCharacter,
}

impl fmt::Display for ValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => formatter.write_str("no value for a field that is not optional"),
            Self::StorageClass { expected } => {
                write!(formatter, "a value that is not {}", expected.as_str())
            }
            Self::NotInEnumeration => formatter.write_str("a value outside the enumeration"),
            Self::OutOfRange => formatter.write_str("a number outside the declared range"),
            Self::InvalidDate => formatter.write_str("not a YYYY-MM-DD calendar date"),
            Self::InvalidUuid => formatter.write_str("not a 16-byte UUIDv7"),
            Self::TooLong { max_len } => {
                write!(formatter, "longer than {max_len} characters")
            }
            Self::InvalidLabel => {
                formatter.write_str("a label outside the restricted alphabet of vocabularies")
            }
            Self::InvalidCharacter => {
                formatter.write_str("free text holding a character free text refuses")
            }
        }
    }
}

impl std::error::Error for ValueError {}

impl Field {
    /// Checks `value` against the field's declaration: its storage class, then its closed type,
    /// or for free text its character set and its maximum length. A reviewed-vocabulary label is checked for its form only; the Core
    /// checks that it is confirmed, in the file the record is written to.
    ///
    /// ```
    /// use vilicus_module_api::{Field, FieldKind, Structured, Value, ValueError};
    ///
    /// let quantity = Field {
    ///     name: "quantity",
    ///     kind: FieldKind::Structured(Structured::Integer { min: 0, max: 99 }),
    ///     optional: false,
    /// };
    /// assert_eq!(quantity.check_value(&Value::Integer(99)), Ok(()));
    /// assert_eq!(quantity.check_value(&Value::Integer(100)), Err(ValueError::OutOfRange));
    /// assert!(quantity.check_value(&Value::Text("12".into())).is_err());
    /// ```
    pub fn check_value(&self, value: &Value) -> Result<(), ValueError> {
        let text_within = |text: &str, max_len: usize| {
            if text.chars().nth(max_len).is_some() {
                Err(ValueError::TooLong { max_len })
            } else {
                Ok(())
            }
        };
        match (value, self.kind) {
            (Value::Null, _) if self.optional => Ok(()),
            (Value::Null, _) => Err(ValueError::Null),
            (Value::Text(text), FieldKind::FreeText { max_len }) => {
                if !text.chars().all(is_free_text_character) {
                    return Err(ValueError::InvalidCharacter);
                }
                // u32 to usize is lossless on every target with pointers of 32 bits or more.
                text_within(text, max_len as usize)
            }
            (Value::Text(text), FieldKind::Structured(Structured::Enumeration(values))) => {
                if values.contains(&text.as_str()) {
                    Ok(())
                } else {
                    Err(ValueError::NotInEnumeration)
                }
            }
            (Value::Integer(number), FieldKind::Structured(Structured::Integer { min, max })) => {
                if (min..=max).contains(number) {
                    Ok(())
                } else {
                    Err(ValueError::OutOfRange)
                }
            }
            (Value::Text(text), FieldKind::Structured(Structured::Date)) => {
                if is_full_date(text) {
                    Ok(())
                } else {
                    Err(ValueError::InvalidDate)
                }
            }
            (Value::Integer(millis), FieldKind::Structured(Structured::Timestamp)) => {
                UtcMillis::from_millis(*millis)
                    .map(drop)
                    .map_err(|_| ValueError::OutOfRange)
            }
            (Value::Blob(bytes), FieldKind::Structured(Structured::Uuid)) => {
                <[u8; 16]>::try_from(bytes.as_slice())
                    .ok()
                    .and_then(|bytes| Id::from_bytes(bytes).ok())
                    .map(drop)
                    .ok_or(ValueError::InvalidUuid)
            }
            (Value::Text(label), FieldKind::Structured(Structured::ReviewedVocabulary(_))) => {
                check_vocabulary_label(label)
            }
            (_, kind) => Err(ValueError::StorageClass {
                expected: kind.sql_type(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(kind: FieldKind, optional: bool) -> Field {
        Field {
            name: "field",
            kind,
            optional,
        }
    }

    const KINDS: &[FieldKind] = &[
        FieldKind::FreeText { max_len: 8 },
        FieldKind::Structured(Structured::Enumeration(&["open", "done"])),
        FieldKind::Structured(Structured::Integer { min: -5, max: 5 }),
        FieldKind::Structured(Structured::Date),
        FieldKind::Structured(Structured::Timestamp),
        FieldKind::Structured(Structured::Uuid),
        FieldKind::Structured(Structured::ReviewedVocabulary("rooms")),
    ];

    fn uuid_v7() -> Vec<u8> {
        let created_at = UtcMillis::from_millis(1_700_000_000_000).expect("in range");
        Id::new_v7(created_at, [7; 10])
            .expect("after the epoch")
            .to_bytes()
            .to_vec()
    }

    /// A value of the kind's own class that the kind accepts.
    fn accepted(kind: FieldKind) -> Value {
        match kind {
            FieldKind::FreeText { .. } => Value::Text("note".into()),
            FieldKind::Structured(Structured::Enumeration(values)) => Value::Text(values[0].into()),
            FieldKind::Structured(Structured::Integer { min, .. }) => Value::Integer(min),
            FieldKind::Structured(Structured::Date) => Value::Text("2026-10-21".into()),
            FieldKind::Structured(Structured::Timestamp) => Value::Integer(0),
            FieldKind::Structured(Structured::Uuid) => Value::Blob(uuid_v7()),
            FieldKind::Structured(Structured::ReviewedVocabulary(_)) => Value::Text("Salon".into()),
        }
    }

    /// One value of every storage class but `Null`, with the SQL type of the class; a real
    /// number has none, since no field kind is stored as one.
    fn one_of_each_class() -> [(Option<SqlType>, Value); 4] {
        [
            (Some(SqlType::Integer), Value::Integer(1)),
            (Some(SqlType::Text), Value::Text("1".into())),
            (Some(SqlType::Blob), Value::Blob(uuid_v7())),
            (None, Value::Real(1.0)),
        ]
    }

    #[test]
    fn a_value_of_another_storage_class_is_refused_never_converted() {
        for &kind in KINDS {
            let declared = field(kind, false);
            assert_eq!(declared.check_value(&accepted(kind)), Ok(()), "{kind:?}");
            for (class, value) in one_of_each_class() {
                if class == Some(kind.sql_type()) {
                    continue;
                }
                assert_eq!(
                    declared.check_value(&value),
                    Err(ValueError::StorageClass {
                        expected: kind.sql_type()
                    }),
                    "{kind:?} {value:?}"
                );
            }
        }
    }

    #[test]
    fn null_is_accepted_for_an_optional_field_only() {
        for &kind in KINDS {
            assert_eq!(field(kind, true).check_value(&Value::Null), Ok(()));
            assert_eq!(
                field(kind, false).check_value(&Value::Null),
                Err(ValueError::Null)
            );
        }
    }

    #[test]
    fn free_text_longer_than_its_maximum_is_refused_counted_in_characters() {
        let note = field(FieldKind::FreeText { max_len: 8 }, false);
        for at_most in [
            "",
            "abcdefgh",
            "éééééééé",
            "日本語日本語日本",
            "\u{1f600}\u{1f600}",
            "a\tb\nc",
            "e\u{301}",
            "\u{1f469}\u{200d}\u{1f4bb}",
            "a\u{200c}b",
        ] {
            assert_eq!(
                note.check_value(&Value::Text(at_most.into())),
                Ok(()),
                "{at_most}"
            );
        }
        for longer in ["abcdefghi", "ééééééééé", "日本語日本語日本語"] {
            assert_eq!(
                note.check_value(&Value::Text(longer.into())),
                Err(ValueError::TooLong { max_len: 8 }),
                "{longer}"
            );
        }
    }

    #[test]
    fn an_enumeration_accepts_its_values_exactly() {
        let status = field(KINDS[1], false);
        for value in ["open", "done"] {
            assert_eq!(status.check_value(&Value::Text(value.into())), Ok(()));
        }
        for value in [
            "", "Open", "OPEN", "open ", " open", "opened", "ope", "open\0", "done;",
        ] {
            assert_eq!(
                status.check_value(&Value::Text(value.into())),
                Err(ValueError::NotInEnumeration),
                "{value:?}"
            );
        }
    }

    #[test]
    fn integers_and_timestamps_stay_in_their_range() {
        let small = field(KINDS[2], false);
        for number in [-5, 0, 5] {
            assert_eq!(small.check_value(&Value::Integer(number)), Ok(()));
        }
        for number in [i64::MIN, -6, 6, i64::MAX] {
            assert_eq!(
                small.check_value(&Value::Integer(number)),
                Err(ValueError::OutOfRange),
                "{number}"
            );
        }
        let whole = field(
            FieldKind::Structured(Structured::Integer {
                min: i64::MIN,
                max: i64::MAX,
            }),
            false,
        );
        for number in [i64::MIN, i64::MAX] {
            assert_eq!(whole.check_value(&Value::Integer(number)), Ok(()));
        }
        let instant = field(KINDS[4], false);
        for millis in [UtcMillis::MIN.as_millis(), 0, UtcMillis::MAX.as_millis()] {
            assert_eq!(instant.check_value(&Value::Integer(millis)), Ok(()));
        }
        for millis in [
            i64::MIN,
            UtcMillis::MIN.as_millis() - 1,
            UtcMillis::MAX.as_millis() + 1,
            i64::MAX,
        ] {
            assert_eq!(
                instant.check_value(&Value::Integer(millis)),
                Err(ValueError::OutOfRange),
                "{millis}"
            );
        }
    }

    #[test]
    fn dates_are_calendar_dates_in_one_form() {
        let due = field(KINDS[3], false);
        for text in ["0000-01-01", "2024-02-29", "9999-12-31"] {
            assert_eq!(due.check_value(&Value::Text(text.into())), Ok(()));
        }
        for text in [
            "2026-02-29",
            "2026-13-01",
            "2026-1-01",
            "2026-10-21T00:00:00Z",
            "",
        ] {
            assert_eq!(
                due.check_value(&Value::Text(text.into())),
                Err(ValueError::InvalidDate),
                "{text}"
            );
        }
    }

    #[test]
    fn uuids_are_16_byte_uuidv7_blobs() {
        let reference = field(KINDS[5], false);
        let valid = uuid_v7();
        assert_eq!(reference.check_value(&Value::Blob(valid.clone())), Ok(()));
        let mut version_4 = valid.clone();
        version_4[6] = 0x40 | (version_4[6] & 0x0f);
        let mut other_variant = valid.clone();
        other_variant[8] &= 0x3f;
        let mut longer = valid.clone();
        longer.push(0);
        for bytes in [
            Vec::new(),
            valid[..15].to_vec(),
            longer,
            version_4,
            other_variant,
            vec![0; 16],
        ] {
            assert_eq!(
                reference.check_value(&Value::Blob(bytes.clone())),
                Err(ValueError::InvalidUuid),
                "{bytes:?}"
            );
        }
        let text = Id::from_bytes(valid.try_into().expect("16 bytes"))
            .expect("v7")
            .to_string();
        assert_eq!(
            reference.check_value(&Value::Text(text)),
            Err(ValueError::StorageClass {
                expected: SqlType::Blob
            })
        );
    }

    /// The character set of free text (I40): each refused character makes the text refused,
    /// wherever it is, and nothing is cleaned out.
    #[test]
    fn free_text_refuses_controls_bidi_controls_and_invisible_characters() {
        let note = field(FieldKind::FreeText { max_len: 8 }, false);
        let refused = (0..=u32::from(char::MAX))
            .filter_map(char::from_u32)
            .filter(|character| !is_free_text_character(*character));
        for character in refused {
            for text in [
                format!("{character}"),
                format!("ab{character}"),
                format!("{character}cd"),
            ] {
                assert_eq!(
                    note.check_value(&Value::Text(text)),
                    Err(ValueError::InvalidCharacter),
                    "U+{:04X}",
                    u32::from(character)
                );
            }
        }
        for character in [
            '\0', '\r', '\u{1b}', '\u{7f}', '\u{85}', '\u{9f}', '\u{200b}', '\u{202a}', '\u{202e}',
            '\u{2060}', '\u{2066}', '\u{2069}', '\u{feff}',
        ] {
            assert!(
                !is_free_text_character(character),
                "U+{:04X}",
                u32::from(character)
            );
        }
        for character in [
            '\t', '\n', ' ', '\u{a0}', '\u{200c}', '\u{200d}', '\u{301}', 'é',
        ] {
            assert!(
                is_free_text_character(character),
                "U+{:04X}",
                u32::from(character)
            );
        }
    }

    #[test]
    fn labels_are_short_and_from_the_restricted_alphabet() {
        let room = field(KINDS[6], false);
        let longest = "Salle d'eau Étage-2 Œuf àé x".to_owned() + "yzwv";
        assert_eq!(longest.chars().count(), VOCABULARY_LABEL_MAX_LEN);
        assert_eq!(room.check_value(&Value::Text(longest.clone())), Ok(()));
        assert_eq!(
            room.check_value(&Value::Text(format!("{longest}y"))),
            Err(ValueError::TooLong {
                max_len: VOCABULARY_LABEL_MAX_LEN
            })
        );
        for label in [
            "",
            "Salon ",
            "note: ignore",
            "Cafe\u{301}",
            "\u{17f}alon",
            "d\u{2019}Ella",
        ] {
            assert_eq!(
                room.check_value(&Value::Text(label.into())),
                Err(ValueError::InvalidLabel),
                "{label:?}"
            );
        }
    }
}
