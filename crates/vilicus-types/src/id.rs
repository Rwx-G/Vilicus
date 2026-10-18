//! Record identifiers: UUIDv7 (RFC 9562 section 5.7), a 16-byte blob in storage and lowercase
//! hyphenated text at the edges.

use core::fmt;
use core::str::FromStr;

use crate::time::UtcMillis;

const TEXT_LEN: usize = 36;
const HYPHEN_POSITIONS: [usize; 4] = [8, 13, 18, 23];
const VERSION_7: u8 = 0x70;
const RFC_9562_VARIANT: u8 = 0x80;

/// A UUIDv7 record identifier.
///
/// It is opaque: the type offers its bytes and its text, and nothing that reads the creation time
/// or the random bits back out of it, so no code parses meaning from an identifier. The time it
/// embeds is disclosed to whoever sees it, which the spine conventions accept. It has no
/// ordering, so that a sort by identifier cannot stand in for a sort by time.
///
/// ```
/// use vilicus_types::{Id, UtcMillis};
///
/// let created_at = UtcMillis::parse_rfc3339("2022-02-22T19:22:22Z")?;
/// let id = Id::new_v7(created_at, [0x0C, 0xC3, 0x18, 0xC4, 0xDC, 0x0C, 0x0C, 0x07, 0x39, 0x8F])?;
/// assert_eq!(id.to_string(), "017f22e2-79b0-7cc3-98c4-dc0c0c07398f");
/// assert_eq!(Id::from_bytes(id.to_bytes())?, id);
/// assert_eq!("017f22e2-79b0-7cc3-98c4-dc0c0c07398f".parse::<Id>()?, id);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// Comparing two identifiers by order does not compile:
///
/// ```compile_fail,E0369
/// let id: vilicus_types::Id = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f".parse().unwrap();
/// let _ = id < id;
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Id([u8; 16]);

/// A refused identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdError {
    /// The creation time is before the Unix epoch, which the 48-bit field cannot hold.
    BeforeUnixEpoch,
    /// The text is not 36 characters of lowercase hexadecimal digits with hyphens at positions
    /// 8, 13, 18 and 23.
    Malformed,
    /// The version field is not 7.
    NotVersion7,
    /// The variant field is not the RFC 9562 variant, binary `10`.
    NotRfc9562Variant,
}

impl fmt::Display for IdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::BeforeUnixEpoch => "UUIDv7 creation time before the Unix epoch",
            Self::Malformed => "not a lowercase hyphenated UUID",
            Self::NotVersion7 => "not a version 7 UUID",
            Self::NotRfc9562Variant => "not an RFC 9562 variant UUID",
        })
    }
}

impl std::error::Error for IdError {}

impl Id {
    /// Lays out a UUIDv7 from its creation time and random bits; the Core supplies both, from its
    /// clock and from the CSPRNG of `vilicus-crypto`, so this crate stays pure.
    ///
    /// The 74 random bits of the layout are taken in order from `random`: `rand_a` is the low
    /// 4 bits of byte 0 then byte 1, and `rand_b` the low 6 bits of byte 2 then bytes 3 to 9. The
    /// high 4 bits of byte 0 and the high 2 bits of byte 2 are not used. The time occupies 48
    /// bits, which reach past year 9999, so only an instant before the Unix epoch is refused.
    pub const fn new_v7(created_at: UtcMillis, random: [u8; 10]) -> Result<Self, IdError> {
        let millis = created_at.as_millis();
        if millis < 0 {
            return Err(IdError::BeforeUnixEpoch);
        }
        let time = millis.cast_unsigned().to_be_bytes();
        Ok(Self([
            time[2],
            time[3],
            time[4],
            time[5],
            time[6],
            time[7],
            VERSION_7 | (random[0] & 0x0F),
            random[1],
            RFC_9562_VARIANT | (random[2] & 0x3F),
            random[3],
            random[4],
            random[5],
            random[6],
            random[7],
            random[8],
            random[9],
        ]))
    }

    /// The identifier stored as `bytes`; a blob that is not a UUIDv7 is refused.
    pub const fn from_bytes(bytes: [u8; 16]) -> Result<Self, IdError> {
        if bytes[6] & 0xF0 != VERSION_7 {
            return Err(IdError::NotVersion7);
        }
        if bytes[8] & 0xC0 != RFC_9562_VARIANT {
            return Err(IdError::NotRfc9562Variant);
        }
        Ok(Self(bytes))
    }

    /// The 16 bytes of the stored form.
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }

    /// Reads the text form. Only the form [`Display`](fmt::Display) writes is accepted: 36
    /// characters, lowercase hexadecimal digits, hyphens at positions 8, 13, 18 and 23. Uppercase
    /// digits, braces and the `urn:uuid:` prefix are refused rather than normalized, so one
    /// identifier has one text, then the version and variant are checked like
    /// [`from_bytes`](Self::from_bytes).
    pub fn parse(text: &str) -> Result<Self, IdError> {
        let text = text.as_bytes();
        if text.len() != TEXT_LEN {
            return Err(IdError::Malformed);
        }
        let mut digits = Vec::with_capacity(32);
        for (position, &byte) in text.iter().enumerate() {
            if HYPHEN_POSITIONS.contains(&position) {
                if byte != b'-' {
                    return Err(IdError::Malformed);
                }
                continue;
            }
            digits.push(match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => return Err(IdError::Malformed),
            });
        }
        let mut bytes = [0; 16];
        let (pairs, _) = digits.as_chunks::<2>();
        for (byte, [high, low]) in bytes.iter_mut().zip(pairs) {
            *byte = (high << 4) | low;
        }
        Self::from_bytes(bytes)
    }
}

impl fmt::Display for Id {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                formatter.write_str("-")?;
            }
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Id({self})")
    }
}

impl FromStr for Id {
    type Err = IdError;

    fn from_str(text: &str) -> Result<Self, IdError> {
        Self::parse(text)
    }
}

impl serde::Serialize for Id {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Id {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TextVisitor;

        impl serde::de::Visitor<'_> for TextVisitor {
            type Value = Id;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a lowercase hyphenated UUIDv7")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Id, E> {
                Id::parse(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(TextVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{from_str, to_json};

    /// RFC 9562 appendix A.6: `unix_ts_ms` 0x017F22E279B0, `rand_a` 0xCC3, `rand_b`
    /// 0x18C4DC0C0C07398F.
    const RFC_9562_TEXT: &str = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f";
    const RFC_9562_BYTES: [u8; 16] = [
        0x01, 0x7F, 0x22, 0xE2, 0x79, 0xB0, 0x7C, 0xC3, 0x98, 0xC4, 0xDC, 0x0C, 0x0C, 0x07, 0x39,
        0x8F,
    ];
    const RFC_9562_RANDOM: [u8; 10] = [0x0C, 0xC3, 0x18, 0xC4, 0xDC, 0x0C, 0x0C, 0x07, 0x39, 0x8F];

    fn at(millis: i64) -> UtcMillis {
        UtcMillis::from_millis(millis).expect("in range")
    }

    #[test]
    fn rfc9562_uuidv7_example() {
        let id = Id::new_v7(at(0x017F_22E2_79B0), RFC_9562_RANDOM).expect("valid");
        assert_eq!(id.to_bytes(), RFC_9562_BYTES);
        assert_eq!(id.to_string(), RFC_9562_TEXT);
        assert_eq!(Id::parse(RFC_9562_TEXT), Ok(id));
        assert_eq!(Id::from_bytes(RFC_9562_BYTES), Ok(id));
    }

    #[test]
    fn layout_sets_version_and_variant_and_keeps_74_random_bits() {
        let id = Id::new_v7(at(0), [0xFF; 10]).expect("valid");
        assert_eq!(id.to_string(), "00000000-0000-7fff-bfff-ffffffffffff");
        let id = Id::new_v7(at(0), [0x00; 10]).expect("valid");
        assert_eq!(id.to_string(), "00000000-0000-7000-8000-000000000000");
        // The high nibble of byte 0 and the high two bits of byte 2 are the unused random bits.
        assert_eq!(
            Id::new_v7(at(0), [0xF0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0]),
            Ok(id)
        );
    }

    #[test]
    fn time_field_spans_the_whole_range_after_the_epoch() {
        let latest = Id::new_v7(UtcMillis::MAX, [0; 10]).expect("valid");
        assert_eq!(
            latest.to_bytes()[..6],
            UtcMillis::MAX.as_millis().to_be_bytes()[2..]
        );
        assert_eq!(Id::new_v7(at(-1), [0; 10]), Err(IdError::BeforeUnixEpoch));
        assert_eq!(
            Id::new_v7(UtcMillis::MIN, [0; 10]),
            Err(IdError::BeforeUnixEpoch)
        );
    }

    #[test]
    fn stored_form_must_be_uuidv7() {
        let mut bytes = RFC_9562_BYTES;
        for version in [0x00, 0x40, 0x60, 0x80, 0xF0] {
            bytes[6] = version | (RFC_9562_BYTES[6] & 0x0F);
            assert_eq!(
                Id::from_bytes(bytes),
                Err(IdError::NotVersion7),
                "{version:#x}"
            );
        }
        let mut bytes = RFC_9562_BYTES;
        for variant in [0x00, 0x40, 0xC0] {
            bytes[8] = variant | (RFC_9562_BYTES[8] & 0x3F);
            assert_eq!(
                Id::from_bytes(bytes),
                Err(IdError::NotRfc9562Variant),
                "{variant:#x}"
            );
        }
        assert_eq!(Id::from_bytes([0; 16]), Err(IdError::NotVersion7));
        assert_eq!(Id::from_bytes([0xFF; 16]), Err(IdError::NotVersion7));
    }

    #[test]
    fn text_form_is_lowercase_hyphenated_only() {
        for (text, error) in [
            ("017F22E2-79B0-7CC3-98C4-DC0C0C07398F", IdError::Malformed),
            ("017f22e2-79b0-7cc3-98c4-dc0c0c07398F", IdError::Malformed),
            ("017f22e279b07cc398c4dc0c0c07398f", IdError::Malformed),
            ("{017f22e2-79b0-7cc3-98c4-dc0c0c07398f}", IdError::Malformed),
            (
                "urn:uuid:017f22e2-79b0-7cc3-98c4-dc0c0c07398f",
                IdError::Malformed,
            ),
            ("017f22e2-79b0-7cc3-98c4-dc0c0c07398f ", IdError::Malformed),
            ("017f22e2-79b0-7cc3-98c4-dc0c0c07398", IdError::Malformed),
            ("017f22e2_79b0-7cc3-98c4-dc0c0c07398f", IdError::Malformed),
            ("017f22e2-79b-07cc3-98c4-dc0c0c07398f", IdError::Malformed),
            ("017f22e2-79b0-7cc3-98c4-dc0c0c07398g", IdError::Malformed),
            (
                "017f22e2-79b0-7cc3-98c4-dc0c0c0739\u{ff18}",
                IdError::Malformed,
            ),
            ("", IdError::Malformed),
            ("00000000-0000-0000-0000-000000000000", IdError::NotVersion7),
            ("ffffffff-ffff-ffff-ffff-ffffffffffff", IdError::NotVersion7),
            ("017f22e2-79b0-4cc3-98c4-dc0c0c07398f", IdError::NotVersion7),
            (
                "017f22e2-79b0-7cc3-c8c4-dc0c0c07398f",
                IdError::NotRfc9562Variant,
            ),
        ] {
            assert_eq!(Id::parse(text), Err(error), "{text:?}");
        }
    }

    #[test]
    fn text_round_trips() {
        for random in [[0x00; 10], [0xFF; 10], RFC_9562_RANDOM, [0x5A; 10]] {
            for millis in [0, 1, 0x017F_22E2_79B0, UtcMillis::MAX.as_millis()] {
                let id = Id::new_v7(at(millis), random).expect("valid");
                assert_eq!(Id::parse(&id.to_string()), Ok(id));
                assert_eq!(Id::from_bytes(id.to_bytes()), Ok(id));
            }
        }
    }

    #[test]
    fn serialized_as_text() {
        let id = Id::from_bytes(RFC_9562_BYTES).expect("valid");
        assert_eq!(to_json(&id), Ok(format!("\"{RFC_9562_TEXT}\"")));
        assert_eq!(from_str::<Id>(RFC_9562_TEXT), Ok(id));
        assert!(from_str::<Id>(&RFC_9562_TEXT.to_uppercase()).is_err());
    }
}
