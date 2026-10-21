//! The id of a call (spine AD-28): what the Core deduplicates a repeated call by.

use core::fmt;

use crate::id::Id;

/// The id a caller gives a call, 16 bytes stored as a blob. Any RFC 9562 UUID of versions 1 to 8
/// is accepted: a client or a capability token principal generates a UUIDv7 before any queueing
/// (AD-28), while a home rule's action takes a name-based UUID over the rule, the trigger event
/// and the action index, so a re-delivered trigger repeats it (AD-39). The nil and max UUIDs,
/// the versions RFC 9562 does not define and the other variants are refused. Like [`Id`] it is
/// opaque and unordered.
///
/// ```
/// use vilicus_types::{CallId, Id};
///
/// let mut name_based = [0x5a; 16];
/// name_based[6] = 0x58; // version 5
/// name_based[8] = 0x9c; // the RFC 9562 variant
/// assert!(CallId::from_bytes(name_based).is_ok());
/// let id: Id = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f".parse()?;
/// assert_eq!(CallId::from(id).to_bytes(), id.to_bytes());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CallId([u8; 16]);

/// A refused call id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallIdError {
    /// The variant field is not the RFC 9562 variant, binary `10`.
    NotRfc9562Variant,
    /// The version field is not one of versions 1 to 8.
    UnknownVersion,
}

impl fmt::Display for CallIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotRfc9562Variant => "not an RFC 9562 variant UUID",
            Self::UnknownVersion => "not a UUID of versions 1 to 8",
        })
    }
}

impl std::error::Error for CallIdError {}

impl CallId {
    /// The call id stored as `bytes`; refused unless it is an RFC 9562 UUID of versions 1 to 8.
    pub const fn from_bytes(bytes: [u8; 16]) -> Result<Self, CallIdError> {
        if bytes[8] & 0xC0 != 0x80 {
            return Err(CallIdError::NotRfc9562Variant);
        }
        let version = bytes[6] >> 4;
        if version < 1 || version > 8 {
            return Err(CallIdError::UnknownVersion);
        }
        Ok(Self(bytes))
    }

    /// The 16 bytes of the stored form.
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

/// A UUIDv7 a caller generated is a call id.
impl From<Id> for CallId {
    fn from(id: Id) -> Self {
        Self(id.to_bytes())
    }
}

impl fmt::Display for CallId {
    /// The lowercase hyphenated text of the UUID.
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

impl fmt::Debug for CallId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "CallId({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(version: u8, variant: u8) -> [u8; 16] {
        let mut bytes = [0x3c; 16];
        bytes[6] = (version << 4) | 0x0c;
        bytes[8] = variant | 0x0c;
        bytes
    }

    #[test]
    fn every_rfc_9562_version_is_a_call_id_and_nothing_else_is() {
        for version in 1..=8 {
            let bytes = with(version, 0x80);
            assert_eq!(
                CallId::from_bytes(bytes).map(CallId::to_bytes),
                Ok(bytes),
                "{version}"
            );
        }
        for version in [0, 9, 10, 15] {
            assert_eq!(
                CallId::from_bytes(with(version, 0x80)),
                Err(CallIdError::UnknownVersion),
                "{version}"
            );
        }
        for variant in [0x00, 0x40, 0xC0, 0xE0] {
            assert_eq!(
                CallId::from_bytes(with(7, variant)),
                Err(CallIdError::NotRfc9562Variant),
                "{variant:#x}"
            );
        }
        assert!(CallId::from_bytes([0; 16]).is_err(), "the nil UUID");
        assert!(CallId::from_bytes([0xff; 16]).is_err(), "the max UUID");
    }

    #[test]
    fn a_call_id_reads_as_its_uuid() {
        let id: Id = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"
            .parse()
            .expect("a UUIDv7");
        assert_eq!(
            CallId::from(id).to_string(),
            "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"
        );
        assert_eq!(
            format!("{:?}", CallId::from(id)),
            "CallId(017f22e2-79b0-7cc3-98c4-dc0c0c07398f)"
        );
    }
}
