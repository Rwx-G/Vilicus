//! The MAC of the `wrappers.db` record set (gate AD36-1): the AD-36 construction authenticates
//! each record, and this MAC authenticates the set, so that a deleted record or an older file is
//! seen. It is HMAC-SHA-256 under a key derived from the household key, over a monotonic counter
//! and every record of the set; the counter is also cross-checked with `core.db`, which the Core
//! does outside this crate.

use crate::aws_lc::{self, HMAC_SHA256_LEN};
use crate::derive::Label;
use crate::error::{CryptoError, WrapperError};
use crate::hierarchy::{Role, sealed::HoldsKey};
use crate::key::SymmetricKey;

/// The format version of a stored wrapper set MAC this Core writes and reads.
pub const WRAPPER_SET_MAC_VERSION: u16 = 1;

/// The algorithm identifier of HMAC-SHA-256 in a stored wrapper set MAC, numbered from 0x0001 as
/// the wrapper identifiers are (D153).
const MAC_HMAC_SHA256: u16 = 0x0001;

/// Bytes of a stored wrapper set MAC: format version, algorithm, household key version, tag.
pub const WRAPPER_SET_MAC_LEN: usize = 2 + 2 + 4 + HMAC_SHA256_LEN;

/// The domain of the MAC input, which starts with it and its end byte.
pub(crate) const SET_MAC_DOMAIN: Label = crate::label!("vilicus/v1/wrappers/set");

/// The MAC key of the `wrappers.db` record set, derived from the household key of one version
/// ([`HouseholdKey::wrapper_set_key`](crate::HouseholdKey::wrapper_set_key)). Not `Clone`,
/// `Debug` or `Display`; its slot is wiped when it is dropped.
pub struct WrapperSetKey {
    key: SymmetricKey,
    household_key_version: u32,
}

impl HoldsKey for WrapperSetKey {
    const ROLE: Option<Role> = Some(Role::WrapperSetKey);

    fn symmetric(&self) -> &SymmetricKey {
        &self.key
    }
}

/// The MAC of one state of the `wrappers.db` record set: the household key version whose set key
/// computed it, and the HMAC-SHA-256 tag. Stored with its format version and algorithm identifier
/// first, as every value of `wrappers.db` is (`doc/key-management.md` section 2, "Stored values").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrapperSetMac {
    household_key_version: u32,
    tag: [u8; HMAC_SHA256_LEN],
}

/// The MAC input of a record set: the domain label and its end byte, the format version, the
/// algorithm, the household key version and the counter, the record count, then each record
/// preceded by its length, in ascending byte order, so the same set gives the same input whatever
/// order it is read in.
struct MacInput<'a> {
    header: [u8; 2 + 2 + 4 + 8 + 4],
    lengths: Vec<[u8; 4]>,
    records: Vec<&'a [u8]>,
}

impl<'a> MacInput<'a> {
    fn new(
        household_key_version: u32,
        counter: u64,
        records: &[&'a [u8]],
    ) -> Result<Self, CryptoError> {
        let mut sorted = records.to_vec();
        sorted.sort_unstable();
        let count = u32::try_from(sorted.len())
            .map_err(|_| CryptoError::MacInputTooLong { len: sorted.len() })?;
        let lengths = sorted
            .iter()
            .map(|record| {
                u32::try_from(record.len())
                    .map(u32::to_be_bytes)
                    .map_err(|_| CryptoError::MacInputTooLong { len: record.len() })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut header = [0_u8; 20];
        header[..2].copy_from_slice(&WRAPPER_SET_MAC_VERSION.to_be_bytes());
        header[2..4].copy_from_slice(&MAC_HMAC_SHA256.to_be_bytes());
        header[4..8].copy_from_slice(&household_key_version.to_be_bytes());
        header[8..16].copy_from_slice(&counter.to_be_bytes());
        header[16..].copy_from_slice(&count.to_be_bytes());
        Ok(Self {
            header,
            lengths,
            records: sorted,
        })
    }

    fn parts(&self) -> Vec<&[u8]> {
        let mut parts: Vec<&[u8]> = Vec::with_capacity(3 + 2 * self.records.len());
        parts.extend(SET_MAC_DOMAIN.encoded());
        parts.push(&self.header);
        for (len, record) in self.lengths.iter().zip(&self.records) {
            parts.push(len);
            parts.push(record);
        }
        parts
    }
}

impl WrapperSetKey {
    pub(crate) fn from_key(key: SymmetricKey, household_key_version: u32) -> Self {
        Self {
            key,
            household_key_version,
        }
    }

    /// The version of the household key this set key derives from.
    pub fn household_key_version(&self) -> u32 {
        self.household_key_version
    }

    /// The MAC of the record set `records` at `counter`, each record in the encoding the store
    /// gives it; the order of `records` does not matter, and a record longer than `u32::MAX`
    /// bytes, or more than `u32::MAX` records, are refused ([`CryptoError::MacInputTooLong`]).
    pub fn seal(&self, counter: u64, records: &[&[u8]]) -> Result<WrapperSetMac, CryptoError> {
        let input = MacInput::new(self.household_key_version, counter, records)?;
        let tag = self
            .key
            .slot()
            .with_key(|key| aws_lc::hmac_sha256(key, &input.parts()))?;
        Ok(WrapperSetMac {
            household_key_version: self.household_key_version,
            tag,
        })
    }

    /// Checks that `mac` is the MAC of `records` at `counter` under this key, in constant time:
    /// [`CryptoError::HouseholdKeyVersion`] when `mac` states another household key version, and
    /// [`CryptoError::Mac`] when the counter, a record, or the tag differs, a record is missing or
    /// one was added.
    pub fn verify(
        &self,
        mac: &WrapperSetMac,
        counter: u64,
        records: &[&[u8]],
    ) -> Result<(), CryptoError> {
        if mac.household_key_version != self.household_key_version {
            return Err(CryptoError::HouseholdKeyVersion {
                stated: mac.household_key_version,
                held: self.household_key_version,
            });
        }
        let input = MacInput::new(self.household_key_version, counter, records)?;
        self.key
            .slot()
            .with_key(|key| aws_lc::verify_hmac_sha256(key, &input.parts(), &mac.tag))?
            .map_err(|_| CryptoError::Mac)
    }
}

impl WrapperSetMac {
    /// The household key version whose set key computed this MAC.
    pub fn household_key_version(&self) -> u32 {
        self.household_key_version
    }

    /// The stored form: format version, algorithm identifier, household key version and tag, the
    /// integers big-endian.
    pub fn to_bytes(&self) -> [u8; WRAPPER_SET_MAC_LEN] {
        let mut bytes = [0_u8; WRAPPER_SET_MAC_LEN];
        bytes[..2].copy_from_slice(&WRAPPER_SET_MAC_VERSION.to_be_bytes());
        bytes[2..4].copy_from_slice(&MAC_HMAC_SHA256.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.household_key_version.to_be_bytes());
        bytes[8..].copy_from_slice(&self.tag);
        bytes
    }

    /// Reads a MAC stored by [`to_bytes`](Self::to_bytes). Another format version or algorithm
    /// identifier, a truncated value and trailing bytes are refused, never read another way.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WrapperError> {
        let field = |range: std::ops::Range<usize>| bytes.get(range).ok_or(WrapperError::Truncated);
        let version = u16::from_be_bytes([field(0..1)?[0], field(1..2)?[0]]);
        if version < WRAPPER_SET_MAC_VERSION {
            return Err(WrapperError::OlderThanAccepted { version });
        }
        if version > WRAPPER_SET_MAC_VERSION {
            return Err(WrapperError::UnknownVersion { version });
        }
        let algorithm = u16::from_be_bytes([field(2..3)?[0], field(3..4)?[0]]);
        if algorithm != MAC_HMAC_SHA256 {
            return Err(WrapperError::UnknownMacAlgorithm { id: algorithm });
        }
        let mut version_bytes = [0_u8; 4];
        version_bytes.copy_from_slice(field(4..8)?);
        let mut tag = [0_u8; HMAC_SHA256_LEN];
        tag.copy_from_slice(field(8..WRAPPER_SET_MAC_LEN)?);
        if bytes.len() > WRAPPER_SET_MAC_LEN {
            return Err(WrapperError::TrailingBytes);
        }
        Ok(Self {
            household_key_version: u32::from_be_bytes(version_bytes),
            tag,
        })
    }
}

#[cfg(test)]
mod tests;
