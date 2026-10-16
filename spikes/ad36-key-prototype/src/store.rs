//! Flat binary stand-in for `wrappers.db`.
//!
//! File: `magic "VLCW" || format_version u8 || record_count u16 BE || records`.
//! Record: the fields of [`Field::ORDER`], each `len u16 BE || bytes`, an empty field
//! meaning absent. Trailing bytes are refused. The file is not authenticated as a whole:
//! the construction must hold against any edit of it.

use std::fs;
use std::path::Path;

use crate::encoding::{
    EnrollKeyWrap, FORMAT_VERSION, HkWrap, PubkeyMac, Tagged32, alg, put_length_prefixed,
};
use crate::error::Error;

const MAGIC: &[u8; 4] = b"VLCW";
/// Longest member identifier the store accepts.
pub const MAX_MEMBER_ID_LEN: usize = 255;

/// The fields of a member record, in their stored order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    /// Member identifier, raw bytes.
    MemberId,
    /// Token check hash, until the token is used.
    TokenCheck,
    /// Enrollment authentication key wrapped under a key derived from HK, until HK is wrapped.
    EnrollKeyWrap,
    /// Member public key.
    MemberPublicKey,
    /// Personal inbox public key.
    InboxPublicKey,
    /// Enrollment tag, until HK is wrapped.
    EnrollTag,
    /// Permanent public key MAC.
    PubkeyMac,
    /// HK sealed to the member public key.
    HkWrap,
}

impl Field {
    /// Stored order of the fields in a record.
    pub const ORDER: [Field; 8] = [
        Field::MemberId,
        Field::TokenCheck,
        Field::EnrollKeyWrap,
        Field::MemberPublicKey,
        Field::InboxPublicKey,
        Field::EnrollTag,
        Field::PubkeyMac,
        Field::HkWrap,
    ];

    /// Length of the field's stored encoding when present; `None` for the variable-length
    /// member identifier.
    pub fn encoded_len(self) -> Option<usize> {
        match self {
            Field::MemberId => None,
            Field::TokenCheck
            | Field::MemberPublicKey
            | Field::InboxPublicKey
            | Field::EnrollTag => Some(Tagged32::ENCODED_LEN),
            Field::EnrollKeyWrap => Some(EnrollKeyWrap::ENCODED_LEN),
            Field::PubkeyMac => Some(PubkeyMac::ENCODED_LEN),
            Field::HkWrap => Some(HkWrap::ENCODED_LEN),
        }
    }
}

/// Where a member stands in the ceremony, derived from which fields are present.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberState {
    /// `member_add` ran; the token has not been used.
    AwaitingEnrollment,
    /// Enrollment ran; the next adult unlock verifies the tag and wraps HK.
    AwaitingHouseholdKey,
    /// The permanent MAC is written and HK is wrapped.
    Active,
    /// No legitimate step produces this combination of fields.
    Inconsistent,
}

/// One member's record in `wrappers.db`.
#[derive(Clone)]
pub struct MemberRecord {
    pub(crate) member_id: Vec<u8>,
    pub(crate) token_check: Option<Tagged32>,
    pub(crate) enroll_key_wrap: Option<EnrollKeyWrap>,
    pub(crate) member_pk: Option<Tagged32>,
    pub(crate) inbox_pk: Option<Tagged32>,
    pub(crate) enroll_tag: Option<Tagged32>,
    pub(crate) pubkey_mac: Option<PubkeyMac>,
    pub(crate) hk_wrap: Option<HkWrap>,
}

impl MemberRecord {
    pub(crate) fn new(member_id: &[u8]) -> Self {
        Self {
            member_id: member_id.to_vec(),
            token_check: None,
            enroll_key_wrap: None,
            member_pk: None,
            inbox_pk: None,
            enroll_tag: None,
            pubkey_mac: None,
            hk_wrap: None,
        }
    }

    /// The member identifier.
    pub fn member_id(&self) -> &[u8] {
        &self.member_id
    }

    /// The ceremony state implied by the fields present.
    pub fn state(&self) -> MemberState {
        let present = (
            self.token_check.is_some(),
            self.enroll_key_wrap.is_some(),
            self.member_pk.is_some(),
            self.inbox_pk.is_some(),
            self.enroll_tag.is_some(),
            self.pubkey_mac.is_some(),
            self.hk_wrap.is_some(),
        );
        match present {
            (true, true, false, false, false, false, false) => MemberState::AwaitingEnrollment,
            (false, true, true, true, true, false, false) => MemberState::AwaitingHouseholdKey,
            (false, false, true, true, false, true, true) => MemberState::Active,
            _ => MemberState::Inconsistent,
        }
    }

    /// The stored encoding of one field, `None` when absent. Public values only: no
    /// field holds a key in clear.
    pub fn encoded_field(&self, field: Field) -> Option<Vec<u8>> {
        match field {
            Field::MemberId => Some(self.member_id.clone()),
            Field::TokenCheck => self.token_check.as_ref().map(Tagged32::encode),
            Field::EnrollKeyWrap => self.enroll_key_wrap.as_ref().map(EnrollKeyWrap::encode),
            Field::MemberPublicKey => self.member_pk.as_ref().map(Tagged32::encode),
            Field::InboxPublicKey => self.inbox_pk.as_ref().map(Tagged32::encode),
            Field::EnrollTag => self.enroll_tag.as_ref().map(Tagged32::encode),
            Field::PubkeyMac => self.pubkey_mac.as_ref().map(PubkeyMac::encode),
            Field::HkWrap => self.hk_wrap.as_ref().map(HkWrap::encode),
        }
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        for field in Field::ORDER {
            put_length_prefixed(out, &self.encoded_field(field).unwrap_or_default())?;
        }
        Ok(())
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, Error> {
        let member_id = reader.length_prefixed()?;
        check_member_id(member_id)?;
        let mut record = Self::new(member_id);
        for field in &Field::ORDER[1..] {
            let bytes = reader.length_prefixed()?;
            if bytes.is_empty() {
                continue;
            }
            match field {
                Field::MemberId => unreachable!("the member identifier is read first"),
                Field::TokenCheck => {
                    record.token_check =
                        Some(Tagged32::decode(bytes, alg::TOKEN_CHECK_HKDF_SHA256)?);
                }
                Field::EnrollKeyWrap => {
                    record.enroll_key_wrap = Some(EnrollKeyWrap::decode(bytes)?)
                }
                Field::MemberPublicKey => {
                    record.member_pk = Some(Tagged32::decode(bytes, alg::PUBLIC_KEY_X25519)?);
                }
                Field::InboxPublicKey => {
                    record.inbox_pk = Some(Tagged32::decode(bytes, alg::PUBLIC_KEY_X25519)?);
                }
                Field::EnrollTag => {
                    record.enroll_tag =
                        Some(Tagged32::decode(bytes, alg::MAC_HMAC_SHA256_HKDF_SHA256)?);
                }
                Field::PubkeyMac => record.pubkey_mac = Some(PubkeyMac::decode(bytes)?),
                Field::HkWrap => record.hk_wrap = Some(HkWrap::decode(bytes)?),
            }
        }
        Ok(record)
    }
}

pub(crate) fn check_member_id(member_id: &[u8]) -> Result<(), Error> {
    if member_id.is_empty() || member_id.len() > MAX_MEMBER_ID_LEN {
        return Err(Error::InvalidMemberId);
    }
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        if self.bytes.len() < len {
            return Err(Error::MalformedStore("truncated"));
        }
        let (head, tail) = self.bytes.split_at(len);
        self.bytes = tail;
        Ok(head)
    }

    fn u16(&mut self) -> Result<u16, Error> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn length_prefixed(&mut self) -> Result<&'a [u8], Error> {
        let len = self.u16()?;
        self.take(usize::from(len))
    }
}

/// The whole `wrappers.db`: every member record.
#[derive(Clone)]
pub struct Store {
    pub(crate) members: Vec<MemberRecord>,
}

impl Store {
    pub(crate) fn empty() -> Self {
        Self {
            members: Vec::new(),
        }
    }

    /// Reads and parses `wrappers.db`. Any unexpected byte is an error, never repaired.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let bytes = fs::read(path)?;
        let mut reader = Reader { bytes: &bytes };
        if reader.take(MAGIC.len())? != MAGIC {
            return Err(Error::MalformedStore("bad magic"));
        }
        if reader.take(1)? != [FORMAT_VERSION] {
            return Err(Error::UnsupportedFormat);
        }
        let count = reader.u16()?;
        let mut members = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let record = MemberRecord::decode(&mut reader)?;
            if members
                .iter()
                .any(|known: &MemberRecord| known.member_id == record.member_id)
            {
                return Err(Error::MalformedStore("duplicate member identifier"));
            }
            members.push(record);
        }
        if !reader.bytes.is_empty() {
            return Err(Error::MalformedStore("trailing bytes"));
        }
        Ok(Self { members })
    }

    /// Writes the store to a sibling temporary file, then renames it over `path`.
    pub(crate) fn save(&self, path: &Path) -> Result<(), Error> {
        let bytes = self.encode()?;
        let temporary = path.with_extension("db.tmp");
        fs::write(&temporary, &bytes)?;
        fs::rename(&temporary, path)?;
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(FORMAT_VERSION);
        let count = u16::try_from(self.members.len())
            .map_err(|_| Error::MalformedStore("too many members"))?;
        bytes.extend_from_slice(&count.to_be_bytes());
        for record in &self.members {
            record.encode(&mut bytes)?;
        }
        Ok(bytes)
    }

    /// The record of `member_id`, if any.
    pub fn member(&self, member_id: &[u8]) -> Option<&MemberRecord> {
        self.members
            .iter()
            .find(|record| record.member_id == member_id)
    }

    pub(crate) fn member_mut(&mut self, member_id: &[u8]) -> Option<&mut MemberRecord> {
        self.members
            .iter_mut()
            .find(|record| record.member_id == member_id)
    }
}
