//! Versioned key wrappers (spine AD-18, `doc/key-management.md` section 9).
//!
//! A wrapper is one key sealed with AES-256-GCM under a key encryption key (KEK), with what is
//! needed to obtain that KEK again and to refuse what this Core does not know. The crate
//! documentation lays out its encoding, and `the_encoding_is_the_documented_layout` holds the
//! encoder to that table.

use vilicus_types::{Id, UtcMillis};

use crate::aws_lc::{self, NONCE_LEN, TAG_LEN};
use crate::derive::Label;
use crate::error::{CryptoError, WrapperError};
use crate::key::{KEY_LEN, Slot, SymmetricKey};

/// The format version this Core writes.
pub const FORMAT_VERSION: u16 = 1;

/// The oldest format version this Core reads; an older wrapper is refused as a downgrade.
pub const OLDEST_ACCEPTED_FORMAT_VERSION: u16 = 1;

/// The longest salt or credential reference a wrapper holds: 1023 bytes, the longest credential
/// id WebAuthn allows.
pub const MAX_KEK_REFERENCE_LEN: usize = 1023;

/// The Argon2 version of the suite's Argon2id, 0x13 (RFC 9106).
pub const ARGON2_VERSION: u32 = 0x13;

const KDF_NONE: u16 = 0x0001;
const KDF_ARGON2ID: u16 = 0x0002;
const KEK_DIRECT: u16 = 0x0001;
const KEK_HKDF_SHA256: u16 = 0x0002;
const AEAD_AES_256_GCM: u16 = 0x0001;

/// How the secret behind the KEK was stretched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Kdf {
    /// No stretching: the KEK comes from a key, not from a secret a person types.
    None,
    /// Argon2id, version [`ARGON2_VERSION`], with its cost parameters; the salt is the wrapper's
    /// [`kek_reference`](Wrapper::kek_reference).
    Argon2id(Argon2idParams),
}

impl Kdf {
    /// The identifier written in a wrapper.
    pub const fn id(self) -> u16 {
        match self {
            Self::None => KDF_NONE,
            Self::Argon2id(_) => KDF_ARGON2ID,
        }
    }
}

/// The cost parameters of an Argon2id KDF, as RFC 9106 names them. A wrapper carries them as
/// they were used; which costs the Core accepts is the passphrase path's to check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2idParams {
    /// m, the memory size in KiB.
    pub memory_kib: u32,
    /// t, the number of passes.
    pub passes: u32,
    /// p, the number of lanes.
    pub lanes: u32,
}

/// How the KEK was obtained from the KDF output, or from the key it derives from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KekDerivation {
    /// The KDF output, or the key, is the KEK.
    Direct,
    /// The KEK is derived by HKDF-SHA-256 under a versioned label (see
    /// the derivations of the key hierarchy).
    HkdfSha256,
}

impl KekDerivation {
    /// The identifier written in a wrapper.
    pub const fn id(self) -> u16 {
        match self {
            Self::Direct => KEK_DIRECT,
            Self::HkdfSha256 => KEK_HKDF_SHA256,
        }
    }
}

/// The AEAD that seals the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Aead {
    /// AES-256-GCM with a random 96-bit nonce and a 128-bit tag.
    Aes256Gcm,
}

impl Aead {
    /// The identifier written in a wrapper.
    pub const fn id(self) -> u16 {
        match self {
            Self::Aes256Gcm => AEAD_AES_256_GCM,
        }
    }
}

/// What a new wrapper states besides the sealed key: how its KEK was obtained, the salt or
/// credential reference needed to obtain it again, its creation time and its id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrapParams {
    kdf: Kdf,
    kek_derivation: KekDerivation,
    kek_reference: Vec<u8>,
    created_at: UtcMillis,
    id: Id,
}

impl WrapParams {
    /// The parameters of a new wrapper: how the secret behind its KEK was stretched (`kdf`), how
    /// the KEK was obtained from that output or its parent key (`kek_derivation`), the salt of
    /// the KDF or the reference of the credential the KEK is recomputed from, empty when there is
    /// neither (`kek_reference`, at most [`MAX_KEK_REFERENCE_LEN`] bytes), when the wrapper is
    /// made and its id.
    pub fn new(
        kdf: Kdf,
        kek_derivation: KekDerivation,
        kek_reference: Vec<u8>,
        created_at: UtcMillis,
        id: Id,
    ) -> Result<Self, CryptoError> {
        let len = kek_reference.len();
        if len > MAX_KEK_REFERENCE_LEN {
            return Err(CryptoError::KekReferenceTooLong { len });
        }
        Ok(Self {
            kdf,
            kek_derivation,
            kek_reference,
            created_at,
            id,
        })
    }
}

/// A key wrapped under a KEK, with its format version and algorithm identifiers.
///
/// Made by [`wrap_key`](Self::wrap_key), read back by [`from_bytes`](Self::from_bytes), opened by
/// [`unwrap_key`](Self::unwrap_key). The additional data binds the whole header, the purpose of
/// the wrap, a [`Label`], and a context the caller chooses, such as the member it belongs to: a
/// wrapper opens only for the purpose and the record it was made for.
///
/// ```
/// use vilicus_crypto::{Kdf, KekDerivation, Label, SymmetricKey, WrapParams, Wrapper, label};
/// use vilicus_types::{Id, UtcMillis};
///
/// const MEMBER_PRIVATE_KEY: Label = label!("vilicus/v1/wrap/member-private-key");
/// const INBOX_PRIVATE_KEY: Label = label!("vilicus/v1/wrap/inbox-private-key");
/// # vilicus_crypto::harden_process()?;
/// # vilicus_crypto::lock_key_memory()?;
/// let kek = SymmetricKey::generate()?;
/// let private_key = SymmetricKey::generate()?;
/// let created_at = UtcMillis::from_millis(1_793_577_600_000)?;
/// let id = Id::new_v7(created_at, [7; 10])?;
/// let params = WrapParams::new(Kdf::None, KekDerivation::Direct, Vec::new(), created_at, id)?;
/// let stored =
///     Wrapper::wrap_key(&kek, &private_key, MEMBER_PRIVATE_KEY, params, b"member 1")?.to_bytes();
///
/// let wrapper = Wrapper::from_bytes(&stored)?;
/// let opened = wrapper.unwrap_key(&kek, MEMBER_PRIVATE_KEY, b"member 1")?;
/// assert!(wrapper.unwrap_key(&kek, MEMBER_PRIVATE_KEY, b"member 2").is_err());
/// assert!(wrapper.unwrap_key(&kek, INBOX_PRIVATE_KEY, b"member 1").is_err());
/// # drop(opened);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wrapper {
    version: u16,
    kdf: Kdf,
    kek_derivation: KekDerivation,
    aead: Aead,
    kek_reference: Vec<u8>,
    created_at: UtcMillis,
    id: Id,
    nonce: [u8; NONCE_LEN],
    ciphertext: [u8; KEY_LEN],
    tag: [u8; TAG_LEN],
}

impl Wrapper {
    /// Wraps `key` under `kek` with AES-256-GCM and a nonce drawn from the CSPRNG of aws-lc-rs,
    /// in the current format version. `purpose` names what the key is for and `context` the
    /// record it belongs to; both join the additional data and must be given again to open the
    /// wrapper. An empty context is refused ([`CryptoError::EmptyContext`]): two wrappers of one
    /// purpose under one KEK would otherwise open in each other's place.
    pub fn wrap_key(
        kek: &SymmetricKey,
        key: &SymmetricKey,
        purpose: Label,
        params: WrapParams,
        context: &[u8],
    ) -> Result<Self, CryptoError> {
        let mut nonce = [0; NONCE_LEN];
        aws_lc::fill_random(&mut nonce).map_err(|_| CryptoError::Random)?;
        Self::wrap_key_with_nonce(kek, key, purpose, params, nonce, context)
    }

    /// [`wrap_key`](Self::wrap_key) with a given nonce, for the tests that pin the encoding.
    pub(crate) fn wrap_key_with_nonce(
        kek: &SymmetricKey,
        key: &SymmetricKey,
        purpose: Label,
        params: WrapParams,
        nonce: [u8; NONCE_LEN],
        context: &[u8],
    ) -> Result<Self, CryptoError> {
        let mut wrapper = Self {
            version: FORMAT_VERSION,
            kdf: params.kdf,
            kek_derivation: params.kek_derivation,
            aead: Aead::Aes256Gcm,
            kek_reference: params.kek_reference,
            created_at: params.created_at,
            id: params.id,
            nonce,
            ciphertext: [0; KEY_LEN],
            tag: [0; TAG_LEN],
        };
        let additional_data = wrapper.additional_data(purpose, context)?;
        // The key is copied into a buffer the crate wipes and sealed there, so a failed seal
        // leaves no plaintext copy behind.
        let mut sealed = Slot::new()?;
        // Each guarded call fails once the pool is wiped (`CryptoError::KeyMemory`), so a KEK
        // wiped during the seal never yields a wrapper.
        sealed.with_key_mut(|out| key.slot().with_key(|bytes| out.copy_from_slice(bytes)))??;
        let tag = kek
            .slot()
            .with_key(|kek| {
                sealed.with_key_mut(|in_out| {
                    aws_lc::seal_aes_256_gcm(kek, nonce, &additional_data, in_out)
                })
            })??
            .map_err(|_| CryptoError::Seal)?;
        sealed.with_key(|bytes| wrapper.ciphertext.copy_from_slice(bytes))?;
        wrapper.tag = tag;
        Ok(wrapper)
    }

    /// Opens the wrapper with `kek` and the `purpose` and `context` it was wrapped with, into a
    /// new key. A wrong KEK, another purpose or context, or an edited wrapper is
    /// [`CryptoError::Open`], and the buffer the open wrote into is wiped.
    pub fn unwrap_key(
        &self,
        kek: &SymmetricKey,
        purpose: Label,
        context: &[u8],
    ) -> Result<SymmetricKey, CryptoError> {
        let additional_data = self.additional_data(purpose, context)?;
        let mut opened = Slot::new()?;
        kek.slot()
            .with_key(|kek| {
                opened.with_key_mut(|out| {
                    aws_lc::open_aes_256_gcm(
                        kek,
                        self.nonce,
                        &additional_data,
                        &self.ciphertext,
                        &self.tag,
                        out,
                    )
                })
            })??
            .map_err(|_| CryptoError::Open)?;
        Ok(SymmetricKey::from_slot(opened))
    }

    /// The stored form: the header, then the ciphertext and the tag, laid out as the crate
    /// documentation's table states.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header();
        bytes.extend_from_slice(&self.ciphertext);
        bytes.extend_from_slice(&self.tag);
        bytes
    }

    /// Reads a wrapper encoded by [`to_bytes`](Self::to_bytes). A format version older than
    /// [`OLDEST_ACCEPTED_FORMAT_VERSION`] or newer than [`FORMAT_VERSION`], an algorithm
    /// identifier the version does not define, and any malformed field are refused, never read
    /// another way.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WrapperError> {
        let mut reader = Reader(bytes);
        let version = reader.u16()?;
        if version < OLDEST_ACCEPTED_FORMAT_VERSION {
            return Err(WrapperError::OlderThanAccepted { version });
        }
        if version > FORMAT_VERSION {
            return Err(WrapperError::UnknownVersion { version });
        }
        let kdf_id = reader.u16()?;
        let kek_derivation = match reader.u16()? {
            KEK_DIRECT => KekDerivation::Direct,
            KEK_HKDF_SHA256 => KekDerivation::HkdfSha256,
            id => return Err(WrapperError::UnknownKekDerivation { id }),
        };
        let aead = match reader.u16()? {
            AEAD_AES_256_GCM => Aead::Aes256Gcm,
            id => return Err(WrapperError::UnknownAead { id }),
        };
        let kdf = match kdf_id {
            KDF_NONE => Kdf::None,
            KDF_ARGON2ID => {
                let argon2_version = reader.u32()?;
                if argon2_version != ARGON2_VERSION {
                    return Err(WrapperError::UnknownArgon2Version {
                        version: argon2_version,
                    });
                }
                Kdf::Argon2id(Argon2idParams {
                    memory_kib: reader.u32()?,
                    passes: reader.u32()?,
                    lanes: reader.u32()?,
                })
            }
            id => return Err(WrapperError::UnknownKdf { id }),
        };
        let len = usize::from(reader.u16()?);
        if len > MAX_KEK_REFERENCE_LEN {
            return Err(WrapperError::KekReferenceTooLong { len });
        }
        let kek_reference = reader.take(len)?.to_vec();
        let created_at = UtcMillis::from_millis(i64::from_be_bytes(reader.array()?))
            .map_err(|_| WrapperError::InvalidCreationTime)?;
        let id = Id::from_bytes(reader.array()?).map_err(|_| WrapperError::InvalidId)?;
        let nonce = reader.array()?;
        let ciphertext = reader.array()?;
        let tag = reader.array()?;
        if !reader.0.is_empty() {
            return Err(WrapperError::TrailingBytes);
        }
        Ok(Self {
            version,
            kdf,
            kek_derivation,
            aead,
            kek_reference,
            created_at,
            id,
            nonce,
            ciphertext,
            tag,
        })
    }

    /// The format version.
    pub fn version(&self) -> u16 {
        self.version
    }

    /// How the secret behind the KEK was stretched.
    pub fn kdf(&self) -> Kdf {
        self.kdf
    }

    /// How the KEK was obtained from the KDF output or its parent key.
    pub fn kek_derivation(&self) -> KekDerivation {
        self.kek_derivation
    }

    /// The AEAD that sealed the key.
    pub fn aead(&self) -> Aead {
        self.aead
    }

    /// The salt or credential reference the KEK is obtained again with; empty when there is
    /// neither.
    pub fn kek_reference(&self) -> &[u8] {
        &self.kek_reference
    }

    /// When the wrapper was made.
    pub fn created_at(&self) -> UtcMillis {
        self.created_at
    }

    /// The wrapper's id.
    pub fn id(&self) -> Id {
        self.id
    }

    /// Every field before the ciphertext, encoded.
    fn header(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64 + self.kek_reference.len() + KEY_LEN + TAG_LEN);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&self.kdf.id().to_be_bytes());
        bytes.extend_from_slice(&self.kek_derivation.id().to_be_bytes());
        bytes.extend_from_slice(&self.aead.id().to_be_bytes());
        if let Kdf::Argon2id(params) = self.kdf {
            for value in [
                ARGON2_VERSION,
                params.memory_kib,
                params.passes,
                params.lanes,
            ] {
                bytes.extend_from_slice(&value.to_be_bytes());
            }
        }
        // At most MAX_KEK_REFERENCE_LEN, below u16::MAX: WrapParams::new and from_bytes check it.
        bytes.extend_from_slice(&(self.kek_reference.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.kek_reference);
        bytes.extend_from_slice(&self.created_at.as_millis().to_be_bytes());
        bytes.extend_from_slice(&self.id.to_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes
    }

    /// The header, the purpose's label and its end byte, then the context, which must not be
    /// empty.
    fn additional_data(&self, purpose: Label, context: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if context.is_empty() {
            return Err(CryptoError::EmptyContext);
        }
        let mut additional_data = self.header();
        for part in purpose.encoded() {
            additional_data.extend_from_slice(part);
        }
        additional_data.extend_from_slice(context);
        Ok(additional_data)
    }
}

/// The unread rest of an encoding.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], WrapperError> {
        let Some((taken, rest)) = self.0.split_at_checked(len) else {
            return Err(WrapperError::Truncated);
        };
        self.0 = rest;
        Ok(taken)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], WrapperError> {
        let mut array = [0; N];
        array.copy_from_slice(self.take(N)?);
        Ok(array)
    }

    fn u16(&mut self) -> Result<u16, WrapperError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, WrapperError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
}

#[cfg(test)]
mod tests;
