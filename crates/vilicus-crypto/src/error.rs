//! The errors of the crate: a refused key operation, and a refused wrapper encoding.

use core::fmt;

/// A key operation that did not complete. No variant carries key material or says more than
/// which step failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// The CSPRNG of aws-lc-rs failed to fill a key or a nonce.
    Random,
    /// AES-256-GCM refused to seal.
    Seal,
    /// The wrapper did not open: a wrong key encryption key, another context, or a wrapper whose
    /// bytes were changed. AES-256-GCM does not tell these apart, and neither does this error.
    Open,
    /// HKDF-SHA-256 refused to derive.
    Derive,
    /// The salt or credential reference given to a new wrapper is longer than
    /// [`MAX_KEK_REFERENCE_LEN`](crate::MAX_KEK_REFERENCE_LEN).
    KekReferenceTooLong {
        /// Its length in bytes.
        len: usize,
    },
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Random => formatter.write_str("the CSPRNG failed"),
            Self::Seal => formatter.write_str("the wrap could not be sealed"),
            Self::Open => formatter.write_str("the wrapper did not open"),
            Self::Derive => formatter.write_str("the key could not be derived"),
            Self::KekReferenceTooLong { len } => {
                write!(
                    formatter,
                    "salt or credential reference of {len} bytes is too long"
                )
            }
        }
    }
}

impl std::error::Error for CryptoError {}

/// A refused wrapper encoding. A refused wrapper is never repaired, read under another version or
/// opened with other algorithms than it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrapperError {
    /// The bytes end before the wrapper does.
    Truncated,
    /// Bytes follow the end of the wrapper.
    TrailingBytes,
    /// The format version is older than
    /// [`OLDEST_ACCEPTED_FORMAT_VERSION`](crate::OLDEST_ACCEPTED_FORMAT_VERSION): a downgrade.
    OlderThanAccepted {
        /// The version the bytes state.
        version: u16,
    },
    /// The format version is newer than [`FORMAT_VERSION`](crate::FORMAT_VERSION).
    UnknownVersion {
        /// The version the bytes state.
        version: u16,
    },
    /// The KDF identifier names no KDF of the format version.
    UnknownKdf {
        /// The identifier the bytes state.
        id: u16,
    },
    /// The KEK derivation identifier names no derivation of the format version.
    UnknownKekDerivation {
        /// The identifier the bytes state.
        id: u16,
    },
    /// The AEAD identifier names no AEAD of the format version.
    UnknownAead {
        /// The identifier the bytes state.
        id: u16,
    },
    /// The Argon2 version of an Argon2id KDF is not 0x13, the one the suite uses.
    UnknownArgon2Version {
        /// The version the bytes state.
        version: u32,
    },
    /// The salt or credential reference is longer than
    /// [`MAX_KEK_REFERENCE_LEN`](crate::MAX_KEK_REFERENCE_LEN).
    KekReferenceTooLong {
        /// The length the bytes state.
        len: usize,
    },
    /// The creation time is outside the instants `vilicus_types::UtcMillis` holds.
    InvalidCreationTime,
    /// The wrapper id is not a UUIDv7.
    InvalidId,
}

impl fmt::Display for WrapperError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => formatter.write_str("wrapper truncated"),
            Self::TrailingBytes => formatter.write_str("bytes after the end of the wrapper"),
            Self::OlderThanAccepted { version } => {
                write!(
                    formatter,
                    "wrapper format version {version} is older than accepted"
                )
            }
            Self::UnknownVersion { version } => {
                write!(formatter, "unknown wrapper format version {version}")
            }
            Self::UnknownKdf { id } => write!(formatter, "unknown KDF identifier {id:#06x}"),
            Self::UnknownKekDerivation { id } => {
                write!(formatter, "unknown KEK derivation identifier {id:#06x}")
            }
            Self::UnknownAead { id } => write!(formatter, "unknown AEAD identifier {id:#06x}"),
            Self::UnknownArgon2Version { version } => {
                write!(formatter, "unknown Argon2 version {version:#x}")
            }
            Self::KekReferenceTooLong { len } => {
                write!(
                    formatter,
                    "salt or credential reference of {len} bytes is too long"
                )
            }
            Self::InvalidCreationTime => formatter.write_str("wrapper creation time out of range"),
            Self::InvalidId => formatter.write_str("wrapper id is not a UUIDv7"),
        }
    }
}

impl std::error::Error for WrapperError {}
