//! The errors of the crate: a refused key operation, a refused wrapper encoding, and key memory
//! that could not be set up or handed out.

use core::fmt;

/// A key operation that did not complete. No variant carries key material or says more than
/// which step failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
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
    /// A part of a derivation's context is longer than `u16::MAX` bytes, the most its length
    /// prefix holds.
    ContextPartTooLong {
        /// Its length in bytes.
        len: usize,
    },
    /// A wrapper was made or opened with an empty context, which would let two wrappers of one
    /// purpose under one KEK open in each other's place.
    EmptyContext,
    /// The salt or credential reference given to a new wrapper is longer than
    /// [`MAX_KEK_REFERENCE_LEN`](crate::MAX_KEK_REFERENCE_LEN).
    KekReferenceTooLong {
        /// Its length in bytes.
        len: usize,
    },
    /// The key pool gave no slot for the key or for a working buffer of the operation.
    KeyMemory(KeyMemoryError),
    /// A key's credential file could not be opened or read.
    Credential {
        /// The `errno` of the failed call, 0 when the system gave none.
        errno: i32,
    },
    /// A key's credential file does not hold exactly one 256-bit key.
    CredentialLength,
    /// A record of a MAC's input is longer than `u32::MAX` bytes, or the input holds more than
    /// `u32::MAX` records: the most their `u32` length or count holds.
    MacInputTooLong {
        /// The length or the count.
        len: usize,
    },
    /// A MAC did not verify: the authenticated bytes, the key or the tag differ from those it was
    /// computed with. The check does not tell these apart, and neither does this error.
    Mac,
    /// A MAC states another household key version than the key it is checked with.
    HouseholdKeyVersion {
        /// The version the MAC states.
        stated: u32,
        /// The version of the key it is checked with.
        held: u32,
    },
}

impl From<KeyMemoryError> for CryptoError {
    fn from(error: KeyMemoryError) -> Self {
        Self::KeyMemory(error)
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Random => formatter.write_str("the CSPRNG failed"),
            Self::Seal => formatter.write_str("the wrap could not be sealed"),
            Self::Open => formatter.write_str("the wrapper did not open"),
            Self::Derive => formatter.write_str("the key could not be derived"),
            Self::ContextPartTooLong { len } => {
                write!(
                    formatter,
                    "derivation context part of {len} bytes is too long"
                )
            }
            Self::EmptyContext => formatter.write_str("a wrapper's context is empty"),
            Self::KekReferenceTooLong { len } => {
                write!(
                    formatter,
                    "salt or credential reference of {len} bytes is too long"
                )
            }
            Self::KeyMemory(error) => write!(formatter, "{error}"),
            Self::Credential { errno } => {
                write!(
                    formatter,
                    "the key's credential could not be read (errno {errno})"
                )
            }
            Self::CredentialLength => {
                formatter.write_str("the key's credential does not hold exactly one 256-bit key")
            }
            Self::MacInputTooLong { len } => {
                write!(
                    formatter,
                    "MAC input part or record count of {len} is too long"
                )
            }
            Self::Mac => formatter.write_str("the MAC did not verify"),
            Self::HouseholdKeyVersion { stated, held } => write!(
                formatter,
                "the MAC states household key version {stated}, the key is version {held}"
            ),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Key memory that could not be set up at the Core's start, or a slot the pool could not hand
/// out (spine AD-4, D131). Each start error stops the Core: none is answered by keeping keys
/// in unlocked memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyMemoryError {
    /// `PR_SET_DUMPABLE` 0, `RLIMIT_CORE` 0 or reading them back failed.
    Harden {
        /// The `errno` of the failed call.
        errno: i32,
    },
    /// The key pool was asked for in a process that is still dumpable or may write a core file:
    /// [`harden_process`](crate::harden_process) comes first.
    NotHardened,
    /// The process holds `CAP_IPC_LOCK`, which the Core's unit never grants: with it,
    /// `LimitMEMLOCK` bounds nothing.
    CapIpcLock,
    /// `/proc/self/status` could not be read or did not hold the field asked for.
    ProcessStatus {
        /// The `errno` of the failed read, 0 for a missing or unreadable field.
        errno: i32,
    },
    /// Mapping the pool or protecting its guard pages failed.
    Map {
        /// The `errno` of the failed call.
        errno: i32,
    },
    /// An `madvise` of the pool failed.
    Advise {
        /// The advice refused.
        advice: &'static str,
        /// The `errno` of the failed call.
        errno: i32,
    },
    /// `mlock` refused the pool: the Core's `LimitMEMLOCK` is below the pool's size.
    Lock {
        /// The pool's size in bytes, what `mlock` was asked to lock.
        bytes: usize,
        /// The `errno` of the failed call.
        errno: i32,
    },
    /// The process already has its key pool.
    AlreadyLocked,
    /// Blocking SIGTERM, opening its signalfd or starting the thread that takes it failed.
    Sigterm {
        /// The error number of the failed call.
        errno: i32,
    },
    /// SIGTERM was to be blocked while other threads run, which would still receive it.
    ThreadsRunning {
        /// The process's thread count.
        threads: usize,
    },
    /// No key pool is locked yet, so no key can be created.
    NotLocked,
    /// Every slot of the pool is in use.
    Exhausted,
    /// The pool was wiped as the process ends; it hands out no slot.
    Wiped,
}

impl fmt::Display for KeyMemoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Harden { errno } => {
                write!(
                    formatter,
                    "the process could not be made non-dumpable (errno {errno})"
                )
            }
            Self::NotHardened => formatter.write_str(
                "the key pool needs a non-dumpable process with RLIMIT_CORE 0: harden it first",
            ),
            Self::CapIpcLock => formatter
                .write_str("the process holds CAP_IPC_LOCK, which the Core's unit never grants"),
            Self::ProcessStatus { errno } => {
                write!(
                    formatter,
                    "/proc/self/status could not be read (errno {errno})"
                )
            }
            Self::Map { errno } => write!(
                formatter,
                "the key pool could not be mapped (errno {errno})"
            ),
            Self::Advise { advice, errno } => {
                write!(formatter, "{advice} of the key pool failed (errno {errno})")
            }
            Self::Lock { bytes, errno } => write!(
                formatter,
                "mlock refused the key pool of {bytes} bytes (errno {errno}): the Core's \
                 LimitMEMLOCK must cover it, and it does not start on unlocked memory"
            ),
            Self::AlreadyLocked => formatter.write_str("the process already has its key pool"),
            Self::Sigterm { errno } => {
                write!(
                    formatter,
                    "SIGTERM could not be taken on a thread of its own (errno {errno})"
                )
            }
            Self::ThreadsRunning { threads } => write!(
                formatter,
                "SIGTERM must be blocked while the process has one thread, not {threads}"
            ),
            Self::NotLocked => formatter.write_str("no key pool is locked"),
            Self::Exhausted => formatter.write_str("every slot of the key pool is in use"),
            Self::Wiped => formatter.write_str("the key pool was wiped"),
        }
    }
}

impl std::error::Error for KeyMemoryError {}

/// A refused encoding of a stored value of the crate, a wrapper or a wrapper set MAC. A refused
/// value is never repaired, read under another version or checked with other algorithms than it
/// names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
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
    /// The MAC algorithm identifier of a stored MAC names no algorithm of its format version.
    UnknownMacAlgorithm {
        /// The identifier the bytes state.
        id: u16,
    },
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
            Self::UnknownMacAlgorithm { id } => {
                write!(formatter, "unknown MAC algorithm identifier {id:#06x}")
            }
        }
    }
}

impl std::error::Error for WrapperError {}
