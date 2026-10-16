use std::fmt;

/// Every way a ceremony step can fail. No variant carries key material.
#[derive(Debug)]
pub enum Error {
    /// Reading or writing `wrappers.db` failed.
    Io(std::io::Error),
    /// `wrappers.db` or one of its fields does not parse.
    MalformedStore(&'static str),
    /// A stored value names a format version or algorithm this build does not accept.
    UnsupportedFormat,
    /// `create_first_member` found an existing household.
    HouseholdExists,
    /// The member identifier is empty or longer than the store allows.
    InvalidMemberId,
    /// `member_add` named a member that already has a record.
    MemberExists,
    /// No record carries this member identifier.
    UnknownMember,
    /// The record is not in the state this step needs.
    WrongState,
    /// The enrollment token does not match the stored check hash, or was already used.
    TokenRefused,
    /// The permanent MAC does not verify over the stored public keys.
    PublicKeyMacMismatch,
    /// The household key wrap did not open for this member.
    HouseholdKeyUnwrapFailed,
    /// A primitive reported a failure (CSPRNG, key construction).
    Crypto,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Io(err) => return write!(f, "wrappers.db I/O failed: {err}"),
            Self::MalformedStore(what) => return write!(f, "wrappers.db is malformed: {what}"),
            Self::UnsupportedFormat => "unsupported format version or algorithm identifier",
            Self::HouseholdExists => "a household already exists",
            Self::InvalidMemberId => "invalid member identifier",
            Self::MemberExists => "member already exists",
            Self::UnknownMember => "unknown member",
            Self::WrongState => "member record is not in the expected state",
            Self::TokenRefused => "enrollment token refused",
            Self::PublicKeyMacMismatch => "public key MAC does not verify",
            Self::HouseholdKeyUnwrapFailed => "household key wrap does not open",
            Self::Crypto => "cryptographic primitive failure",
        };
        f.write_str(text)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<aws_lc_rs::error::Unspecified> for Error {
    fn from(_: aws_lc_rs::error::Unspecified) -> Self {
        Self::Crypto
    }
}
