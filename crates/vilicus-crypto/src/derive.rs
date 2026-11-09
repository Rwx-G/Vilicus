//! Key derivation: HKDF-SHA-256 with a versioned label (spine AD-18, `doc/key-management.md`
//! section 2).

use core::fmt;

use crate::aws_lc;
use crate::error::CryptoError;
use crate::key::{Slot, SymmetricKey};

/// The byte that ends a label wherever the crate encodes one. No label contains it, so no
/// encoded label is a prefix of another.
const LABEL_END: u8 = 0x00;

/// A versioned domain label: the start of the HKDF `info` of a derivation, and the purpose a
/// wrapper is bound to (see [`Wrapper::wrap_key`](crate::Wrapper::wrap_key)).
///
/// A label starts with [`PREFIX`](Self::PREFIX), the version of the scheme, has at least one byte
/// after it, and holds printable ASCII only (0x21 to 0x7e). Wherever the crate encodes a label it
/// writes it followed by a 0x00 byte, which no label holds, so the encoding of one label is never
/// a prefix of another's: `vilicus/v1/db` and `vilicus/v1/db/` are two separate domains.
///
/// [`label!`](crate::label!) builds one at compile time, so a label that breaks a rule fails the
/// build and nothing can panic at run time; [`new`](Self::new) returns the refusal instead.
///
/// ```
/// use vilicus_crypto::{Label, LabelError, label};
///
/// const FILE_KEY: Label = label!("vilicus/v1/db/");
/// assert_eq!(FILE_KEY.as_str(), "vilicus/v1/db/");
/// assert_eq!(Label::new("vilicus/db/files/"), Err(LabelError::Unversioned));
/// ```
///
/// ```compile_fail,E0080
/// let _ = vilicus_crypto::label!("vilicus/db/files/");
/// ```
///
/// ```compile_fail,E0080
/// let _ = vilicus_crypto::label!("vilicus/v1/");
/// ```
///
/// ```compile_fail,E0080
/// let _ = vilicus_crypto::label!("vilicus/v1/db file");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Label(&'static str);

/// Why a text is not a [`Label`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LabelError {
    /// It does not start with [`Label::PREFIX`].
    Unversioned,
    /// It ends at [`Label::PREFIX`].
    NoName,
    /// It holds a byte outside printable ASCII.
    InvalidByte,
}

impl fmt::Display for LabelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unversioned => "a label starts with vilicus/v1/",
            Self::NoName => "a label has a name after vilicus/v1/",
            Self::InvalidByte => "a label holds printable ASCII only",
        })
    }
}

impl std::error::Error for LabelError {}

impl Label {
    /// The start of every label: the product and the version of the scheme.
    pub const PREFIX: &'static str = "vilicus/v1/";

    /// The label `label`, or why it is not one. Use [`label!`](crate::label!) for a label known
    /// when the crate is built.
    pub const fn new(label: &'static str) -> Result<Self, LabelError> {
        let bytes = label.as_bytes();
        let prefix = Self::PREFIX.as_bytes();
        if bytes.len() < prefix.len() {
            return Err(LabelError::Unversioned);
        }
        let mut index = 0;
        while index < prefix.len() {
            if bytes[index] != prefix[index] {
                return Err(LabelError::Unversioned);
            }
            index += 1;
        }
        if bytes.len() == prefix.len() {
            return Err(LabelError::NoName);
        }
        while index < bytes.len() {
            if !bytes[index].is_ascii_graphic() {
                return Err(LabelError::InvalidByte);
            }
            index += 1;
        }
        Ok(Self(label))
    }

    /// The label's text.
    pub const fn as_str(self) -> &'static str {
        self.0
    }

    /// The label as the crate encodes it: its bytes, then the end byte.
    pub(crate) fn encoded(self) -> [&'static [u8]; 2] {
        [self.0.as_bytes(), &[LABEL_END]]
    }
}

/// A [`Label`] checked when the crate is built: a text that is not a label fails the build.
///
/// ```
/// const WRAP: vilicus_crypto::Label = vilicus_crypto::label!("vilicus/v1/hk/enroll-wrap/");
/// # let _ = WRAP;
/// ```
#[macro_export]
macro_rules! label {
    ($text:literal) => {
        const {
            match $crate::Label::new($text) {
                Ok(label) => label,
                Err(_) => panic!("not a Vilicus label: see vilicus_crypto::Label"),
            }
        }
    };
}

/// The HKDF `info` of `label` and `context`, in parts: the encoded label, then each context part
/// preceded by its length as a `u16` big-endian, so that no two pairs of a label and a context
/// give the same `info`. `lengths` holds the length prefixes the parts borrow.
fn info_parts<'a>(
    label: Label,
    context: &[&'a [u8]],
    lengths: &'a mut Vec<[u8; 2]>,
) -> Result<Vec<&'a [u8]>, CryptoError> {
    for part in context {
        let len = u16::try_from(part.len())
            .map_err(|_| CryptoError::ContextPartTooLong { len: part.len() })?;
        lengths.push(len.to_be_bytes());
    }
    let mut info: Vec<&'a [u8]> = Vec::with_capacity(2 + 2 * context.len());
    info.extend(label.encoded());
    for (len, part) in lengths.iter().zip(context) {
        info.push(len);
        info.push(part);
    }
    Ok(info)
}

/// The key derived from `parent` by HKDF-SHA-256 with no salt and a 32-byte output. Its `info`
/// is `label` and its end byte, then each part of `context` preceded by its length as a `u16`
/// big-endian; a part longer than `u16::MAX` bytes is refused.
///
/// Not exported from the crate root: the crate's own derivations each name their registry entry
/// (`hierarchy`), and only the `testing` feature re-exports it, for the key memory harness; a
/// caller that could derive from any key under any label could derive another role's key
/// (story 4.3 review, M1).
pub fn derive_key(
    parent: &SymmetricKey,
    label: Label,
    context: &[&[u8]],
) -> Result<SymmetricKey, CryptoError> {
    let mut lengths = Vec::with_capacity(context.len());
    let info = info_parts(label, context, &mut lengths)?;
    let mut derived = Slot::new()?;
    parent
        .slot()
        .with_key(|ikm| derived.with_key_mut(|out| aws_lc::hkdf_sha256(ikm, &info, out)))??
        .map_err(|_| CryptoError::Derive)?;
    Ok(SymmetricKey::from_slot(derived))
}

#[cfg(test)]
mod tests;
