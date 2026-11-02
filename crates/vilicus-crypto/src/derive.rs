//! Key derivation: HKDF-SHA-256 with a versioned label (spine AD-18, `doc/key-management.md`
//! section 2).

use crate::aws_lc;
use crate::error::CryptoError;
use crate::key::{Slot, SymmetricKey};

/// The versioned domain label that starts the HKDF `info` of a derivation, such as
/// `vilicus/v1/db/` or `vilicus/v1/partition/home`.
///
/// A label starts with [`PREFIX`](Self::PREFIX), the version of the derivation scheme, and has at
/// least one byte after it. [`new`](Self::new) checks this when the label is built, so a label
/// written as a `const` that breaks the rule fails the build:
///
/// ```
/// use vilicus_crypto::Label;
///
/// const FILE_KEY: Label = Label::new("vilicus/v1/db/");
/// assert_eq!(FILE_KEY.as_str(), "vilicus/v1/db/");
/// ```
///
/// ```compile_fail,E0080
/// const UNVERSIONED: vilicus_crypto::Label = vilicus_crypto::Label::new("vilicus/db/files/");
/// ```
///
/// ```compile_fail,E0080
/// const PREFIX_ONLY: vilicus_crypto::Label = vilicus_crypto::Label::new("vilicus/v1/");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Label(&'static str);

impl Label {
    /// The start of every label: the product and the version of the derivation scheme.
    pub const PREFIX: &'static str = "vilicus/v1/";

    /// The label `label`.
    ///
    /// # Panics
    ///
    /// When `label` does not start with [`PREFIX`](Self::PREFIX) or ends there; in a `const`,
    /// this is a build error.
    pub const fn new(label: &'static str) -> Self {
        let bytes = label.as_bytes();
        let prefix = Self::PREFIX.as_bytes();
        assert!(
            bytes.len() > prefix.len(),
            "an HKDF label has a name after vilicus/v1/"
        );
        let mut index = 0;
        while index < prefix.len() {
            assert!(
                bytes[index] == prefix[index],
                "an HKDF label starts with vilicus/v1/"
            );
            index += 1;
        }
        Self(label)
    }

    /// The label's text.
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// The key derived from `parent` by HKDF-SHA-256 with no salt and a 32-byte output, its `info`
/// being `label` followed by each part of `context` in order, without separators: the caller
/// lays out the context so that no two contexts of one label share their bytes, as
/// `doc/key-management.md` section 2 does with fixed-width fields and one variable-length field.
///
/// ```
/// use vilicus_crypto::{Label, SymmetricKey, derive_key};
///
/// const FILE_KEY: Label = Label::new("vilicus/v1/db/");
/// let root = SymmetricKey::generate()?;
/// let file_key = derive_key(&root, FILE_KEY, &[b"tasks/household/", &1_u32.to_be_bytes()])?;
/// # drop(file_key);
/// # Ok::<(), vilicus_crypto::CryptoError>(())
/// ```
pub fn derive_key(
    parent: &SymmetricKey,
    label: Label,
    context: &[&[u8]],
) -> Result<SymmetricKey, CryptoError> {
    let mut info: Vec<&[u8]> = Vec::with_capacity(1 + context.len());
    info.push(label.0.as_bytes());
    info.extend_from_slice(context);
    let mut derived = Slot::zeroed();
    parent
        .slot()
        .with_bytes(|ikm| derived.with_bytes_mut(|out| aws_lc::hkdf_sha256(ikm, &info, out)))
        .map_err(|_| CryptoError::Derive)?;
    Ok(SymmetricKey::from_slot(derived))
}
