//! The key types and the buffer that holds their bytes (spine AD-4).

use zeroize::Zeroize;

use crate::aws_lc;
use crate::error::CryptoError;

/// Bytes of every key of the suite: 256 bits, the key of AES-256-GCM and the output of
/// HKDF-SHA-256.
pub const KEY_LEN: usize = 32;

/// The buffer of one key, the only place the crate keeps key bytes.
///
/// Today it is a heap allocation wiped on drop with volatile writes; it is not locked yet. Its
/// bytes are reached only through [`with_bytes`](Self::with_bytes) and
/// [`with_bytes_mut`](Self::with_bytes_mut), which lend them for one closure, so a buffer taken
/// from a locked pool can replace the allocation without changing a caller (D131).
pub(crate) struct Slot {
    bytes: Box<[u8; KEY_LEN]>,
}

impl Slot {
    /// A buffer of zeros.
    pub(crate) fn zeroed() -> Self {
        Self {
            bytes: Box::new([0; KEY_LEN]),
        }
    }

    /// Lends the bytes to `operation`.
    pub(crate) fn with_bytes<R>(&self, operation: impl FnOnce(&[u8; KEY_LEN]) -> R) -> R {
        operation(&self.bytes)
    }

    /// Lends the bytes to `operation`, to be written.
    pub(crate) fn with_bytes_mut<R>(
        &mut self,
        operation: impl FnOnce(&mut [u8; KEY_LEN]) -> R,
    ) -> R {
        operation(&mut self.bytes)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.bytes.zeroize();
        #[cfg(test)]
        wiped::record(&self.bytes);
    }
}

/// A 256-bit symmetric key: a member DEK, the household key, a key encryption key, a derived
/// file key, any key of the suite.
///
/// It is created by [`generate`](Self::generate), [`derive_key`](crate::derive_key) or
/// [`Wrapper::unwrap_key`](crate::Wrapper::unwrap_key), and its bytes never leave the crate.
/// It does not implement `Clone`, `Copy`, `Debug` or `Display`, and its buffer is wiped when it
/// is dropped.
///
/// ```compile_fail,E0599
/// let key = vilicus_crypto::SymmetricKey::generate()?;
/// let _copy = key.clone();
/// # Ok::<(), vilicus_crypto::CryptoError>(())
/// ```
///
/// ```compile_fail,E0277
/// let key = vilicus_crypto::SymmetricKey::generate()?;
/// println!("{key:?}");
/// # Ok::<(), vilicus_crypto::CryptoError>(())
/// ```
///
/// ```compile_fail,E0277
/// let key = vilicus_crypto::SymmetricKey::generate()?;
/// println!("{key}");
/// # Ok::<(), vilicus_crypto::CryptoError>(())
/// ```
pub struct SymmetricKey {
    slot: Slot,
}

impl SymmetricKey {
    /// A new key drawn from the CSPRNG of aws-lc-rs.
    ///
    /// ```
    /// let key = vilicus_crypto::SymmetricKey::generate()?;
    /// # drop(key);
    /// # Ok::<(), vilicus_crypto::CryptoError>(())
    /// ```
    pub fn generate() -> Result<Self, CryptoError> {
        let mut slot = Slot::zeroed();
        slot.with_bytes_mut(|bytes| aws_lc::fill_random(bytes))
            .map_err(|_| CryptoError::Random)?;
        Ok(Self { slot })
    }

    pub(crate) fn from_slot(slot: Slot) -> Self {
        Self { slot }
    }

    pub(crate) fn slot(&self) -> &Slot {
        &self.slot
    }
}

#[cfg(test)]
mod tests;

/// What every dropped [`Slot`] held once wiped, read by the tests through this hook (AC3 of
/// Story 4.1): the buffer's address and a copy of its bytes, taken after the wipe and before
/// the allocation is freed. Recorded per thread, so concurrent tests do not see each other's.
#[cfg(test)]
pub(crate) mod wiped {
    use std::cell::RefCell;

    use super::KEY_LEN;

    thread_local! {
        static SEEN: RefCell<Vec<(usize, [u8; KEY_LEN])>> = const { RefCell::new(Vec::new()) };
    }

    pub(crate) fn record(bytes: &[u8; KEY_LEN]) {
        SEEN.with(|seen| seen.borrow_mut().push((bytes.as_ptr().addr(), *bytes)));
    }

    /// Every buffer dropped on this thread since the last call, oldest first.
    pub(crate) fn take() -> Vec<(usize, [u8; KEY_LEN])> {
        SEEN.with(|seen| std::mem::take(&mut *seen.borrow_mut()))
    }
}
