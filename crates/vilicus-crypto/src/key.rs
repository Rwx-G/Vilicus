//! The key types and the buffer that holds their bytes (spine AD-4).

use crate::aws_lc;
use crate::error::CryptoError;
pub(crate) use crate::memory::Slot;

/// Bytes of every key of the suite: 256 bits, the key of AES-256-GCM and the output of
/// HKDF-SHA-256.
pub const KEY_LEN: usize = 32;

/// A 256-bit symmetric key: a member DEK, the household key, a key encryption key, a derived
/// file key, any key of the suite.
///
/// It is created by [`generate`](Self::generate), [`derive_key`](crate::derive_key) or
/// [`Wrapper::unwrap_key`](crate::Wrapper::unwrap_key), in a slot of the locked key pool
/// ([`lock_key_memory`](crate::lock_key_memory)), and its bytes never leave the crate. It does
/// not implement `Clone`, `Copy`, `Debug` or `Display`, and its slot is wiped when it is dropped.
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
    /// A new key drawn from the CSPRNG of aws-lc-rs, in a slot of the locked pool: it fails with
    /// [`CryptoError::KeyMemory`] while no pool is locked, once every slot is in use and once the
    /// pool is wiped.
    ///
    /// ```
    /// # vilicus_crypto::harden_process()?;
    /// # vilicus_crypto::lock_key_memory()?;
    /// let key = vilicus_crypto::SymmetricKey::generate()?;
    /// # drop(key);
    /// # Ok::<(), vilicus_crypto::CryptoError>(())
    /// ```
    pub fn generate() -> Result<Self, CryptoError> {
        let mut slot = Slot::new()?;
        slot.with_key_mut(|bytes| aws_lc::fill_random(bytes))
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
