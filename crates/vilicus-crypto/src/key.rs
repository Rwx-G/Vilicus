//! The key types and the buffer that holds their bytes (spine AD-4).

use crate::aws_lc;
use crate::error::CryptoError;
pub(crate) use crate::memory::KeySlot as Slot;
use crate::memory::{SQLCIPHER_KEY_TEXT_LEN, TextSlot};

/// Bytes of every key of the suite: 256 bits, the key of AES-256-GCM and the output of
/// HKDF-SHA-256.
pub const KEY_LEN: usize = 32;

/// A 256-bit symmetric key: a member DEK, the household key, a key encryption key, a derived
/// file key, any key of the suite.
///
/// It is created by [`generate`](Self::generate), a derivation of the key hierarchy or
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
        slot.with_key_mut(|bytes| aws_lc::fill_random(bytes))?
            .map_err(|_| CryptoError::Random)?;
        Ok(Self { slot })
    }

    /// Lends SQLCipher's raw key text of this key, `x'`, its lowercase hex digits, then `'`
    /// ([`SQLCIPHER_KEY_TEXT_LEN`](crate::SQLCIPHER_KEY_TEXT_LEN) bytes), to `operation`, which
    /// keys a file with it. The text is written in a slot of the locked pool's text class, never
    /// elsewhere, lent under the guard of a key operation, and wiped when the call returns; the
    /// hex digits are computed without a table or a branch on the key. It fails with
    /// [`CryptoError::KeyMemory`] when no text slot is free or once the pool is wiped.
    ///
    /// ```
    /// # vilicus_crypto::harden_process()?;
    /// # vilicus_crypto::lock_key_memory()?;
    /// let key = vilicus_crypto::SymmetricKey::generate()?;
    /// let shape = key.with_sqlcipher_key_text(|text| {
    ///     (text.len(), text.starts_with(b"x'"), text.ends_with(b"'"))
    /// })?;
    /// assert_eq!(shape, (vilicus_crypto::SQLCIPHER_KEY_TEXT_LEN, true, true));
    /// # Ok::<(), vilicus_crypto::CryptoError>(())
    /// ```
    pub fn with_sqlcipher_key_text<R>(
        &self,
        operation: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, CryptoError> {
        let mut text = TextSlot::new()?;
        text.with_key_mut(|buffer| self.slot.with_key(|key| write_key_text(key, buffer)))??;
        Ok(text.with_key(|buffer| operation(&buffer[..SQLCIPHER_KEY_TEXT_LEN]))?)
    }

    pub(crate) fn from_slot(slot: Slot) -> Self {
        Self { slot }
    }

    pub(crate) fn slot(&self) -> &Slot {
        &self.slot
    }
}

/// The lowercase hex digit of `nibble`, below 16, computed without a branch or a table index on
/// it: `0`..`9` are 48 + nibble, `a`..`f` 39 more, added when 9 - nibble is negative.
fn hex_digit(nibble: u8) -> u8 {
    let nibble = i16::from(nibble);
    let digit = 48 + nibble + (((9 - nibble) >> 8) & 39);
    digit.to_le_bytes()[0]
}

/// The quote around the hex digits of a key text.
const QUOTE: u8 = 0x27;

/// Writes `x'`, the hex digits of `key`, then `'` at the start of `buffer`.
fn write_key_text(key: &[u8; KEY_LEN], buffer: &mut [u8]) {
    buffer[0] = b'x';
    buffer[1] = QUOTE;
    for (index, byte) in key.iter().enumerate() {
        buffer[2 + 2 * index] = hex_digit(byte >> 4);
        buffer[3 + 2 * index] = hex_digit(byte & 0x0f);
    }
    buffer[2 + 2 * KEY_LEN] = QUOTE;
}

#[cfg(test)]
mod tests;
