//! What the testbed's tests name of the storage layer, which no crate but the Core may depend on
//! (AD-3, D140): the files they create and bring up, the identity of a call's journal and outbox
//! rows, the states those rows stand in, and the key text of their test files. Compiled with the
//! `testing` feature, which ci/check_packaging.py refuses in a release artefact (D102), and in the
//! Core's own test builds.
//!
//! It opens no file: the testbed's tests reach a module file's handles through the Core's own
//! paths, a partition's bring-up ([`bring_up`](crate::startup::bring_up)), as the gates that run
//! against it need.

pub use vilicus_storage::{
    CORE_SCHEMA_VERSION, CallKey, DeliveryState, EffectState, Error as StorageError, FileKeying,
    KEY_TEXT_LEN, KeyEpoch, MigrationTrack, ModuleFile, OutboxState, Partition, SqlValue,
};

/// Creates `file`, a new module file whose Core track is at the Core's version and whose module
/// track has run nothing, keyed with `key` at `epoch`, and closes it: what a partition's bring-up
/// then migrates to its module's versions.
pub fn create_module_file(
    file: &ModuleFile,
    key: &dyn FileKeying,
    epoch: KeyEpoch,
) -> Result<(), StorageError> {
    vilicus_storage::create(file, key, epoch)?.close()
}

/// A fixed SQLCipher key text that keys the test files of the Core and the testbed as the text
/// the Core lends from a file key does: test code only, the product's `FileKeying` being the
/// Core's file keys, whose text `vilicus-crypto` writes in its locked pool (D154).
pub struct TestKeyText(pub [u8; KEY_TEXT_LEN]);

impl FileKeying for TestKeyText {
    fn lend_key_text(
        &self,
        key_with: &mut dyn FnMut(&[u8]) -> Result<(), StorageError>,
    ) -> Result<(), StorageError> {
        key_with(&self.0)
    }
}

/// The key text of `key`, `x'`, its lowercase hex digits, then `'`, as a [`TestKeyText`].
pub const fn sqlcipher_key_text(key: [u8; 32]) -> TestKeyText {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = [b'\''; KEY_TEXT_LEN];
    text[0] = b'x';
    let mut index = 0;
    while index < key.len() {
        text[2 + 2 * index] = HEX[(key[index] >> 4) as usize];
        text[3 + 2 * index] = HEX[(key[index] & 0x0f) as usize];
        index += 1;
    }
    TestKeyText(text)
}
