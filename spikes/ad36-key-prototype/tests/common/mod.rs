//! Shared test harness. The attacker is modelled as raw byte edits of `wrappers.db` by a
//! process that can write the disk but never holds HK. Assertions never format key bytes.

// Each integration test binary uses a different subset of these helpers.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ad36_key_prototype::{
    Field, MemberSecrets, Store, UnlockedAdult, adult_unlock_wrap_pending, create_first_member,
    enroll, member_add, unlock,
};

static NEXT_DIR: AtomicU32 = AtomicU32::new(0);

/// A fresh directory holding one household's `wrappers.db`, removed on drop.
pub struct Household {
    dir: PathBuf,
}

impl Household {
    pub fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default();
        let dir = std::env::temp_dir().join(format!(
            "ad36-spike-{}-{nanos}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).expect("create test directory");
        Self { dir }
    }

    pub fn store(&self) -> PathBuf {
        self.dir.join("wrappers.db")
    }
}

impl Drop for Household {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Alice, the first member, unlocked.
pub fn founded(household: &Household) -> (MemberSecrets, UnlockedAdult) {
    let alice = create_first_member(&household.store(), b"alice").expect("first member");
    let alice_unlocked = unlock(&household.store(), &alice).expect("alice unlocks");
    (alice, alice_unlocked)
}

/// `member add` by `adult`, then enrollment with the printed token.
pub fn added_and_enrolled(
    household: &Household,
    adult: &UnlockedAdult,
    member_id: &[u8],
) -> MemberSecrets {
    let token = member_add(&household.store(), adult, member_id).expect("member add");
    enroll(&household.store(), member_id, &token).expect("enrollment")
}

/// Bob as an active adult: added by Alice, enrolled, HK wrapped at Alice's next unlock.
pub fn with_active_bob(household: &Household) -> (UnlockedAdult, MemberSecrets) {
    let (_alice, alice_unlocked) = founded(household);
    let bob = added_and_enrolled(household, &alice_unlocked, b"bob");
    let report = adult_unlock_wrap_pending(&household.store(), &alice_unlocked).expect("unlock");
    assert_eq!(report.wrapped, vec![b"bob".to_vec()]);
    (alice_unlocked, bob)
}

/// A key pair held by the attacker, from a household the attacker controls.
pub fn attacker_keys() -> (Household, MemberSecrets) {
    let elsewhere = Household::new();
    let mallory = create_first_member(&elsewhere.store(), b"mallory").expect("attacker keys");
    (elsewhere, mallory)
}

/// The stored encoding of one field of one member, as an attacker reading the file sees it.
pub fn stored_field(store: &Path, member_id: &[u8], field: Field) -> Vec<u8> {
    Store::load(store)
        .expect("store parses")
        .member(member_id)
        .expect("member exists")
        .encoded_field(field)
        .expect("field present")
}

/// Replaces the single occurrence of `old` in the raw file with `new` of the same length.
pub fn overwrite(store: &Path, old: &[u8], new: &[u8]) {
    assert_eq!(old.len(), new.len(), "raw edits keep the file length");
    let mut bytes = fs::read(store).expect("read store");
    let positions: Vec<usize> = bytes
        .windows(old.len())
        .enumerate()
        .filter(|(_, window)| *window == old)
        .map(|(position, _)| position)
        .collect();
    assert_eq!(positions.len(), 1, "edited bytes occur exactly once");
    bytes[positions[0]..positions[0] + new.len()].copy_from_slice(new);
    fs::write(store, bytes).expect("write store");
}

/// Empties one field of one record: its length prefix becomes 0, its bytes are removed.
pub fn remove_field(store: &Path, member_id: &[u8], field: Field) {
    let encoded = stored_field(store, member_id, field);
    let len = u16::try_from(encoded.len()).expect("field fits a u16 prefix");
    let prefixed = [&len.to_be_bytes()[..], &encoded].concat();
    let bytes = fs::read(store).expect("read store");
    let at = bytes
        .windows(prefixed.len())
        .position(|window| window == prefixed)
        .expect("field present in the file");
    let edited = [&bytes[..at], &[0, 0][..], &bytes[at + prefixed.len()..]].concat();
    fs::write(store, edited).expect("write store");
}

/// The same encoded field with its last byte flipped: header intact, value altered.
pub fn with_last_byte_flipped(field: &[u8]) -> Vec<u8> {
    let mut edited = field.to_vec();
    if let Some(last) = edited.last_mut() {
        *last ^= 0x01;
    }
    edited
}

/// The encoded public-key field with its 32-byte value replaced by `value`.
pub fn with_value(field: &[u8], value: &[u8; 32]) -> Vec<u8> {
    let mut edited = field.to_vec();
    let header_len = edited.len() - value.len();
    edited[header_len..].copy_from_slice(value);
    edited
}
