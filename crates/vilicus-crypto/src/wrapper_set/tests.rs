//! The MAC of the `wrappers.db` record set (Story 4.3, decision task, gate AD36-1): a known answer,
//! and each change to the set, the counter or the key that it must refuse.

use super::*;
use crate::hierarchy::HouseholdKey;
use crate::key::Slot;
use crate::test_support::hex;

fn household(bytes: [u8; 32], version: u32) -> HouseholdKey {
    let mut slot = Slot::new().expect("slot");
    slot.with_key_mut(|key| *key = bytes).expect("planted");
    HouseholdKey::from_key(SymmetricKey::from_slot(slot), version)
}

fn sequence() -> [u8; 32] {
    core::array::from_fn(|index| u8::try_from(index).expect("small"))
}

/// The MAC input pinned against HMAC-SHA-256 computed with Python's `hmac` and `hashlib`, under the
/// set key of the household key 0x00..0x1f at version 3: the domain label and its end byte, the
/// format version, the algorithm, the household key version, the counter, the record count, then
/// each record in ascending order with its `u32` big-endian length.
#[test]
fn the_set_mac_matches_a_known_answer_whatever_the_order() {
    let key = household(sequence(), 3).wrapper_set_key().expect("set key");
    assert_eq!(key.household_key_version(), 3);
    let expected = hex("ff6da22f9d61f4585cbbbe2138054952e9d153bd182f298926789772a900922c");
    for records in [[&b"beta"[..], b"alpha"], [b"alpha", b"beta"]] {
        let mac = key.seal(9, &records).expect("seal");
        assert_eq!(mac.tag.to_vec(), expected);
        assert_eq!(key.verify(&mac, 9, &records), Ok(()));
    }
}

/// Each change an attacker who writes `wrappers.db` but holds no household key can make is
/// refused: a record deleted, added or edited, an older counter (a rolled-back file), another
/// household key or version, an edited tag.
#[test]
fn a_changed_set_counter_or_key_is_refused() {
    let hk = household(sequence(), 3);
    let key = hk.wrapper_set_key().expect("set key");
    let records: [&[u8]; 3] = [
        b"dek wrapper of member 1",
        b"dek wrapper of member 2",
        b"pk",
    ];
    let mac = key.seal(5, &records).expect("seal");
    assert_eq!(key.verify(&mac, 5, &records), Ok(()));
    let refused: [(&str, u64, Vec<&[u8]>); 5] = [
        ("a record deleted", 5, records[..2].to_vec()),
        (
            "a record added",
            5,
            [&records[..], &[b"vetoed member"]].concat(),
        ),
        (
            "a record edited",
            5,
            vec![records[0], b"dek wrapper of member 3", records[2]],
        ),
        ("an older counter", 4, records.to_vec()),
        ("an empty set", 5, Vec::new()),
    ];
    for (change, counter, set) in refused {
        assert_eq!(
            key.verify(&mac, counter, &set),
            Err(CryptoError::Mac),
            "{change}"
        );
    }
    let mut edited = mac.clone();
    edited.tag[0] ^= 1;
    assert_eq!(key.verify(&edited, 5, &records), Err(CryptoError::Mac));
    let other = household([0x42; 32], 3).wrapper_set_key().expect("set key");
    assert_eq!(other.verify(&mac, 5, &records), Err(CryptoError::Mac));
    let next = household(sequence(), 4).wrapper_set_key().expect("set key");
    assert_eq!(
        next.verify(&mac, 5, &records),
        Err(CryptoError::HouseholdKeyVersion { stated: 3, held: 4 })
    );
    let relabelled = WrapperSetMac {
        household_key_version: 4,
        tag: mac.tag,
    };
    assert_eq!(next.verify(&relabelled, 5, &records), Err(CryptoError::Mac));
}

/// The stored form round-trips and starts with its format version and algorithm identifier; any
/// other version, algorithm or length is refused.
#[test]
fn the_stored_mac_is_versioned_and_refuses_any_other_shape() {
    let key = household(sequence(), 3).wrapper_set_key().expect("set key");
    let mac = key.seal(1, &[b"record"]).expect("seal");
    let bytes = mac.to_bytes();
    assert_eq!(&bytes[..8], &[0, 1, 0, 1, 0, 0, 0, 3]);
    assert_eq!(WrapperSetMac::from_bytes(&bytes), Ok(mac.clone()));
    assert_eq!(mac.household_key_version(), 3);
    for len in 0..bytes.len() {
        assert_eq!(
            WrapperSetMac::from_bytes(&bytes[..len]),
            Err(WrapperError::Truncated),
            "{len} bytes"
        );
    }
    let mut longer = bytes.to_vec();
    longer.push(0);
    assert_eq!(
        WrapperSetMac::from_bytes(&longer),
        Err(WrapperError::TrailingBytes)
    );
    let with = |index: usize, value: u8| {
        let mut changed = bytes;
        changed[index] = value;
        WrapperSetMac::from_bytes(&changed)
    };
    assert_eq!(
        with(1, 0),
        Err(WrapperError::OlderThanAccepted { version: 0 })
    );
    assert_eq!(with(1, 2), Err(WrapperError::UnknownVersion { version: 2 }));
    assert_eq!(with(3, 2), Err(WrapperError::UnknownMacAlgorithm { id: 2 }));
}
