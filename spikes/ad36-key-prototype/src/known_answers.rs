//! Known-answer tests pinning the byte composition of the fixed encodings. The expected
//! values were computed outside this crate (Python `hmac` and `hashlib`, HKDF per RFC 5869
//! with a zero salt), so a change in length prefixes, field order, salt or context breaks
//! them even where a round trip through this crate would still pass.

use crate::ceremony::{
    EnrollmentToken, enroll_wrap_key, enrollment_key, pubkey_mac_key, token_check,
};
use crate::encoding::{EnrollKeyWrap, Tagged32, alg, label, mac_input, versioned_context};
use crate::primitives::Secret32;
use crate::store::{MemberRecord, Store};

const MEMBER_ID: &[u8] = b"alice";
const HK_VERSION: u32 = 1;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex literal"))
        .collect()
}

fn token() -> EnrollmentToken {
    EnrollmentToken::from_bytes([0x0a; 16])
}

fn household_key() -> Secret32 {
    Secret32::from_bytes([0x0b; 32])
}

#[test]
fn mac_input_is_length_prefixed_in_fixed_order() {
    let member_pk = Tagged32::new(alg::PUBLIC_KEY_X25519, [0x11; 32]);
    let inbox_pk = Tagged32::new(alg::PUBLIC_KEY_X25519, [0x22; 32]);
    let input = mac_input(MEMBER_ID, &member_pk, &inbox_pk).expect("mac input");
    assert_eq!(
        input,
        hex(concat!(
            "0005616c696365",
            "00220104",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "00220104",
            "2222222222222222222222222222222222222222222222222222222222222222",
        ))
    );
}

#[test]
fn versioned_contexts_put_the_version_last() {
    assert_eq!(
        versioned_context(label::PUBKEY_MAC, MEMBER_ID, HK_VERSION),
        hex("76696c696375732f76312f7075626b65792d6d61632f616c69636500000001")
    );
    assert_eq!(
        versioned_context(label::HK_WRAP, MEMBER_ID, HK_VERSION),
        hex("76696c696375732f76312f686b2f777261702f616c69636500000001")
    );
}

#[test]
fn token_check_derivation() {
    let check = token_check(&token(), MEMBER_ID).expect("hkdf");
    assert!(
        check.expose()[..]
            == hex("5a2fab7a0fb73698f4178812b762da50d2efd15e3e17dad7ff8f14fb2038df47")
    );
}

#[test]
fn enrollment_key_derivation() {
    let key = enrollment_key(&token(), MEMBER_ID).expect("hkdf");
    assert!(
        key.expose()[..] == hex("17504f0efa5840baa820a7475ff0fb4f6e9d2e0fb275831904d52fd7db059a45")
    );
}

#[test]
fn enrollment_wrap_key_derivation_binds_the_hk_version() {
    let key = enroll_wrap_key(&household_key(), MEMBER_ID, HK_VERSION).expect("hkdf");
    assert!(
        key.expose()[..] == hex("afcde7e2fd674ed1068bf8172eb574f6a4a41955afc3747bfb056e2b6660ce24")
    );
}

#[test]
fn pubkey_mac_key_derivation_binds_the_hk_version() {
    let key = pubkey_mac_key(&household_key(), MEMBER_ID, HK_VERSION).expect("hkdf");
    assert!(
        key.expose()[..] == hex("229afaee49d0090fb0d7fc0c8568fc6b416bd95d352bfce061ca9d7f9b09c440")
    );
    let next = pubkey_mac_key(&household_key(), MEMBER_ID, HK_VERSION + 1).expect("hkdf");
    assert!(next.expose() != key.expose());
}

#[test]
fn no_label_is_a_prefix_of_another() {
    for (index, first) in label::ALL.iter().enumerate() {
        for (other, second) in label::ALL.iter().enumerate() {
            assert!(index == other || !second.starts_with(first));
        }
    }
}

#[test]
fn empty_store_header() {
    assert_eq!(
        Store::empty().encode().expect("encode"),
        hex("564c4357010000")
    );
}

#[test]
fn store_record_encoding() {
    let mut record = MemberRecord::new(MEMBER_ID);
    record.token_check = Some(Tagged32::new(alg::TOKEN_CHECK_HKDF_SHA256, [0x33; 32]));
    record.enroll_key_wrap = Some(EnrollKeyWrap {
        hk_version: HK_VERSION,
        nonce: [0x44; 12],
        ciphertext: vec![0x55; 48],
    });
    let mut store = Store::empty();
    store.members.push(record);
    assert_eq!(
        store.encode().expect("encode"),
        hex(concat!(
            "564c4357010001",
            "0005616c696365",
            "00220101",
            "3333333333333333333333333333333333333333333333333333333333333333",
            "0042010200000001",
            "444444444444444444444444",
            "555555555555555555555555555555555555555555555555",
            "555555555555555555555555555555555555555555555555",
            "00000000000000000000",
        ))
    );
}
