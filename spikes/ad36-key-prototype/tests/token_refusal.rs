//! I/O matrix: wrong or reused token. Enrollment is refused and nothing is stored.

mod common;

use std::fs;

use ad36_key_prototype::{EnrollmentToken, Error, TOKEN_LEN, enroll, member_add};
use common::{Household, founded};

#[test]
fn wrong_token_is_refused_and_nothing_is_stored() {
    let household = Household::new();
    let (_alice, alice_unlocked) = founded(&household);
    let _token = member_add(&household.store(), &alice_unlocked, b"bob").expect("member add");
    let before = fs::read(household.store()).expect("read store");

    let wrong = EnrollmentToken::from_bytes([0x5a; TOKEN_LEN]);
    assert!(matches!(
        enroll(&household.store(), b"bob", &wrong),
        Err(Error::TokenRefused)
    ));
    assert!(fs::read(household.store()).expect("read store") == before);
}

#[test]
fn token_issued_for_another_member_is_refused() {
    let household = Household::new();
    let (_alice, alice_unlocked) = founded(&household);
    let _bob_token = member_add(&household.store(), &alice_unlocked, b"bob").expect("add bob");
    let carol_token = member_add(&household.store(), &alice_unlocked, b"carol").expect("add carol");
    let before = fs::read(household.store()).expect("read store");

    assert!(matches!(
        enroll(&household.store(), b"bob", &carol_token),
        Err(Error::TokenRefused)
    ));
    assert!(fs::read(household.store()).expect("read store") == before);
}

#[test]
fn reused_token_is_refused_and_nothing_is_stored() {
    let household = Household::new();
    let (_alice, alice_unlocked) = founded(&household);
    let token = member_add(&household.store(), &alice_unlocked, b"bob").expect("member add");
    let _bob = enroll(&household.store(), b"bob", &token).expect("first use");
    let after_first_use = fs::read(household.store()).expect("read store");

    assert!(matches!(
        enroll(&household.store(), b"bob", &token),
        Err(Error::TokenRefused)
    ));
    assert!(fs::read(household.store()).expect("read store") == after_first_use);
}

#[test]
fn token_for_an_unknown_member_is_refused() {
    let household = Household::new();
    let (_alice, alice_unlocked) = founded(&household);
    let token = member_add(&household.store(), &alice_unlocked, b"bob").expect("member add");
    let before = fs::read(household.store()).expect("read store");
    assert!(matches!(
        enroll(&household.store(), b"dave", &token),
        Err(Error::TokenRefused)
    ));
    assert!(fs::read(household.store()).expect("read store") == before);
}
