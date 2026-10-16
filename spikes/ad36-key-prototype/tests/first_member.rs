//! I/O matrix: first member. HK is created with the member's key pairs, the permanent
//! MAC is written at once and HK is wrapped.

mod common;

use ad36_key_prototype::{
    Error, FIRST_HK_VERSION, Field, MemberState, Store, create_first_member, unlock,
};
use common::{Household, founded};

#[test]
fn first_member_is_active_with_permanent_mac_and_hk_wrap() {
    let household = Household::new();
    let (alice, alice_unlocked) = founded(&household);

    let store = Store::load(&household.store()).expect("store parses");
    let record = store.member(b"alice").expect("alice exists");
    assert_eq!(record.state(), MemberState::Active);
    for absent in [Field::TokenCheck, Field::EnrollKeyWrap, Field::EnrollTag] {
        assert!(
            record.encoded_field(absent).is_none(),
            "{absent:?} is absent"
        );
    }
    assert_eq!(alice_unlocked.hk_version(), FIRST_HK_VERSION);
    assert_eq!(alice_unlocked.member_id(), alice.member_id());
}

#[test]
fn a_second_household_cannot_be_created_over_the_first() {
    let household = Household::new();
    let _ = founded(&household);
    assert!(matches!(
        create_first_member(&household.store(), b"eve"),
        Err(Error::HouseholdExists)
    ));
}

#[test]
fn secrets_never_appear_in_debug_output() {
    let household = Household::new();
    let (alice, alice_unlocked) = founded(&household);

    let printed = format!("{alice:?} {alice_unlocked:?}");
    assert!(printed.contains("alice"));
    assert!(!printed.contains('['), "no byte array is printed");
    assert!(printed.contains(".."), "key fields are elided");
}

#[test]
fn unlock_rejects_a_member_of_another_household() {
    let household = Household::new();
    let _ = founded(&household);
    let elsewhere = Household::new();
    let stranger = create_first_member(&elsewhere.store(), b"stranger").expect("stranger");
    assert!(matches!(
        unlock(&household.store(), &stranger),
        Err(Error::UnknownMember)
    ));
}
