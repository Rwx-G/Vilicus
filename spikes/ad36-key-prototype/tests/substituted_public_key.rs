//! I/O matrix: public key substituted before the unlock. An attacker who writes
//! `wrappers.db` without HK replaces the member or inbox public key of an enrolled member;
//! the next adult unlock refuses with a distinct reason, records an alert and wraps no HK.

mod common;

use ad36_key_prototype::{
    Alert, Error, Field, MemberState, Refusal, Store, adult_unlock_wrap_pending, unlock,
};
use common::{
    Household, added_and_enrolled, attacker_keys, founded, overwrite, stored_field, with_value,
};

fn substitution_is_refused(field: Field) {
    let household = Household::new();
    let (_alice, alice_unlocked) = founded(&household);
    let _bob = added_and_enrolled(&household, &alice_unlocked, b"bob");
    let (_elsewhere, mallory) = attacker_keys();

    let attacker_value = match field {
        Field::MemberPublicKey => mallory.member_public_key(),
        _ => mallory.inbox_public_key(),
    };
    let honest = stored_field(&household.store(), b"bob", field);
    overwrite(
        &household.store(),
        &honest,
        &with_value(&honest, &attacker_value),
    );

    let report = adult_unlock_wrap_pending(&household.store(), &alice_unlocked).expect("unlock");
    assert!(report.wrapped.is_empty(), "no HK wrap");
    assert_eq!(
        report.alerts,
        vec![Alert {
            member_id: b"bob".to_vec(),
            refusal: Refusal::EnrollmentTagMismatch,
        }]
    );

    let store = Store::load(&household.store()).expect("store parses");
    let record = store.member(b"bob").expect("bob exists");
    assert_eq!(record.state(), MemberState::AwaitingHouseholdKey);
    assert!(record.encoded_field(Field::HkWrap).is_none());
    assert!(record.encoded_field(Field::PubkeyMac).is_none());
}

#[test]
fn substituted_member_public_key_gets_no_hk() {
    substitution_is_refused(Field::MemberPublicKey);
}

#[test]
fn substituted_inbox_public_key_gets_no_hk() {
    substitution_is_refused(Field::InboxPublicKey);
}

#[test]
fn attacker_holding_the_substituted_private_key_gets_no_wrap() {
    let household = Household::new();
    let (_alice, alice_unlocked) = founded(&household);
    let _bob = added_and_enrolled(&household, &alice_unlocked, b"bob");
    let (_elsewhere, mallory) = attacker_keys();

    let honest = stored_field(&household.store(), b"bob", Field::MemberPublicKey);
    overwrite(
        &household.store(),
        &honest,
        &with_value(&honest, &mallory.member_public_key()),
    );
    let _ = adult_unlock_wrap_pending(&household.store(), &alice_unlocked).expect("unlock");

    // Mallory's public key is now the one stored for Bob, yet no wrap exists to open.
    let store = Store::load(&household.store()).expect("store parses");
    assert!(
        store
            .member(b"bob")
            .expect("bob")
            .encoded_field(Field::HkWrap)
            .is_none()
    );
    assert!(matches!(
        unlock(&household.store(), &mallory),
        Err(Error::UnknownMember)
    ));
}

#[test]
fn alert_repeats_at_every_adult_unlock() {
    let household = Household::new();
    let (_alice, alice_unlocked) = founded(&household);
    let _bob = added_and_enrolled(&household, &alice_unlocked, b"bob");
    let (_elsewhere, mallory) = attacker_keys();
    let honest = stored_field(&household.store(), b"bob", Field::MemberPublicKey);
    overwrite(
        &household.store(),
        &honest,
        &with_value(&honest, &mallory.member_public_key()),
    );

    for _ in 0..2 {
        let report =
            adult_unlock_wrap_pending(&household.store(), &alice_unlocked).expect("unlock");
        assert!(report.wrapped.is_empty());
        assert_eq!(report.alerts.len(), 1);
    }
}
