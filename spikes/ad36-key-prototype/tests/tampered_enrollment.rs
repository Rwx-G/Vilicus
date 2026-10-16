//! I/O matrix: the enrollment tag or the wrapped enrollment key is edited. No HK wrap.
//! Also: a record no ceremony step produces, and an enrollment made under an older HK
//! version, which is reported as stale rather than as tampering.

mod common;

use ad36_key_prototype::{Field, MemberState, Refusal, Store, adult_unlock_wrap_pending};
use common::{
    Household, added_and_enrolled, founded, overwrite, remove_field, stored_field, with_active_bob,
    with_last_byte_flipped,
};

/// Offset of the HK version inside an encoded enrollment key wrap, after `version, alg_id`.
const WRAP_HK_VERSION_OFFSET: usize = 2;

fn refused_after_edit(field: Field, expected: Refusal) {
    let household = Household::new();
    let (_alice, alice_unlocked) = founded(&household);
    let _bob = added_and_enrolled(&household, &alice_unlocked, b"bob");

    let honest = stored_field(&household.store(), b"bob", field);
    overwrite(
        &household.store(),
        &honest,
        &with_last_byte_flipped(&honest),
    );

    let report = adult_unlock_wrap_pending(&household.store(), &alice_unlocked).expect("unlock");
    assert!(report.wrapped.is_empty(), "no HK wrap");
    assert_eq!(report.alerts.len(), 1);
    assert_eq!(report.alerts[0].refusal, expected);
    let store = Store::load(&household.store()).expect("store parses");
    assert_eq!(
        store.member(b"bob").expect("bob").state(),
        MemberState::AwaitingHouseholdKey
    );
}

#[test]
fn edited_enrollment_tag_is_refused() {
    refused_after_edit(Field::EnrollTag, Refusal::EnrollmentTagMismatch);
}

#[test]
fn edited_wrapped_enrollment_key_is_refused() {
    refused_after_edit(Field::EnrollKeyWrap, Refusal::EnrollmentKeyUnwrapFailed);
}

#[test]
fn enrollment_material_moved_to_another_member_is_refused() {
    let household = Household::new();
    let (_alice, alice_unlocked) = founded(&household);
    let _bob = added_and_enrolled(&household, &alice_unlocked, b"bob");
    let _carol = added_and_enrolled(&household, &alice_unlocked, b"carol");

    // Carol's genuine wrap and tag copied onto Bob's record: the wrap key and the AES-GCM
    // additional data both bind the member identifier.
    for field in [Field::EnrollKeyWrap, Field::EnrollTag] {
        let bobs = stored_field(&household.store(), b"bob", field);
        let carols = stored_field(&household.store(), b"carol", field);
        overwrite(&household.store(), &bobs, &carols);
    }

    let report = adult_unlock_wrap_pending(&household.store(), &alice_unlocked).expect("unlock");
    assert_eq!(report.wrapped, vec![b"carol".to_vec()]);
    assert_eq!(report.alerts.len(), 1);
    assert_eq!(report.alerts[0].member_id, b"bob".to_vec());
    assert_eq!(report.alerts[0].refusal, Refusal::EnrollmentKeyUnwrapFailed);
}

#[test]
fn enrollment_tag_moved_from_another_member_is_refused() {
    let household = Household::new();
    let (_alice, alice_unlocked) = founded(&household);
    let _bob = added_and_enrolled(&household, &alice_unlocked, b"bob");
    let _carol = added_and_enrolled(&household, &alice_unlocked, b"carol");

    let bobs = stored_field(&household.store(), b"bob", Field::EnrollTag);
    let carols = stored_field(&household.store(), b"carol", Field::EnrollTag);
    overwrite(&household.store(), &bobs, &carols);

    let report = adult_unlock_wrap_pending(&household.store(), &alice_unlocked).expect("unlock");
    assert_eq!(report.wrapped, vec![b"carol".to_vec()]);
    assert_eq!(report.alerts.len(), 1);
    assert_eq!(report.alerts[0].member_id, b"bob".to_vec());
    assert_eq!(report.alerts[0].refusal, Refusal::EnrollmentTagMismatch);
}

#[test]
fn inconsistent_record_raises_an_alert() {
    let household = Household::new();
    let (alice_unlocked, _bob) = with_active_bob(&household);

    // An active record that loses its HK wrap matches no ceremony state.
    remove_field(&household.store(), b"bob", Field::HkWrap);

    let report = adult_unlock_wrap_pending(&household.store(), &alice_unlocked).expect("unlock");
    assert!(report.wrapped.is_empty(), "nothing wrapped");
    assert!(report.stale.is_empty());
    assert_eq!(report.alerts.len(), 1);
    assert_eq!(report.alerts[0].member_id, b"bob".to_vec());
    assert_eq!(report.alerts[0].refusal, Refusal::InconsistentRecord);
}

#[test]
fn enrollment_under_another_hk_version_is_stale_not_tampering() {
    let household = Household::new();
    let (_alice, alice_unlocked) = founded(&household);
    let _bob = added_and_enrolled(&household, &alice_unlocked, b"bob");

    // Stands for an HK rotation between `member add` and this unlock, which the spike does
    // not implement: the wrap names an HK version other than the unlocking adult's.
    let honest = stored_field(&household.store(), b"bob", Field::EnrollKeyWrap);
    let mut other_version = honest.clone();
    other_version[WRAP_HK_VERSION_OFFSET + 3] ^= 0x03;
    overwrite(&household.store(), &honest, &other_version);

    let report = adult_unlock_wrap_pending(&household.store(), &alice_unlocked).expect("unlock");
    assert!(report.wrapped.is_empty(), "no HK wrap");
    assert!(report.alerts.is_empty(), "no tampering alert");
    assert_eq!(report.stale, vec![b"bob".to_vec()]);
    let store = Store::load(&household.store()).expect("store parses");
    assert_eq!(
        store.member(b"bob").expect("bob").state(),
        MemberState::AwaitingHouseholdKey
    );
}
