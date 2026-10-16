//! I/O matrix: further adult, honest path. `member add` by an unlocked adult, enrollment
//! with the token, then the next adult unlock verifies the tag, writes the permanent MAC
//! and wraps HK to the new public key.

mod common;

use ad36_key_prototype::{Field, MemberState, Store, adult_unlock_wrap_pending, unlock};
use common::{Household, added_and_enrolled, founded, with_active_bob};

#[test]
fn enrolled_adult_awaits_hk_until_the_next_adult_unlock() {
    let household = Household::new();
    let (_alice, alice_unlocked) = founded(&household);
    let bob = added_and_enrolled(&household, &alice_unlocked, b"bob");

    let store = Store::load(&household.store()).expect("store parses");
    let record = store.member(b"bob").expect("bob exists");
    assert_eq!(record.state(), MemberState::AwaitingHouseholdKey);
    assert!(
        record.encoded_field(Field::TokenCheck).is_none(),
        "token is single use"
    );
    assert!(
        unlock(&household.store(), &bob).is_err(),
        "no HK before the wrap"
    );
}

#[test]
fn next_adult_unlock_verifies_the_tag_and_wraps_hk() {
    let household = Household::new();
    let (alice_unlocked, bob) = with_active_bob(&household);

    let store = Store::load(&household.store()).expect("store parses");
    let record = store.member(b"bob").expect("bob exists");
    assert_eq!(record.state(), MemberState::Active);
    for discarded in [Field::EnrollKeyWrap, Field::EnrollTag] {
        assert!(
            record.encoded_field(discarded).is_none(),
            "{discarded:?} discarded"
        );
    }

    let bob_unlocked = unlock(&household.store(), &bob).expect("bob unlocks");
    assert_eq!(bob_unlocked.hk_version(), alice_unlocked.hk_version());

    let again = adult_unlock_wrap_pending(&household.store(), &alice_unlocked).expect("unlock");
    assert!(
        again.wrapped.is_empty() && again.alerts.is_empty(),
        "nothing left pending"
    );
}

#[test]
fn both_adults_hold_the_same_household_key() {
    let household = Household::new();
    let (alice_unlocked, bob) = with_active_bob(&household);
    let bob_unlocked = unlock(&household.store(), &bob).expect("bob unlocks");

    // Bob authorizes Carol under the HK he unwrapped; Alice's unlock can only open Carol's
    // enrollment key if her HK is the same key.
    let carol = added_and_enrolled(&household, &bob_unlocked, b"carol");
    let report = adult_unlock_wrap_pending(&household.store(), &alice_unlocked).expect("unlock");
    assert_eq!(report.wrapped, vec![b"carol".to_vec()]);
    assert!(report.alerts.is_empty());
    assert!(unlock(&household.store(), &carol).is_ok());
}
