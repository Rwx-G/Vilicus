//! I/O matrix: public key and permanent MAC edited after the first wrap. A later HK wrap
//! or re-wrap is refused.

mod common;

use ad36_key_prototype::{Error, Field, rewrap_household_key, unlock};
use common::{
    Household, attacker_keys, overwrite, stored_field, with_active_bob, with_last_byte_flipped,
    with_value,
};

/// Offset of the HK version inside an encoded permanent MAC, after `version, alg_id`.
const MAC_HK_VERSION_OFFSET: usize = 2;

#[test]
fn honest_rewrap_succeeds() {
    let household = Household::new();
    let (alice_unlocked, bob) = with_active_bob(&household);
    rewrap_household_key(&household.store(), &alice_unlocked, b"bob").expect("rewrap");
    assert!(unlock(&household.store(), &bob).is_ok());
}

#[test]
fn rewrap_after_public_key_and_mac_edit_is_refused() {
    let household = Household::new();
    let (alice_unlocked, bob) = with_active_bob(&household);
    let (_elsewhere, mallory) = attacker_keys();

    let honest_pk = stored_field(&household.store(), b"bob", Field::MemberPublicKey);
    overwrite(
        &household.store(),
        &honest_pk,
        &with_value(&honest_pk, &mallory.member_public_key()),
    );
    let honest_mac = stored_field(&household.store(), b"bob", Field::PubkeyMac);
    overwrite(
        &household.store(),
        &honest_mac,
        &with_last_byte_flipped(&honest_mac),
    );
    let wrap_before = stored_field(&household.store(), b"bob", Field::HkWrap);

    assert!(matches!(
        rewrap_household_key(&household.store(), &alice_unlocked, b"bob"),
        Err(Error::PublicKeyMacMismatch)
    ));
    assert!(
        stored_field(&household.store(), b"bob", Field::HkWrap) == wrap_before,
        "no new HK wrap"
    );
    assert!(
        unlock(&household.store(), &bob).is_err(),
        "the edited record no longer opens"
    );
}

#[test]
fn another_members_mac_copied_onto_the_record_is_refused() {
    let household = Household::new();
    let (alice_unlocked, _bob) = with_active_bob(&household);

    // A genuine MAC from another record: its key derivation binds the member identifier.
    let alices_mac = stored_field(&household.store(), b"alice", Field::PubkeyMac);
    let bobs_mac = stored_field(&household.store(), b"bob", Field::PubkeyMac);
    overwrite(&household.store(), &bobs_mac, &alices_mac);

    assert!(matches!(
        rewrap_household_key(&household.store(), &alice_unlocked, b"bob"),
        Err(Error::PublicKeyMacMismatch)
    ));
}

#[test]
fn mac_relabelled_to_another_hk_version_is_refused() {
    let household = Household::new();
    let (alice_unlocked, _bob) = with_active_bob(&household);

    let honest_mac = stored_field(&household.store(), b"bob", Field::PubkeyMac);
    let mut relabelled = honest_mac.clone();
    relabelled[MAC_HK_VERSION_OFFSET + 3] ^= 0x02;
    overwrite(&household.store(), &honest_mac, &relabelled);

    assert!(matches!(
        rewrap_household_key(&household.store(), &alice_unlocked, b"bob"),
        Err(Error::PublicKeyMacMismatch)
    ));
}

#[test]
fn unlock_refuses_an_edited_inbox_public_key_of_an_active_member() {
    let household = Household::new();
    let (_alice_unlocked, bob) = with_active_bob(&household);
    let (_elsewhere, mallory) = attacker_keys();

    // MAC and HK wrap untouched: the wrap still opens, the member's own MAC check refuses.
    let honest = stored_field(&household.store(), b"bob", Field::InboxPublicKey);
    overwrite(
        &household.store(),
        &honest,
        &with_value(&honest, &mallory.inbox_public_key()),
    );

    assert!(matches!(
        unlock(&household.store(), &bob),
        Err(Error::PublicKeyMacMismatch)
    ));
}
