//! Story 4.3: module files keyed from their partition root at their epoch (AC1, AC2, AC3), and
//! `wrappers.db`, which needs neither `core.db` nor the instance key (AC4) and whose record set is
//! authenticated as a whole (the decision task, gate AD36-1).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use vilicus_crypto::{InstanceKey, MemberDek, PartitionRoot};
use vilicus_storage::{KeyEpoch, ModuleFile, Read, Write};
use vilicus_types::{Id, ModuleName, Partition};

use super::*;

/// Hardens the test process and locks its key pool once, as the Core's start does
/// (`vilicus_crypto::start_key_memory`, D154), so the tests can hold keys.
fn key_memory() {
    static STARTED: std::sync::Once = std::sync::Once::new();
    STARTED.call_once(|| {
        vilicus_crypto::harden_process().expect("hardened");
        match vilicus_crypto::lock_key_memory() {
            Ok(()) | Err(vilicus_crypto::KeyMemoryError::AlreadyLocked) => {}
            Err(error) => panic!("the key pool of the tests: {error}"),
        }
    });
}

static NEXT_DIR: AtomicU32 = AtomicU32::new(0);

fn scratch(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "vilicus-core-keys-{}-{}-{label}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).expect("scratch directory");
    dir
}

fn member(last: u8) -> Id {
    let mut bytes = *b"\x01\x7f\x22\xe2\x79\xb0\x7c\xc3\x98\xc4\xdc\x0c\x0c\x07\x39\x00";
    bytes[15] = last;
    Id::from_bytes(bytes).expect("a UUIDv7")
}

fn tasks() -> ModuleName {
    ModuleName::from_static("tasks")
}

/// The storage layer's key text length is the one `vilicus-crypto` writes, which neither crate
/// can read from the other (AD-3).
#[test]
fn the_storage_layer_takes_the_key_text_the_key_memory_writes() {
    assert_eq!(
        vilicus_storage::KEY_TEXT_LEN,
        vilicus_crypto::SQLCIPHER_KEY_TEXT_LEN
    );
}

/// AC1 and AC2: a personal module file is created under the key its member's DEK derives for it,
/// at the epoch that key carries, written in the sidecar and in `_meta`; it opens again with the
/// key derived from the sidecar's epoch, and with no other: another module's key, another
/// member's DEK, another version of the DEK are each refused with their typed error.
#[test]
fn a_file_opens_with_the_key_its_root_derives_at_its_epoch() {
    key_memory();
    let dir = scratch("ac1-open");
    let dek = MemberDek::generate(member(1), 1).expect("dek");
    let file = ModuleFile::new(&dir, tasks(), Partition::Member(member(1)));
    let created = dek.file_key(&tasks(), 0).expect("file key");
    create_file(&file, &created)
        .expect("create")
        .close()
        .expect("close");
    let epoch = KeyEpoch {
        partition_root_version: 1,
        generation: 0,
    };
    assert_eq!(vilicus_storage::read_epoch(&file).expect("sidecar"), epoch);
    let key = file_key(&dek, &file).expect("file key");
    assert_eq!(epoch_of(&key), epoch);
    open_file::<Read>(&file, &key)
        .expect("open")
        .close()
        .expect("close");

    let calendar = dek
        .file_key(&ModuleName::from_static("calendar"), 0)
        .expect("other module");
    assert!(matches!(
        open_file::<Read>(&file, &calendar),
        Err(KeyError::OtherModule)
    ));
    let other = MemberDek::generate(member(2), 1).expect("other dek");
    assert!(matches!(
        file_key(&other, &file),
        Err(KeyError::OtherPartition { .. })
    ));
    let other_key = other.file_key(&tasks(), 0).expect("other member's key");
    assert!(matches!(
        open_file::<Read>(&file, &other_key),
        Err(KeyError::OtherPartition { .. })
    ));
    let rotated = MemberDek::generate(member(1), 2).expect("rotated dek");
    assert!(matches!(
        file_key(&rotated, &file),
        Err(KeyError::OtherEpoch { file: found, .. }) if found == epoch
    ));
}

/// AC2: a re-key under the key of the next generation writes the new epoch in the sidecar and in
/// `_meta`; the old key no longer opens the file, the key derived from the new epoch does, and a
/// sidecar edited to disagree with `_meta` refuses the open with its typed error.
#[test]
fn a_rekey_moves_the_file_to_the_key_of_its_next_generation() {
    key_memory();
    let dir = scratch("ac2-rekey");
    let dek = MemberDek::generate(member(1), 1).expect("dek");
    let file = ModuleFile::new(&dir, tasks(), Partition::Member(member(1)));
    let first = dek.file_key(&tasks(), 0).expect("file key");
    let mut handle = create_file(&file, &first).expect("create");
    let next = dek.file_key(&tasks(), 1).expect("next generation");
    rekey_file(&mut handle, &next).expect("rekey");
    handle.close().expect("close");
    let epoch = KeyEpoch {
        partition_root_version: 1,
        generation: 1,
    };
    assert_eq!(vilicus_storage::read_epoch(&file).expect("sidecar"), epoch);
    assert!(matches!(
        open_file::<Read>(&file, &first),
        Err(KeyError::Storage(vilicus_storage::Error::WrongKey))
    ));
    let derived = file_key(&dek, &file).expect("key of the new epoch");
    assert_eq!(epoch_of(&derived), epoch);
    open_file::<Write>(&file, &derived)
        .expect("open")
        .close()
        .expect("close");
    fs::write(
        file.epoch_path(),
        "vilicus key epoch 1\npartition_root_version 1\ngeneration 0\n",
    )
    .expect("edit the sidecar");
    assert!(matches!(
        open_file::<Read>(&file, &derived),
        Err(KeyError::Storage(
            vilicus_storage::Error::EpochMismatch { .. }
        ))
    ));
}

/// AC3: the home partition root, from the instance key read from its credential, keys the home
/// partition's files only: its key is refused for a household or personal file before any key
/// text is lent.
#[test]
fn the_instance_key_keys_no_personal_or_household_file() {
    key_memory();
    let dir = scratch("ac3-instance");
    let credential = dir.join("instance-key");
    fs::write(&credential, [0x42; 32]).expect("credential");
    let instance = InstanceKey::from_credential(&credential, 1).expect("instance key");
    let root = instance.home_partition_root().expect("home root");
    let home = ModuleFile::new(&dir, ModuleName::from_static("home"), Partition::Home);
    create_file(&home, &root.file_key(home.module(), 0).expect("home key"))
        .expect("create")
        .close()
        .expect("close");
    open_file::<Read>(&home, &file_key(&root, &home).expect("home key"))
        .expect("open")
        .close()
        .expect("close");
    for partition in [Partition::Household, Partition::Member(member(1))] {
        let file = ModuleFile::new(&dir, ModuleName::from_static("home"), partition);
        assert!(matches!(
            file_key(&root, &file),
            Err(KeyError::OtherPartition { .. })
        ));
        let key = root.file_key(file.module(), 0).expect("home key");
        assert!(matches!(
            create_file(&file, &key),
            Err(KeyError::OtherPartition { .. })
        ));
        assert!(!file.path().exists());
    }
}

/// The tests below hold a household key, whose creation is story 4.6's: `vilicus_crypto::testing`
/// stands in for it, which the workspace's test build compiles through the testbed's `testing`
/// feature.
#[cfg(feature = "testing")]
mod with_the_household_key {
    use rusqlite::Connection;
    use vilicus_crypto::testing;
    use vilicus_storage::{KekKind, PublicKeyKind, PublicKeyRow, WRAPPERS_FILE_NAME};
    use vilicus_types::UtcMillis;

    use super::*;

    fn wrap_params(seed: u8) -> (UtcMillis, Id) {
        let created_at = UtcMillis::from_millis(1_793_577_600_000).expect("time");
        (created_at, Id::new_v7(created_at, [seed; 10]).expect("id"))
    }

    fn dek_wrapper(dek: &MemberDek, kind: KekKind, kek: &SymmetricKey, seed: u8) -> WrapperChange {
        let (created_at, id) = wrap_params(seed);
        Wrappers::dek_wrapper_change(
            dek,
            kind,
            kek,
            Kdf::None,
            KekDerivation::Direct,
            Vec::new(),
            created_at,
            id,
        )
        .expect("wrapper change")
    }

    fn key_bytes(dek: &MemberDek) -> [u8; 32] {
        testing::with_key(dek, |bytes| *bytes).expect("read")
    }

    fn raw(dir: &Path) -> Connection {
        Connection::open(dir.join(WRAPPERS_FILE_NAME)).expect("open with no key")
    }

    /// Writes `changes`, verified and sealed under the one `set_key`, and returns the counter.
    fn write(wrappers: &mut Wrappers, set_key: &WrapperSetKey, changes: &[WrapperChange]) -> u64 {
        let written = wrappers.write(set_key, set_key, changes).expect("write");
        assert!(written.checkpoint.is_none(), "{:?}", written.checkpoint);
        written.counter
    }

    /// AC4 (D4, AD-4): `wrappers.db` holds a member's DEK wrapper under each KEK in a file of its
    /// own, beside no `core.db`, and the DEK unwraps from it with the KEK alone: with `core.db`
    /// and the instance key lost, the counter is unchecked, the DEK comes back, before the set is
    /// verified for the unlocking member's own wrapper and through the verified set afterwards,
    /// and it derives the key that opens the member's personal file.
    #[test]
    fn a_member_dek_unwraps_without_core_db_or_the_instance_key() {
        key_memory();
        let dir = scratch("ac4-unwrap");
        let hk = testing::household_key(1).expect("household key");
        let set_key = hk.wrapper_set_key().expect("set key");
        let dek = MemberDek::generate(member(1), 1).expect("dek");
        let passphrase_kek = SymmetricKey::generate().expect("passphrase kek");
        let recovery_kek = SymmetricKey::generate().expect("recovery kek");
        let file = ModuleFile::new(&dir, tasks(), Partition::Member(member(1)));
        create_file(&file, &dek.file_key(&tasks(), 0).expect("key"))
            .expect("create")
            .close()
            .expect("close");
        let mut wrappers = Wrappers::create(&dir).expect("create wrappers.db");
        let changes = [
            dek_wrapper(&dek, KekKind::Passphrase, &passphrase_kek, 1),
            dek_wrapper(&dek, KekKind::Recovery, &recovery_kek, 2),
        ];
        assert_eq!(write(&mut wrappers, &set_key, &changes), 1);
        wrappers.close().expect("close");
        let original = key_bytes(&dek);
        drop(dek);

        assert!(!dir.join("core.db").exists());
        let wrappers = Wrappers::open(&dir).expect("open wrappers.db");
        for (kind, kek) in [
            (KekKind::Passphrase, &passphrase_kek),
            (KekKind::Recovery, &recovery_kek),
        ] {
            let own = wrappers
                .unwrap_own_dek(member(1), kind, kek)
                .expect("unwrap")
                .expect("a wrapper of that kind");
            assert_eq!(key_bytes(&own), original);
            open_file::<Read>(&file, &file_key(&own, &file).expect("file key"))
                .expect("the member's file opens")
                .close()
                .expect("close");
        }
        let verified = wrappers.open_verified(&set_key, None).expect("verified");
        assert_eq!(verified.counter_check(), CounterCheck::Unchecked);
        let dek = verified
            .unwrap_member_dek(member(1), KekKind::Recovery, &recovery_kek)
            .expect("unwrap")
            .expect("the wrapper");
        assert_eq!(key_bytes(&dek), original);
        assert!(matches!(
            wrappers.unwrap_own_dek(member(1), KekKind::Passphrase, &recovery_kek),
            Err(KeyError::Crypto(CryptoError::Open))
        ));
        assert!(
            verified
                .unwrap_member_dek(member(2), KekKind::Passphrase, &passphrase_kek)
                .expect("read")
                .is_none()
        );
        let row = vilicus_storage::open_wrappers(&dir)
            .expect("open")
            .own_dek_wrapper(member(1), KekKind::Passphrase)
            .expect("read")
            .expect("row");
        let stored = Wrapper::from_bytes(&row.wrapper).expect("a versioned wrapper");
        assert_eq!(
            (stored.version(), stored.kdf(), stored.aead().id()),
            (vilicus_crypto::FORMAT_VERSION, Kdf::None, 0x0001)
        );
        assert_eq!(row.dek_version, 1);
    }

    /// The decision task (gate AD36-1): what an attacker who writes `wrappers.db` but holds no
    /// household key can do to the set is seen. A deleted record, an edited counter and a removed
    /// MAC fail the set's check, and a write over such a set is refused, so the Core never seals
    /// it; an older copy of the file, whose MAC was valid for its own counter, is refused by the
    /// counter `core.db` keeps.
    #[test]
    fn a_deleted_record_or_an_older_file_is_seen() {
        key_memory();
        let dir = scratch("ad36-1-set");
        let hk = testing::household_key(1).expect("household key");
        let set_key = hk.wrapper_set_key().expect("set key");
        let kek = SymmetricKey::generate().expect("kek");
        let first = MemberDek::generate(member(1), 1).expect("dek");
        let second = MemberDek::generate(member(2), 1).expect("dek");
        let mut wrappers = Wrappers::create(&dir).expect("create");
        assert_eq!(
            wrappers
                .open_verified(&set_key, Some(0))
                .expect("a fresh file")
                .counter(),
            0
        );
        let changes = [
            dek_wrapper(&first, KekKind::Passphrase, &kek, 1),
            WrapperChange::PutPublicKey(PublicKeyRow {
                member: member(1),
                kind: PublicKeyKind::Member,
                generation: 0,
                public_key: vec![0x00, 0x01, 0x00, 0x20, 0x07],
            }),
        ];
        write(&mut wrappers, &set_key, &changes);
        wrappers.close().expect("close");
        let older = fs::read(dir.join(WRAPPERS_FILE_NAME)).expect("copy of the file at counter 1");
        let mut wrappers = Wrappers::open(&dir).expect("open");
        let second_wrapper = [dek_wrapper(&second, KekKind::Passphrase, &kek, 2)];
        assert_eq!(write(&mut wrappers, &set_key, &second_wrapper), 2);
        let verified = wrappers.open_verified(&set_key, Some(2)).expect("verifies");
        assert_eq!(
            (verified.counter(), verified.counter_check()),
            (2, CounterCheck::Matches)
        );
        assert_eq!(verified.public_keys().len(), 1);
        assert_eq!(
            wrappers
                .open_verified(&set_key, Some(1))
                .expect("verifies")
                .counter_check(),
            CounterCheck::Ahead { by: 1 }
        );
        wrappers.close().expect("close");

        let other_hk = testing::household_key(1).expect("another household key");
        let wrappers = Wrappers::open(&dir).expect("open");
        assert!(matches!(
            wrappers.open_verified(&other_hk.wrapper_set_key().expect("set key"), Some(2)),
            Err(KeyError::SetMac(CryptoError::Mac))
        ));
        drop(wrappers);

        raw(&dir)
            .execute_batch(
                "DELETE FROM member_dek_wrappers WHERE kek_kind = 1 AND member_id = (SELECT max(member_id) FROM member_dek_wrappers)",
            )
            .expect("delete a record");
        let mut wrappers = Wrappers::open(&dir).expect("open");
        assert!(matches!(
            wrappers.open_verified(&set_key, Some(2)),
            Err(KeyError::SetMac(CryptoError::Mac))
        ));
        assert!(matches!(
            wrappers.write(
                &set_key,
                &set_key,
                &[dek_wrapper(&second, KekKind::Recovery, &kek, 3)]
            ),
            Err(KeyError::SetMac(CryptoError::Mac))
        ));
        drop(wrappers);
        assert_eq!(
            raw(&dir)
                .query_row("SELECT counter FROM wrapper_set", [], |row| row
                    .get::<_, i64>(0))
                .expect("counter"),
            2,
            "the refused write left the counter"
        );

        fs::write(dir.join(WRAPPERS_FILE_NAME), &older).expect("restore the older file");
        let wrappers = Wrappers::open(&dir).expect("open");
        assert_eq!(
            wrappers
                .open_verified(&set_key, None)
                .expect("its own MAC holds")
                .counter(),
            1
        );
        assert!(matches!(
            wrappers.open_verified(&set_key, Some(2)),
            Err(KeyError::RolledBack {
                wrappers: 1,
                core: 2
            })
        ));
        drop(wrappers);
        raw(&dir)
            .execute_batch("UPDATE wrapper_set SET counter = 2")
            .expect("raise the counter to core.db's copy");
        let wrappers = Wrappers::open(&dir).expect("open");
        assert!(matches!(
            wrappers.open_verified(&set_key, Some(2)),
            Err(KeyError::SetMac(CryptoError::Mac))
        ));
        drop(wrappers);
        raw(&dir)
            .execute_batch("UPDATE wrapper_set SET mac = NULL")
            .expect("remove the MAC");
        let wrappers = Wrappers::open(&dir).expect("open");
        assert!(matches!(
            wrappers.open_verified(&set_key, Some(2)),
            Err(KeyError::Unsealed)
        ));
        drop(wrappers);
        raw(&dir)
            .execute_batch("UPDATE wrapper_set SET counter = 0")
            .expect("make it look fresh");
        let wrappers = Wrappers::open(&dir).expect("open");
        assert!(matches!(
            wrappers.open_verified(&set_key, None),
            Err(KeyError::Unsealed)
        ));
    }

    /// Story 4.3 review, H1, as the reviewer ran it: a victim rotates their recovery wrapper, an
    /// attacker who writes the disk plants a trigger that puts the old wrapper back when the Core
    /// next writes a passphrase wrapper. The planted file is refused at open and inside the next
    /// write, so the Core never seals the trigger's work: the new recovery KEK still opens the DEK
    /// and the old one does not.
    #[test]
    fn a_planted_trigger_never_runs_inside_a_sealed_write() {
        key_memory();
        let dir = scratch("h1-trigger");
        let hk = testing::household_key(1).expect("household key");
        let set_key = hk.wrapper_set_key().expect("set key");
        let dek = MemberDek::generate(member(1), 1).expect("dek");
        let passphrase = SymmetricKey::generate().expect("kek");
        let old_recovery = SymmetricKey::generate().expect("kek");
        let new_recovery = SymmetricKey::generate().expect("kek");
        let mut wrappers = Wrappers::create(&dir).expect("create");
        let first = [
            dek_wrapper(&dek, KekKind::Passphrase, &passphrase, 1),
            dek_wrapper(&dek, KekKind::Recovery, &old_recovery, 2),
        ];
        write(&mut wrappers, &set_key, &first);
        let old_row = vilicus_storage::open_wrappers(&dir)
            .expect("open")
            .own_dek_wrapper(member(1), KekKind::Recovery)
            .expect("read")
            .expect("row");
        let rotated = [dek_wrapper(&dek, KekKind::Recovery, &new_recovery, 3)];
        assert_eq!(write(&mut wrappers, &set_key, &rotated), 2);
        let mut old_hex = String::new();
        for byte in &old_row.wrapper {
            old_hex.push_str(&format!("{byte:02x}"));
        }
        let mut member_hex = String::new();
        for byte in member(1).to_bytes() {
            member_hex.push_str(&format!("{byte:02x}"));
        }
        raw(&dir)
            .execute_batch(&format!(
                "CREATE TRIGGER t AFTER INSERT ON member_dek_wrappers WHEN NEW.kek_kind = 1 \
                 BEGIN INSERT OR REPLACE INTO member_dek_wrappers \
                 VALUES (x'{member_hex}', 2, 1, x'{old_hex}'); END;"
            ))
            .expect("plant the trigger");
        assert!(matches!(
            wrappers.open_verified(&set_key, Some(2)),
            Err(KeyError::Storage(
                vilicus_storage::Error::WrappersSchemaChanged
            ))
        ));
        let next = [dek_wrapper(&dek, KekKind::Passphrase, &passphrase, 4)];
        assert!(matches!(
            wrappers.write(&set_key, &set_key, &next),
            Err(KeyError::Storage(
                vilicus_storage::Error::WrappersSchemaChanged
            ))
        ));
        drop(wrappers);
        assert!(matches!(
            Wrappers::open(&dir),
            Err(KeyError::Storage(
                vilicus_storage::Error::WrappersSchemaChanged
            ))
        ));
        raw(&dir)
            .execute_batch("DROP TRIGGER t;")
            .expect("drop the trigger");
        let wrappers = Wrappers::open(&dir).expect("open");
        let verified = wrappers.open_verified(&set_key, Some(2)).expect("verified");
        assert!(
            verified
                .unwrap_member_dek(member(1), KekKind::Recovery, &new_recovery)
                .expect("the new recovery KEK opens it")
                .is_some()
        );
        assert!(matches!(
            verified.unwrap_member_dek(member(1), KekKind::Recovery, &old_recovery),
            Err(KeyError::Crypto(CryptoError::Open))
        ));
    }

    /// A MAC computed under one household key version does not verify under the next, and a
    /// write verified under one key and sealed under the next re-seals the set for the next: the
    /// rewrite of a rotation (key management section 5).
    #[test]
    fn a_rotation_re_seals_the_set_under_the_next_household_key() {
        key_memory();
        let dir = scratch("ad36-1-version");
        let hk = testing::household_key(1).expect("household key");
        let next = testing::household_key(2).expect("next version");
        let (key, next_key) = (
            hk.wrapper_set_key().expect("set key"),
            next.wrapper_set_key().expect("set key"),
        );
        let kek = SymmetricKey::generate().expect("kek");
        let dek = MemberDek::generate(member(1), 1).expect("dek");
        let mut wrappers = Wrappers::create(&dir).expect("create");
        write(
            &mut wrappers,
            &key,
            &[dek_wrapper(&dek, KekKind::Passphrase, &kek, 1)],
        );
        assert!(matches!(
            wrappers.open_verified(&next_key, Some(1)),
            Err(KeyError::SetMac(CryptoError::HouseholdKeyVersion {
                stated: 1,
                held: 2
            }))
        ));
        let rewritten = wrappers
            .write(
                &key,
                &next_key,
                &[dek_wrapper(&dek, KekKind::Passphrase, &kek, 2)],
            )
            .expect("re-seal");
        assert_eq!(rewritten.counter, 2);
        assert_eq!(
            wrappers
                .open_verified(&next_key, Some(2))
                .expect("verifies under the next version")
                .counter(),
            2
        );
        assert!(matches!(
            wrappers.open_verified(&key, Some(2)),
            Err(KeyError::SetMac(CryptoError::HouseholdKeyVersion { .. }))
        ));
    }
}
