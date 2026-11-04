//! Story 4.3: the file keys of AC1, the instance and audit key derivations of AC3, the member DEK
//! wrappers of AC4, and the registry that holds every derivation and label of the crate.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use vilicus_types::{Id, ModuleName, Partition, UtcMillis};

use super::*;
use crate::test_support::hex;
use crate::wrapper::{Kdf, KekDerivation};

/// A key holding `bytes`, planted in a slot of the pool.
fn key_of(bytes: [u8; 32]) -> SymmetricKey {
    let mut slot = Slot::new().expect("slot");
    slot.with_key_mut(|key| *key = bytes).expect("planted");
    SymmetricKey::from_slot(slot)
}

fn bytes_of(key: &impl HoldsKey) -> [u8; 32] {
    key.symmetric()
        .slot()
        .with_key(|bytes| *bytes)
        .expect("read")
}

fn sequence() -> [u8; 32] {
    core::array::from_fn(|index| u8::try_from(index).expect("small"))
}

fn member() -> Id {
    "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"
        .parse()
        .expect("test id")
}

fn household(bytes: [u8; 32], version: u32) -> HouseholdKey {
    HouseholdKey::from_key(key_of(bytes), version)
}

fn dek(bytes: [u8; 32], member: Id, version: u32) -> MemberDek {
    MemberDek {
        key: key_of(bytes),
        member,
        version,
    }
}

fn home(bytes: [u8; 32], version: u32) -> HomePartitionRoot {
    HomePartitionRoot {
        key: key_of(bytes),
        version,
    }
}

/// The derivations pinned against HKDF-SHA-256 computed with Python's `hmac` and `hashlib`, an
/// implementation independent of aws-lc-rs, from the root 0x00..0x1f: the `info` layout of D153
/// with each context part this module states.
#[test]
fn each_derivation_matches_a_known_answer() {
    let root = sequence();
    let instance = InstanceKey {
        key: key_of(root),
        version: 1,
    };
    let audit = AuditKey { key: key_of(root) };
    let tasks = ModuleName::from_static("tasks");
    let cases: [(&str, [u8; 32]); 6] = [
        (
            "b421e6334792c6e038b770df07a85de3f5d84555ea420138d7b525cfdb85b9f8",
            bytes_of(&instance.home_partition_root().expect("home root")),
        ),
        (
            "2b0fbb431592523b2ea237425f5c8c4ca4831e45dcfb0a74cb20c8fc3154b686",
            bytes_of(&instance.core_metadata_key().expect("core.db key")),
        ),
        (
            "a3a285aba2422c1fac9dede6dd1e169203868e5af031a3d72920a3e5d3d4cef4",
            bytes_of(&audit.database_key().expect("audit.db key")),
        ),
        (
            "f4326520699464ddeee274afefbd82d8bd878b0246e231b6dfb7658263d995f6",
            bytes_of(&household(root, 1).file_key(&tasks, 0).expect("file key")),
        ),
        (
            "415d980419e3d82209468790b56a03b026f11a78523aa1a3c1b8a6953b17148d",
            bytes_of(
                &dek(root, member(), 2)
                    .file_key(&tasks, 5)
                    .expect("file key"),
            ),
        ),
        (
            "f9ffe031a3d8a97c36c35717266bd73e18f421be12616fa9cc873b0e3207bfb3",
            bytes_of(&household(root, 3).wrapper_set_key().expect("set key")),
        ),
    ];
    for (expected, derived) in cases {
        assert_eq!(derived.to_vec(), hex(expected));
    }
}

/// A deterministic generator for the property test: xorshift64*, never a key source.
struct Cases(u64);

impl Cases {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// One module file at one key epoch, as the property test draws it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct FileAt {
    module: &'static str,
    partition: Partition,
    version: u32,
    generation: u32,
}

/// AC1 (D3, AD-5), as a property: over files drawn at random, every root built from the same 256
/// bits, two different files or epochs never get one key. The draw is narrow on purpose (four
/// modules, three partitions, two versions, three generations) so that most pairs share all but
/// one field: two files of one partition, the same module in two partitions, one file at two
/// epochs.
#[test]
fn no_two_files_or_epochs_share_a_key() {
    const MODULES: [&str; 4] = ["tasks", "calendar", "meals", "tasks2"];
    let root = sequence();
    let members = [
        member(),
        "017f22e2-79b0-7cc3-98c4-dc0c0c073990"
            .parse()
            .expect("test id"),
    ];
    let mut cases = Cases(0x5649_4c49_4355_5334);
    let mut seen: HashMap<[u8; 32], FileAt> = HashMap::new();
    let mut distinct = BTreeSet::new();
    for _ in 0..400 {
        let module = MODULES[usize::try_from(cases.below(4)).expect("small")];
        let partition = match cases.below(4) {
            0 => Partition::Household,
            1 => Partition::Home,
            pick => Partition::Member(members[usize::try_from(pick - 2).expect("small")]),
        };
        let version = u32::try_from(cases.below(2)).expect("small") + 1;
        let generation = u32::try_from(cases.below(3)).expect("small");
        let name = ModuleName::from_static(module);
        let key = match partition {
            Partition::Household => household(root, version).file_key(&name, generation),
            Partition::Home => home(root, version).file_key(&name, generation),
            Partition::Member(id) => dek(root, id, version).file_key(&name, generation),
        }
        .expect("file key");
        assert_eq!(key.partition(), partition);
        assert_eq!(key.module(), &name);
        assert_eq!(
            (key.partition_root_version(), key.generation()),
            (version, generation)
        );
        assert_eq!(key.role(), Role::FileKey(PartitionKind::of(partition)));
        let file = FileAt {
            module,
            partition,
            version,
            generation,
        };
        distinct.insert(format!("{file:?}"));
        if let Some(earlier) = seen.insert(bytes_of(&key), file.clone()) {
            assert_eq!(earlier, file, "two files share a key");
        }
    }
    assert_eq!(seen.len(), distinct.len());
    assert!(
        distinct.len() > 60,
        "the draw covers {} files",
        distinct.len()
    );
}

/// The roles a derivation chain of [`DERIVATIONS`] reaches from `start`, `start` included.
fn reached_from(start: Role) -> Vec<Role> {
    let mut reached = vec![start];
    loop {
        let before = reached.len();
        for derivation in DERIVATIONS {
            if reached.iter().any(|role| role.is(derivation.parent))
                && !reached.iter().any(|role| role.is(derivation.child))
            {
                reached.push(derivation.child);
            }
        }
        if reached.len() == before {
            return reached;
        }
    }
}

/// Every label of the crate's source with the role of the key it is used with: each derivation's
/// label under its parent, and the purposes and MAC domains under the key they bind.
fn every_label() -> Vec<(Label, Role)> {
    let mut labels: Vec<(Label, Role)> = DERIVATIONS.iter().map(|d| (d.label, d.parent)).collect();
    labels.push((MEMBER_DEK_WRAP, Role::MemberDek));
    labels.push((crate::wrapper_set::SET_MAC_DOMAIN, Role::WrapperSetKey));
    labels
}

/// AC3 (D9), over every label of the crate: no chain of derivations from the instance key (nor
/// from the audit key) reaches a member DEK, the household key, a personal or household file key
/// or the household key's set MAC key, and the roots it does reach open the home partition only.
#[test]
fn no_derivation_from_the_instance_key_opens_a_personal_or_household_file() {
    let personal_or_household = [
        Role::MemberDek,
        Role::HouseholdKey,
        Role::FileKey(PartitionKind::Personal),
        Role::FileKey(PartitionKind::Household),
        Role::WrapperSetKey,
    ];
    for start in [Role::InstanceKey, Role::AuditKey] {
        let reached = reached_from(start);
        for (label, role) in every_label() {
            if reached.iter().any(|reached| reached.is(role)) {
                let children: Vec<Role> = DERIVATIONS
                    .iter()
                    .filter(|d| d.label.as_str() == label.as_str() && d.parent.is(role))
                    .map(|d| d.child)
                    .collect();
                for child in children {
                    assert!(
                        !personal_or_household.iter().any(|kept| kept.is(child)),
                        "{} from {start:?} reaches {child:?}",
                        label.as_str()
                    );
                }
            }
        }
        assert!(
            !reached
                .iter()
                .any(|role| personal_or_household.iter().any(|kept| kept.is(*role))),
            "{start:?} reaches {reached:?}"
        );
    }
    let instance = InstanceKey {
        key: key_of(sequence()),
        version: 4,
    };
    let root = instance.home_partition_root().expect("home root");
    assert_eq!((root.partition(), root.version()), (Partition::Home, 4));
    let key = root
        .file_key(&ModuleName::from_static("home"), 0)
        .expect("home file key");
    assert_eq!(key.partition(), Partition::Home);
    let core = instance.core_metadata_key().expect("core.db key");
    assert_eq!(core.database(), Database::CoreMetadata);
}

/// The text of every source file of the crate outside its tests, each with its path.
fn sources() -> Vec<(PathBuf, String)> {
    fn walk(directory: &Path, found: &mut Vec<(PathBuf, String)>) {
        for entry in fs::read_dir(directory).expect("source directory") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                walk(&path, found);
            } else if path.extension().is_some_and(|e| e == "rs")
                && path.file_name().is_some_and(|n| n != "tests.rs")
            {
                let text = fs::read_to_string(&path).expect("source file");
                found.push((path, text));
            }
        }
    }
    let mut found = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut found,
    );
    found
}

/// Every label built in the crate's code, doc comments and test modules left out, is one of
/// [`every_label`]: a new label is registered with its role or this fails, so the AC3 test runs
/// over every label there is.
#[test]
fn every_label_of_the_crate_is_registered() {
    let registered: BTreeSet<&str> = every_label().iter().map(|(l, _)| l.as_str()).collect();
    let mut built = BTreeSet::new();
    for (path, text) in sources() {
        for line in text.lines().filter(|l| !l.trim_start().starts_with("//")) {
            for (index, _) in line.match_indices("label!(\"") {
                let rest = &line[index + "label!(\"".len()..];
                let label = &rest[..rest.find('"').expect("closing quote")];
                assert!(
                    registered.contains(label),
                    "{label} in {} is not registered",
                    path.display()
                );
                built.insert(label.to_string());
            }
        }
    }
    let built: BTreeSet<&str> = built.iter().map(String::as_str).collect();
    assert_eq!(built, registered);
}

/// Every `Derivation` constant of the source is in [`DERIVATIONS`], so the AC3 test reads them all.
#[test]
fn every_derivation_is_registered() {
    let text = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/hierarchy.rs"))
        .expect("hierarchy.rs");
    let defined: BTreeSet<&str> = text
        .lines()
        .filter_map(|line| line.strip_prefix("pub(crate) const "))
        .filter_map(|rest| rest.strip_suffix(": Derivation = Derivation {"))
        .collect();
    let start = text.find("const DERIVATIONS").expect("registry");
    let registry = &text[start..start + text[start..].find("];").expect("end of the registry")];
    let listed: BTreeSet<&str> = registry
        .lines()
        .skip(1)
        .map(|line| line.trim().trim_end_matches(','))
        .filter(|name| !name.is_empty())
        .collect();
    assert_eq!(defined, listed);
    assert_eq!(listed.len(), DERIVATIONS.len());
}

/// The crate documentation's table of the hierarchy names every registered label, and no other.
#[test]
fn the_documented_hierarchy_is_the_registry() {
    let text = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
        .expect("lib.rs");
    let documented: BTreeSet<&str> = text
        .lines()
        .filter(|line| line.starts_with("//! | "))
        .flat_map(|line| line.split('`').skip(1).step_by(2))
        .filter(|code| code.starts_with(Label::PREFIX))
        .collect();
    let registered: BTreeSet<&str> = DERIVATIONS.iter().map(|d| d.label.as_str()).collect();
    assert_eq!(documented, registered);
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vilicus-crypto-{}-{name}", std::process::id()));
    fs::create_dir_all(&dir).expect("scratch directory");
    dir.join("credential")
}

/// The instance key is read from its credential straight into the pool; a credential that is not
/// exactly 32 bytes, or that cannot be read, is refused.
#[test]
fn a_credential_holds_exactly_one_key() {
    let path = scratch("credential");
    fs::write(&path, sequence()).expect("credential");
    let instance = InstanceKey::from_credential(&path, 7).expect("instance key");
    assert_eq!((bytes_of(&instance), instance.version()), (sequence(), 7));
    let audit = AuditKey::from_credential(&path).expect("audit key");
    assert_eq!(bytes_of(&audit), sequence());
    for len in [0, 31, 33, 64] {
        fs::write(&path, vec![0x5a; len]).expect("credential");
        assert_eq!(
            InstanceKey::from_credential(&path, 1).err(),
            Some(CryptoError::CredentialLength),
            "{len} bytes"
        );
    }
    fs::remove_file(&path).expect("remove");
    assert_eq!(
        InstanceKey::from_credential(&path, 1).err(),
        Some(CryptoError::Credential { errno: 2 })
    );
}

fn params() -> WrapParams {
    let created_at = UtcMillis::from_millis(1_793_577_600_000).expect("time");
    WrapParams::new(
        Kdf::None,
        KekDerivation::Direct,
        Vec::new(),
        created_at,
        Id::new_v7(created_at, [7; 10]).expect("id"),
    )
    .expect("params")
}

/// A member DEK wrapper opens with its KEK as that member's DEK of that version only.
#[test]
fn a_member_dek_wrapper_opens_only_as_its_member_and_version() {
    let kek = SymmetricKey::generate().expect("kek");
    let original = MemberDek::generate(member(), 2).expect("dek");
    let stored = original.wrap(&kek, params()).expect("wrap").to_bytes();
    let wrapper = Wrapper::from_bytes(&stored).expect("read back");
    let opened = MemberDek::unwrap(&wrapper, &kek, member(), 2).expect("unwrap");
    assert_eq!(bytes_of(&opened), bytes_of(&original));
    assert_eq!((opened.member(), opened.version()), (member(), 2));
    let other: Id = "017f22e2-79b0-7cc3-98c4-dc0c0c073990"
        .parse()
        .expect("test id");
    let other_kek = SymmetricKey::generate().expect("kek");
    for refused in [
        MemberDek::unwrap(&wrapper, &kek, other, 2),
        MemberDek::unwrap(&wrapper, &kek, member(), 3),
        MemberDek::unwrap(&wrapper, &other_kek, member(), 2),
    ] {
        assert_eq!(refused.err(), Some(CryptoError::Open));
    }
    let purpose = crate::label!("vilicus/v1/wrap/member-private-key");
    assert_eq!(
        wrapper
            .unwrap_key(&kek, purpose, &MemberDek::wrap_context(member(), 2))
            .err(),
        Some(CryptoError::Open)
    );
}
