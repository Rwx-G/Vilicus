//! What the testbed's gates share: a household of partitions whose module files are created,
//! unlocked and brought up through the Core's own paths, a clock and ids fixed by the test, and
//! the calls the gates make (Story 3.10).

use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use vilicus_core::api::{ApiFiles, Apis, Layered, NoApiFiles};
use vilicus_core::availability::{Generation, ModuleStates, MonotonicClock};
use vilicus_core::boundary::Boundary;
use vilicus_core::bus::{DeliveryReport, Link, LinkTable, deliver_outbox};
use vilicus_core::handlers::Handlers;
use vilicus_core::record::{Authority, Call, Consumed, Invocation, Stamper};
use vilicus_core::registry::{FileToMigrate, Registry};
use vilicus_core::startup::{BringUpReport, Delivery, NothingToRekey, PartitionFiles, bring_up};
use vilicus_core::testing::{
    CallKey, KeyEpoch, ModuleFile, Partition, StorageError, create_module_file,
};
use vilicus_module_api::Value;
use vilicus_types::{
    CallId, HANDLER_TIME_BUDGET, Id, ModuleName, Principal, Source, Taint, UtcMillis,
};

/// Test key only; the Core derives one key per file.
pub(crate) const KEY: [u8; 32] = [0x5e; 32];

const EPOCH: KeyEpoch = KeyEpoch {
    partition_root_version: 1,
    generation: 0,
};

/// 2026-10-21T12:00:00Z.
const NOON: i64 = 1_792_584_000_000;

/// A monotonic clock that never moves: no call outlives its time budget, whatever the host's load.
struct StillClock;

impl MonotonicClock for StillClock {
    fn now(&self) -> Duration {
        Duration::ZERO
    }
}

/// The wall clock and the random bits of the ids the Core stamps: fixed by the test.
pub(crate) struct TestStamper {
    issued: u32,
}

impl Stamper for TestStamper {
    fn now(&mut self) -> UtcMillis {
        UtcMillis::from_millis(NOON).expect("in range")
    }

    fn id_random(&mut self) -> [u8; 10] {
        self.issued += 1;
        let mut random = [0; 10];
        random[6..].copy_from_slice(&self.issued.to_be_bytes());
        random
    }
}

/// A link table that keeps what it is asked to register.
#[derive(Default)]
pub(crate) struct Links(pub(crate) Vec<Link>);

impl LinkTable for Links {
    fn register(&mut self, link: &Link) -> Result<(), StorageError> {
        self.0.push(link.clone());
        Ok(())
    }
}

/// The member whose id ends with `last`.
pub(crate) fn member(last: u8) -> Id {
    let mut random = [0x3c; 10];
    random[9] = last;
    Id::new_v7(UtcMillis::from_millis(NOON).expect("in range"), random).expect("after the epoch")
}

pub(crate) fn ella() -> Id {
    member(1)
}

pub(crate) fn noe() -> Id {
    member(2)
}

/// A member's own action, from a web session (AD-8).
pub(crate) fn own_action(member: Id) -> Call {
    Call {
        principal: Principal::Member,
        source: Source::Member(member),
        session: Taint::Trusted,
        consumed: Consumed::NOTHING,
        authority: Authority::OwnAction { member },
        read: Vec::new(),
        implicit_inputs: Vec::new(),
    }
}

/// The key of `call`'s rows in the journal and the outbox of the file it wrote (AD-26).
pub(crate) fn key<'a>(call: &'a Call, invocation: &Invocation) -> CallKey<'a> {
    CallKey {
        principal: call.principal,
        source: &call.source,
        call_id: invocation.call_id,
    }
}

pub(crate) fn text(value: &str) -> Value {
    Value::Text(value.into())
}

/// A household: module files in each of its partitions, the availability states the Core holds
/// of them, and the files of each partition brought up, as the Core holds them once they serve.
pub(crate) struct House {
    directory: PathBuf,
    pub(crate) states: ModuleStates,
    stamper: RefCell<TestStamper>,
    pub(crate) links: RefCell<Links>,
    partitions: Vec<(Generation, PartitionFiles)>,
}

impl House {
    /// A new household under a scratch directory named after `label`, with a new file of every
    /// module of `registry` in each of `partitions`, none unlocked yet.
    pub(crate) fn new(label: &str, registry: &Registry, partitions: &[Partition]) -> Self {
        let directory =
            std::env::temp_dir().join(format!("vilicus-testbed-{label}-{}", std::process::id()));
        if directory.exists() {
            std::fs::remove_dir_all(&directory).expect("clear the scratch directory");
        }
        std::fs::create_dir_all(&directory).expect("create the scratch directory");
        for partition in partitions {
            for module in registry.modules() {
                let file =
                    ModuleFile::new(&directory, ModuleName::from_static(module.name), *partition);
                create_module_file(&file, &KEY, EPOCH).expect("create");
            }
        }
        Self {
            directory,
            states: ModuleStates::with_clock(Arc::new(StillClock)),
            stamper: RefCell::new(TestStamper { issued: 0 }),
            links: RefCell::new(Links::default()),
            partitions: Vec::new(),
        }
    }

    /// The file of `module` in `partition`.
    pub(crate) fn file(&self, module: &'static str, partition: Partition) -> ModuleFile {
        ModuleFile::new(&self.directory, ModuleName::from_static(module), partition)
    }

    /// Unlocks `partition` (FR-11, AD-54) and brings its files up with `registry` and `handlers`,
    /// as the Core does once the partition's keys are derived: re-key, migration, then delivery of
    /// each outbox, the consumers reading through the typed APIs of the partition's files, then of
    /// the household's. The partition must not be up already.
    pub(crate) fn unlock(
        &mut self,
        partition: Partition,
        registry: &Registry,
        handlers: Handlers,
    ) -> BringUpReport {
        let generation = self.states.unlock_partition(registry, partition);
        let files: Vec<ModuleFile> = registry
            .modules()
            .iter()
            .map(|module| self.file(module.name, partition))
            .collect();
        let targets: Vec<FileToMigrate<'_>> = files
            .iter()
            .map(|file| FileToMigrate {
                file,
                key: &KEY,
                verified_backup: None,
            })
            .collect();
        let household: &dyn ApiFiles = match self.files(Partition::Household) {
            Some(files) if partition != Partition::Household => files,
            _ => &NoApiFiles,
        };
        let boundary = Boundary {
            states: &self.states,
            budget: HANDLER_TIME_BUDGET,
            apis: Some(Apis {
                registry: *registry,
                files: household,
            }),
        };
        let mut code = handlers;
        let (open, report) = bring_up(
            registry,
            &boundary,
            generation,
            &targets,
            &mut NothingToRekey,
            Delivery {
                code: &mut code,
                links: &mut *self.links.borrow_mut(),
                stamper: &mut *self.stamper.borrow_mut(),
            },
        )
        .expect("the bring-up starts");
        self.partitions.push((generation, open));
        report
    }

    /// Locks `partition` and closes its files, as the lock path will (Story 5.1).
    pub(crate) fn lock(&mut self, partition: Partition) {
        self.states.lock_partition(partition);
        let index = self
            .partitions
            .iter()
            .position(|(generation, _)| generation.partition() == partition)
            .expect("an unlocked partition");
        let (_, files) = self.partitions.remove(index);
        files.close().expect("close the files");
    }

    /// The generation `partition` was unlocked under, while it is up.
    pub(crate) fn generation(&self, partition: Partition) -> Generation {
        self.partitions
            .iter()
            .find(|(generation, _)| generation.partition() == partition)
            .map(|(generation, _)| *generation)
            .expect("an unlocked partition")
    }

    /// The files of `partition`, while it is up.
    pub(crate) fn files(&self, partition: Partition) -> Option<&PartitionFiles> {
        self.partitions
            .iter()
            .find(|(generation, _)| generation.partition() == partition)
            .map(|(_, files)| files)
    }

    /// Runs `body` with the boundary of a call in `partition`: its typed API reads served from the
    /// partition's files, then from the household's.
    pub(crate) fn with_boundary<T>(
        &self,
        partition: Partition,
        registry: &Registry,
        body: impl FnOnce(&Boundary<'_>) -> T,
    ) -> T {
        let own = self.files(partition).expect("an unlocked partition");
        let household: &dyn ApiFiles = match self.files(Partition::Household) {
            Some(files) if partition != Partition::Household => files,
            _ => &NoApiFiles,
        };
        let files = Layered {
            first: own,
            then: household,
        };
        body(&Boundary {
            states: &self.states,
            budget: HANDLER_TIME_BUDGET,
            apis: Some(Apis {
                registry: *registry,
                files: &files,
            }),
        })
    }

    /// A new call id and no request hash, as a caller gives them (AD-28).
    pub(crate) fn invocation(&self) -> Invocation {
        let mut stamper = self.stamper.borrow_mut();
        let now = stamper.now();
        let id = Id::new_v7(now, stamper.id_random()).expect("after the epoch");
        Invocation {
            call_id: CallId::from(id),
            request_hash: None,
            delivery: None,
        }
    }

    /// The clock and ids of the Core's stamps.
    pub(crate) fn stamper(&self) -> std::cell::RefMut<'_, TestStamper> {
        self.stamper.borrow_mut()
    }

    /// One delivery pass over the outbox of `module`'s file in `partition`, its consumers run by
    /// `handlers` inside the boundary of a call in that partition.
    pub(crate) fn deliver(
        &self,
        module: &'static str,
        partition: Partition,
        registry: &Registry,
        handlers: Handlers,
    ) -> DeliveryReport {
        let files = self.files(partition).expect("an unlocked partition");
        let source = files
            .handle(&ModuleName::from_static(module))
            .expect("an open file");
        let mut code = handlers;
        self.with_boundary(partition, registry, |boundary| {
            deliver_outbox(
                registry,
                source,
                files,
                boundary,
                &mut code,
                &mut *self.links.borrow_mut(),
                &mut *self.stamper.borrow_mut(),
            )
        })
        .expect("the pass runs")
    }
}

impl Drop for House {
    fn drop(&mut self) {
        for (_, files) in self.partitions.drain(..) {
            // The scratch directory goes next, whatever the closes report.
            let _ = files.close();
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
