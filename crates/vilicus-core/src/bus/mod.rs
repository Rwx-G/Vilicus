//! The event bus of the Core (FR-24, AD-10, AD-27, AD-29, D20, D107): the delivery of the events
//! and link requests a module file's outbox holds, once the calls that wrote them committed.
//!
//! [`deliver_outbox`] reads the pending rows of one source file in commit order. Each event goes
//! to the consumers the registry gives its topic, those of the modules the topic's access list
//! names, each in a call of its own on the consumer module's file of the same partition: principal
//! `Event`, `source` `event(<event id>)`, the emitting call's id as its `call_id`, the emitting
//! call's author, and the emitting record as of its emission as its implicit input, so each write
//! of the consumer stores the most restrictive taint of its inputs (AD-27, D147). The consumer
//! records the event in `_consumed` in the transaction of its effect, so a second delivery of the
//! event, after a crash between the consumer's commit and the source's record, runs nothing
//! (AD-10): delivery is at least once, the effect once.
//!
//! Delivery is ordered per source file and consumer: an event a consumer has not received holds
//! back that consumer's later events, and only that consumer's. A consumer whose file is not
//! ready (AD-54), as the availability states report it, its partition locked included, keeps its
//! events in the source outbox, and that is not a failure; an event that outlives the outbox's
//! retention while its consumer is in a lasting state (deactivated, faulted, failed migration,
//! newer than code) is moved to that consumer's dead letters, with an alert, so the outbox does
//! not grow without bound behind a consumer that may never return (D150). Each consumer's code
//! runs inside the boundary of AD-9: a panic or an overrun of its time budget faults the consumer's
//! module for the partition, with an alert, and its later events wait for it as for any consumer
//! that is not ready. A failed delivery, a refusal, a panic or an overrun of the consumer's code,
//! or an event whose row does not decode, is counted; the fifth moves the event to the source
//! file's dead letters, returns a typed instance admin alert, and lets the consumer's later events
//! proceed, so the consumer sees a gap (AD-29). An event is closed once every consumer received it
//! or dead-lettered it. The outbox is read a page at a time, each row on its own, so no row,
//! however damaged, stops the rows after it. A panic of the Core itself is not caught here (AD-9,
//! D131).
//!
//! A link request is registered by the Core in the link table of the partition, after the
//! module's transaction and never inside it, once the linking record is still in its file and the
//! linked record is found in its module's file of the same partition; otherwise it is refused,
//! with an alert (AD-10). A link table that fails keeps the request pending. In V0.1, events and
//! links stay in their source partition (D107): every consumer or target file must be of the
//! source file's partition, or the delivery stops.
//!
//! The source file is delivered only once its migrations ran, both tracks at the code's versions
//! (AD-29); a consumer file that is not is not ready. The bring-up of a partition calls
//! [`deliver_outbox`] for each file once its files are re-keyed and migrated
//! ([`bring_up`](crate::startup::bring_up)); the consumers' code is the handler table's
//! ([`Handlers`](crate::handlers::Handlers)), behind the [`ConsumerCode`] port.

#[cfg(test)]
mod tests;

use core::fmt;
use std::collections::HashSet;
use std::time::Duration;

use vilicus_module_api::{Consumer, Event, ModuleDeclaration, Records, WriteError};
use vilicus_storage::{
    CORE_SCHEMA_VERSION, DeliveryState, EventRow, Handle, Inspect, LinkRow, MigrationTrack,
    OutboxKind, OutboxPurge, OutboxRow, OutboxState, Partition, PendingRow, SqlValue, Write,
};
use vilicus_types::{
    AvailabilityState, EVENT_DELIVERY_ATTEMPTS, Id, ModuleName, OUTBOX_RETENTION, Principal,
    Source, UtcMillis,
};

use crate::alert::InstanceAdminAlert;
use crate::availability::Fault;
use crate::boundary::{Boundary, HandlerError};
use crate::record::{
    Authority, Call, CallResult, Consumed, EventDelivery, Invocation, RecordError, Stamper,
    decode_provenance,
};
use crate::registry::Registry;

/// The module files of the partition being delivered, as the Core holds them.
pub trait ConsumerFiles {
    /// The write handle of `module`'s file in the partition, when the Core holds it open; for
    /// the source module itself, the source handle. Whether the file is ready is the availability
    /// states' (AD-54): a file they report ready whose handle is not open is not ready, and keeps
    /// the events of its consumers, and the link requests to it, in the source outbox, which is
    /// not a failed delivery.
    fn open(&self, module: &ModuleName) -> Option<&Handle<Write>>;
}

/// The code of the consumers: the handler table binds it ([`Handlers`](crate::handlers::Handlers)).
pub trait ConsumerCode {
    /// Runs `consumer` of `module` on `event`, writing through `records` in the consumer's call.
    /// An error, or a write the Core refuses, fails the delivery and rolls the call back.
    fn consume(
        &mut self,
        module: &'static ModuleDeclaration,
        consumer: &'static Consumer,
        event: &Event<'_>,
        records: &mut dyn Records,
    ) -> Result<(), WriteError>;
}

/// The link table of a partition, in `core.<partition>.db` (AD-10, `doc/architecture.md`
/// section 5.3): cross-module references by opaque ids, registered by the Core alone.
pub trait LinkTable {
    /// Registers `link`. The bus registers a link at least once: a link already registered under
    /// its id is registered again after a crash before the request was closed, and is the same
    /// link.
    fn register(&mut self, link: &Link) -> Result<(), vilicus_storage::Error>;
}

/// A cross-module link, from a record of one module to a record of another, in one partition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    /// The id of the request that asked for it.
    pub id: Id,
    /// The partition that holds both records, and the link table.
    pub partition: Partition,
    /// The module of the linking record.
    pub module: ModuleName,
    /// The linking record.
    pub record: Id,
    /// The module of the linked record.
    pub target_module: ModuleName,
    /// The linked record.
    pub target: Id,
}

/// How many failed deliveries of one event to one consumer move it to the dead letters (AD-29).
pub const MAX_DELIVERY_ATTEMPTS: u32 = EVENT_DELIVERY_ATTEMPTS;

/// How many pending rows of the outbox a pass reads at a time: their payloads are read one row
/// at a time, so a pass holds at most this many positions, ids and names, however long the
/// outbox.
pub const OUTBOX_PAGE: u32 = 256;

/// What became of one event for one consumer in a delivery pass.
#[derive(Debug)]
pub struct Delivery {
    /// The event.
    pub event: Id,
    /// The consumer, `<module>.<consumer>`.
    pub consumer: String,
    /// What became of it.
    pub outcome: DeliveryOutcome,
}

/// What became of one delivery.
#[derive(Debug)]
#[non_exhaustive]
pub enum DeliveryOutcome {
    /// The consumer's call committed.
    Delivered,
    /// The consumer had already recorded the event: a repeated delivery, which ran nothing.
    AlreadyConsumed,
    /// The delivery failed; it is attempted again in a later pass, and holds back the consumer's
    /// later events until then.
    Failed {
        /// The failed attempts so far.
        attempts: u32,
        /// Why it failed.
        cause: FailureCause,
    },
    /// The delivery failed on its last attempt: the event is in the dead letters, and the
    /// consumer's later events proceed.
    DeadLettered {
        /// The dead letter.
        dead_letter: Id,
        /// Why the last attempt failed.
        cause: FailureCause,
    },
    /// The consumer's file is not ready, in `state`: the event stays in the source outbox, not
    /// counted as a failure (AD-54).
    NotReady {
        /// The state of the consumer's file.
        state: AvailabilityState,
    },
    /// The event outlived the outbox's retention while the consumer's file is in a lasting state:
    /// it is in the consumer's dead letters, without an attempt counted, and the consumer's later
    /// events proceed (D150).
    Expired {
        /// The dead letter.
        dead_letter: Id,
        /// The state of the consumer's file.
        state: AvailabilityState,
    },
    /// An earlier event of the same consumer is not delivered yet: this one waits its turn.
    Waiting,
}

/// Why a delivery failed.
#[derive(Debug)]
pub enum FailureCause {
    /// The consumer's code returned an error, or the Core refused a write of its call.
    Refused(RecordError),
    /// The consumer's code panicked; its call was rolled back and its module is faulted for the
    /// partition (AD-9).
    Panicked,
    /// The consumer's code ran past the handler time budget; its call was rolled back and its
    /// module is faulted for the partition (AD-9).
    TimeBudget,
    /// The event's row of the outbox, or the provenance it holds, does not decode: no consumer
    /// code ran.
    Malformed,
}

/// What became of one link request in a delivery pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkOutcome {
    /// The link is in the partition's link table.
    Registered,
    /// The linked record is not in its module's file of this partition, or the module is not
    /// registered: the request is closed unregistered, with an alert.
    Refused,
    /// The target module's file is not ready: the request stays pending.
    TargetNotReady,
    /// The link table failed (its file not open, a storage error): the request stays pending,
    /// and the pass goes on with the next row.
    TableUnavailable,
}

/// What one delivery pass did.
#[derive(Debug, Default)]
pub struct DeliveryReport {
    /// Each event and consumer the pass considered, in commit order.
    pub deliveries: Vec<Delivery>,
    /// Each link request the pass considered, in commit order, with its outcome.
    pub links: Vec<(Id, LinkOutcome)>,
    /// The events the pass closed: every consumer received or dead-lettered them.
    pub closed: Vec<Id>,
    /// The alerts to the instance admin: dead letters, expired events, faulted consumers, refused
    /// links and rows of the outbox no id names.
    pub alerts: Vec<InstanceAdminAlert>,
}

/// Why a delivery pass stopped.
#[derive(Debug)]
#[non_exhaustive]
pub enum DeliveryError {
    /// The source file belongs to no registered module.
    UnregisteredModule(ModuleName),
    /// The source file's migrations have not all run: its outbox waits for them (AD-29).
    NotMigrated {
        /// The track behind or ahead.
        track: MigrationTrack,
        /// The file's version of that track.
        found: u32,
        /// The code's version of that track.
        latest: u32,
    },
    /// A consumer or target file of another partition was offered: in V0.1 nothing leaves its
    /// source partition (D107, AD-10).
    CrossPartition {
        /// The module of the file.
        module: ModuleName,
    },
    /// The file offered for a module is another module's.
    WrongModule {
        /// The module asked for.
        module: ModuleName,
    },
    /// The Core's clock gave a time before the Unix epoch, which no id holds.
    ClockBeforeEpoch,
    /// The storage layer failed on the source file.
    Storage(vilicus_storage::Error),
}

impl fmt::Display for DeliveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnregisteredModule(module) => {
                write!(formatter, "module {module} is not registered")
            }
            Self::NotMigrated {
                track,
                found,
                latest,
            } => write!(
                formatter,
                "the source file's {track} track is at version {found}, the code's at {latest}: \
                 its outbox waits for its migrations"
            ),
            Self::CrossPartition { module } => write!(
                formatter,
                "a file of {module} from another partition was offered; events and links stay \
                 in their partition"
            ),
            Self::WrongModule { module } => {
                write!(
                    formatter,
                    "the file offered for {module} is another module's"
                )
            }
            Self::ClockBeforeEpoch => {
                formatter.write_str("the clock is before the Unix epoch; no id can be stamped")
            }
            Self::Storage(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for DeliveryError {}

impl From<vilicus_storage::Error> for DeliveryError {
    fn from(error: vilicus_storage::Error) -> Self {
        Self::Storage(error)
    }
}

/// One delivery pass over the outbox of `source`, the write handle of a module file of
/// `registry`: every pending event to every consumer whose file `boundary`'s availability states
/// report ready and `files` holds open, every pending link request to `links`, in commit order, a
/// page of [`OUTBOX_PAGE`] rows at a time, with `code` for the consumers' code, run inside
/// `boundary` (AD-9), and `stamper` for the time and the ids. The pass makes at most one attempt
/// per event and consumer; the next pass retries what failed and delivers what was not ready. An
/// event older than [`OUTBOX_RETENTION`] for a consumer in a lasting state is dead-lettered for it
/// (D150). A row that does not decode fails its deliveries, or is refused, and never stops the
/// pass; nor does a link table that fails.
///
/// Refused, before anything is delivered, when the source file's module is not registered or its
/// migrations have not run; stopped when `files` offers a file of another partition or module,
/// or the source file fails. What the pass delivered before it stopped stays delivered. A panic
/// of the Core, outside the consumer's code, is not caught here (AD-9, D131).
pub fn deliver_outbox(
    registry: &Registry,
    source: &Handle<Write>,
    files: &dyn ConsumerFiles,
    boundary: &Boundary<'_>,
    code: &mut dyn ConsumerCode,
    links: &mut dyn LinkTable,
    stamper: &mut dyn Stamper,
) -> Result<DeliveryReport, DeliveryError> {
    let emitter = registry
        .module(source.file().module())
        .ok_or_else(|| DeliveryError::UnregisteredModule(source.file().module().clone()))?;
    if let Some((track, found, latest)) = behind_or_ahead(source, emitter)? {
        return Err(DeliveryError::NotMigrated {
            track,
            found,
            latest,
        });
    }
    let mut pass = Pass {
        registry,
        emitter,
        source,
        files,
        boundary,
        stamper,
        held_back: HashSet::new(),
        report: DeliveryReport::default(),
    };
    let mut after = 0;
    loop {
        let page = source.pending_outbox(after, OUTBOX_PAGE)?;
        let Some(last) = page.last() else {
            break;
        };
        after = last.seq;
        for row in &page {
            pass.deliver(row, code, links)?;
        }
    }
    Ok(pass.report)
}

/// The retention step of the outbox of the file `handle` writes (AD-26): deletes every closed
/// event and link request and every `done` effect intent created before `now` minus
/// [`OUTBOX_RETENTION`], an event that still has a dead letter excepted, under `secure_delete` =
/// ON, then checkpoints in TRUNCATE mode until the WAL is empty ([`Handle::purge_outbox`]).
pub fn purge_expired_outbox(
    handle: &Handle<Write>,
    now: UtcMillis,
) -> Result<OutboxPurge, vilicus_storage::Error> {
    handle.purge_outbox(cutoff(now, OUTBOX_RETENTION))
}

fn cutoff(now: UtcMillis, retention: Duration) -> UtcMillis {
    let retention_millis = i64::try_from(retention.as_millis()).unwrap_or(i64::MAX);
    UtcMillis::from_millis(now.as_millis().saturating_sub(retention_millis))
        .unwrap_or(UtcMillis::MIN)
}

/// The first track of `handle`'s file that is not at the code's version, with the file's and
/// the code's versions; `None` once both tracks are current.
fn behind_or_ahead<R: Inspect>(
    handle: &Handle<R>,
    module: &ModuleDeclaration,
) -> Result<Option<(MigrationTrack, u32, u32)>, vilicus_storage::Error> {
    for (track, latest) in [
        (MigrationTrack::Core, CORE_SCHEMA_VERSION),
        (MigrationTrack::Module, module.latest_version()),
    ] {
        let found = handle.schema_version(track)?;
        if found != latest {
            return Ok(Some((track, found, latest)));
        }
    }
    Ok(None)
}

/// One delivery pass over one source file.
struct Pass<'a> {
    registry: &'a Registry,
    emitter: &'static ModuleDeclaration,
    source: &'a Handle<Write>,
    files: &'a dyn ConsumerFiles,
    boundary: &'a Boundary<'a>,
    stamper: &'a mut dyn Stamper,
    /// The consumers with an event not delivered in this pass: their later events wait.
    held_back: HashSet<String>,
    report: DeliveryReport,
}

/// A row of the outbox read whole, or the failure to: a column outside its stored form.
fn read_row(source: &Handle<Write>, seq: i64) -> Result<Option<OutboxRow>, DeliveryError> {
    match source.outbox_row(seq) {
        Ok(row) => Ok(Some(row)),
        Err(vilicus_storage::Error::MalformedCoreRow { .. }) => Ok(None),
        Err(other) => Err(other.into()),
    }
}

/// Whether a consumer or link target file can be delivered to.
enum Readiness<'a> {
    /// Its write handle.
    Ready(&'a Handle<Write>),
    /// It is not ready, in this state.
    NotReady(AvailabilityState),
}

/// What one attempt to deliver an event to a consumer became.
enum Attempt {
    /// The consumer's call committed, or had already run.
    Done(CallResult<()>),
    /// The attempt failed, and counts.
    Failed(FailureCause),
    /// The consumer's file stopped being ready before its code ran: no attempt.
    NotReady(AvailabilityState),
}

impl<'a> Pass<'a> {
    /// The file of `module` in the source file's partition, when the availability states report
    /// it ready and `files` holds it open, held to that partition and that module, and to the
    /// code's versions. A file reported ready that is not open is reported `opening`, and one
    /// whose migrations have not run `migrating`: neither is delivered to.
    fn ready_file(
        &self,
        module: &'static ModuleDeclaration,
    ) -> Result<Readiness<'a>, DeliveryError> {
        let name = ModuleName::from_static(module.name);
        let state = self
            .boundary
            .states
            .state(&name, self.source.file().partition());
        if state != AvailabilityState::Ready {
            return Ok(Readiness::NotReady(state));
        }
        let files: &'a dyn ConsumerFiles = self.files;
        let Some(handle) = files.open(&name) else {
            return Ok(Readiness::NotReady(AvailabilityState::Opening));
        };
        if handle.file().partition() != self.source.file().partition() {
            return Err(DeliveryError::CrossPartition { module: name });
        }
        if *handle.file().module() != name {
            return Err(DeliveryError::WrongModule { module: name });
        }
        Ok(match behind_or_ahead(handle, module)? {
            None => Readiness::Ready(handle),
            Some(_) => Readiness::NotReady(AvailabilityState::Migrating),
        })
    }

    /// One pending row: a row no id names is refused at once, with an alert, since no delivery
    /// can be recorded for it; an event is delivered, or fails, consumer by consumer; a link
    /// request is registered or refused.
    fn deliver(
        &mut self,
        row: &PendingRow,
        code: &mut dyn ConsumerCode,
        links: &mut dyn LinkTable,
    ) -> Result<(), DeliveryError> {
        let Some(id) = row.id else {
            let now = self.stamper.now();
            self.source.refuse_outbox_row(row.seq, now)?;
            self.report
                .alerts
                .push(InstanceAdminAlert::malformed_outbox_row(
                    self.source.file(),
                    row.seq,
                ));
            return Ok(());
        };
        let read = read_row(self.source, row.seq)?;
        match (row.kind, read) {
            (OutboxKind::Event, Some(OutboxRow::Event(event))) => {
                self.deliver_event(id, &row.name, Some(&event), code)
            }
            (OutboxKind::Event, _) => self.deliver_event(id, &row.name, None, code),
            (OutboxKind::Link, Some(OutboxRow::Link(link))) => self.register_link(&link, links),
            (OutboxKind::Link, _) => self.refuse_link(id, &row.name),
        }
    }

    /// Delivers the event `id` of `topic` to each of its consumers; `event` is `None` when its
    /// row does not decode, which fails each delivery without running the consumer.
    fn deliver_event(
        &mut self,
        id: Id,
        topic: &str,
        event: Option<&EventRow>,
        code: &mut dyn ConsumerCode,
    ) -> Result<(), DeliveryError> {
        let mut done = true;
        for (module, consumer) in self.registry.receivers(self.emitter, topic) {
            let name = format!("{}.{}", module.name, consumer.name);
            let earlier = self.source.delivery(id, &name)?;
            if earlier
                .as_ref()
                .is_some_and(|delivery| delivery.state != DeliveryState::Failing)
            {
                continue;
            }
            let outcome = if self.held_back.contains(&name) {
                DeliveryOutcome::Waiting
            } else {
                match self.ready_file(module)? {
                    Readiness::NotReady(state) => self.not_ready(id, topic, &name, event, state)?,
                    Readiness::Ready(handle) => {
                        let attempt = match event {
                            Some(event) => self.consume(handle, module, consumer, event, code),
                            None => Attempt::Failed(FailureCause::Malformed),
                        };
                        self.settle(id, topic, &name, attempt)?
                    }
                }
            };
            if !matches!(
                outcome,
                DeliveryOutcome::Delivered
                    | DeliveryOutcome::AlreadyConsumed
                    | DeliveryOutcome::DeadLettered { .. }
                    | DeliveryOutcome::Expired { .. }
            ) {
                done = false;
                self.held_back.insert(name.clone());
            }
            self.report.deliveries.push(Delivery {
                event: id,
                consumer: name,
                outcome,
            });
        }
        if done {
            let now = self.stamper.now();
            self.source
                .close_outbox_row(id, OutboxState::Delivered, now)?;
            self.report.closed.push(id);
        }
        Ok(())
    }

    /// The outcome for `consumer`, whose file is not ready, in `state`, of the event `event` of
    /// `topic`: it stays in the source outbox, unless it outlived the outbox's retention while the
    /// consumer's state is lasting, when it is dead-lettered for the consumer without an attempt,
    /// with an alert (D150). An event whose row does not decode has no time to age by, and stays.
    fn not_ready(
        &mut self,
        event: Id,
        topic: &str,
        consumer: &str,
        row: Option<&EventRow>,
        state: AvailabilityState,
    ) -> Result<DeliveryOutcome, DeliveryError> {
        let now = self.stamper.now();
        let expired = row.is_some_and(|row| row.created_at < cutoff(now, OUTBOX_RETENTION));
        if !(state.is_lasting() && expired) {
            return Ok(DeliveryOutcome::NotReady { state });
        }
        let dead_letter = Id::new_v7(now, self.stamper.id_random())
            .map_err(|_| DeliveryError::ClockBeforeEpoch)?;
        self.source
            .dead_letter_delivery(event, consumer, now, dead_letter)?;
        self.report.alerts.push(InstanceAdminAlert::EventExpired {
            module: self.source.file().module().clone(),
            partition: self.source.file().partition(),
            file_name: self.source.file().file_name(),
            dead_letter,
            event,
            topic: topic.to_owned(),
            consumer: consumer.to_owned(),
            state,
        });
        Ok(DeliveryOutcome::Expired { dead_letter, state })
    }

    /// One attempt to deliver `event` to `consumer` of `module`, on `handle`, the consumer
    /// module's file: the consumer's code in a call of its own, principal `Event`, inside the
    /// boundary of AD-9. A panic or an overrun of the consumer's code faults its module, with an
    /// alert, and fails the attempt; a panic of the Core around it unwinds on, out of the pass. An
    /// event whose provenance does not decode fails its delivery without running the consumer, so
    /// it ends in the dead letters rather than block the outbox (AD-29).
    fn consume(
        &mut self,
        handle: &Handle<Write>,
        module: &'static ModuleDeclaration,
        consumer: &'static Consumer,
        event: &EventRow,
        code: &mut dyn ConsumerCode,
    ) -> Attempt {
        let Ok(emitting_record) = decode_provenance(&event.provenance) else {
            return Attempt::Failed(FailureCause::Malformed);
        };
        let call = Call {
            principal: Principal::Event,
            source: Source::Event(event.id),
            session: emitting_record.labels.overall(),
            consumed: Consumed::NOTHING,
            authority: Authority::Unapproved {
                author: event.author,
                acting_for: event.member,
            },
            read: Vec::new(),
            implicit_inputs: vec![emitting_record],
        };
        let invocation = Invocation {
            call_id: event.call_id,
            request_hash: None,
            delivery: Some(EventDelivery {
                event: event.id,
                consumer: consumer.name,
            }),
        };
        let delivered = Event {
            id: event.id,
            topic: &event.topic,
            emitter: self.emitter.name,
            version: event.version,
            record: event.record,
            payload: &event.payload,
        };
        let attempt = self.boundary.run(
            handle,
            module,
            &call,
            &invocation,
            self.stamper,
            |records| code.consume(module, consumer, &delivered, records),
        );
        match attempt {
            Ok(result) => Attempt::Done(result),
            Err(HandlerError::Faulted { fault, alert }) => {
                self.report.alerts.extend(alert.map(|alert| *alert));
                Attempt::Failed(match fault {
                    Fault::Panicked => FailureCause::Panicked,
                    Fault::TimeBudget => FailureCause::TimeBudget,
                })
            }
            Err(HandlerError::Unavailable(unavailable)) => Attempt::NotReady(unavailable.state()),
            Err(HandlerError::Refused(error)) => Attempt::Failed(FailureCause::Refused(error)),
            Err(_) => Attempt::Failed(FailureCause::Refused(RecordError::InconsistentCall)),
        }
    }

    /// Records in the source file what became of one attempt, after the consumer's call ended.
    fn settle(
        &mut self,
        event: Id,
        topic: &str,
        consumer: &str,
        attempt: Attempt,
    ) -> Result<DeliveryOutcome, DeliveryError> {
        let now = self.stamper.now();
        let cause = match attempt {
            Attempt::Done(result) => {
                self.source.record_delivered(event, consumer, now)?;
                return Ok(match result {
                    CallResult::Committed(_) => DeliveryOutcome::Delivered,
                    CallResult::Deduplicated(_) | CallResult::AlreadyConsumed => {
                        DeliveryOutcome::AlreadyConsumed
                    }
                });
            }
            Attempt::NotReady(state) => return Ok(DeliveryOutcome::NotReady { state }),
            Attempt::Failed(cause) => cause,
        };
        let dead_letter = Id::new_v7(now, self.stamper.id_random())
            .map_err(|_| DeliveryError::ClockBeforeEpoch)?;
        let recorded = self.source.record_failed_delivery(
            event,
            consumer,
            now,
            MAX_DELIVERY_ATTEMPTS,
            dead_letter,
        )?;
        if recorded.state == DeliveryState::DeadLetter {
            self.report.alerts.push(InstanceAdminAlert::dead_letter(
                self.source.file(),
                dead_letter,
                event,
                topic,
                consumer,
            ));
            Ok(DeliveryOutcome::DeadLettered { dead_letter, cause })
        } else {
            Ok(DeliveryOutcome::Failed {
                attempts: recorded.attempts,
                cause,
            })
        }
    }

    /// Registers `link` once its linking record is still in the source file and its target in
    /// its module's file of the same partition; refuses it when either is missing or the module
    /// is not registered; keeps it pending when the target file is not ready or the link table
    /// fails.
    fn register_link(
        &mut self,
        link: &LinkRow,
        table: &mut dyn LinkTable,
    ) -> Result<(), DeliveryError> {
        let target_module = ModuleName::parse(&link.target_module)
            .ok()
            .and_then(|name| self.registry.module(&name));
        let outcome = match target_module {
            _ if !holds(self.source, self.emitter, link.record)? => LinkOutcome::Refused,
            None => LinkOutcome::Refused,
            Some(module) => match self.ready_file(module)? {
                Readiness::NotReady(_) => LinkOutcome::TargetNotReady,
                Readiness::Ready(handle) if holds(handle, module, link.target)? => {
                    let registered = table.register(&Link {
                        id: link.id,
                        partition: self.source.file().partition(),
                        module: self.source.file().module().clone(),
                        record: link.record,
                        target_module: ModuleName::from_static(module.name),
                        target: link.target,
                    });
                    if registered.is_ok() {
                        LinkOutcome::Registered
                    } else {
                        LinkOutcome::TableUnavailable
                    }
                }
                Readiness::Ready(_) => LinkOutcome::Refused,
            },
        };
        match outcome {
            LinkOutcome::Registered => {
                let now = self.stamper.now();
                self.source
                    .close_outbox_row(link.id, OutboxState::Delivered, now)?;
                self.report.links.push((link.id, outcome));
                Ok(())
            }
            LinkOutcome::Refused => self.refuse_link(link.id, &link.target_module),
            LinkOutcome::TargetNotReady | LinkOutcome::TableUnavailable => {
                self.report.links.push((link.id, outcome));
                Ok(())
            }
        }
    }

    /// Closes the link request `id` to `target_module` unregistered, with an alert.
    fn refuse_link(&mut self, id: Id, target_module: &str) -> Result<(), DeliveryError> {
        let now = self.stamper.now();
        self.source
            .close_outbox_row(id, OutboxState::Refused, now)?;
        self.report.alerts.push(InstanceAdminAlert::link_refused(
            self.source.file(),
            id,
            target_module,
        ));
        self.report.links.push((id, LinkOutcome::Refused));
        Ok(())
    }
}

/// True when a table of `module` holds the record `id` in `handle`'s file.
fn holds(
    handle: &Handle<Write>,
    module: &'static ModuleDeclaration,
    id: Id,
) -> Result<bool, DeliveryError> {
    for table in module.tables {
        let found = handle.query_values(
            &format!("SELECT 1 FROM {} WHERE id = ?1", table.name),
            &[SqlValue::Blob(id.to_bytes().to_vec())],
        )?;
        if !found.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}
