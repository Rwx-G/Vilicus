//! Events, link requests and their delivery, in a module file's outbox (AD-10, AD-26, AD-29).
//!
//! A call that changes a record may emit an event about it, or request a cross-module link from
//! it: the Core writes the row to `_outbox` in the transaction of the call's writes, so the change
//! and its row commit together in one file or not at all (AD-10). The emitter is the module whose
//! file holds the row: only the Core writes `_outbox`, and only in the call of that module. The
//! Core then delivers each event, in commit order (`seq`), to each of its consumers, and records
//! where each delivery stands in `_deliveries`, in a transaction of its own after the consumer's:
//! failed attempts, delivered, or moved to `_dead_letter` once the attempts are spent. An event
//! whose every delivery is done, and a link request the Core registered or refused, is closed,
//! never deleted until the outbox's retention purge, which deletes the closed rows older than its
//! cutoff under `secure_delete` = ON and checkpoints, like the journal's (D132).
//!
//! The storage layer keeps the Core's encodings (an event's payload and the provenance of its
//! emitting record) as opaque blobs and decides nothing about consumers: which consumers an event
//! has, how many attempts it gets and when a row is closed are the Core's.
//!
//! Every statement is one of the Core's own, under [`Policy::Core`](crate::authorizer); module
//! SQL can neither write nor read `_outbox`, `_deliveries` or `_dead_letter`.

use core::fmt;

use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, OptionalExtension, Row};
use vilicus_types::{CallId, Id, Principal, UtcMillis};

use crate::error::{Error, Result};
use crate::handle::{self, Handle, Write};
use crate::journal::{
    CallKey, malformed, read_id, read_optional_id, read_time, require_transaction,
};

/// The `kind` of an event row of `_outbox`.
const EVENT_KIND: &str = "event";

/// The `kind` of a link request row of `_outbox`.
const LINK_KIND: &str = "link";

/// Where an event or a link request of the outbox stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OutboxState {
    /// Committed with its call, not yet closed.
    Pending,
    /// An event delivered to, or dead-lettered for, every consumer; a link registered.
    Delivered,
    /// A link request the Core refused to register.
    Refused,
}

impl OutboxState {
    /// Every state, in declaration order.
    pub const ALL: [Self; 3] = [Self::Pending, Self::Delivered, Self::Refused];

    /// The stored form.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Delivered => "delivered",
            Self::Refused => "refused",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|state| state.as_str() == name)
    }
}

impl fmt::Display for OutboxState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// An event as a call emits it.
#[derive(Clone, Copy, Debug)]
pub struct EventIntent<'a> {
    /// The emitting call.
    pub call: CallKey<'a>,
    /// The hash of the call's request, when the pipeline gives one.
    pub request_hash: Option<&'a [u8]>,
    /// The event's id, a UUIDv7 the Core stamped.
    pub id: Id,
    /// The topic, `<module>.<entity>.<past_verb>`.
    pub topic: &'a str,
    /// The payload version the Core stamped from the topic's declaration.
    pub version: u32,
    /// The record the event is about, which the call changed.
    pub record: Id,
    /// The provenance of that record as of the emission, as the Core encoded it.
    pub provenance: &'a [u8],
    /// The emitting call's author.
    pub author: Option<Id>,
    /// The member the emitting call made, approved or acted for.
    pub member: Option<Id>,
    /// The payload, as the module encoded it.
    pub payload: &'a [u8],
    /// The time of the call.
    pub created_at: UtcMillis,
}

/// An event read back from the outbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRow {
    /// Its position in the file's outbox, in commit order.
    pub seq: i64,
    /// The event's id.
    pub id: Id,
    /// The id of the emitting call.
    pub call_id: CallId,
    /// The principal of the emitting call.
    pub principal: Principal,
    /// The `source` of the emitting call.
    pub source: String,
    /// The emitting call's author.
    pub author: Option<Id>,
    /// The member the emitting call made, approved or acted for.
    pub member: Option<Id>,
    /// The topic.
    pub topic: String,
    /// The payload version.
    pub version: u32,
    /// The record the event is about.
    pub record: Id,
    /// The encoded provenance of that record as of the emission.
    pub provenance: Vec<u8>,
    /// The payload.
    pub payload: Vec<u8>,
    /// Where it stands.
    pub state: OutboxState,
    /// When the call emitted it.
    pub created_at: UtcMillis,
    /// When its state last changed.
    pub updated_at: UtcMillis,
}

/// A cross-module link as a call requests it (AD-10): from a record the call changed to a record
/// of another module, by opaque ids.
#[derive(Clone, Copy, Debug)]
pub struct LinkIntent<'a> {
    /// The requesting call.
    pub call: CallKey<'a>,
    /// The hash of the call's request, when the pipeline gives one.
    pub request_hash: Option<&'a [u8]>,
    /// The request's id, a UUIDv7 the Core stamped.
    pub id: Id,
    /// The linking record, which the call changed.
    pub record: Id,
    /// The module of the linked record.
    pub target_module: &'a str,
    /// The linked record.
    pub target: Id,
    /// The member the call made, approved or acted for.
    pub member: Option<Id>,
    /// The time of the call.
    pub created_at: UtcMillis,
}

/// A link request read back from the outbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkRow {
    /// Its position in the file's outbox, in commit order.
    pub seq: i64,
    /// The request's id.
    pub id: Id,
    /// The id of the requesting call.
    pub call_id: CallId,
    /// The linking record.
    pub record: Id,
    /// The module of the linked record.
    pub target_module: String,
    /// The linked record.
    pub target: Id,
    /// Where it stands.
    pub state: OutboxState,
    /// When the call requested it.
    pub created_at: UtcMillis,
    /// When its state last changed.
    pub updated_at: UtcMillis,
}

/// The kind of a row of the outbox the Core delivers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OutboxKind {
    /// An event.
    Event,
    /// A link request.
    Link,
}

/// A pending event or link request as the Core lists it, before it reads the rest of the row:
/// a row whose other columns do not decode is listed all the same, so it cannot hide the rows
/// after it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRow {
    /// Its position in the file's outbox, in commit order.
    pub seq: i64,
    /// Its kind.
    pub kind: OutboxKind,
    /// Its id, when it decodes.
    pub id: Option<Id>,
    /// The topic of an event, the target module of a link request.
    pub name: String,
}

/// An event or a link request read back whole.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutboxRow {
    /// An event.
    Event(EventRow),
    /// A link request.
    Link(LinkRow),
}

/// Where the delivery of one event to one consumer stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DeliveryState {
    /// At least one attempt failed, and attempts are left.
    Failing,
    /// The consumer recorded the event.
    Delivered,
    /// The attempts are spent: the event is in the consumer's dead letters.
    DeadLetter,
}

impl DeliveryState {
    /// Every state, in declaration order.
    pub const ALL: [Self; 3] = [Self::Failing, Self::Delivered, Self::DeadLetter];

    /// The stored form.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Failing => "failing",
            Self::Delivered => "delivered",
            Self::DeadLetter => "dead_letter",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|state| state.as_str() == name)
    }
}

/// The delivery of one event to one consumer, read back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryRow {
    /// The event.
    pub event: Id,
    /// The consumer, as the Core names it.
    pub consumer: String,
    /// The failed attempts.
    pub attempts: u32,
    /// Where it stands.
    pub state: DeliveryState,
    /// When it last changed.
    pub updated_at: UtcMillis,
}

/// An event a consumer kept failing (AD-29).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeadLetter {
    /// The dead letter's id, which `vilicus events replay` names.
    pub id: Id,
    /// The event.
    pub event: Id,
    /// The consumer.
    pub consumer: String,
    /// The failed attempts.
    pub attempts: u32,
    /// When the last attempt failed.
    pub failed_at: UtcMillis,
}

/// What an outbox retention purge did: the rows it deleted from `_outbox` and `_deliveries`,
/// and the TRUNCATE checkpoint attempts it took until the WAL was empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutboxPurge {
    /// The rows deleted.
    pub deleted: usize,
    /// The checkpoint attempts, from 1.
    pub checkpoint_attempts: u32,
}

const EVENT_COLUMNS: &str = "seq, id, call_id, principal, source, author, member, name, version, \
                             record_id, provenance, payload, state, created_at, updated_at";

const LINK_COLUMNS: &str =
    "seq, id, call_id, record_id, name, target, state, created_at, updated_at";

fn read_state(row: &Row<'_>, index: usize) -> Result<OutboxState> {
    let state: String = row.get(index)?;
    OutboxState::from_name(&state).ok_or(malformed("_outbox", "state"))
}

fn read_call_id(row: &Row<'_>, index: usize) -> Result<CallId> {
    let bytes: Vec<u8> = row.get(index)?;
    <[u8; 16]>::try_from(bytes.as_slice())
        .ok()
        .and_then(|bytes| CallId::from_bytes(bytes).ok())
        .ok_or(malformed("_outbox", "call_id"))
}

fn event_row(row: &Row<'_>) -> Result<EventRow> {
    let principal: String = row.get(3)?;
    Ok(EventRow {
        seq: row.get(0)?,
        id: read_id(row, 1, "_outbox", "id")?,
        call_id: read_call_id(row, 2)?,
        principal: Principal::ALL
            .iter()
            .copied()
            .find(|known| known.as_str() == principal)
            .ok_or(malformed("_outbox", "principal"))?,
        source: row.get(4)?,
        author: read_optional_id(row, 5, "_outbox", "author")?,
        member: read_optional_id(row, 6, "_outbox", "member")?,
        topic: row.get(7)?,
        version: row
            .get::<_, Option<i64>>(8)?
            .and_then(|version| u32::try_from(version).ok())
            .ok_or(malformed("_outbox", "version"))?,
        record: read_id(row, 9, "_outbox", "record_id")?,
        provenance: row
            .get::<_, Option<Vec<u8>>>(10)?
            .ok_or(malformed("_outbox", "provenance"))?,
        payload: row.get(11)?,
        state: read_state(row, 12)?,
        created_at: read_time(row, 13, "_outbox", "created_at")?,
        updated_at: read_time(row, 14, "_outbox", "updated_at")?,
    })
}

fn link_row(row: &Row<'_>) -> Result<LinkRow> {
    Ok(LinkRow {
        seq: row.get(0)?,
        id: read_id(row, 1, "_outbox", "id")?,
        call_id: read_call_id(row, 2)?,
        record: read_id(row, 3, "_outbox", "record_id")?,
        target_module: row.get(4)?,
        target: read_id(row, 5, "_outbox", "target")?,
        state: read_state(row, 6)?,
        created_at: read_time(row, 7, "_outbox", "created_at")?,
        updated_at: read_time(row, 8, "_outbox", "updated_at")?,
    })
}

fn query<T>(
    connection: &Connection,
    sql: &str,
    values: &[SqlValue],
    read: impl Fn(&Row<'_>) -> Result<T>,
) -> Result<Vec<T>> {
    let mut statement = connection.prepare(sql)?;
    let mut rows = statement.query(rusqlite::params_from_iter(values))?;
    let mut read_rows = Vec::new();
    while let Some(row) = rows.next()? {
        read_rows.push(read(row)?);
    }
    Ok(read_rows)
}

fn events_where(
    connection: &Connection,
    filter: &str,
    values: &[SqlValue],
) -> Result<Vec<EventRow>> {
    query(
        connection,
        &format!(
            "SELECT {EVENT_COLUMNS} FROM _outbox WHERE kind = '{EVENT_KIND}' AND {filter} \
             ORDER BY seq"
        ),
        values,
        event_row,
    )
}

fn links_where(connection: &Connection, filter: &str, values: &[SqlValue]) -> Result<Vec<LinkRow>> {
    query(
        connection,
        &format!(
            "SELECT {LINK_COLUMNS} FROM _outbox WHERE kind = '{LINK_KIND}' AND {filter} \
             ORDER BY seq"
        ),
        values,
        link_row,
    )
}

fn id_value(id: Id) -> SqlValue {
    SqlValue::Blob(id.to_bytes().to_vec())
}

/// The state of the outbox row `id` of `kind`, if the file holds one.
fn outbox_state(connection: &Connection, id: Id, kind: &str) -> Result<Option<OutboxState>> {
    connection
        .query_row(
            "SELECT state FROM _outbox WHERE id = ?1 AND kind = ?2",
            rusqlite::params![id.to_bytes(), kind],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|state| OutboxState::from_name(&state).ok_or(malformed("_outbox", "state")))
        .transpose()
}

fn delivery_row(row: &Row<'_>) -> Result<DeliveryRow> {
    let state: String = row.get(3)?;
    Ok(DeliveryRow {
        event: read_id(row, 0, "_deliveries", "event_id")?,
        consumer: row.get(1)?,
        attempts: u32::try_from(row.get::<_, i64>(2)?)
            .map_err(|_| malformed("_deliveries", "attempts"))?,
        state: DeliveryState::from_name(&state).ok_or(malformed("_deliveries", "state"))?,
        updated_at: read_time(row, 4, "_deliveries", "updated_at")?,
    })
}

fn delivery_of(connection: &Connection, event: Id, consumer: &str) -> Result<Option<DeliveryRow>> {
    Ok(query(
        connection,
        "SELECT event_id, consumer, attempts, state, updated_at FROM _deliveries \
         WHERE event_id = ?1 AND consumer = ?2",
        &[id_value(event), SqlValue::Text(consumer.to_owned())],
        delivery_row,
    )?
    .into_iter()
    .next())
}

fn write_delivery(connection: &Connection, delivery: &DeliveryRow) -> Result<()> {
    connection.execute(
        "INSERT INTO _deliveries (event_id, consumer, attempts, state, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT (event_id, consumer) DO UPDATE SET attempts = excluded.attempts, \
         state = excluded.state, updated_at = excluded.updated_at",
        rusqlite::params![
            delivery.event.to_bytes(),
            delivery.consumer,
            delivery.attempts,
            delivery.state.as_str(),
            delivery.updated_at.as_millis(),
        ],
    )?;
    Ok(())
}

/// The rows the retention purge deletes, older than `?1`: closed events and link requests, and
/// `done` effect intents, except an event that still has a dead letter, whose payload a replay
/// needs. A `pending`, `failed` or `unknown` effect intent is kept: the Core still performs,
/// retries or reports it.
const EXPIRED_OUTBOX_ROWS: &str = "created_at < ?1 \
     AND ((kind IN ('event', 'link') AND state IN ('delivered', 'refused')) \
          OR (kind = 'effect' AND state = 'done')) \
     AND id NOT IN (SELECT event_id FROM _dead_letter)";

impl Handle<Write> {
    /// Writes `event` to `_outbox` as `pending`, inside the write transaction the caller holds,
    /// so it commits with the change it is about or not at all (AD-10). Fails with
    /// [`Error::NoTransaction`] outside a transaction, and refuses an empty topic with
    /// [`Error::InvalidOutboxRow`].
    pub fn append_event(&self, event: &EventIntent<'_>) -> Result<()> {
        if event.topic.is_empty() {
            return Err(Error::InvalidOutboxRow);
        }
        self.under_core_policy(|connection| {
            require_transaction(connection)?;
            connection.execute(
                "INSERT INTO _outbox (id, kind, call_id, request_hash, principal, source, member, \
                 name, payload, state, attempts, created_at, updated_at, author, version, \
                 record_id, provenance) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0, ?11, ?11, ?12, ?13, ?14, ?15)",
                rusqlite::params![
                    event.id.to_bytes(),
                    EVENT_KIND,
                    event.call.call_id.to_bytes(),
                    event.request_hash,
                    event.call.principal.as_str(),
                    event.call.source.to_string(),
                    event.member.map(Id::to_bytes),
                    event.topic,
                    event.payload,
                    OutboxState::Pending.as_str(),
                    event.created_at.as_millis(),
                    event.author.map(Id::to_bytes),
                    event.version,
                    event.record.to_bytes(),
                    event.provenance,
                ],
            )?;
            Ok(())
        })
    }

    /// Writes the link request `link` to `_outbox` as `pending`, inside the write transaction the
    /// caller holds: the link itself is registered by the Core when it delivers the row, never in
    /// the module's transaction (AD-10). Fails with [`Error::NoTransaction`] outside a
    /// transaction, and refuses an empty target module with [`Error::InvalidOutboxRow`].
    pub fn append_link(&self, link: &LinkIntent<'_>) -> Result<()> {
        if link.target_module.is_empty() {
            return Err(Error::InvalidOutboxRow);
        }
        self.under_core_policy(|connection| {
            require_transaction(connection)?;
            connection.execute(
                "INSERT INTO _outbox (id, kind, call_id, request_hash, principal, source, member, \
                 name, payload, state, attempts, created_at, updated_at, record_id, target) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, x'', ?9, 0, ?10, ?10, ?11, ?12)",
                rusqlite::params![
                    link.id.to_bytes(),
                    LINK_KIND,
                    link.call.call_id.to_bytes(),
                    link.request_hash,
                    link.call.principal.as_str(),
                    link.call.source.to_string(),
                    link.member.map(Id::to_bytes),
                    link.target_module,
                    OutboxState::Pending.as_str(),
                    link.created_at.as_millis(),
                    link.record.to_bytes(),
                    link.target.to_bytes(),
                ],
            )?;
            Ok(())
        })
    }

    /// The pending events and link requests of the file after `after` in commit order, at most
    /// `limit` of them: what the Core delivers, a page at a time, without their payloads. Only
    /// the position, the kind, the id and the name of each are read, so a row whose other columns
    /// do not decode is listed, and read on its own ([`outbox_row`](Self::outbox_row)).
    pub fn pending_outbox(&self, after: i64, limit: u32) -> Result<Vec<PendingRow>> {
        self.under_core_policy(|connection| {
            query(
                connection,
                &format!(
                    "SELECT seq, kind, id, name FROM _outbox \
                     WHERE state = '{}' AND kind IN ('{EVENT_KIND}', '{LINK_KIND}') AND seq > ?1 \
                     ORDER BY seq LIMIT ?2",
                    OutboxState::Pending.as_str()
                ),
                &[
                    SqlValue::Integer(after),
                    SqlValue::Integer(i64::from(limit)),
                ],
                |row| {
                    let kind: String = row.get(1)?;
                    Ok(PendingRow {
                        seq: row.get(0)?,
                        kind: if kind == EVENT_KIND {
                            OutboxKind::Event
                        } else {
                            OutboxKind::Link
                        },
                        id: read_optional_id(row, 2, "_outbox", "id").ok().flatten(),
                        name: row.get(3)?,
                    })
                },
            )
        })
    }

    /// The event or link request at position `seq` of the outbox, read whole; a column outside
    /// its stored form is [`Error::MalformedCoreRow`], and a position that holds neither
    /// [`Error::OutboxRowNotFound`].
    pub fn outbox_row(&self, seq: i64) -> Result<OutboxRow> {
        self.under_core_policy(|connection| {
            let at = [SqlValue::Integer(seq)];
            if let Some(event) = events_where(connection, "seq = ?1", &at)?
                .into_iter()
                .next()
            {
                return Ok(OutboxRow::Event(event));
            }
            links_where(connection, "seq = ?1", &at)?
                .into_iter()
                .next()
                .map(OutboxRow::Link)
                .ok_or(Error::OutboxRowNotFound)
        })
    }

    /// Closes the pending row at position `seq` as `refused`, at `at`, in a transaction of its
    /// own: a row whose id does not decode, which no delivery can name. A row that is not pending
    /// is [`Error::OutboxRowNotPending`].
    pub fn refuse_outbox_row(&self, seq: i64, at: UtcMillis) -> Result<()> {
        self.under_core_policy(|connection| {
            handle::in_transaction(connection, || {
                let refused = connection.execute(
                    "UPDATE _outbox SET state = ?2, updated_at = ?3 WHERE seq = ?1 AND state = ?4",
                    rusqlite::params![
                        seq,
                        OutboxState::Refused.as_str(),
                        at.as_millis(),
                        OutboxState::Pending.as_str(),
                    ],
                )?;
                if refused == 1 {
                    Ok(())
                } else {
                    Err(Error::OutboxRowNotPending)
                }
            })
        })
    }

    /// Every event the file's outbox holds, in commit order, whatever its state.
    pub fn outbox_events(&self) -> Result<Vec<EventRow>> {
        self.under_core_policy(|connection| events_where(connection, "1", &[]))
    }

    /// Every link request the file's outbox holds, in commit order, whatever its state.
    pub fn outbox_links(&self) -> Result<Vec<LinkRow>> {
        self.under_core_policy(|connection| links_where(connection, "1", &[]))
    }

    /// Where the delivery of `event` to `consumer` stands; `None` before any attempt was recorded.
    pub fn delivery(&self, event: Id, consumer: &str) -> Result<Option<DeliveryRow>> {
        self.under_core_policy(|connection| delivery_of(connection, event, consumer))
    }

    /// Records, at `at` and in a transaction of its own, that `consumer` recorded `event`: after
    /// the consumer's own transaction committed, never inside it, since the two are in two files
    /// (AD-10). Recording it again is harmless; a delivery is at least once. A delivery moved to
    /// the dead letters stays there, refused with [`Error::OutboxRowNotPending`]: only its replay
    /// (`vilicus events replay`) takes it out. Fails with [`Error::OutboxRowNotFound`] when the
    /// file holds no such event.
    pub fn record_delivered(
        &self,
        event: Id,
        consumer: &str,
        at: UtcMillis,
    ) -> Result<DeliveryRow> {
        self.under_core_policy(|connection| {
            let mut recorded = None;
            handle::in_transaction(connection, || {
                outbox_state(connection, event, EVENT_KIND)?.ok_or(Error::OutboxRowNotFound)?;
                let earlier = delivery_of(connection, event, consumer)?;
                if earlier
                    .as_ref()
                    .is_some_and(|delivery| delivery.state == DeliveryState::DeadLetter)
                {
                    return Err(Error::OutboxRowNotPending);
                }
                let delivery = DeliveryRow {
                    event,
                    consumer: consumer.to_owned(),
                    attempts: earlier.map_or(0, |delivery| delivery.attempts),
                    state: DeliveryState::Delivered,
                    updated_at: at,
                };
                write_delivery(connection, &delivery)?;
                recorded = Some(delivery);
                Ok(())
            })?;
            recorded.ok_or(Error::OutboxRowNotFound)
        })
    }

    /// Records, at `at` and in a transaction of its own, one failed attempt to deliver `event`
    /// to `consumer`. The attempt that reaches `max_attempts` moves the event to the dead letters
    /// in the same transaction, as `_dead_letter` row `dead_letter` (AD-29), and the delivery is
    /// then [`DeliveryState::DeadLetter`]. A delivery that is no longer failing is refused with
    /// [`Error::OutboxRowNotPending`], and an event the file does not hold with
    /// [`Error::OutboxRowNotFound`].
    pub fn record_failed_delivery(
        &self,
        event: Id,
        consumer: &str,
        at: UtcMillis,
        max_attempts: u32,
        dead_letter: Id,
    ) -> Result<DeliveryRow> {
        self.under_core_policy(|connection| {
            let mut recorded = None;
            handle::in_transaction(connection, || {
                outbox_state(connection, event, EVENT_KIND)?.ok_or(Error::OutboxRowNotFound)?;
                let earlier = delivery_of(connection, event, consumer)?;
                if earlier
                    .as_ref()
                    .is_some_and(|delivery| delivery.state != DeliveryState::Failing)
                {
                    return Err(Error::OutboxRowNotPending);
                }
                let attempts = earlier.map_or(0, |delivery| delivery.attempts) + 1;
                let spent = attempts >= max_attempts;
                let delivery = DeliveryRow {
                    event,
                    consumer: consumer.to_owned(),
                    attempts,
                    state: if spent {
                        DeliveryState::DeadLetter
                    } else {
                        DeliveryState::Failing
                    },
                    updated_at: at,
                };
                write_delivery(connection, &delivery)?;
                if spent {
                    connection.execute(
                        "INSERT INTO _dead_letter (id, event_id, consumer, attempts, failed_at) \
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        rusqlite::params![
                            dead_letter.to_bytes(),
                            event.to_bytes(),
                            consumer,
                            attempts,
                            at.as_millis(),
                        ],
                    )?;
                }
                recorded = Some(delivery);
                Ok(())
            })?;
            recorded.ok_or(Error::OutboxRowNotFound)
        })
    }

    /// Closes the pending event or link request `id` as `state`, at `at`, in a transaction of
    /// its own: an event once every delivery is done, a link once the Core registered or refused
    /// it. A row that is not pending keeps its state and the call fails with
    /// [`Error::OutboxRowNotPending`]; `state` [`OutboxState::Pending`] closes nothing and is
    /// refused the same way.
    pub fn close_outbox_row(&self, id: Id, state: OutboxState, at: UtcMillis) -> Result<()> {
        self.under_core_policy(|connection| {
            handle::in_transaction(connection, || {
                let current = match outbox_state(connection, id, EVENT_KIND)? {
                    Some(current) => current,
                    None => {
                        outbox_state(connection, id, LINK_KIND)?.ok_or(Error::OutboxRowNotFound)?
                    }
                };
                if current != OutboxState::Pending || state == OutboxState::Pending {
                    return Err(Error::OutboxRowNotPending);
                }
                connection.execute(
                    "UPDATE _outbox SET state = ?2, updated_at = ?3 WHERE id = ?1",
                    rusqlite::params![id.to_bytes(), state.as_str(), at.as_millis()],
                )?;
                Ok(())
            })
        })
    }

    /// Every dead letter of the file, oldest first.
    pub fn dead_letters(&self) -> Result<Vec<DeadLetter>> {
        self.under_core_policy(|connection| {
            query(
                connection,
                "SELECT id, event_id, consumer, attempts, failed_at FROM _dead_letter \
                 ORDER BY failed_at, id",
                &[],
                |row| {
                    Ok(DeadLetter {
                        id: read_id(row, 0, "_dead_letter", "id")?,
                        event: read_id(row, 1, "_dead_letter", "event_id")?,
                        consumer: row.get(2)?,
                        attempts: u32::try_from(row.get::<_, i64>(3)?)
                            .map_err(|_| malformed("_dead_letter", "attempts"))?,
                        failed_at: read_time(row, 4, "_dead_letter", "failed_at")?,
                    })
                },
            )
        })
    }

    /// The retention purge of the outbox (AD-26): deletes, in a transaction of its own, every
    /// closed event and link request and every `done` effect intent created before `cutoff`,
    /// with the delivery rows of those events, except an event that still has a dead letter;
    /// then checkpoints the WAL in TRUNCATE mode until it is empty, as the journal's purge does
    /// ([`purge_journal`](Self::purge_journal)), so payloads leave the file and the WAL (D132).
    /// A `done` intent that is gone no longer blocks a repeat of its key (AD-28). The cutoff is
    /// the Core's, never a module's. Refuses to run inside an open transaction
    /// ([`Error::TransactionOpen`]); a checkpoint that stays busy is
    /// [`Error::DeletedNotCheckpointed`].
    pub fn purge_outbox(&self, cutoff: UtcMillis) -> Result<OutboxPurge> {
        self.require_no_transaction()?;
        let deleted = self.under_core_policy(|connection| {
            let mut deleted = 0;
            handle::in_transaction(connection, || {
                let at = [cutoff.as_millis()];
                deleted = connection.execute(
                    &format!(
                        "DELETE FROM _deliveries WHERE event_id IN \
                         (SELECT id FROM _outbox WHERE {EXPIRED_OUTBOX_ROWS})"
                    ),
                    at,
                )?;
                deleted += connection.execute(
                    &format!("DELETE FROM _outbox WHERE {EXPIRED_OUTBOX_ROWS}"),
                    at,
                )?;
                Ok(())
            })?;
            Ok(deleted)
        })?;
        let checkpoint_attempts = handle::checkpoint_after_delete(self, deleted)?;
        Ok(OutboxPurge {
            deleted,
            checkpoint_attempts,
        })
    }
}
