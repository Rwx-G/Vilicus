//! Effect intents and consumed events of a module file (AD-10, AD-26, AD-28, NFR-3).
//!
//! A handler that needs an outbound effect does not perform it: the Core writes an effect intent
//! to `_outbox`, with its business idempotency key, in the transaction of the call's writes, and
//! performs it after the commit; the outcome is recorded in the same row, in a transaction of its
//! own. An intent is unique in its file by its effect's name and its idempotency key: the same
//! request of the same caller is the earlier intent, any other request of that pair is a conflict.
//! A `done` intent blocks a repeat only while its row is kept, until the outbox's retention purge
//! ([`Handle::purge_outbox`]). An intent is `pending` until an outcome is recorded, then `done`,
//! `failed` or `unknown`.
//! Only a `failed` intent goes back to `pending`, keeping its id and key, so only the Core
//! retries and always with the same key; an `unknown` one is reported to the member and never
//! retried. A consumer of an event records the event id in `_consumed` in the transaction of its
//! effect.
//!
//! Every statement is one of the Core's own, under [`Policy::Core`](crate::authorizer); module
//! SQL can neither write nor read `_outbox` or `_consumed`.

use core::fmt;

use rusqlite::types::Value as SqlValue;
use rusqlite::{OptionalExtension, Row};
use vilicus_types::{CallId, EffectOutcome, Id, Principal, UtcMillis};

use crate::error::{Error, Result};
use crate::handle::{self, Handle, Write};
use crate::journal::{
    CallKey, malformed, read_id, read_optional_id, read_time, require_transaction,
};

/// The `kind` of an effect intent row of `_outbox`; events and link requests have their own
/// (`event.rs`).
const EFFECT_KIND: &str = "effect";

/// Where an effect intent stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EffectState {
    /// Written with the call, not yet performed, or failed and put back by a retry.
    Pending,
    /// The plugin reported it done.
    Done,
    /// The plugin reported it failed; the Core may retry it with the same key.
    Failed,
    /// The plugin could not tell; reported to the member, never retried blindly.
    Unknown,
}

impl EffectState {
    /// Every state, in declaration order.
    pub const ALL: [Self; 4] = [Self::Pending, Self::Done, Self::Failed, Self::Unknown];

    /// The stored form.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Done => EffectOutcome::Done.as_str(),
            Self::Failed => EffectOutcome::Failed.as_str(),
            Self::Unknown => EffectOutcome::Unknown.as_str(),
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|state| state.as_str() == name)
    }
}

impl From<EffectOutcome> for EffectState {
    fn from(outcome: EffectOutcome) -> Self {
        match outcome {
            EffectOutcome::Done => Self::Done,
            EffectOutcome::Failed => Self::Failed,
            EffectOutcome::Unknown => Self::Unknown,
        }
    }
}

impl fmt::Display for EffectState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// An effect intent as a call writes it.
#[derive(Clone, Copy, Debug)]
pub struct EffectIntent<'a> {
    /// The call that needs the effect.
    pub call: CallKey<'a>,
    /// The hash of the call's request, when the pipeline gives one.
    pub request_hash: Option<&'a [u8]>,
    /// The member an `unknown` outcome is reported to: the one who made or approved the call, or
    /// the one it acts for.
    pub member: Option<Id>,
    /// When no member is named, the adult an `unknown` outcome is reported to first, before every
    /// other adult of the household: the adult who validated the rule or playbook of the call.
    pub first_adult: Option<Id>,
    /// The intent's id, a UUIDv7 the Core stamped.
    pub id: Id,
    /// The effect, as the module names it.
    pub effect: &'a str,
    /// The business idempotency key, derived from the effect's parameters (AD-28): with the
    /// effect's name, it identifies the intent in the file.
    pub idempotency_key: &'a [u8],
    /// The parameters of the effect, as the module encoded them.
    pub payload: &'a [u8],
    /// The time of the call.
    pub created_at: UtcMillis,
}

/// An effect intent read back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectRow {
    /// The intent's id.
    pub id: Id,
    /// The id of the call that wrote it.
    pub call_id: CallId,
    /// The hash of that call's request, if it carried one.
    pub request_hash: Option<Vec<u8>>,
    /// The principal of that call.
    pub principal: Principal,
    /// The `source` of that call.
    pub source: String,
    /// The member an `unknown` outcome is reported to.
    pub member: Option<Id>,
    /// When no member is named, the adult an `unknown` outcome is reported to first.
    pub first_adult: Option<Id>,
    /// The effect.
    pub effect: String,
    /// The business idempotency key.
    pub idempotency_key: Vec<u8>,
    /// The parameters.
    pub payload: Vec<u8>,
    /// Where it stands.
    pub state: EffectState,
    /// The outcomes recorded so far: one per attempt the Core made.
    pub attempts: u32,
    /// When the call wrote it.
    pub created_at: UtcMillis,
    /// When its state last changed.
    pub updated_at: UtcMillis,
}

const EFFECT_COLUMNS: &str = "id, call_id, principal, member, name, idempotency_key, payload, \
                              state, attempts, created_at, updated_at, request_hash, source, \
                              first_adult";

fn effect_row(row: &Row<'_>) -> Result<EffectRow> {
    let principal: String = row.get(2)?;
    let state: String = row.get(7)?;
    let call_id: Vec<u8> = row.get(1)?;
    Ok(EffectRow {
        id: read_id(row, 0, "_outbox", "id")?,
        call_id: <[u8; 16]>::try_from(call_id.as_slice())
            .ok()
            .and_then(|bytes| CallId::from_bytes(bytes).ok())
            .ok_or(malformed("_outbox", "call_id"))?,
        request_hash: row.get(11)?,
        source: row.get(12)?,
        first_adult: read_optional_id(row, 13, "_outbox", "first_adult")?,
        principal: Principal::ALL
            .iter()
            .copied()
            .find(|known| known.as_str() == principal)
            .ok_or(malformed("_outbox", "principal"))?,
        member: read_optional_id(row, 3, "_outbox", "member")?,
        effect: row.get(4)?,
        idempotency_key: row.get(5)?,
        payload: row.get(6)?,
        state: EffectState::from_name(&state).ok_or(malformed("_outbox", "state"))?,
        attempts: u32::try_from(row.get::<_, i64>(8)?)
            .map_err(|_| malformed("_outbox", "attempts"))?,
        created_at: read_time(row, 9, "_outbox", "created_at")?,
        updated_at: read_time(row, 10, "_outbox", "updated_at")?,
    })
}

fn query_effects(
    connection: &rusqlite::Connection,
    filter: &str,
    values: &[SqlValue],
) -> Result<Vec<EffectRow>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {EFFECT_COLUMNS} FROM _outbox WHERE kind = '{EFFECT_KIND}' AND {filter} ORDER BY seq"
    ))?;
    let mut rows = statement.query(rusqlite::params_from_iter(values))?;
    let mut effects = Vec::new();
    while let Some(row) = rows.next()? {
        effects.push(effect_row(row)?);
    }
    Ok(effects)
}

fn effect_by_id(connection: &rusqlite::Connection, id: Id) -> Result<EffectRow> {
    query_effects(
        connection,
        "id = ?1",
        &[SqlValue::Blob(id.to_bytes().to_vec())],
    )?
    .into_iter()
    .next()
    .ok_or(Error::EffectNotFound)
}

impl Handle<Write> {
    /// Writes `intent` to `_outbox` as `pending`, inside the write transaction the caller holds,
    /// so the intent commits with the call's writes or not at all (AD-28). When an intent of the
    /// same effect name and idempotency key is already in the file, nothing is written: if it
    /// carries the same payload and was requested by the same principal and `source`, it is
    /// returned, the same effect never requested twice; otherwise the request fails with
    /// [`Error::EffectConflict`], since one key cannot name two effects. Fails with
    /// [`Error::NoTransaction`] outside a transaction, and refuses an empty key or effect name
    /// with [`Error::InvalidEffectIntent`].
    pub fn append_effect(&self, intent: &EffectIntent<'_>) -> Result<EffectRow> {
        if intent.idempotency_key.is_empty() || intent.effect.is_empty() {
            return Err(Error::InvalidEffectIntent);
        }
        self.under_core_policy(|connection| {
            require_transaction(connection)?;
            let earlier = query_effects(
                connection,
                "name = ?1 AND idempotency_key = ?2",
                &[
                    SqlValue::Text(intent.effect.to_owned()),
                    SqlValue::Blob(intent.idempotency_key.to_vec()),
                ],
            )?;
            if let Some(earlier) = earlier.into_iter().next() {
                let same_request = earlier.payload == intent.payload
                    && earlier.principal == intent.call.principal
                    && earlier.source == intent.call.source.to_string();
                return if same_request {
                    Ok(earlier)
                } else {
                    Err(Error::EffectConflict)
                };
            }
            connection.execute(
                "INSERT INTO _outbox (id, kind, call_id, principal, source, member, name, \
                 idempotency_key, payload, state, attempts, created_at, updated_at, \
                 request_hash, first_adult) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0, ?11, ?11, ?12, ?13)",
                rusqlite::params![
                    intent.id.to_bytes(),
                    EFFECT_KIND,
                    intent.call.call_id.to_bytes(),
                    intent.call.principal.as_str(),
                    intent.call.source.to_string(),
                    intent.member.map(Id::to_bytes),
                    intent.effect,
                    intent.idempotency_key,
                    intent.payload,
                    EffectState::Pending.as_str(),
                    intent.created_at.as_millis(),
                    intent.request_hash,
                    intent.first_adult.map(Id::to_bytes),
                ],
            )?;
            effect_by_id(connection, intent.id)
        })
    }

    /// The effect intents the call `key` wrote in this file, in the order it wrote them.
    pub fn effects_of_call(&self, key: &CallKey<'_>) -> Result<Vec<EffectRow>> {
        self.under_core_policy(|connection| {
            query_effects(
                connection,
                "principal = ?1 AND source = ?2 AND call_id = ?3",
                &[
                    SqlValue::Text(key.principal.as_str().to_owned()),
                    SqlValue::Text(key.source.to_string()),
                    SqlValue::Blob(key.call_id.to_bytes().to_vec()),
                ],
            )
        })
    }

    /// Every effect intent of the file in `state`, in commit order: the `pending` ones are those
    /// the Core performs, the `unknown` ones those it reports.
    pub fn effects_in_state(&self, state: EffectState) -> Result<Vec<EffectRow>> {
        self.under_core_policy(|connection| {
            query_effects(
                connection,
                "state = ?1",
                &[SqlValue::Text(state.as_str().to_owned())],
            )
        })
    }

    /// Records the outcome a plugin returned for the `pending` intent `id`, at `at`, in a
    /// transaction of its own, after the call's commit (AD-28). An intent that is not `pending`
    /// keeps its state and the call fails with [`Error::EffectNotPending`]: an outcome is
    /// recorded once per attempt.
    pub fn record_effect_outcome(
        &self,
        id: Id,
        outcome: EffectOutcome,
        at: UtcMillis,
    ) -> Result<EffectRow> {
        self.move_effect(id, EffectState::Pending, EffectState::from(outcome), at, 1)
    }

    /// Puts the `failed` intent `id` back to `pending`, with its id, its key and its payload, so
    /// the Core performs it again with the same key (AD-28). Any other state is refused with
    /// [`Error::EffectNotRetryable`]: a `done` intent is done, a `pending` one is not yet tried,
    /// and an `unknown` one may have taken place, so retrying it blindly could apply it twice.
    pub fn retry_effect(&self, id: Id, at: UtcMillis) -> Result<EffectRow> {
        self.move_effect(id, EffectState::Failed, EffectState::Pending, at, 0)
    }

    fn move_effect(
        &self,
        id: Id,
        from: EffectState,
        to: EffectState,
        at: UtcMillis,
        attempts: i64,
    ) -> Result<EffectRow> {
        self.under_core_policy(|connection| {
            let mut moved = None;
            handle::in_transaction(connection, || {
                let current = effect_by_id(connection, id)?;
                if current.state != from {
                    return Err(if from == EffectState::Pending {
                        Error::EffectNotPending {
                            state: current.state,
                        }
                    } else {
                        Error::EffectNotRetryable {
                            state: current.state,
                        }
                    });
                }
                connection.execute(
                    "UPDATE _outbox SET state = ?2, attempts = attempts + ?3, updated_at = ?4 \
                     WHERE id = ?1",
                    rusqlite::params![id.to_bytes(), to.as_str(), attempts, at.as_millis()],
                )?;
                moved = Some(effect_by_id(connection, id)?);
                Ok(())
            })?;
            moved.ok_or(Error::EffectNotFound)
        })
    }

    /// True when the consumer `consumer` recorded the event `event` in this file.
    pub fn is_consumed(&self, event: Id, consumer: &str) -> Result<bool> {
        self.under_core_policy(|connection| {
            Ok(connection
                .query_row(
                    "SELECT 1 FROM _consumed WHERE event_id = ?1 AND consumer = ?2",
                    rusqlite::params![event.to_bytes(), consumer],
                    |_| Ok(()),
                )
                .optional()?
                .is_some())
        })
    }

    /// Records that `consumer` consumed the event `event` at `at`, inside the write transaction
    /// of its effect, which the caller holds (AD-10, AD-26): the record commits with the effect
    /// or not at all. Fails with [`Error::NoTransaction`] outside a transaction; a second record
    /// of the same event for the same consumer fails on the table's primary key.
    pub fn record_consumed(&self, event: Id, consumer: &str, at: UtcMillis) -> Result<()> {
        self.under_core_policy(|connection| {
            require_transaction(connection)?;
            connection.execute(
                "INSERT INTO _consumed (event_id, consumer, consumed_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![event.to_bytes(), consumer, at.as_millis()],
            )?;
            Ok(())
        })
    }
}
