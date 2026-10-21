//! One call of a module through the typed record API (AD-9): every write of the call in one
//! `BEGIN IMMEDIATE` transaction on the module file's write handle, each stamped by the Core and
//! journaled in the same transaction (AD-26), the call deduplicated by its caller's `call_id`
//! (AD-28), its effect intents, events and link requests written to the outbox (AD-10, AD-29)
//! and the event it consumes recorded with it.

use vilicus_module_api::{
    EVENT_PAYLOAD_MAX_LEN, FieldKind, ModuleDeclaration, ReadRecord, Records, Table, Value,
    WriteError, Written, is_identifier, topic_module,
};
use vilicus_storage::{
    AuthorityKind, CallKey, EffectIntent, EventIntent, Handle, JournalEntry, JournalRow,
    LinkIntent, Role, SqlValue, Write,
};
use vilicus_types::{
    CallId, DataType, EffectiveTaint, Id, ModuleName, Principal, Rev, Source, Taint, UtcMillis,
};

use super::envelope::{self, data_types_text};
use super::journal;
use super::provenance::{self, RecordProvenance, Stamp, Stored};
use super::{
    RecordError, declared_table, from_stored, in_write_transaction, insert_row, update_row,
};
use crate::api::{self, ApiReads};

/// Who makes a call and on what authority, as the pipeline established it (AD-8, AD-7). The
/// module never sees it: the Core stamps each write of the call from it.
#[derive(Clone)]
pub struct Call {
    /// The principal of the call.
    pub principal: Principal,
    /// What the Core stamps as each record's `source` (spine conventions, `source` vocabulary).
    pub source: Source,
    /// The taint of what the call consumed before it writes: for an AI or plugin principal, its
    /// session taint, `external` once the session read an `external` datum or `member` free text
    /// (`doc/architecture.md` section 9.3); for an event, its emitting call's taint (AD-27);
    /// otherwise `trusted`.
    pub session: Taint,
    /// What an AI or plugin session consumed before the call, which every write of the call holds
    /// whatever inputs it declares; [`Consumed::NOTHING`] for every other principal.
    pub consumed: Consumed,
    /// Whether a member made or approved the call's writes.
    pub authority: Authority,
    /// The records of other files the call read, with the provenance the Core read with them: a
    /// write may name them as inputs. A record of the written file is read from the file itself.
    pub read: Vec<RecordProvenance>,
    /// The records every write of the call is derived from without the module naming them: the
    /// definition of a rule or a playbook an adult validated, or the record whose event a call
    /// consumes. They count as inputs of each write, and stand for its declared inputs.
    pub implicit_inputs: Vec<RecordProvenance>,
}

/// What an AI or plugin session consumed before a call (D103, AD-7), as its capability token
/// recorded it: the data types of every datum it read, and the most restrictive effective taint
/// among them as the member it acts for saw them, `member` for another member's structured
/// fields included, which do not taint the session (D70). A write of the call holds at least
/// these data types and derives from at least this taint, so declaring fewer inputs never lowers
/// what it stores.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Consumed {
    /// The data types of what the session read.
    pub data_types: Vec<DataType>,
    /// The most restrictive effective taint of what the session read.
    pub taint: EffectiveTaint,
}

impl Consumed {
    /// A session that read nothing, and every principal that has no session.
    pub const NOTHING: Self = Self {
        data_types: Vec::new(),
        taint: EffectiveTaint::Trusted,
    };
}

/// Whether a member made or approved a call's writes, which decides their stored taint and
/// author (AD-6, D70, D99, D104).
#[derive(Clone)]
pub enum Authority {
    /// The member's own action, from a `Member` or `Cli` principal: stored `trusted` with the
    /// member as author.
    OwnAction {
        /// The member.
        member: Id,
    },
    /// A member's explicit approval of an `AiTask` or `Plugin` request, a light confirmation of
    /// an elevated request: its structured fields are stored `trusted` with the member as author,
    /// and free text drafted in a tainted session keeps `external`, however edited.
    Approved {
        /// The approving member.
        member: Id,
        /// The texts the member wrote in full in an empty field of the approval screen.
        written: Vec<String>,
        /// The assistant's drafts of the request, as the model wrote them.
        drafts: Vec<String>,
    },
    /// No member made or approved the writes: their taint is the most restrictive of the call's
    /// session taint and of its inputs as `acting_for` sees them.
    Unapproved {
        /// The author the conventions give the principal: the validating adult of a rule of
        /// human origin, the emitting call's author for an event, the member an AI task acts for,
        /// or none.
        author: Option<Id>,
        /// The member the call acts for, whose view of each input counts: a `trusted` input
        /// another member authored reads as `member`, and stores `external`.
        acting_for: Option<Id>,
    },
}

/// The clock and random source the Core stamps a write with: the time of the write, and the
/// random bits of a new record's UUIDv7. The Core's durable clock (AD-30) and its random source
/// supply them; a test supplies fixed ones.
pub trait Stamper {
    /// The time of a write.
    fn now(&mut self) -> UtcMillis;
    /// The random bits of a new id, as [`Id::new_v7`] takes them.
    fn id_random(&mut self) -> [u8; 10];
}

/// What one call is beside who makes it: the id its caller gave it, the hash of its request, and,
/// for a consumer of an event, the delivery it reacts to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invocation {
    /// The call's id: a UUIDv7 the caller generated before any queueing (AD-28), or a rule
    /// action's name-based id (AD-39). A second call of the same principal and `source` with this
    /// id, against the same file, is this call.
    pub call_id: CallId,
    /// The SHA-256 of the request's canonical encoding (AD-13), when the pipeline gives it: a
    /// second call of the same key whose journaled or outbox rows carry another hash reuses the
    /// call id for another request and is refused ([`RecordError::CallIdReused`]), rather than
    /// answered with the first call's result. Either side without a hash compares as equal.
    pub request_hash: Option<[u8; 32]>,
    /// The event an `Event` call consumes; `None` for every other principal (AD-27).
    pub delivery: Option<EventDelivery>,
}

/// The delivery of one event to one consumer (AD-10, AD-27): the consumer records the event id
/// in `_consumed` in the transaction of its effect, so a second delivery produces no second
/// effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventDelivery {
    /// The event's id.
    pub event: Id,
    /// The consumer, as the pipeline names it.
    pub consumer: &'static str,
}

/// An effect intent a call wrote to the outbox (AD-28): the effect is performed by the Core after
/// the commit, never by the module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestedEffect {
    /// The intent's id.
    pub id: Id,
    /// The effect, as the module named it.
    pub effect: String,
    /// The business idempotency key the module derived from the effect's parameters.
    pub idempotency_key: Vec<u8>,
}

/// The most inputs one write may have, declared and implicit together: a write naming more is
/// refused ([`RecordError::TooManyInputs`]). Far above what a derivation reads, and low enough
/// that resolving and journaling them stays cheap.
pub const MAX_WRITE_INPUTS: usize = 4096;

/// A record a call changed: what the write journal of the call records (AD-26).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordChange {
    /// The table, as the journal names it: a table a later migration removed (Story 3.7) is
    /// still named, though the module no longer declares it.
    pub table: String,
    /// The record.
    pub id: Id,
    /// Its revision before the write; `None` for an insert.
    pub before: Option<Rev>,
    /// Its revision after the write; `None` for a delete.
    pub after: Option<Rev>,
    /// The inputs of the write, each once: those it declared, in the order given, then the
    /// call's implicit inputs.
    pub inputs: Vec<Id>,
}

/// A committed call: what the module's code returned, every record it changed and every effect
/// intent it wrote, in order.
#[derive(Debug)]
pub struct CallOutcome<T> {
    /// What the module's code returned.
    pub value: T,
    /// Every record the call changed.
    pub changes: Vec<RecordChange>,
    /// Every effect intent the call wrote; an effect whose key an earlier intent holds is that
    /// intent's, and not listed again.
    pub effects: Vec<RequestedEffect>,
}

/// What became of a call.
#[derive(Debug)]
pub enum CallResult<T> {
    /// The module's code ran and the call committed.
    Committed(CallOutcome<T>),
    /// A call of the same principal, `source` and `call_id` wrote in this file before: the
    /// module's code did not run, nothing was written, and this is that call's result, read
    /// back from the journal and the outbox (AD-26, AD-28).
    Deduplicated(EarlierCall),
    /// The consumer already recorded the event in `_consumed`: the module's code did not run
    /// and nothing was written (AD-10).
    AlreadyConsumed,
}

/// The result of an earlier call of the same key, as the file holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EarlierCall {
    /// Every record it changed, in order.
    pub changes: Vec<RecordChange>,
    /// Every effect intent it wrote, in order.
    pub effects: Vec<RequestedEffect>,
}

/// Runs `body`, the module's code for one call, in one `BEGIN IMMEDIATE` transaction on
/// `handle`, the write handle of a file of `module`. `body` writes through the
/// [`Records`] it receives, and the transaction commits only when `body` returns `Ok` and no
/// write of the call was refused; otherwise it is rolled back and nothing of the call is stored,
/// its journal rows, effect intents and consumed event included. A refused write ends the call
/// with that refusal, whatever `body` returns after it; an error `body` returns of its own is
/// [`RecordError::Aborted`]. A panic, in `body` or in the Core while it writes, rolls the
/// transaction back as it unwinds; catching it is the caller's (AD-9).
///
/// In the transaction, before `body` runs, the Core looks the call up by its principal, its
/// `source` and the `call_id` of `invocation` in the file's journal and outbox: a call of that
/// key that wrote is this one, and its result is returned without running `body`
/// ([`CallResult::Deduplicated`]); a call that wrote nothing left no row, so it is not
/// deduplicated (AD-26, AD-28). Then a consumer's delivery already recorded in `_consumed` is
/// [`CallResult::AlreadyConsumed`]. Each write of the call journals its record, before and after
/// images, revisions, the call's principal, authority and member, and the provenance of its
/// inputs, implicit ones included; a consumer's call records its event in `_consumed` before the
/// commit.
///
/// The call is refused before any write when its authority does not fit its principal, or a
/// delivery its principal ([`RecordError::InconsistentCall`]).
///
/// The call serves no typed API read: each [`Records::read`] of `body` is
/// [`RecordError::UnknownQuery`]. The boundary of AD-9 runs module code with the reads its
/// [`Boundary`](crate::boundary::Boundary) serves.
pub fn run_call<T>(
    handle: &Handle<Write>,
    module: &'static ModuleDeclaration,
    call: &Call,
    invocation: &Invocation,
    stamper: &mut dyn Stamper,
    body: impl FnOnce(&mut dyn Records) -> Result<T, WriteError>,
) -> Result<CallResult<T>, RecordError> {
    run_call_reading(handle, module, call, invocation, None, stamper, body)
}

/// [`run_call`], with the typed API reads of `body` served from `reads` (AD-5): each record a read
/// returns counts as an input of every later write of the call.
pub(crate) fn run_call_reading<T>(
    handle: &Handle<Write>,
    module: &'static ModuleDeclaration,
    call: &Call,
    invocation: &Invocation,
    reads: Option<ApiReads<'_>>,
    stamper: &mut dyn Stamper,
    body: impl FnOnce(&mut dyn Records) -> Result<T, WriteError>,
) -> Result<CallResult<T>, RecordError> {
    check_call(call, invocation)?;
    let key = CallKey {
        principal: call.principal,
        source: &call.source,
        call_id: invocation.call_id,
    };
    in_write_transaction(handle, || {
        if let Some(earlier) = earlier_call(handle, &key, invocation.request_hash)? {
            return Ok(CallResult::Deduplicated(earlier));
        }
        if let Some(delivery) = invocation.delivery
            && handle.is_consumed(delivery.event, delivery.consumer)?
        {
            return Ok(CallResult::AlreadyConsumed);
        }
        let started = stamper.now();
        let mut records = CallRecords {
            handle,
            module,
            call,
            key,
            request_hash: invocation.request_hash,
            started,
            stamper,
            changes: Vec::new(),
            removed: Vec::new(),
            effects: Vec::new(),
            reads,
            read_records: Vec::new(),
            refusal: None,
        };
        let returned = body(&mut records);
        let CallRecords {
            changes,
            effects,
            refusal,
            ..
        } = records;
        match (refusal, returned) {
            (Some(refusal), _) => Err(refusal),
            (None, Err(error)) => Err(RecordError::Aborted(error)),
            (None, Ok(value)) => {
                if let Some(delivery) = invocation.delivery {
                    handle.record_consumed(delivery.event, delivery.consumer, started)?;
                }
                Ok(CallResult::Committed(CallOutcome {
                    value,
                    changes,
                    effects,
                }))
            }
        }
    })
}

/// The result of the earlier call of `key` in this file, if one wrote there: its journal rows and
/// its effect intents. A row whose request hash differs from `request_hash`, both being given,
/// is another request under the same call id, refused with [`RecordError::CallIdReused`].
fn earlier_call(
    handle: &Handle<Write>,
    key: &CallKey<'_>,
    request_hash: Option<[u8; 32]>,
) -> Result<Option<EarlierCall>, RecordError> {
    let journal = handle.journaled_call(key)?;
    let effects = handle.effects_of_call(key)?;
    if journal.is_empty() && effects.is_empty() {
        return Ok(None);
    }
    let other_request = |earlier: &Option<Vec<u8>>| matches!((earlier, request_hash), (Some(earlier), Some(hash)) if earlier.as_slice() != hash);
    if journal.iter().any(|row| other_request(&row.request_hash))
        || effects
            .iter()
            .any(|effect| other_request(&effect.request_hash))
    {
        return Err(RecordError::CallIdReused);
    }
    Ok(Some(EarlierCall {
        changes: journal
            .into_iter()
            .map(journaled_change)
            .collect::<Result<_, _>>()?,
        effects: effects
            .into_iter()
            .map(|effect| RequestedEffect {
                id: effect.id,
                effect: effect.effect,
                idempotency_key: effect.idempotency_key,
            })
            .collect(),
    }))
}

/// The change a journal `row` records. The row may name a table a migration
/// removed since the call (Story 3.7): its rows stay journaled until retention removes them, and
/// a repeated call still gets the first call's changes, under the table's journaled name.
fn journaled_change(row: JournalRow) -> Result<RecordChange, RecordError> {
    Ok(RecordChange {
        table: row.table,
        id: row.record,
        before: row.rev_before,
        after: row.rev_after,
        inputs: journal::decode_inputs(&row.inputs)?
            .into_iter()
            .map(|input| input.id)
            .collect(),
    })
}

/// Refuses a call whose authority or source does not fit its principal: only `Member` and `Cli`
/// act as a member themselves, and always do; only a request of a token principal is approved;
/// the `source` stamped on its records is one the principal produces; what it consumed fits its
/// session; and only an `Event` call, and every one, consumes a delivered event (AD-27).
fn check_call(call: &Call, invocation: &Invocation) -> Result<(), RecordError> {
    let acts_as_member = matches!(call.principal, Principal::Member | Principal::Cli);
    let authority_fits = match call.authority {
        Authority::OwnAction { .. } => acts_as_member,
        Authority::Approved { .. } => {
            matches!(call.principal, Principal::AiTask | Principal::Plugin)
        }
        Authority::Unapproved { .. } => !acts_as_member,
    };
    let delivery_fits = invocation.delivery.is_some() == (call.principal == Principal::Event);
    if authority_fits && source_fits(call) && consumed_fits(call) && delivery_fits {
        Ok(())
    } else {
        Err(RecordError::InconsistentCall)
    }
}

/// How the journal names a call's authority, and the member it names: the one who made or
/// approved the call, or the one it acts for.
fn journaled_authority(authority: &Authority) -> (AuthorityKind, Option<Id>) {
    match *authority {
        Authority::OwnAction { member } => (AuthorityKind::OwnAction, Some(member)),
        Authority::Approved { member, .. } => (AuthorityKind::Approved, Some(member)),
        Authority::Unapproved { acting_for, .. } => (AuthorityKind::Unapproved, acting_for),
    }
}

/// The author of the call's writes, as the conventions give it: the member who made or approved
/// them, or the author an unapproved call names (the validating adult of a rule, the emitting
/// call's author for an event, the member an AI task acts for).
fn call_author(authority: &Authority) -> Option<Id> {
    match *authority {
        Authority::OwnAction { member } | Authority::Approved { member, .. } => Some(member),
        Authority::Unapproved { author, .. } => author,
    }
}

/// Whom an `unknown` outcome of the call's effect is reported to: the member the journal names;
/// when it names none (a rule, an event, an adapter, a display, a plugin acting for nobody), every
/// adult of the household, the call's author first when it has one, the adult who validated the
/// rule or playbook.
fn effect_report(authority: &Authority) -> (Option<Id>, Option<Id>) {
    match (journaled_authority(authority), authority) {
        ((_, Some(member)), _) => (Some(member), None),
        ((_, None), Authority::Unapproved { author, .. }) => (None, *author),
        ((_, None), _) => (None, None),
    }
}

/// True when what the call says it consumed fits its principal and its session taint: only an AI
/// or plugin session consumes, and a tainted session consumed something other than `trusted`,
/// which carries data types, while an untainted one consumed nothing `external`
/// (`doc/architecture.md` section 9.3, D103). An AI task's unapproved writes are authored by the
/// member it acts for (spine conventions, D147).
fn consumed_fits(call: &Call) -> bool {
    if !matches!(call.principal, Principal::AiTask | Principal::Plugin) {
        return call.consumed == Consumed::NOTHING;
    }
    if let (Principal::AiTask, Authority::Unapproved { author, acting_for }) =
        (call.principal, &call.authority)
        && author != acting_for
    {
        return false;
    }
    match call.session {
        Taint::External => {
            call.consumed.taint != EffectiveTaint::Trusted && !call.consumed.data_types.is_empty()
        }
        Taint::Trusted => call.consumed.taint != EffectiveTaint::External,
    }
}

/// The closed mapping from a principal to the `source` its records carry (spine conventions,
/// `source` vocabulary): a member's own action is `member(<that member>)`; a scheduled task acts
/// as an AI task; a plugin delivers its own content or an import; every other principal stamps
/// its own kind. `system` and `module(<name>)` are the Core's own writes, which no call makes.
fn source_fits(call: &Call) -> bool {
    match (call.principal, &call.source) {
        (Principal::Member | Principal::Cli, Source::Member(source)) => {
            matches!(call.authority, Authority::OwnAction { member } if member == *source)
        }
        (Principal::AiTask, Source::AiTask(_) | Source::ScheduledTask(_))
        | (Principal::Plugin, Source::Plugin(_) | Source::Import(_))
        | (Principal::Event, Source::Event(_))
        | (Principal::Rule, Source::Rule(_))
        | (Principal::Display, Source::Display(_))
        | (Principal::Adapter, Source::Adapter(_))
        | (Principal::Playbook, Source::Playbook(_)) => true,
        _ => false,
    }
}

/// The [`Records`] of one call: the module's writes, each stamped, checked and journaled in the
/// call's transaction.
struct CallRecords<'a> {
    handle: &'a Handle<Write>,
    module: &'static ModuleDeclaration,
    call: &'a Call,
    key: CallKey<'a>,
    request_hash: Option<[u8; 32]>,
    /// The time the call started, read once before the module's code runs: the time of every
    /// journal row, effect intent and consumed event of the call, so a retention cutoff never
    /// splits a call.
    started: UtcMillis,
    stamper: &'a mut dyn Stamper,
    changes: Vec<RecordChange>,
    /// The provenance of each record the call deleted, read before the delete: what an event
    /// about the deletion carries.
    removed: Vec<RecordProvenance>,
    effects: Vec<RequestedEffect>,
    /// What the call's typed API reads are served from; `None` refuses them.
    reads: Option<ApiReads<'a>>,
    /// The provenance of each record the call read through another module's typed API, each id
    /// once: an input of every write the call makes after the read (AD-7).
    read_records: Vec<RecordProvenance>,
    /// The first refused write of the call, which ends it.
    refusal: Option<RecordError>,
}

impl Records for CallRecords<'_> {
    fn insert(
        &mut self,
        table: &str,
        fields: &[(&str, Value)],
        inputs: &[Id],
    ) -> Result<Written, WriteError> {
        self.attempt(|records| records.insert_record(table, fields, inputs))
    }

    fn update(
        &mut self,
        table: &str,
        id: Id,
        expected: Rev,
        fields: &[(&str, Value)],
        inputs: &[Id],
    ) -> Result<Written, WriteError> {
        self.attempt(|records| records.update_record(table, id, expected, fields, inputs))
    }

    fn delete(&mut self, table: &str, id: Id) -> Result<(), WriteError> {
        self.attempt(|records| records.delete_record(table, id))
    }

    fn request_effect(
        &mut self,
        effect: &str,
        idempotency_key: &[u8],
        payload: &[u8],
    ) -> Result<Id, WriteError> {
        self.attempt(|records| records.request(effect, idempotency_key, payload))
    }

    fn emit(&mut self, topic: &str, record: Id, payload: &[u8]) -> Result<Id, WriteError> {
        self.attempt(|records| records.emit_event(topic, record, payload))
    }

    fn request_link(
        &mut self,
        record: Id,
        target_module: &str,
        target: Id,
    ) -> Result<Id, WriteError> {
        self.attempt(|records| records.link(record, target_module, target))
    }

    fn read(&mut self, module: &str, query: &str, id: Id) -> Result<ReadRecord, WriteError> {
        self.attempt(|records| records.read_through_api(module, query, id))
    }
}

impl CallRecords<'_> {
    /// Runs one write unless an earlier one was refused; a refusal is kept, and ends the call.
    fn attempt<R>(
        &mut self,
        write: impl FnOnce(&mut Self) -> Result<R, RecordError>,
    ) -> Result<R, WriteError> {
        if self.refusal.is_some() {
            return Err(WriteError::CallRefused);
        }
        write(self).map_err(|error| {
            let refused = write_error(&error);
            self.refusal = Some(error);
            refused
        })
    }

    fn insert_record(
        &mut self,
        table: &str,
        fields: &[(&str, Value)],
        inputs: &[Id],
    ) -> Result<Written, RecordError> {
        let table = declared_table(self.module, table)?;
        let (input_ids, inputs) = self.resolve_inputs(table, inputs)?;
        let stamp = provenance::stamp(self.call, table, fields, &inputs, None)?;
        let now = self.stamper.now();
        let id = Id::new_v7(now, self.stamper.id_random()).map_err(|_| RecordError::Invalid {
            table: table.name,
            column: "id",
            error: vilicus_module_api::ValueError::OutOfRange,
        })?;
        let envelope = [
            ("id", Value::Blob(id.to_bytes().to_vec())),
            ("source", Value::Text(self.call.source.to_string())),
            (
                "taint",
                Value::Text(stamp.labels.taint().as_str().to_owned()),
            ),
            (
                "text_taint",
                Value::Text(stamp.labels.text_taint().as_str().to_owned()),
            ),
            (
                "data_types",
                Value::Text(data_types_text(&stamp.data_types)),
            ),
            ("author", author_value(&stamp)),
            ("created_at", Value::Integer(now.as_millis())),
            ("updated_at", Value::Integer(now.as_millis())),
            ("rev", Value::Integer(Rev::FIRST.get())),
        ];
        insert_row(
            self.handle,
            table,
            &envelope,
            fields,
            &provenance::floor(self.call, &inputs),
        )?;
        let after = journal::image(self.handle, table, id)?;
        self.journal(
            RecordChange {
                table: table.name.to_owned(),
                id,
                before: None,
                after: Some(Rev::FIRST),
                inputs: input_ids,
            },
            None,
            after,
            &journal::encode_inputs(&inputs, &self.implicit_inputs())?,
        )?;
        Ok(Written {
            id,
            rev: Rev::FIRST,
        })
    }

    fn update_record(
        &mut self,
        table: &str,
        id: Id,
        expected: Rev,
        fields: &[(&str, Value)],
        inputs: &[Id],
    ) -> Result<Written, RecordError> {
        let table = declared_table(self.module, table)?;
        let (input_ids, inputs) = self.resolve_inputs(table, inputs)?;
        let (stored, rev) = read_stored(self.handle, table, id)?;
        if rev != expected {
            return Err(RecordError::StaleRevision { table: table.name });
        }
        let stamp = provenance::stamp(self.call, table, fields, &inputs, Some(&stored))?;
        let next = expected.next().ok_or(RecordError::Invalid {
            table: table.name,
            column: "rev",
            error: vilicus_module_api::ValueError::OutOfRange,
        })?;
        let now = self.stamper.now();
        let envelope = [
            ("source", Value::Text(self.call.source.to_string())),
            (
                "taint",
                Value::Text(stamp.labels.taint().as_str().to_owned()),
            ),
            (
                "text_taint",
                Value::Text(stamp.labels.text_taint().as_str().to_owned()),
            ),
            (
                "data_types",
                Value::Text(data_types_text(&stamp.data_types)),
            ),
            ("author", author_value(&stamp)),
            ("updated_at", Value::Integer(now.as_millis())),
            ("rev", Value::Integer(next.get())),
        ];
        let before = journal::image(self.handle, table, id)?;
        update_row(
            self.handle,
            table,
            id,
            &envelope,
            fields,
            &provenance::floor(self.call, &inputs),
        )?;
        let after = journal::image(self.handle, table, id)?;
        self.journal(
            RecordChange {
                table: table.name.to_owned(),
                id,
                before: Some(rev),
                after: Some(next),
                inputs: input_ids,
            },
            before,
            after,
            &journal::encode_inputs(&inputs, &self.implicit_inputs())?,
        )?;
        Ok(Written { id, rev: next })
    }

    fn delete_record(&mut self, table: &str, id: Id) -> Result<(), RecordError> {
        let table = declared_table(self.module, table)?;
        let key = [SqlValue::Blob(id.to_bytes().to_vec())];
        let row = self
            .handle
            .query_values(
                &format!("SELECT rev FROM {} WHERE id = ?1", table.name),
                &key,
            )?
            .into_iter()
            .next()
            .ok_or(RecordError::RecordNotFound { table: table.name })?;
        let rev = stored_rev(table, row.into_iter().next().map(from_stored))?;
        if let Some(provenance) = self.read_in_table(table, id)? {
            self.removed.push(provenance);
        }
        let before = journal::image(self.handle, table, id)?;
        self.handle
            .execute_values(&format!("DELETE FROM {} WHERE id = ?1", table.name), &key)?;
        let implicit: Vec<RecordProvenance> = self
            .call
            .implicit_inputs
            .iter()
            .chain(self.reads_beside_implicit())
            .cloned()
            .collect();
        let inputs = journal::encode_inputs(&implicit, &implicit)?;
        self.journal(
            RecordChange {
                table: table.name.to_owned(),
                id,
                before: Some(rev),
                after: None,
                inputs: implicit.iter().map(|input| input.id).collect(),
            },
            before,
            None,
            &inputs,
        )
    }

    /// Journals `change` in the call's transaction, at the call's start time, with the record's
    /// images and the encoded provenance of its inputs, then keeps it for the call's outcome.
    fn journal(
        &mut self,
        change: RecordChange,
        image_before: Option<Vec<u8>>,
        image_after: Option<Vec<u8>>,
        inputs: &[u8],
    ) -> Result<(), RecordError> {
        let (authority, member) = journaled_authority(&self.call.authority);
        self.handle.append_journal(&JournalEntry {
            call: self.key,
            request_hash: self.request_hash.as_ref().map(<[u8; 32]>::as_slice),
            authority,
            member,
            change_index: u32::try_from(self.changes.len())
                .map_err(|_| RecordError::InvalidJournal)?,
            table: &change.table,
            record: change.id,
            rev_before: change.before,
            rev_after: change.after,
            image_before: image_before.as_deref(),
            image_after: image_after.as_deref(),
            inputs,
            created_at: self.started,
        })?;
        self.changes.push(change);
        Ok(())
    }

    /// Writes an effect intent of the call to the outbox (AD-28): the effect `effect`, an
    /// identifier, with its business idempotency key, which may not be empty, and its parameters.
    /// The same request of the same caller that the file already holds under that name and key
    /// is returned instead, unchanged; any other request under them is
    /// [`RecordError::EffectConflict`].
    fn request(
        &mut self,
        effect: &str,
        idempotency_key: &[u8],
        payload: &[u8],
    ) -> Result<Id, RecordError> {
        if self.call.principal == Principal::Event {
            return Err(RecordError::NotInConsumer);
        }
        if !is_identifier(effect) || idempotency_key.is_empty() {
            return Err(RecordError::InvalidEffect);
        }
        let now = self.stamper.now();
        let id =
            Id::new_v7(now, self.stamper.id_random()).map_err(|_| RecordError::InvalidEffect)?;
        let (member, first_adult) = effect_report(&self.call.authority);
        let intent = self
            .handle
            .append_effect(&EffectIntent {
                call: self.key,
                request_hash: self.request_hash.as_ref().map(<[u8; 32]>::as_slice),
                member,
                first_adult,
                id,
                effect,
                idempotency_key,
                payload,
                created_at: self.started,
            })
            .map_err(|error| match error {
                vilicus_storage::Error::EffectConflict => RecordError::EffectConflict,
                other => RecordError::Storage(other),
            })?;
        if intent.id == id {
            self.effects.push(RequestedEffect {
                id,
                effect: intent.effect,
                idempotency_key: intent.idempotency_key,
            });
        }
        Ok(intent.id)
    }

    /// Writes an event of `topic` about `record` to the outbox (AD-10, AD-29): the topic is one the
    /// module declares, so the emitter is the module whose call this is, and the payload version
    /// is the topic's current one. The event carries the provenance of `record` as the call leaves
    /// it, raised to what the call itself derives from ([`provenance::call_floor`]), its data
    /// types joined by those an AI or plugin session consumed ([`provenance::floor`]), without
    /// its free text, and the call's author and member: what a consumer's call derives from
    /// (AD-27, D147). A consumer's call emits nothing; a payload is at most
    /// `EVENT_PAYLOAD_MAX_LEN` bytes.
    fn emit_event(&mut self, topic: &str, record: Id, payload: &[u8]) -> Result<Id, RecordError> {
        if self.call.principal == Principal::Event {
            return Err(RecordError::NotInConsumer);
        }
        let declared = self
            .module
            .topic(topic)
            .ok_or_else(|| match topic_module(topic) {
                Some(emitter) if emitter != self.module.name => RecordError::ForeignTopic,
                _ => RecordError::UnknownTopic,
            })?;
        if payload.len() > EVENT_PAYLOAD_MAX_LEN {
            return Err(RecordError::PayloadTooLong);
        }
        let mut provenance = self.changed_record(record)?;
        let floor = provenance::call_floor(self.call);
        provenance.labels = provenance.labels.most_restrictive(floor);
        provenance.data_types = provenance::floor(self.call, std::slice::from_ref(&provenance));
        provenance.free_text = Vec::new();
        let encoded = journal::encode_inputs(std::slice::from_ref(&provenance), &[])?;
        let now = self.stamper.now();
        let id =
            Id::new_v7(now, self.stamper.id_random()).map_err(|_| RecordError::InvalidEvent)?;
        let (_, member) = journaled_authority(&self.call.authority);
        self.handle.append_event(&EventIntent {
            call: self.key,
            request_hash: self.request_hash.as_ref().map(<[u8; 32]>::as_slice),
            id,
            topic: declared.name,
            version: declared.version,
            record,
            provenance: &encoded,
            author: call_author(&self.call.authority),
            member,
            payload,
            created_at: self.started,
        })?;
        Ok(id)
    }

    /// Writes a request to link `record`, which the call inserted or updated, to `target` of
    /// `target_module` (AD-10). The Core registers it after the commit, in the link table of the
    /// partition, once it finds `target` in that module's file of the same partition.
    fn link(&mut self, record: Id, target_module: &str, target: Id) -> Result<Id, RecordError> {
        if !ModuleName::is_valid(target_module) || target_module == self.module.name {
            return Err(RecordError::InvalidLink);
        }
        let kept = self
            .changes
            .iter()
            .rev()
            .find(|change| change.id == record)
            .is_some_and(|change| change.after.is_some());
        if !kept {
            return Err(RecordError::UnchangedRecord);
        }
        let now = self.stamper.now();
        let id = Id::new_v7(now, self.stamper.id_random()).map_err(|_| RecordError::InvalidLink)?;
        let (_, member) = journaled_authority(&self.call.authority);
        self.handle.append_link(&LinkIntent {
            call: self.key,
            request_hash: self.request_hash.as_ref().map(<[u8; 32]>::as_slice),
            id,
            record,
            target_module,
            target,
            member,
            created_at: self.started,
        })?;
        Ok(id)
    }

    /// The provenance of `record`, which the call changed, as the call leaves it: read from the
    /// file when the record is there, or as it was read before the call deleted it.
    fn changed_record(&self, record: Id) -> Result<RecordProvenance, RecordError> {
        let change = self
            .changes
            .iter()
            .rev()
            .find(|change| change.id == record)
            .ok_or(RecordError::UnchangedRecord)?;
        let found = if change.after.is_some() {
            self.read_in_file(record)?
        } else {
            self.removed
                .iter()
                .rev()
                .find(|removed| removed.id == record)
                .cloned()
        };
        found.ok_or(RecordError::UnchangedRecord)
    }

    /// The provenance of each input, each id once: the snapshot the call carries when the id is
    /// one of its implicit inputs (D147: an implicit input counts as captured, even when the
    /// module names it), otherwise a record of this file, read in the write transaction, or one
    /// the call read from another file; then the call's other implicit inputs, the records it read
    /// through another module's typed API included. A snapshot whose record the call also read
    /// afresh counts as the two combined, the most restrictive of both
    /// ([`RecordProvenance::combined`]), so a fresher read never lowers a snapshot. A write that
    /// must declare inputs and has none is refused, and so is one of more than
    /// [`MAX_WRITE_INPUTS`] inputs, declared and implicit together.
    fn resolve_inputs(
        &self,
        table: &'static Table,
        inputs: &[Id],
    ) -> Result<(Vec<Id>, Vec<RecordProvenance>), RecordError> {
        let implicit = self.implicit_inputs();
        if inputs.len().saturating_add(implicit.len()) > MAX_WRITE_INPUTS {
            return Err(RecordError::TooManyInputs { table: table.name });
        }
        if inputs.is_empty() && implicit.is_empty() && provenance::requires_inputs(self.call) {
            return Err(RecordError::MissingInputs { table: table.name });
        }
        let mut ids: Vec<Id> = Vec::with_capacity(inputs.len());
        let mut resolved = Vec::with_capacity(inputs.len());
        for id in inputs {
            if ids.contains(id) {
                continue;
            }
            let found = match implicit.iter().find(|implicit| implicit.id == *id) {
                Some(implicit) => implicit.clone(),
                None => match self.read_in_file(*id)? {
                    Some(found) => found,
                    None => self
                        .call
                        .read
                        .iter()
                        .find(|read| read.id == *id)
                        .cloned()
                        .ok_or(RecordError::UnknownInput { table: table.name })?,
                },
            };
            ids.push(*id);
            resolved.push(found);
        }
        for implicit in implicit {
            if !ids.contains(&implicit.id) {
                ids.push(implicit.id);
                resolved.push(implicit);
            }
        }
        Ok((ids, resolved))
    }

    /// The inputs every write of the call derives from without the module naming them, as a write
    /// counts them: the call's implicit inputs, each captured ([`captured`](Self::captured)), then
    /// each record the call has read so far through another module's typed API that is not one of
    /// them (AD-7).
    fn implicit_inputs(&self) -> Vec<RecordProvenance> {
        self.call
            .implicit_inputs
            .iter()
            .map(|implicit| self.captured(implicit))
            .chain(self.reads_beside_implicit().cloned())
            .collect()
    }

    /// The records the call read through another module's typed API that are not among its
    /// implicit inputs.
    fn reads_beside_implicit(&self) -> impl Iterator<Item = &RecordProvenance> {
        self.read_records.iter().filter(|read| {
            !self
                .call
                .implicit_inputs
                .iter()
                .any(|implicit| implicit.id == read.id)
        })
    }

    /// An implicit input as a write counts it: its snapshot, combined with each fresher read of
    /// the same record the call made, before the call or through a typed API during it.
    fn captured(&self, implicit: &RecordProvenance) -> RecordProvenance {
        self.call
            .read
            .iter()
            .chain(&self.read_records)
            .filter(|read| read.id == implicit.id)
            .fold(implicit.clone(), |captured, fresher| {
                captured.combined(fresher)
            })
    }

    /// Reads the record `id` through the query `query` of `module` (AD-5), and keeps its
    /// provenance as an input of every later write of the call, combined with an earlier read of
    /// the same record.
    fn read_through_api(
        &mut self,
        module: &str,
        query: &str,
        id: Id,
    ) -> Result<ReadRecord, RecordError> {
        let reads = self.reads.ok_or(RecordError::UnknownQuery)?;
        let (record, provenance) = api::read(
            reads,
            self.module,
            self.handle.file().partition(),
            module,
            query,
            id,
        )?;
        match self
            .read_records
            .iter_mut()
            .find(|read| read.id == provenance.id)
        {
            Some(earlier) => *earlier = earlier.combined(&provenance),
            None => self.read_records.push(provenance),
        }
        Ok(record)
    }

    /// The provenance of the record `id` of this file, in whichever of the module's tables holds
    /// it, its free text included.
    fn read_in_file(&self, id: Id) -> Result<Option<RecordProvenance>, RecordError> {
        for table in self.module.tables {
            if let Some(provenance) = self.read_in_table(table, id)? {
                return Ok(Some(provenance));
            }
        }
        Ok(None)
    }

    /// The provenance of the record `id` of `table`, its free text included, if the table holds
    /// it.
    fn read_in_table(
        &self,
        table: &'static Table,
        id: Id,
    ) -> Result<Option<RecordProvenance>, RecordError> {
        Ok(read_record(self.handle, table, id)?.map(|(provenance, _)| provenance))
    }
}

/// The record `id` of `table` on `handle`, if the table holds it: its provenance, its free text
/// included, and the value of each of the table's fields, in declared order.
pub(crate) fn read_record<R: Role>(
    handle: &Handle<R>,
    table: &'static Table,
    id: Id,
) -> Result<Option<(RecordProvenance, Vec<Value>)>, RecordError> {
    let columns: Vec<&str> = PROVENANCE_COLUMNS
        .into_iter()
        .chain(table.fields.iter().map(|field| field.name))
        .collect();
    let rows = handle.query_values(
        &format!(
            "SELECT {} FROM {} WHERE id = ?1",
            columns.join(", "),
            table.name
        ),
        &[SqlValue::Blob(id.to_bytes().to_vec())],
    )?;
    match rows.into_iter().next() {
        Some(row) => {
            let mut values = row.into_iter().map(from_stored);
            let mut provenance = provenance_of(table, id, &mut values)?;
            let fields: Vec<Value> = values.collect();
            provenance.free_text = free_text_of(table, fields.iter().cloned());
            Ok(Some((provenance, fields)))
        }
        None => Ok(None),
    }
}

/// The envelope columns a record's provenance is read from, in the order [`provenance_of`] takes
/// them.
const PROVENANCE_COLUMNS: [&str; 4] = ["taint", "text_taint", "author", "data_types"];

/// Reads the record `id` of `table` that an update changes: its provenance and field values; and
/// its revision.
fn read_stored(
    handle: &Handle<Write>,
    table: &'static Table,
    id: Id,
) -> Result<(Stored, Rev), RecordError> {
    let columns: Vec<&str> = PROVENANCE_COLUMNS
        .into_iter()
        .chain(["rev"])
        .chain(table.fields.iter().map(|field| field.name))
        .collect();
    let row = handle
        .query_values(
            &format!(
                "SELECT {} FROM {} WHERE id = ?1",
                columns.join(", "),
                table.name
            ),
            &[SqlValue::Blob(id.to_bytes().to_vec())],
        )?
        .into_iter()
        .next()
        .ok_or(RecordError::RecordNotFound { table: table.name })?;
    let mut values = row.into_iter().map(from_stored);
    let mut provenance = provenance_of(table, id, &mut values)?;
    let rev = stored_rev(table, values.next())?;
    let held: Vec<Value> = values.collect();
    provenance.free_text = free_text_of(table, held.iter().cloned());
    Ok((Stored { provenance, held }, rev))
}

/// The free-text values of a row of `table`, from its field values in declared order.
fn free_text_of(table: &'static Table, values: impl Iterator<Item = Value>) -> Vec<String> {
    table
        .fields
        .iter()
        .zip(values)
        .filter_map(|(field, value)| match (field.kind, value) {
            (FieldKind::FreeText { .. }, Value::Text(text)) => Some(text),
            _ => None,
        })
        .collect()
}

/// The provenance of the record `id` of `table` from its stored `taint`, `text_taint`, `author`
/// and `data_types`, the next four of `columns`, each held to its stored form and the labels to
/// each other; its free text is the caller's to read.
fn provenance_of(
    table: &'static Table,
    id: Id,
    columns: &mut impl Iterator<Item = Value>,
) -> Result<RecordProvenance, RecordError> {
    let mut next = |name: &'static str| {
        let value = columns.next().unwrap_or(Value::Null);
        let column = vilicus_module_api::ENVELOPE
            .iter()
            .find(|column| column.name == name)
            .ok_or(RecordError::UnknownColumn { table: table.name })?;
        envelope::check(table, column, &value)?;
        Ok::<_, RecordError>(value)
    };
    let malformed = |column| RecordError::InvalidEnvelope {
        table: table.name,
        column,
    };
    let taint = next("taint")?;
    let labels = envelope::check_labels(table, &taint, &next("text_taint")?)?;
    let author = match next("author")? {
        Value::Blob(bytes) => Some(
            <[u8; 16]>::try_from(bytes.as_slice())
                .ok()
                .and_then(|bytes| Id::from_bytes(bytes).ok())
                .ok_or(malformed("author"))?,
        ),
        _ => None,
    };
    let data_types = match next("data_types")? {
        Value::Text(text) => text
            .split(',')
            .map(|name| {
                DataType::ALL
                    .iter()
                    .copied()
                    .find(|data_type| data_type.as_str() == name)
            })
            .collect::<Option<Vec<_>>>(),
        _ => None,
    }
    .ok_or(malformed("data_types"))?;
    Ok(RecordProvenance {
        id,
        labels,
        author,
        data_types,
        free_text: Vec::new(),
    })
}

/// A stored revision, held to its stored form.
fn stored_rev(table: &'static Table, value: Option<Value>) -> Result<Rev, RecordError> {
    match value {
        Some(Value::Integer(rev)) => Rev::new(rev),
        _ => None,
    }
    .ok_or(RecordError::InvalidEnvelope {
        table: table.name,
        column: "rev",
    })
}

fn author_value(stamp: &Stamp) -> Value {
    stamp.author.map_or(Value::Null, |author| {
        Value::Blob(author.to_bytes().to_vec())
    })
}

/// What the module's code learns of a refused write: the names its declaration holds, and no
/// more of a failure inside the Core.
fn write_error(error: &RecordError) -> WriteError {
    match *error {
        RecordError::UnknownTable { .. } => WriteError::UnknownTable,
        RecordError::UnknownColumn { table } => WriteError::UnknownColumn { table },
        RecordError::DuplicateColumn { table, column } => {
            WriteError::DuplicateColumn { table, column }
        }
        RecordError::MissingColumn { table, column } => WriteError::MissingColumn { table, column },
        RecordError::EmptyUpdate { table } => WriteError::EmptyUpdate { table },
        RecordError::Invalid {
            table,
            column,
            error,
        } => WriteError::Invalid {
            table,
            column,
            error,
        },
        RecordError::UnconfirmedLabel {
            table,
            column,
            vocabulary,
        } => WriteError::UnconfirmedLabel {
            table,
            column,
            vocabulary,
        },
        RecordError::RecordNotFound { table } => WriteError::RecordNotFound { table },
        RecordError::StaleRevision { table } => WriteError::StaleRevision { table },
        RecordError::MissingInputs { table } => WriteError::MissingInputs { table },
        RecordError::UnknownInput { table } => WriteError::UnknownInput { table },
        RecordError::UndeclaredDataType { table } => WriteError::UndeclaredDataType { table },
        RecordError::TooManyInputs { table } => WriteError::TooManyInputs { table },
        RecordError::InvalidEffect => WriteError::InvalidEffect,
        RecordError::EffectConflict => WriteError::EffectConflict,
        RecordError::UnknownTopic => WriteError::UnknownTopic,
        RecordError::ForeignTopic => WriteError::ForeignTopic,
        RecordError::UnchangedRecord => WriteError::UnchangedRecord,
        RecordError::PayloadTooLong => WriteError::PayloadTooLong,
        RecordError::InvalidLink => WriteError::InvalidLink,
        RecordError::NotInConsumer => WriteError::NotInConsumer,
        RecordError::UnknownQuery => WriteError::UnknownQuery,
        RecordError::QueryNotAllowed { .. } => WriteError::QueryNotAllowed,
        RecordError::Unavailable(_) => WriteError::ModuleUnavailable,
        RecordError::IdChanged { .. }
        | RecordError::InvalidJournal
        | RecordError::InvalidEvent
        | RecordError::CallIdReused
        | RecordError::InvalidEnvelope { .. }
        | RecordError::UnknownVocabulary { .. }
        | RecordError::InvalidLabel { .. }
        | RecordError::DataTypesBelowInputs { .. }
        | RecordError::InconsistentCall
        | RecordError::Aborted(_)
        | RecordError::Storage(_) => WriteError::Failed,
    }
}
