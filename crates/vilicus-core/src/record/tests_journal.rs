//! Story 3.6: each write of a call is journaled in the call's transaction with both images, both
//! revisions, the principal and the provenance of its inputs, implicit ones included (AC2); a
//! repeated call is deduplicated on its principal, `source` and `call_id`, and a call that wrote
//! nothing is not (AC3); an effect intent commits with its call and its outcome is recorded after
//! (AC4); a consumer's call records its event in `_consumed` with its effect (AC5); and a record's
//! wrapped key is never part of an image (D132).

use std::cell::Cell;

use vilicus_module_api::{DataType, ENVELOPE, Records, Value, WriteError};
use vilicus_storage::{AuthorityKind, CallKey, EffectState, Handle, JournalRow, Write};
use vilicus_types::{EffectOutcome, Id, Principal, Rev, Source, Taint};

use super::envelope::data_types_text;
use super::journal::decode_inputs;
use super::tests::{content, noon, open_new, raw_connection, raw_rows};
use super::tests_call::{
    TestStamper, approved, ella, member_id, new_invocation, noe, note, notes_module, own_action,
    provenance, task,
};
use super::{
    Authority, Call, CallResult, Consumed, EventDelivery, Invocation, MAX_WRITE_INPUTS,
    RecordError, ReportTo, decode_row, effects_to_perform, record_effect_outcome,
    retry_failed_effect, run_call,
};

fn key<'a>(call: &'a Call, invocation: &Invocation) -> CallKey<'a> {
    CallKey {
        principal: call.principal,
        source: &call.source,
        call_id: invocation.call_id,
    }
}

/// The stored row of the record `id` of `table`, each column with its name, as an image holds it.
fn stored_row(
    handle: &Handle<Write>,
    table: &str,
    fields: &[&str],
    id: Id,
) -> Vec<(String, Value)> {
    let names: Vec<&str> = ENVELOPE
        .iter()
        .map(|column| column.name)
        .chain(fields.iter().copied())
        .collect();
    let row = handle
        .query_values(
            &format!("SELECT {} FROM {table} WHERE id = ?1", names.join(", ")),
            &[vilicus_storage::SqlValue::Blob(id.to_bytes().to_vec())],
        )
        .expect("read")
        .into_iter()
        .next()
        .expect("the record exists");
    names
        .into_iter()
        .map(str::to_owned)
        .zip(row.into_iter().map(super::from_stored))
        .collect()
}

const NOTE_FIELDS: [&str; 4] = ["title", "body", "status", "quantity"];

fn decoded(image: Option<&Vec<u8>>) -> Option<Vec<(String, Value)>> {
    image.map(|bytes| decode_row(bytes).expect("an image decodes"))
}

/// The journal's rows, read without the storage layer: what the file holds.
fn journal_count(handle: &Handle<Write>) -> i64 {
    match raw_rows(
        &raw_connection(handle.file()),
        "SELECT count(*) FROM _journal",
    )[0][0]
    {
        vilicus_storage::SqlValue::Integer(count) => count,
        ref other => panic!("a count: {other:?}"),
    }
}

/// AC2: an insert, an update and a delete of one call each journal their record, in the order of
/// the call, with the stored row before and after, both revisions, the call's principal, source,
/// authority and member, the time of the write, and the inputs with their provenance.
#[test]
fn every_write_of_a_call_is_journaled_with_its_images_and_inputs() {
    let module = notes_module();
    let (_, handle) = open_new(module, "journal-rows");
    let mut stamper = TestStamper::at(noon());
    let by = own_action(ella());
    let first = new_invocation(&by);
    let CallResult::Committed(seeded) =
        run_call(&handle, module, &by, &first, &mut stamper, |records| {
            let kept = records.insert("notes", &note("Pommes"), &[])?;
            let gone = records.insert("notes", &note("Poires"), &[])?;
            Ok((kept, gone))
        })
        .expect("the first call commits")
    else {
        panic!("a new call runs")
    };
    let (kept, gone) = seeded.value;
    let before_update = stored_row(&handle, "notes", &NOTE_FIELDS, kept.id);
    let before_delete = stored_row(&handle, "notes", &NOTE_FIELDS, gone.id);

    stamper.later(60_000);
    let second = new_invocation(&by);
    let outcome = run_call(&handle, module, &by, &second, &mut stamper, |records| {
        records.update(
            "notes",
            kept.id,
            kept.rev,
            &[("title", Value::Text("Pommes vertes".into()))],
            &[gone.id],
        )?;
        records.delete("notes", gone.id)
    })
    .expect("the second call commits");
    assert!(matches!(outcome, CallResult::Committed(_)));

    let rows: Vec<JournalRow> = handle.journaled_call(&key(&by, &second)).expect("read");
    assert_eq!(rows.len(), 2);
    let (update, delete) = (&rows[0], &rows[1]);
    assert_eq!(
        (update.change_index, update.table.as_str(), update.record),
        (0, "notes", kept.id)
    );
    assert_eq!(
        (update.rev_before, update.rev_after),
        (Some(Rev::FIRST), Rev::new(2))
    );
    assert_eq!(decoded(update.image_before.as_ref()), Some(before_update));
    assert_eq!(
        decoded(update.image_after.as_ref()),
        Some(stored_row(&handle, "notes", &NOTE_FIELDS, kept.id))
    );
    assert_eq!(
        (
            delete.change_index,
            delete.record,
            delete.rev_before,
            delete.rev_after
        ),
        (1, gone.id, Some(Rev::FIRST), None)
    );
    assert_eq!(decoded(delete.image_before.as_ref()), Some(before_delete));
    assert_eq!(delete.image_after, None);
    for row in &rows {
        assert_eq!(row.authority, AuthorityKind::OwnAction);
        assert_eq!(row.member, Some(ella()));
        assert_eq!(row.created_at, stamper_time(noon(), 60_000));
    }
    let inputs = decode_inputs(&update.inputs).expect("inputs decode");
    assert_eq!(inputs.len(), 1);
    assert_eq!(
        (
            inputs[0].id,
            inputs[0].implicit,
            inputs[0].taint.as_str(),
            inputs[0].text_taint.as_str()
        ),
        (gone.id, false, "trusted", "trusted")
    );
    assert_eq!(inputs[0].author, Some(ella()));
    assert!(decode_inputs(&delete.inputs).expect("decode").is_empty());

    let inserts = handle.journaled_call(&key(&by, &first)).expect("read");
    let image_names: Vec<String> = decoded(inserts[0].image_after.as_ref())
        .expect("an insert has an after image")
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    assert!(
        image_names.contains(&"taint".to_owned()) && image_names.contains(&"text_taint".to_owned())
    );
    assert_eq!(
        (
            inserts[0].rev_before,
            inserts[0].rev_after,
            inserts[0].image_before.as_ref()
        ),
        (None, Some(Rev::FIRST), None)
    );
    assert_eq!(journal_count(&handle), 4);
}

fn stamper_time(start: vilicus_types::UtcMillis, millis: i64) -> vilicus_types::UtcMillis {
    vilicus_types::UtcMillis::from_millis(start.as_millis() + millis).expect("in range")
}

/// AC2, the call's implicit inputs (I9, D147): a rule's write journals the definition it carries
/// as an implicit input, with the provenance the pipeline captured, after the inputs it declared.
#[test]
fn implicit_inputs_are_journaled_with_their_provenance() {
    let module = notes_module();
    let (_, handle) = open_new(module, "journal-implicit");
    let mut stamper = TestStamper::at(noon());
    let listed = match run_call(
        &handle,
        module,
        &own_action(ella()),
        &new_invocation(&own_action(ella())),
        &mut stamper,
        |records| records.insert("notes", &note("Liste"), &[]),
    )
    .expect("commits")
    {
        CallResult::Committed(outcome) => outcome.value,
        _ => panic!("a new call runs"),
    };
    let definition = provenance(
        member_id(40),
        Taint::External,
        Some(noe()),
        &[DataType::Meals],
    );
    let rule = Call {
        principal: Principal::Rule,
        source: Source::Rule(task()),
        session: Taint::Trusted,
        consumed: Consumed::NOTHING,
        authority: Authority::Unapproved {
            author: Some(ella()),
            acting_for: Some(ella()),
        },
        read: Vec::new(),
        implicit_inputs: vec![definition.clone()],
    };
    let invocation = new_invocation(&rule);
    run_call(
        &handle,
        module,
        &rule,
        &invocation,
        &mut stamper,
        |records| records.insert("notes", &note("Rappel"), &[listed.id]),
    )
    .expect("commits");
    let rows = handle
        .journaled_call(&key(&rule, &invocation))
        .expect("read");
    assert_eq!(rows[0].authority, AuthorityKind::Unapproved);
    assert_eq!(rows[0].member, Some(ella()));
    let inputs = decode_inputs(&rows[0].inputs).expect("decode");
    let summary: Vec<(Id, bool, &str, Option<Id>, &str)> = inputs
        .iter()
        .map(|input| {
            (
                input.id,
                input.implicit,
                input.text_taint.as_str(),
                input.author,
                input.data_types.as_str(),
            )
        })
        .collect();
    let declared_types = data_types_text(&[DataType::Meals, DataType::ShoppingList]);
    assert_eq!(
        summary,
        [
            (
                listed.id,
                false,
                "trusted",
                Some(ella()),
                declared_types.as_str()
            ),
            (definition.id, true, "external", Some(noe()), "meals"),
        ]
    );

    // Review M3 and its nit: a delete journals the call's implicit inputs, and an implicit input
    // the module names is the captured snapshot, marked implicit, counted once (D147).
    let second = new_invocation(&rule);
    let CallResult::Committed(outcome) =
        run_call(&handle, module, &rule, &second, &mut stamper, |records| {
            records.insert("notes", &note("Rappel"), &[definition.id, listed.id])?;
            records.delete("notes", listed.id)
        })
        .expect("commits")
    else {
        panic!("a new call runs")
    };
    assert_eq!(outcome.changes[0].inputs, [definition.id, listed.id]);
    assert_eq!(outcome.changes[1].inputs, [definition.id]);
    let rows = handle.journaled_call(&key(&rule, &second)).expect("read");
    let marks = |bytes: &[u8]| -> Vec<(Id, bool, String)> {
        decode_inputs(bytes)
            .expect("decode")
            .into_iter()
            .map(|input| (input.id, input.implicit, input.text_taint))
            .collect()
    };
    assert_eq!(
        marks(&rows[0].inputs),
        [
            (definition.id, true, "external".to_owned()),
            (listed.id, false, "trusted".to_owned()),
        ]
    );
    assert_eq!(rows[1].rev_after, None);
    assert_eq!(
        marks(&rows[1].inputs),
        [(definition.id, true, "external".to_owned())]
    );
}

/// Story 3.6 review, minor 1: a write of more than `MAX_WRITE_INPUTS` inputs, declared and
/// implicit together, is refused with a typed error before any input is read.
#[test]
fn a_write_with_too_many_inputs_is_refused() {
    let module = notes_module();
    let (_, handle) = open_new(module, "too-many-inputs");
    let mut stamper = TestStamper::at(noon());
    let by = own_action(ella());
    let empty = content(&handle);
    let inputs: Vec<Id> = (0..=u16::try_from(MAX_WRITE_INPUTS).expect("small"))
        .map(|n| {
            let mut random = [0x44; 10];
            random[8..].copy_from_slice(&n.to_be_bytes());
            Id::new_v7(noon(), random).expect("after the epoch")
        })
        .collect();
    assert_eq!(inputs.len(), MAX_WRITE_INPUTS + 1);
    let outcome = run_call(
        &handle,
        module,
        &by,
        &new_invocation(&by),
        &mut stamper,
        |records| {
            let refused = records.insert("notes", &note("Pommes"), &inputs);
            assert_eq!(
                refused,
                Err(WriteError::TooManyInputs { table: "notes" }),
                "the module learns why"
            );
            refused
        },
    );
    assert!(
        matches!(outcome, Err(RecordError::TooManyInputs { table: "notes" })),
        "{outcome:?}"
    );
    let mut rule = consumer_call();
    rule.principal = Principal::Rule;
    rule.source = Source::Rule(task());
    rule.implicit_inputs = vec![
        provenance(
            member_id(51),
            Taint::Trusted,
            Some(ella()),
            &[DataType::Meals]
        );
        2
    ];
    let outcome = run_call(
        &handle,
        module,
        &rule,
        &new_invocation(&rule),
        &mut stamper,
        |records| records.insert("notes", &note("Pommes"), &inputs[..MAX_WRITE_INPUTS - 1]),
    );
    assert!(
        matches!(outcome, Err(RecordError::TooManyInputs { .. })),
        "implicit ones count: {outcome:?}"
    );
    assert_eq!(content(&handle), empty);
}

/// A clock that moves a day at every reading.
struct RacingClock(TestStamper);

impl super::Stamper for RacingClock {
    fn now(&mut self) -> vilicus_types::UtcMillis {
        self.0.later(24 * 60 * 60 * 1000);
        super::Stamper::now(&mut self.0)
    }

    fn id_random(&mut self) -> [u8; 10] {
        super::Stamper::id_random(&mut self.0)
    }
}

/// Story 3.6 review, minor 4: every journal row of a call carries the call's start time, however
/// long the call takes, so a retention cutoff keeps or deletes the whole call.
#[test]
fn every_journal_row_of_a_call_carries_its_start_time() {
    let module = notes_module();
    let (_, handle) = open_new(module, "start-time");
    let mut clock = RacingClock(TestStamper::at(noon()));
    let by = own_action(ella());
    let invocation = new_invocation(&by);
    run_call(&handle, module, &by, &invocation, &mut clock, |records| {
        for title in ["Pommes", "Poires", "Prunes"] {
            records.insert("notes", &note(title), &[])?;
        }
        Ok(())
    })
    .expect("commits");
    let rows = handle.journaled_call(&key(&by, &invocation)).expect("read");
    let started = stamper_time(noon(), 24 * 60 * 60 * 1000);
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().all(|row| row.created_at == started), "{rows:?}");
    let updated: Vec<vilicus_storage::SqlValue> =
        super::tests::rows(&handle, "SELECT updated_at FROM notes ORDER BY updated_at")
            .into_iter()
            .map(|mut row| row.remove(0))
            .collect();
    assert_eq!(updated.len(), 3);
    assert_ne!(
        updated[0], updated[2],
        "the writes themselves are later and later"
    );
    let cutoff = stamper_time(noon(), 3 * 24 * 60 * 60 * 1000);
    assert_eq!(
        handle.purge_journal(cutoff).expect("purge").deleted,
        3,
        "the whole call"
    );
}

/// AC2, the same transaction: a call refused after a write, or one whose module panics after a
/// write, leaves no journal row, as it leaves no record.
#[test]
fn a_call_rolled_back_leaves_no_journal_row() {
    let module = notes_module();
    let (_, handle) = open_new(module, "journal-rollback");
    let mut stamper = TestStamper::at(noon());
    let by = own_action(ella());
    let empty = content(&handle);
    let refused = run_call(
        &handle,
        module,
        &by,
        &new_invocation(&by),
        &mut stamper,
        |records| {
            records.insert("notes", &note("Pommes"), &[])?;
            records.insert("notes", &[("title", Value::Text("Poires".into()))], &[])
        },
    );
    assert!(
        matches!(refused, Err(RecordError::MissingColumn { .. })),
        "{refused:?}"
    );
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_call(
            &handle,
            module,
            &by,
            &new_invocation(&by),
            &mut stamper,
            |records| -> Result<(), WriteError> {
                records.insert("notes", &note("Pommes"), &[])?;
                panic!("a module bug")
            },
        )
    }));
    assert!(panicked.is_err());
    assert_eq!(content(&handle), empty);
    assert_eq!(journal_count(&handle), 0);
}

/// AC3 (AD-26, AD-28): a second call of the same principal, source and call id returns the first
/// call's result without running the module's code or writing anything; the same call id from
/// another principal, or for another member, is another call.
#[test]
fn a_repeated_call_returns_the_first_result_and_runs_nothing() {
    let module = notes_module();
    let (_, handle) = open_new(module, "dedup");
    let mut stamper = TestStamper::at(noon());
    let by = own_action(ella());
    let invocation = new_invocation(&by);
    let runs = Cell::new(0);
    let body = |records: &mut dyn Records| {
        runs.set(runs.get() + 1);
        let written = records.insert("notes", &note("Pommes"), &[])?;
        records.request_effect("send_message", b"order-42", b"parameters")?;
        Ok(written)
    };
    let CallResult::Committed(first) =
        run_call(&handle, module, &by, &invocation, &mut stamper, body).expect("commits")
    else {
        panic!("a new call runs")
    };
    assert_eq!((first.changes.len(), first.effects.len()), (1, 1));
    let after_first = content(&handle);
    let again = run_call(&handle, module, &by, &invocation, &mut stamper, body).expect("answered");
    let CallResult::Deduplicated(earlier) = again else {
        panic!("the same call is deduplicated")
    };
    assert_eq!(earlier.changes, first.changes);
    assert_eq!(earlier.effects, first.effects);
    assert_eq!(runs.get(), 1, "the module's code ran once");
    assert_eq!(content(&handle), after_first, "nothing was written");

    let from_the_cli = Call {
        principal: Principal::Cli,
        ..own_action(ella())
    };
    for other in [from_the_cli, own_action(noe())] {
        let outcome = run_call(
            &handle,
            module,
            &other,
            &invocation,
            &mut stamper,
            |records| {
                runs.set(runs.get() + 1);
                records.insert("notes", &note("Poires"), &[])
            },
        )
        .expect("commits");
        assert!(
            matches!(outcome, CallResult::Committed(_)),
            "{:?}",
            other.source
        );
    }
    assert_eq!(runs.get(), 3);
}

/// AC3: a call that writes nothing leaves no row, so the same call id runs again; a call that was
/// rolled back wrote nothing either, so its retry runs and commits.
#[test]
fn a_call_that_writes_nothing_is_not_deduplicated() {
    let module = notes_module();
    let (_, handle) = open_new(module, "dedup-nothing");
    let mut stamper = TestStamper::at(noon());
    let by = own_action(ella());
    let invocation = new_invocation(&by);
    let runs = Cell::new(0);
    for _ in 0..2 {
        let outcome = run_call(&handle, module, &by, &invocation, &mut stamper, |_| {
            runs.set(runs.get() + 1);
            Ok(())
        })
        .expect("commits");
        assert!(matches!(outcome, CallResult::Committed(_)));
    }
    assert_eq!(runs.get(), 2);

    let retried = new_invocation(&by);
    let refused = run_call(&handle, module, &by, &retried, &mut stamper, |records| {
        records.insert("notes", &[("title", Value::Text("Pommes".into()))], &[])
    });
    assert!(refused.is_err());
    let outcome = run_call(&handle, module, &by, &retried, &mut stamper, |records| {
        records.insert("notes", &note("Pommes"), &[])
    })
    .expect("the retry commits");
    assert!(matches!(outcome, CallResult::Committed(_)));
}

/// AC4 (AD-28, NFR-3): an effect intent commits with its call's writes, or not at all; the
/// outcome is recorded after the commit; an `unknown` one is reported to the member and never
/// retried; a `failed` one is retried by the Core with the same key; the same key requested by
/// another call is the same intent.
#[test]
fn an_effect_intent_commits_with_its_call_and_its_outcome_is_recorded_after() {
    let module = notes_module();
    let (_, handle) = open_new(module, "effects");
    let mut stamper = TestStamper::at(noon());
    let by = approved(Taint::Trusted, &[], &[]);

    let rolled_back = run_call(
        &handle,
        module,
        &by,
        &new_invocation(&by),
        &mut stamper,
        |records| {
            records.request_effect("send_message", b"rolled-back", b"x")?;
            records.insert("notes", &[("title", Value::Text("Pommes".into()))], &[])
        },
    );
    assert!(rolled_back.is_err());
    assert!(effects_to_perform(&handle).expect("read").is_empty());
    for (effect, key) in [("Send message", &b"k"[..]), ("send_message", b"")] {
        let refused = run_call(
            &handle,
            module,
            &by,
            &new_invocation(&by),
            &mut stamper,
            |records| records.request_effect(effect, key, b"x"),
        );
        assert!(
            matches!(refused, Err(RecordError::InvalidEffect)),
            "{effect:?} {refused:?}"
        );
    }

    let mut requested = Vec::new();
    for key in [&b"done"[..], b"failed", b"unknown"] {
        let CallResult::Committed(outcome) = run_call(
            &handle,
            module,
            &by,
            &new_invocation(&by),
            &mut stamper,
            |records| {
                records.insert("notes", &note("Commande"), &[])?;
                records.request_effect("send_message", key, b"parameters")
            },
        )
        .expect("commits") else {
            panic!("a new call runs")
        };
        assert_eq!(outcome.effects.len(), 1);
        assert_eq!(outcome.effects[0].id, outcome.value);
        requested.push(outcome.value);
    }
    let CallResult::Committed(repeat) = run_call(
        &handle,
        module,
        &by,
        &new_invocation(&by),
        &mut stamper,
        |records| records.request_effect("send_message", b"done", b"parameters"),
    )
    .expect("commits") else {
        panic!("a new call runs")
    };
    assert_eq!(
        repeat.value, requested[0],
        "the same key is the same intent"
    );
    assert!(repeat.effects.is_empty(), "and the call wrote no intent");
    let pending: Vec<Id> = effects_to_perform(&handle)
        .expect("read")
        .into_iter()
        .map(|effect| effect.id)
        .collect();
    assert_eq!(pending, requested);

    let later = stamper_time(noon(), 1_000);
    assert_eq!(
        record_effect_outcome(&handle, requested[0], EffectOutcome::Done, later).expect("record"),
        None
    );
    assert_eq!(
        record_effect_outcome(&handle, requested[1], EffectOutcome::Failed, later).expect("record"),
        None
    );
    let unknown = record_effect_outcome(&handle, requested[2], EffectOutcome::Unknown, later)
        .expect("record")
        .expect("an unknown outcome is reported");
    assert_eq!(
        (unknown.intent, unknown.report_to),
        (requested[2], ReportTo::Member(ella()))
    );
    assert!(
        retry_failed_effect(&handle, requested[2], later).is_err(),
        "never blindly"
    );
    assert!(
        retry_failed_effect(&handle, requested[0], later).is_err(),
        "done is done"
    );
    retry_failed_effect(&handle, requested[1], later).expect("a failed effect is retried");
    let pending = effects_to_perform(&handle).expect("read");
    assert_eq!(pending.len(), 1);
    assert_eq!(
        (
            pending[0].id,
            pending[0].idempotency_key.as_slice(),
            pending[0].state
        ),
        (requested[1], &b"failed"[..], EffectState::Pending)
    );
}

fn consumer_call() -> Call {
    Call {
        principal: Principal::Event,
        source: Source::Event(task()),
        session: Taint::Trusted,
        consumed: Consumed::NOTHING,
        authority: Authority::Unapproved {
            author: Some(ella()),
            acting_for: Some(ella()),
        },
        read: Vec::new(),
        implicit_inputs: vec![provenance(
            member_id(50),
            Taint::Trusted,
            Some(ella()),
            &[DataType::Meals],
        )],
    }
}

/// AC5 (FR-24, AD-26): a consumer's call records the event in `_consumed` in the transaction of
/// its effect: a rolled-back call records nothing, a committed one records it, and a second
/// delivery of the event to the consumer, whatever its call id, runs nothing.
#[test]
fn a_consumers_call_records_its_event_with_its_effect() {
    let module = notes_module();
    let (_, handle) = open_new(module, "consumed");
    let mut stamper = TestStamper::at(noon());
    let by = consumer_call();
    let delivery = EventDelivery {
        event: member_id(60),
        consumer: "notes",
    };
    let invocation = |call_id: Id| Invocation {
        call_id: call_id.into(),
        request_hash: None,
        delivery: Some(delivery),
    };
    let refused = run_call(
        &handle,
        module,
        &by,
        &invocation(member_id(61)),
        &mut stamper,
        |records| records.insert("notes", &[("title", Value::Text("Pommes".into()))], &[]),
    );
    assert!(refused.is_err());
    assert!(
        !handle
            .is_consumed(delivery.event, delivery.consumer)
            .expect("read")
    );

    let outcome = run_call(
        &handle,
        module,
        &by,
        &invocation(member_id(62)),
        &mut stamper,
        |records| records.insert("notes", &note("Pommes"), &[]),
    )
    .expect("commits");
    assert!(matches!(outcome, CallResult::Committed(_)));
    assert!(
        handle
            .is_consumed(delivery.event, delivery.consumer)
            .expect("read")
    );
    let after = content(&handle);
    let ran = Cell::new(false);
    let again = run_call(
        &handle,
        module,
        &by,
        &invocation(member_id(63)),
        &mut stamper,
        |records| {
            ran.set(true);
            records.insert("notes", &note("Pommes"), &[])
        },
    )
    .expect("answered");
    assert!(matches!(again, CallResult::AlreadyConsumed));
    assert!(!ran.get());
    assert_eq!(content(&handle), after);
    let other_consumer = Invocation {
        call_id: member_id(64).into(),
        request_hash: None,
        delivery: Some(EventDelivery {
            consumer: "digest",
            ..delivery
        }),
    };
    assert!(matches!(
        run_call(&handle, module, &by, &other_consumer, &mut stamper, |_| Ok(
            ()
        ))
        .expect("commits"),
        CallResult::Committed(_)
    ));

    let without_delivery = Invocation {
        call_id: member_id(65).into(),
        request_hash: None,
        delivery: None,
    };
    let by_member = own_action(ella());
    for (call, invocation) in [
        (&by, without_delivery),
        (&by_member, invocation(member_id(66))),
    ] {
        let outcome = run_call(&handle, module, call, &invocation, &mut stamper, |_| Ok(()));
        assert!(
            matches!(outcome, Err(RecordError::InconsistentCall)),
            "{:?}",
            call.principal
        );
    }
}

/// D132, the decision of Story 3.6: a record's wrapped key, kept in the Core table
/// `_record_keys`, is never part of an image: an image holds exactly the envelope and the
/// declared fields of its table, and no byte run of the key.
#[test]
fn an_image_holds_the_tables_columns_and_never_a_wrapped_key() {
    let module = notes_module();
    let (_, handle) = open_new(module, "image-columns");
    let mut stamper = TestStamper::at(noon());
    let by = own_action(ella());
    let invocation = new_invocation(&by);
    let CallResult::Committed(inserted) =
        run_call(&handle, module, &by, &invocation, &mut stamper, |records| {
            records.insert("notes", &note("Coffre"), &[])
        })
        .expect("commits")
    else {
        panic!("a new call runs")
    };
    let wrapped_key = [0xb7_u8; 48];
    handle
        .store_wrapped_record_key(inserted.value.id, &wrapped_key)
        .expect("store the key");
    let update = new_invocation(&by);
    run_call(&handle, module, &by, &update, &mut stamper, |records| {
        records.update(
            "notes",
            inserted.value.id,
            inserted.value.rev,
            &[("status", Value::Text("done".into()))],
            &[],
        )
    })
    .expect("commits");
    let expected: Vec<String> = ENVELOPE
        .iter()
        .map(|column| column.name.to_owned())
        .chain(NOTE_FIELDS.iter().map(|name| (*name).to_owned()))
        .collect();
    for row in handle
        .journaled_call(&key(&by, &invocation))
        .expect("read")
        .into_iter()
        .chain(handle.journaled_call(&key(&by, &update)).expect("read"))
    {
        for image in [row.image_before.as_ref(), row.image_after.as_ref()]
            .into_iter()
            .flatten()
        {
            let names: Vec<String> = decode_row(image)
                .expect("decode")
                .into_iter()
                .map(|(name, _)| name)
                .collect();
            assert_eq!(names, expected);
            assert!(
                !image
                    .windows(8)
                    .any(|window| wrapped_key.windows(8).any(|run| run == window)),
                "no run of 8 bytes of the key"
            );
        }
    }
}

/// Story 3.6 review, decision (a): a call id reused for another request, both carrying a request
/// hash, is refused rather than answered with the first result; the same hash, or a side without
/// one, is the same call.
#[test]
fn a_call_id_reused_for_another_request_is_refused() {
    let module = notes_module();
    let (_, handle) = open_new(module, "call-id-reused");
    let mut stamper = TestStamper::at(noon());
    let by = own_action(ella());
    let first = Invocation {
        request_hash: Some([1; 32]),
        ..new_invocation(&by)
    };
    let body = |records: &mut dyn Records| records.insert("notes", &note("Pommes"), &[]);
    assert!(matches!(
        run_call(&handle, module, &by, &first, &mut stamper, body).expect("commits"),
        CallResult::Committed(_)
    ));
    let after = content(&handle);
    let reused = Invocation {
        request_hash: Some([2; 32]),
        ..first
    };
    let outcome = run_call(&handle, module, &by, &reused, &mut stamper, body);
    assert!(
        matches!(outcome, Err(RecordError::CallIdReused)),
        "{outcome:?}"
    );
    assert_eq!(content(&handle), after);
    for same in [
        first,
        Invocation {
            request_hash: None,
            ..first
        },
    ] {
        assert!(matches!(
            run_call(&handle, module, &by, &same, &mut stamper, body).expect("answered"),
            CallResult::Deduplicated(_)
        ));
    }
}

/// Story 3.6 review, M2, through the typed API: a second request of one name and key with
/// another payload is a conflict that rolls its call back; the same key under another name is
/// another effect.
#[test]
fn an_effect_request_conflicting_with_an_earlier_one_is_refused() {
    let module = notes_module();
    let (_, handle) = open_new(module, "effect-conflict");
    let mut stamper = TestStamper::at(noon());
    let by = own_action(ella());
    let request = |payload: &'static [u8], effect: &'static str| {
        move |records: &mut dyn Records| records.request_effect(effect, b"order-7", payload)
    };
    for (payload, effect) in [(&b"one"[..], "send_message"), (b"one", "cancel_order")] {
        assert!(matches!(
            run_call(
                &handle,
                module,
                &by,
                &new_invocation(&by),
                &mut stamper,
                request(payload, effect)
            )
            .expect("commits"),
            CallResult::Committed(_)
        ));
    }
    let after = content(&handle);
    let conflict = run_call(
        &handle,
        module,
        &by,
        &new_invocation(&by),
        &mut stamper,
        |records| {
            records.insert("notes", &note("Pommes"), &[])?;
            records.request_effect("send_message", b"order-7", b"two")
        },
    );
    assert!(
        matches!(conflict, Err(RecordError::EffectConflict)),
        "{conflict:?}"
    );
    assert_eq!(content(&handle), after, "the call is rolled back");
    let from_noe = own_action(noe());
    let other_caller = run_call(
        &handle,
        module,
        &from_noe,
        &new_invocation(&from_noe),
        &mut stamper,
        request(b"one", "send_message"),
    );
    assert!(
        matches!(other_caller, Err(RecordError::EffectConflict)),
        "{other_caller:?}"
    );
}

/// Story 3.6 review, minor 3: an `unknown` effect of a call that names no member is reported to
/// every adult, the adult who validated the rule first; a call with no author names none first.
#[test]
fn an_unknown_effect_of_a_call_naming_no_member_is_reported_to_every_adult() {
    let module = notes_module();
    let (_, handle) = open_new(module, "unknown-every-adult");
    let mut stamper = TestStamper::at(noon());
    let rule = Call {
        principal: Principal::Rule,
        source: Source::Rule(task()),
        session: Taint::Trusted,
        consumed: Consumed::NOTHING,
        authority: Authority::Unapproved {
            author: Some(noe()),
            acting_for: None,
        },
        read: Vec::new(),
        implicit_inputs: Vec::new(),
    };
    let adapter = Call {
        principal: Principal::Adapter,
        source: Source::Adapter(task()),
        authority: Authority::Unapproved {
            author: None,
            acting_for: None,
        },
        ..rule.clone()
    };
    for (by, first) in [(rule, Some(noe())), (adapter, None)] {
        let key: &'static [u8] = if first.is_some() {
            b"rule-key"
        } else {
            b"adapter-key"
        };
        let CallResult::Committed(outcome) = run_call(
            &handle,
            module,
            &by,
            &new_invocation(&by),
            &mut stamper,
            |records| records.request_effect("open_valve", key, b"x"),
        )
        .expect("commits") else {
            panic!("a new call runs")
        };
        let report = record_effect_outcome(&handle, outcome.value, EffectOutcome::Unknown, noon())
            .expect("record")
            .expect("reported");
        assert_eq!(
            report.report_to,
            ReportTo::EveryAdult { first },
            "{:?}",
            by.principal
        );
    }
}

/// Story 3.6 review, minor 2 (AD-39): a rule action's name-based call id (a version 5 UUID) is a
/// call id, and a re-delivered trigger with it is deduplicated.
#[test]
fn a_name_based_call_id_deduplicates_a_rule_action() {
    let module = notes_module();
    let (_, handle) = open_new(module, "name-based-call-id");
    let mut stamper = TestStamper::at(noon());
    let mut bytes = [0x6b; 16];
    bytes[6] = 0x5b;
    bytes[8] = 0x9b;
    let invocation = Invocation {
        call_id: vilicus_types::CallId::from_bytes(bytes).expect("a version 5 UUID"),
        request_hash: None,
        delivery: None,
    };
    let rule = Call {
        principal: Principal::Rule,
        source: Source::Rule(task()),
        session: Taint::Trusted,
        consumed: Consumed::NOTHING,
        authority: Authority::Unapproved {
            author: Some(ella()),
            acting_for: Some(ella()),
        },
        read: Vec::new(),
        implicit_inputs: vec![provenance(
            member_id(70),
            Taint::Trusted,
            Some(ella()),
            &[DataType::Meals],
        )],
    };
    let body = |records: &mut dyn Records| records.insert("notes", &note("Arrosage"), &[]);
    assert!(matches!(
        run_call(&handle, module, &rule, &invocation, &mut stamper, body).expect("commits"),
        CallResult::Committed(_)
    ));
    assert!(matches!(
        run_call(&handle, module, &rule, &invocation, &mut stamper, body).expect("answered"),
        CallResult::Deduplicated(_)
    ));
}

/// Story 3.6's open point, settled by Story 3.7: a migration that removes a table leaves its
/// journal rows until retention removes them, and a repeated call whose rows name it still gets
/// the first call's changes, under the table's journaled name, rather than a malformed journal.
#[test]
fn a_repeated_call_is_answered_after_a_migration_removed_its_table() {
    let module = notes_module();
    let (file, handle) = open_new(module, "dedup-removed-table");
    let mut stamper = TestStamper::at(noon());
    let by = own_action(ella());
    let invocation = new_invocation(&by);
    let CallResult::Committed(first) =
        run_call(&handle, module, &by, &invocation, &mut stamper, |records| {
            records.insert("notes", &note("Pommes"), &[])
        })
        .expect("commits")
    else {
        panic!("a new call runs")
    };
    handle.close().expect("close");

    let mut without_notes = *module;
    without_notes.tables = without_notes
        .tables
        .iter()
        .copied()
        .filter(|table| table.name != "notes")
        .collect::<Vec<_>>()
        .leak();
    let mut migrations = without_notes.migrations.to_vec();
    migrations.push(crate::registry::frozen("DROP TABLE notes;"));
    without_notes.migrations = migrations.leak();
    let without_notes: &'static _ = Box::leak(Box::new(without_notes));
    let registry = super::tests::registry_of(vec![without_notes]);
    let outcomes = registry
        .migrate_files(&[crate::registry::FileToMigrate {
            file: &file,
            key: &super::tests::KEY,
            verified_backup: None,
        }])
        .expect("run");
    assert!(
        matches!(
            outcomes.as_slice(),
            [crate::registry::FileMigration::Migrated { .. }]
        ),
        "{outcomes:?}"
    );
    let handle = registry
        .open::<Write>(&file, &super::tests::KEY)
        .expect("open");
    let again = run_call(
        &handle,
        without_notes,
        &by,
        &invocation,
        &mut stamper,
        |_| Ok(()),
    )
    .expect("answered");
    let CallResult::Deduplicated(earlier) = again else {
        panic!("the same call is deduplicated")
    };
    assert_eq!(earlier.changes, first.changes);
    assert_eq!(earlier.changes[0].table, "notes");
}
