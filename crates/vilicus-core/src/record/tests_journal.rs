//! Story 3.6: each write of a call is journaled in the call's transaction with both images, both
//! revisions, the principal and the provenance of its inputs, implicit ones included (AC2); a
//! repeated call is deduplicated on its principal, `source` and `call_id`, and a call that wrote
//! nothing is not (AC3); and a record's wrapped key is never part of an image (D132).

use std::cell::Cell;

use vilicus_module_api::{DataType, ENVELOPE, Records, Value, WriteError};
use vilicus_storage::{AuthorityKind, CallKey, Handle, JournalRow, Write};
use vilicus_types::{Id, Principal, Rev, Source, Taint};

use super::envelope::data_types_text;
use super::journal::decode_inputs;
use super::tests::{content, noon, open_new, raw_connection, raw_rows};
use super::tests_call::{
    TestStamper, ella, member_id, new_invocation, noe, note, notes_module, own_action, provenance,
    task,
};
use super::{Authority, Call, CallResult, Consumed, Invocation, RecordError, decode_row, run_call};

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
        records.insert("notes", &note("Pommes"), &[])
    };
    let CallResult::Committed(first) =
        run_call(&handle, module, &by, &invocation, &mut stamper, body).expect("commits")
    else {
        panic!("a new call runs")
    };
    assert_eq!(first.changes.len(), 1);
    let after_first = content(&handle);
    let again = run_call(&handle, module, &by, &invocation, &mut stamper, body).expect("answered");
    let CallResult::Deduplicated(earlier) = again else {
        panic!("the same call is deduplicated")
    };
    assert_eq!(earlier.changes, first.changes);
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
