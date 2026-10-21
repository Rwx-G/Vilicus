//! Story 3.8: events and link requests join the transaction of the call that writes them and are
//! read back in commit order; each delivery to a consumer is recorded after the consumer's
//! commit, a failing one moves to the dead letters at its last attempt; a closed row is closed
//! once; and the outbox's retention purge deletes the closed rows before its cutoff, keeping what
//! the Core still delivers, retries, reports or may replay, then empties the WAL.

use vilicus_types::{EffectOutcome, Id, Principal, Source, UtcMillis};

use super::{EPOCH, KEY, raw_connection, scratch_dir};
use crate::error::Error;
use crate::{
    CallKey, DeliveryState, EffectIntent, EventIntent, Handle, LinkIntent, OutboxKind, OutboxRow,
    OutboxState, Write, create,
};

fn id(last: u8) -> Id {
    let mut bytes = [0x22; 16];
    bytes[6] = 0x70;
    bytes[8] = 0x80;
    bytes[15] = last;
    Id::from_bytes(bytes).expect("a UUIDv7")
}

fn at(millis: i64) -> UtcMillis {
    UtcMillis::from_millis(1_790_000_000_000 + millis).expect("in range")
}

fn new_writer(label: &str) -> Handle<Write> {
    let file = super::module_file(&scratch_dir(label));
    create(&file, &KEY, EPOCH).expect("create")
}

fn event<'a>(call: CallKey<'a>, event_id: Id, created_at: UtcMillis) -> EventIntent<'a> {
    EventIntent {
        call,
        request_hash: None,
        id: event_id,
        topic: "fixture.item.added",
        version: 2,
        record: id(40),
        provenance: b"provenance",
        author: Some(id(1)),
        member: Some(id(1)),
        payload: b"payload",
        created_at,
    }
}

fn link<'a>(call: CallKey<'a>, link_id: Id, created_at: UtcMillis) -> LinkIntent<'a> {
    LinkIntent {
        call,
        request_hash: None,
        id: link_id,
        record: id(40),
        target_module: "meals",
        target: id(41),
        member: Some(id(1)),
        created_at,
    }
}

fn in_transaction(writer: &Handle<Write>, body: impl FnOnce()) {
    writer.execute_batch("BEGIN IMMEDIATE").expect("begin");
    body();
    writer.execute_batch("COMMIT").expect("commit");
}

fn pending_ids(writer: &Handle<Write>) -> Vec<Id> {
    writer
        .pending_outbox(0, 100)
        .expect("read")
        .into_iter()
        .map(|row| row.id.expect("an id"))
        .collect()
}

#[test]
fn events_and_link_requests_join_the_callers_transaction_in_commit_order() {
    let writer = new_writer("outbox-events");
    let source = Source::Member(id(1));
    let call = CallKey {
        principal: Principal::Member,
        source: &source,
        call_id: id(9).into(),
    };
    assert!(matches!(
        writer.append_event(&event(call, id(50), at(0))),
        Err(Error::NoTransaction)
    ));
    assert!(matches!(
        writer.append_link(&link(call, id(51), at(0))),
        Err(Error::NoTransaction)
    ));
    assert!(matches!(
        writer.append_event(&EventIntent {
            topic: "",
            ..event(call, id(50), at(0))
        }),
        Err(Error::InvalidOutboxRow)
    ));
    assert!(matches!(
        writer.append_link(&LinkIntent {
            target_module: "",
            ..link(call, id(51), at(0))
        }),
        Err(Error::InvalidOutboxRow)
    ));

    writer.execute_batch("BEGIN IMMEDIATE").expect("begin");
    writer
        .append_event(&event(call, id(52), at(0)))
        .expect("event");
    writer.execute_batch("ROLLBACK").expect("rollback");
    assert!(pending_ids(&writer).is_empty());

    in_transaction(&writer, || {
        writer
            .append_event(&event(call, id(53), at(1)))
            .expect("event");
        writer
            .append_effect(&EffectIntent {
                call,
                request_hash: None,
                member: None,
                first_adult: None,
                id: id(54),
                effect: "send",
                idempotency_key: b"key",
                payload: b"",
                created_at: at(1),
            })
            .expect("effect");
        writer
            .append_link(&link(call, id(55), at(1)))
            .expect("link");
    });
    in_transaction(&writer, || {
        writer
            .append_event(&event(call, id(56), at(2)))
            .expect("event");
    });
    assert_eq!(pending_ids(&writer), [id(53), id(55), id(56)]);

    let events = writer.outbox_events().expect("read");
    assert_eq!(events.len(), 2);
    let first = &events[0];
    assert_eq!(first.id, id(53));
    assert_eq!(first.call_id.to_bytes(), id(9).to_bytes());
    assert_eq!(first.principal, Principal::Member);
    assert_eq!(first.source, source.to_string());
    assert_eq!((first.author, first.member), (Some(id(1)), Some(id(1))));
    assert_eq!(
        (first.topic.as_str(), first.version, first.record),
        ("fixture.item.added", 2, id(40))
    );
    assert_eq!(first.provenance, b"provenance");
    assert_eq!(first.payload, b"payload");
    assert_eq!(first.state, OutboxState::Pending);
    assert_eq!((first.created_at, first.updated_at), (at(1), at(1)));
    assert!(events[0].seq < events[1].seq);

    let links = writer.outbox_links().expect("read");
    assert_eq!(links.len(), 1);
    assert_eq!(
        (
            links[0].record,
            links[0].target_module.as_str(),
            links[0].target
        ),
        (id(40), "meals", id(41))
    );
    assert_eq!(
        writer.effects_of_call(&call).expect("read").len(),
        1,
        "events and links are not effect intents"
    );
}

#[test]
fn a_failing_delivery_moves_to_the_dead_letters_at_its_last_attempt() {
    let writer = new_writer("deliveries");
    let source = Source::Member(id(1));
    let call = CallKey {
        principal: Principal::Member,
        source: &source,
        call_id: id(9).into(),
    };
    in_transaction(&writer, || {
        writer
            .append_event(&event(call, id(60), at(0)))
            .expect("event");
    });
    assert!(matches!(
        writer.record_failed_delivery(id(61), "meals.react", at(1), 5, id(90)),
        Err(Error::OutboxRowNotFound)
    ));
    assert!(matches!(
        writer.record_delivered(id(61), "meals.react", at(1)),
        Err(Error::OutboxRowNotFound)
    ));
    assert_eq!(writer.delivery(id(60), "meals.react").expect("read"), None);
    for attempt in 1..5 {
        let delivery = writer
            .record_failed_delivery(id(60), "meals.react", at(attempt), 5, id(90))
            .expect("failure");
        assert_eq!(
            (delivery.attempts, delivery.state),
            (
                u32::try_from(attempt).expect("small"),
                DeliveryState::Failing
            )
        );
    }
    assert!(writer.dead_letters().expect("read").is_empty());
    let dead = writer
        .record_failed_delivery(id(60), "meals.react", at(5), 5, id(90))
        .expect("last failure");
    assert_eq!((dead.attempts, dead.state), (5, DeliveryState::DeadLetter));
    let letters = writer.dead_letters().expect("read");
    assert_eq!(letters.len(), 1);
    assert_eq!(
        (
            letters[0].id,
            letters[0].event,
            letters[0].consumer.as_str(),
            letters[0].attempts,
            letters[0].failed_at
        ),
        (id(90), id(60), "meals.react", 5, at(5))
    );
    assert!(matches!(
        writer.record_failed_delivery(id(60), "meals.react", at(6), 5, id(91)),
        Err(Error::OutboxRowNotPending)
    ));
    assert!(
        matches!(
            writer.record_delivered(id(60), "meals.react", at(6)),
            Err(Error::OutboxRowNotPending)
        ),
        "a dead letter leaves the dead letters by its replay only"
    );
    assert_eq!(
        writer
            .delivery(id(60), "meals.react")
            .expect("read")
            .map(|delivery| delivery.state),
        Some(DeliveryState::DeadLetter)
    );
    assert_eq!(writer.dead_letters().expect("read").len(), 1);

    let other = writer
        .record_failed_delivery(id(60), "tasks.react", at(7), 5, id(92))
        .expect("another consumer counts apart");
    assert_eq!(other.attempts, 1);
    let delivered = writer
        .record_delivered(id(60), "tasks.react", at(8))
        .expect("delivered");
    assert_eq!(
        (delivered.attempts, delivered.state),
        (1, DeliveryState::Delivered)
    );
    writer
        .record_delivered(id(60), "tasks.react", at(9))
        .expect("at least once: a second record is harmless");
    assert!(matches!(
        writer.record_failed_delivery(id(60), "tasks.react", at(10), 5, id(93)),
        Err(Error::OutboxRowNotPending)
    ));
}

#[test]
fn an_outbox_row_is_closed_once() {
    let writer = new_writer("outbox-close");
    let source = Source::Member(id(1));
    let call = CallKey {
        principal: Principal::Member,
        source: &source,
        call_id: id(9).into(),
    };
    in_transaction(&writer, || {
        writer
            .append_event(&event(call, id(70), at(0)))
            .expect("event");
        writer
            .append_link(&link(call, id(71), at(0)))
            .expect("link");
    });
    assert!(matches!(
        writer.close_outbox_row(id(70), OutboxState::Pending, at(1)),
        Err(Error::OutboxRowNotPending)
    ));
    writer
        .close_outbox_row(id(70), OutboxState::Delivered, at(1))
        .expect("close the event");
    writer
        .close_outbox_row(id(71), OutboxState::Refused, at(2))
        .expect("refuse the link");
    for (row, state) in [
        (id(70), OutboxState::Delivered),
        (id(71), OutboxState::Delivered),
    ] {
        assert!(matches!(
            writer.close_outbox_row(row, state, at(3)),
            Err(Error::OutboxRowNotPending)
        ));
    }
    assert!(matches!(
        writer.close_outbox_row(id(72), OutboxState::Delivered, at(3)),
        Err(Error::OutboxRowNotFound)
    ));
    assert!(pending_ids(&writer).is_empty());
    let events = writer.outbox_events().expect("read");
    assert_eq!(
        (events[0].state, events[0].updated_at),
        (OutboxState::Delivered, at(1))
    );
    assert_eq!(
        writer.outbox_links().expect("read")[0].state,
        OutboxState::Refused
    );
}

#[test]
fn the_outbox_purge_deletes_closed_rows_before_the_cutoff_and_keeps_the_rest() {
    let writer = new_writer("outbox-purge");
    let source = Source::Member(id(1));
    let call = CallKey {
        principal: Principal::Member,
        source: &source,
        call_id: id(9).into(),
    };
    let effect = |intent: Id, key: &'static [u8]| EffectIntent {
        call,
        request_hash: None,
        member: None,
        first_adult: None,
        id: intent,
        effect: "send",
        idempotency_key: key,
        payload: b"",
        created_at: at(0),
    };
    in_transaction(&writer, || {
        for event_id in [id(1), id(2), id(3)] {
            writer
                .append_event(&event(call, event_id, at(0)))
                .expect("old event");
        }
        writer
            .append_event(&event(call, id(4), at(100)))
            .expect("new event");
        writer.append_link(&link(call, id(5), at(0))).expect("link");
        writer.append_effect(&effect(id(6), b"done")).expect("done");
        writer
            .append_effect(&effect(id(7), b"failed"))
            .expect("failed");
    });
    for (event_id, at_time) in [(id(1), at(1)), (id(4), at(101))] {
        writer
            .record_delivered(event_id, "meals.react", at_time)
            .expect("delivered");
        writer
            .close_outbox_row(event_id, OutboxState::Delivered, at_time)
            .expect("close");
    }
    for attempt in 1..=5 {
        writer
            .record_failed_delivery(id(2), "meals.react", at(attempt), 5, id(80))
            .expect("failure");
    }
    writer
        .close_outbox_row(id(2), OutboxState::Delivered, at(6))
        .expect("every delivery done, one dead");
    writer
        .close_outbox_row(id(5), OutboxState::Refused, at(1))
        .expect("refuse");
    writer
        .record_effect_outcome(id(6), EffectOutcome::Done, at(1))
        .expect("done");
    writer
        .record_effect_outcome(id(7), EffectOutcome::Failed, at(1))
        .expect("failed");

    writer.execute_batch("BEGIN IMMEDIATE").expect("begin");
    assert!(matches!(
        writer.purge_outbox(at(50)),
        Err(Error::TransactionOpen)
    ));
    writer.execute_batch("ROLLBACK").expect("rollback");

    let purge = writer.purge_outbox(at(50)).expect("purge");
    assert_eq!(
        purge.deleted, 4,
        "the closed old event and its delivery, the refused link, the done effect"
    );
    assert_eq!(purge.checkpoint_attempts, 1);
    let events: Vec<Id> = writer
        .outbox_events()
        .expect("read")
        .into_iter()
        .map(|event| event.id)
        .collect();
    assert_eq!(
        events,
        [id(2), id(3), id(4)],
        "a dead-lettered event, a pending one and a recent one stay"
    );
    assert!(writer.outbox_links().expect("read").is_empty());
    assert_eq!(writer.delivery(id(1), "meals.react").expect("read"), None);
    assert!(
        writer
            .delivery(id(4), "meals.react")
            .expect("read")
            .is_some()
    );
    let effects = |state| {
        writer
            .effects_in_state(state)
            .expect("read")
            .into_iter()
            .map(|effect| effect.id)
            .collect::<Vec<_>>()
    };
    assert!(effects(crate::EffectState::Done).is_empty());
    assert_eq!(effects(crate::EffectState::Failed), [id(7)]);
    assert_eq!(
        std::fs::metadata(writer.file().wal_path()).map_or(0, |metadata| metadata.len()),
        0
    );
}

#[test]
fn pending_rows_are_listed_by_page_and_a_row_that_does_not_decode_hides_none_after_it() {
    let writer = new_writer("outbox-pages");
    let source = Source::Member(id(1));
    let call = CallKey {
        principal: Principal::Member,
        source: &source,
        call_id: id(9).into(),
    };
    in_transaction(&writer, || {
        for event_id in [id(1), id(2), id(3)] {
            writer
                .append_event(&event(call, event_id, at(0)))
                .expect("event");
        }
        writer.append_link(&link(call, id(4), at(0))).expect("link");
    });
    let listed = writer.pending_outbox(0, 100).expect("read");
    let seqs: Vec<i64> = listed.iter().map(|row| row.seq).collect();
    assert_eq!(
        listed
            .iter()
            .map(|row| (row.kind, row.id, row.name.as_str()))
            .collect::<Vec<_>>(),
        [
            (OutboxKind::Event, Some(id(1)), "fixture.item.added"),
            (OutboxKind::Event, Some(id(2)), "fixture.item.added"),
            (OutboxKind::Event, Some(id(3)), "fixture.item.added"),
            (OutboxKind::Link, Some(id(4)), "meals"),
        ]
    );
    let first_page = writer.pending_outbox(0, 2).expect("read");
    assert_eq!(first_page, listed[..2]);
    assert_eq!(
        writer.pending_outbox(first_page[1].seq, 2).expect("read"),
        listed[2..]
    );

    let raw = raw_connection(&writer.file().path());
    raw.execute_batch(&format!(
        "UPDATE _outbox SET version = NULL WHERE seq = {};
         UPDATE _outbox SET id = x'00' WHERE seq = {};",
        seqs[0], seqs[1]
    ))
    .expect("damage two rows");
    let listed = writer.pending_outbox(0, 100).expect("still listed");
    assert_eq!(
        listed.iter().map(|row| row.id).collect::<Vec<_>>(),
        [Some(id(1)), None, Some(id(3)), Some(id(4))]
    );
    assert!(matches!(
        writer.outbox_row(seqs[0]),
        Err(Error::MalformedCoreRow {
            table: "_outbox",
            column: "version"
        })
    ));
    assert!(matches!(
        writer.outbox_row(seqs[2]),
        Ok(OutboxRow::Event(event)) if event.id == id(3)
    ));
    assert!(matches!(
        writer.outbox_row(seqs[3]),
        Ok(OutboxRow::Link(link)) if link.id == id(4)
    ));
    assert!(matches!(
        writer.outbox_row(i64::MAX),
        Err(Error::OutboxRowNotFound)
    ));
    writer
        .refuse_outbox_row(seqs[1], at(1))
        .expect("refuse the row no id names");
    assert!(matches!(
        writer.refuse_outbox_row(seqs[1], at(2)),
        Err(Error::OutboxRowNotPending)
    ));
    assert_eq!(
        writer
            .pending_outbox(0, 100)
            .expect("read")
            .iter()
            .map(|row| row.seq)
            .collect::<Vec<_>>(),
        [seqs[0], seqs[2], seqs[3]]
    );
}
