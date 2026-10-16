//! The D105 and D118 verdicts computed from synthetic records.

use push_delivery::config::{Criterion, Night};
use push_delivery::records::{AckRecord, PhoneLabel, Record, SendRecord, ServerKind};
use push_delivery::report::{Outcome, Verdict, compute, explain, percentile};
use push_delivery::token::new_alert_id;

const MINUTE: u64 = 60_000;
const DAY: u64 = 24 * 60 * MINUTE;
/// A start time at midnight UTC, so night hours are easy to place.
const T0: u64 = 1_800_000_000_000 - 1_800_000_000_000 % DAY;

const NIGHT: Night = Night {
    utc_offset_minutes: 0,
    start_hour: 0,
    end_hour: 6,
};

fn phone(n: u32) -> PhoneLabel {
    format!("phone-{n}").parse().unwrap()
}

/// How the synthetic phone treats one alert.
#[derive(Clone, Copy)]
enum Fate {
    AckAfter(u64),
    Never,
    Unpublished,
}

/// `count` alerts spread evenly over `span_ms` from T0, the i-th one meeting `fate(i)`.
fn alerts(
    phone_label: &PhoneLabel,
    server: ServerKind,
    count: u64,
    span_ms: u64,
    fate: impl Fn(u64) -> Fate,
) -> Vec<Record> {
    let mut records = Vec::new();
    for i in 0..count {
        let id = new_alert_id();
        let sent_ms = T0 + i * span_ms / (count - 1);
        let fate = fate(i);
        records.push(Record::Send(SendRecord {
            id: id.clone(),
            phone: phone_label.clone(),
            server,
            sent_ms,
            published: !matches!(fate, Fate::Unpublished),
        }));
        if let Fate::AckAfter(latency) = fate {
            records.push(Record::Ack(AckRecord {
                id,
                arrival_ms: sent_ms + latency,
                phone_ms: Some(sent_ms + latency - 100),
            }));
        }
    }
    records
}

/// The end of the observation: every alert's deadline has passed.
fn after(span_ms: u64) -> u64 {
    T0 + span_ms + 11 * MINUTE
}

fn all_targets() -> Vec<(PhoneLabel, ServerKind)> {
    let mut targets = Vec::new();
    for n in [1, 2] {
        for server in ServerKind::ALL {
            targets.push((phone(n), server));
        }
    }
    targets
}

const WEEK: u64 = 7 * DAY;
const PER_TARGET: u64 = 400;

fn healthy(phone_label: &PhoneLabel, server: ServerKind) -> Vec<Record> {
    alerts(phone_label, server, PER_TARGET, WEEK, |_| {
        Fate::AckAfter(2_000)
    })
}

#[test]
fn every_alert_in_time_passes_everything() {
    let records: Vec<Record> = all_targets()
        .iter()
        .flat_map(|(p, s)| healthy(p, *s))
        .collect();
    let report = compute(
        &all_targets(),
        &records,
        Criterion::D105,
        NIGHT,
        after(WEEK),
    );
    for target in &report.targets {
        assert_eq!(target.verdict, Verdict::Pass, "{}", target.phone);
        assert_eq!(target.evaluated(), PER_TARGET);
        assert_eq!(target.rate_bp(), 10_000);
        assert!(target.night_evaluated >= 7);
        assert_eq!(target.phone_reported_p50_ms, Some(1_900));
    }
    assert_eq!(report.e13, Verdict::Pass);
    let text = report.to_string();
    assert!(text.contains("criterion name=d105"));
    assert!(text.ends_with("e13 verdict=PASS self_hosted=PASS public=PASS criterion=d105"));
    assert!(!text.contains("simulation"));
}

#[test]
fn exactly_99_percent_passes_and_one_less_fails() {
    // 400 alerts: 4 misses is exactly 99 %, 5 misses is below.
    for (misses, expected) in [(4, Verdict::Pass), (5, Verdict::Fail)] {
        let p1 = phone(1);
        let records = alerts(&p1, ServerKind::SelfHosted, PER_TARGET, WEEK, |i| {
            if i % 50 == 7 && i / 50 < misses {
                Fate::Never
            } else {
                Fate::AckAfter(1_000)
            }
        });
        let report = compute(
            &[(p1.clone(), ServerKind::SelfHosted)],
            &records,
            Criterion::D105,
            NIGHT,
            after(WEEK),
        );
        let target = report.target(&p1, ServerKind::SelfHosted).unwrap();
        assert_eq!(target.missing(), misses);
        assert_eq!(target.verdict, expected, "{misses} misses");
    }
}

#[test]
fn late_and_unpublished_alerts_are_not_delivered() {
    let p1 = phone(1);
    let records = alerts(&p1, ServerKind::SelfHosted, PER_TARGET, WEEK, |i| match i {
        10..=12 => Fate::AckAfter(10 * MINUTE + 1),
        20..=21 => Fate::Unpublished,
        30 => Fate::AckAfter(10 * MINUTE),
        _ => Fate::AckAfter(500),
    });
    let report = compute(
        &[(p1.clone(), ServerKind::SelfHosted)],
        &records,
        Criterion::D105,
        NIGHT,
        after(WEEK),
    );
    let target = report.target(&p1, ServerKind::SelfHosted).unwrap();
    assert_eq!(target.late(), 3);
    assert_eq!(target.unpublished(), 2);
    assert_eq!(target.missing(), 0);
    // The deadline itself is in time.
    assert_eq!(target.in_time(), PER_TARGET - 5);
    assert_eq!(target.verdict, Verdict::Fail);
    let explained = explain(target);
    assert_eq!(explained.matches("outcome=late").count(), 3);
    assert_eq!(explained.matches("outcome=unpublished").count(), 2);
}

#[test]
fn an_acknowledgement_for_an_unpublished_alert_does_not_count() {
    let p1 = phone(1);
    let mut records = alerts(&p1, ServerKind::Public, 2, MINUTE, |_| Fate::Unpublished);
    let Record::Send(send) = records[0].clone() else {
        unreachable!()
    };
    records.push(Record::Ack(AckRecord {
        id: send.id,
        arrival_ms: send.sent_ms + 10,
        phone_ms: None,
    }));
    let report = compute(
        &[(p1.clone(), ServerKind::Public)],
        &records,
        Criterion::D105,
        NIGHT,
        after(MINUTE),
    );
    let target = report.target(&p1, ServerKind::Public).unwrap();
    assert_eq!(target.unpublished(), 2);
    assert_eq!(target.in_time(), 0);
}

#[test]
fn alerts_within_their_deadline_are_pending_not_missing() {
    let p1 = phone(1);
    let records = alerts(&p1, ServerKind::SelfHosted, 11, 10 * MINUTE, |_| {
        Fate::Never
    });
    // At T0 + 10 min + 30 s only the alert sent at T0 has passed its deadline.
    let report = compute(
        &[(p1.clone(), ServerKind::SelfHosted)],
        &records,
        Criterion::D105,
        NIGHT,
        T0 + 10 * MINUTE + 30_000,
    );
    let target = report.target(&p1, ServerKind::SelfHosted).unwrap();
    assert_eq!(target.evaluated(), 1);
    assert_eq!(target.pending, 10);
}

#[test]
fn duplicates_count_once_with_the_earliest_arrival_and_unknown_acks_are_reported() {
    let p1 = phone(1);
    let mut records = alerts(&p1, ServerKind::SelfHosted, 2, MINUTE, |_| {
        Fate::AckAfter(11 * MINUTE)
    });
    let Record::Send(first) = records[0].clone() else {
        unreachable!()
    };
    // A replayed acknowledgement that arrives earlier in the file order than the late one is
    // still the earliest arrival and makes the alert in time.
    records.insert(
        0,
        Record::Ack(AckRecord {
            id: first.id.clone(),
            arrival_ms: first.sent_ms + 1_000,
            phone_ms: None,
        }),
    );
    records.push(Record::Ack(AckRecord {
        id: new_alert_id(),
        arrival_ms: T0,
        phone_ms: None,
    }));
    let report = compute(
        &[(p1.clone(), ServerKind::SelfHosted)],
        &records,
        Criterion::D105,
        NIGHT,
        after(MINUTE) + 11 * MINUTE,
    );
    let target = report.target(&p1, ServerKind::SelfHosted).unwrap();
    assert_eq!(target.duplicate_acks, 1);
    assert_eq!(target.in_time(), 1);
    assert_eq!(target.late(), 1);
    assert_eq!(report.unknown_acks, 1);
}

#[test]
fn a_short_or_sparse_or_nightless_run_is_incomplete_not_passed() {
    let p1 = phone(1);
    let target = [(p1.clone(), ServerKind::SelfHosted)];
    // Six days only.
    let six_days = alerts(&p1, ServerKind::SelfHosted, PER_TARGET, 6 * DAY, |_| {
        Fate::AckAfter(1_000)
    });
    let report = compute(&target, &six_days, Criterion::D105, NIGHT, after(6 * DAY));
    assert_eq!(report.targets[0].verdict, Verdict::Incomplete);
    assert_eq!(report.e13, Verdict::Incomplete);
    // A week, but fewer alerts than the minimum.
    let sparse = alerts(&p1, ServerKind::SelfHosted, 50, WEEK, |_| {
        Fate::AckAfter(1_000)
    });
    let report = compute(&target, &sparse, Criterion::D105, NIGHT, after(WEEK));
    assert_eq!(report.targets[0].verdict, Verdict::Incomplete);
    // A week, enough alerts, but a night window that none of them fall in.
    let never_night = Night {
        utc_offset_minutes: 0,
        start_hour: 3,
        end_hour: 3,
    };
    let records = healthy(&p1, ServerKind::SelfHosted);
    let report = compute(&target, &records, Criterion::D105, never_night, after(WEEK));
    assert_eq!(report.targets[0].night_evaluated, 0);
    assert_eq!(report.targets[0].verdict, Verdict::Incomplete);
}

#[test]
fn a_failing_phone_fails_its_server_and_e13_follows_the_self_hosted_server() {
    let (p1, p2) = (phone(1), phone(2));
    let failing = |p: &PhoneLabel, s| {
        alerts(p, s, PER_TARGET, WEEK, |i| {
            if i < 20 {
                Fate::Never
            } else {
                Fate::AckAfter(1_000)
            }
        })
    };
    // Public fails on phone 2 only: the public server is not recommended, E13 still passes.
    let mut records = Vec::new();
    records.extend(healthy(&p1, ServerKind::SelfHosted));
    records.extend(healthy(&p2, ServerKind::SelfHosted));
    records.extend(healthy(&p1, ServerKind::Public));
    records.extend(failing(&p2, ServerKind::Public));
    let report = compute(
        &all_targets(),
        &records,
        Criterion::D105,
        NIGHT,
        after(WEEK),
    );
    assert_eq!(report.server_verdict(ServerKind::Public), Verdict::Fail);
    assert_eq!(report.server_verdict(ServerKind::SelfHosted), Verdict::Pass);
    assert_eq!(report.e13, Verdict::Pass);
    assert!(
        report
            .to_string()
            .contains("server server=public verdict=FAIL status=not-recommended")
    );

    // Self-hosted fails on phone 1 only: E13 fails whatever the public server does.
    let mut records = Vec::new();
    records.extend(failing(&p1, ServerKind::SelfHosted));
    records.extend(healthy(&p2, ServerKind::SelfHosted));
    records.extend(healthy(&p1, ServerKind::Public));
    records.extend(healthy(&p2, ServerKind::Public));
    let report = compute(
        &all_targets(),
        &records,
        Criterion::D105,
        NIGHT,
        after(WEEK),
    );
    assert_eq!(report.server_verdict(ServerKind::SelfHosted), Verdict::Fail);
    assert_eq!(report.server_verdict(ServerKind::Public), Verdict::Pass);
    assert_eq!(report.e13, Verdict::Fail);
}

#[test]
fn a_server_with_a_phone_not_yet_complete_is_incomplete() {
    let (p1, p2) = (phone(1), phone(2));
    let mut records = healthy(&p1, ServerKind::SelfHosted);
    records.extend(alerts(
        &p2,
        ServerKind::SelfHosted,
        PER_TARGET,
        3 * DAY,
        |_| Fate::AckAfter(1_000),
    ));
    let targets = [(p1, ServerKind::SelfHosted), (p2, ServerKind::SelfHosted)];
    let report = compute(&targets, &records, Criterion::D105, NIGHT, after(WEEK));
    assert_eq!(
        report.server_verdict(ServerKind::SelfHosted),
        Verdict::Incomplete
    );
    // No public target configured at all.
    assert_eq!(
        report.server_verdict(ServerKind::Public),
        Verdict::Incomplete
    );
    assert_eq!(report.e13, Verdict::Incomplete);
}

#[test]
fn a_configured_target_without_records_is_reported_and_incomplete() {
    let report = compute(
        &[(phone(3), ServerKind::Public)],
        &[],
        Criterion::D105,
        NIGHT,
        T0,
    );
    assert_eq!(report.targets.len(), 1);
    assert_eq!(report.targets[0].evaluated(), 0);
    assert_eq!(report.targets[0].verdict, Verdict::Incomplete);
}

#[test]
fn simulation_parameters_are_labelled_on_every_verdict_line() {
    let p1 = phone(1);
    let criterion = Criterion {
        deadline_ms: 3_000,
        window_ms: 40_000,
        threshold_bp: 9_900,
        min_alerts: 50,
    };
    let records = alerts(&p1, ServerKind::SelfHosted, 100, 45_000, |_| {
        Fate::AckAfter(100)
    });
    let report = compute(
        &[(p1, ServerKind::SelfHosted)],
        &records,
        criterion,
        NIGHT,
        T0 + 60_000,
    );
    assert_eq!(report.e13, Verdict::Pass);
    let text = report.to_string();
    for line in text
        .lines()
        .filter(|l| l.starts_with("target") || l.starts_with("server") || l.starts_with("e13"))
    {
        assert!(line.ends_with("criterion=simulation"), "{line}");
    }
    assert!(text.contains("this is not an E13 result"));
}

#[test]
fn latency_distribution_uses_nearest_rank() {
    let sorted: Vec<u64> = (1..=100).collect();
    assert_eq!(percentile(&sorted, 50), Some(50));
    assert_eq!(percentile(&sorted, 99), Some(99));
    assert_eq!(percentile(&sorted, 100), Some(100));
    assert_eq!(percentile(&[7], 1), Some(7));
    assert_eq!(percentile(&[], 50), None);

    let p1 = phone(1);
    let records = alerts(&p1, ServerKind::SelfHosted, 4, MINUTE, |i| match i {
        3 => Fate::Never,
        i => Fate::AckAfter((i + 1) * 1_000),
    });
    let report = compute(
        &[(p1.clone(), ServerKind::SelfHosted)],
        &records,
        Criterion::D105,
        NIGHT,
        after(MINUTE),
    );
    let target = report.target(&p1, ServerKind::SelfHosted).unwrap();
    assert_eq!(target.latencies_ms(), vec![1_000, 2_000, 3_000]);
    assert!(matches!(target.outcomes[3].outcome, Outcome::Missing));
    let line = report
        .to_string()
        .lines()
        .find(|l| l.starts_with("target"))
        .unwrap()
        .to_owned();
    assert!(
        line.contains("p50_ms=2000 p90_ms=3000 p99_ms=3000 max_ms=3000"),
        "{line}"
    );
    assert!(
        line.contains("cumulative=le1s:1,le10s:3,le1m:3,le5m:3,le10m:3"),
        "{line}"
    );
}

#[test]
fn a_sender_outage_shows_as_the_largest_gap() {
    let p1 = phone(1);
    let mut records = alerts(&p1, ServerKind::SelfHosted, 3, 2 * MINUTE, |_| {
        Fate::AckAfter(10)
    });
    records.retain(|r| !matches!(r, Record::Send(s) if s.sent_ms == T0 + MINUTE));
    let report = compute(
        &[(p1.clone(), ServerKind::SelfHosted)],
        &records,
        Criterion::D105,
        NIGHT,
        after(2 * MINUTE),
    );
    assert_eq!(
        report
            .target(&p1, ServerKind::SelfHosted)
            .unwrap()
            .max_gap_ms(),
        2 * MINUTE
    );
}
