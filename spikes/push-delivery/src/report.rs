//! Delivery rates, latencies and verdicts, per phone and per server (D105, D118).
//!
//! An alert is evaluated once its deadline has passed at the report time; before that it is
//! pending and left out. An evaluated alert is in time (acknowledged within the deadline), late
//! (acknowledged after it), missing (never acknowledged) or unpublished (refused by the push
//! server or not reaching it). Only in-time alerts count as delivered. The delay is measured to
//! the acknowledgement's arrival at the collector, an upper bound of the reception time, so a
//! pass is never overstated.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use crate::config::{Criterion, Night};
use crate::records::{PhoneLabel, Record, SendRecord, ServerKind};

const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// The latency buckets of the distribution, upper bounds in ms.
const BUCKETS_MS: &[(u64, &str)] = &[
    (1_000, "le1s"),
    (10_000, "le10s"),
    (60_000, "le1m"),
    (300_000, "le5m"),
    (600_000, "le10m"),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail,
    Incomplete,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::Incomplete => "INCOMPLETE",
        })
    }
}

/// What happened to one evaluated alert.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    InTime { latency_ms: u64 },
    Late { latency_ms: u64 },
    Missing,
    Unpublished,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlertOutcome {
    pub id: String,
    pub sent_ms: u64,
    pub outcome: Outcome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetStats {
    pub phone: PhoneLabel,
    pub server: ServerKind,
    pub pending: u64,
    pub outcomes: Vec<AlertOutcome>,
    /// Acknowledgements received again for an alert already acknowledged.
    pub duplicate_acks: u64,
    /// Median of (phone-reported reception time - send time), for alerts whose phone reported
    /// one. Informational: phone clocks are not trusted for the verdict.
    pub phone_reported_p50_ms: Option<i64>,
    pub night_evaluated: u64,
    pub night_in_time: u64,
    pub verdict: Verdict,
}

impl TargetStats {
    pub fn evaluated(&self) -> u64 {
        self.outcomes.len() as u64
    }

    fn count(&self, pick: impl Fn(&Outcome) -> bool) -> u64 {
        self.outcomes.iter().filter(|a| pick(&a.outcome)).count() as u64
    }

    pub fn in_time(&self) -> u64 {
        self.count(|o| matches!(o, Outcome::InTime { .. }))
    }

    pub fn late(&self) -> u64 {
        self.count(|o| matches!(o, Outcome::Late { .. }))
    }

    pub fn missing(&self) -> u64 {
        self.count(|o| matches!(o, Outcome::Missing))
    }

    pub fn unpublished(&self) -> u64 {
        self.count(|o| matches!(o, Outcome::Unpublished))
    }

    /// Time between the first and the last evaluated alert.
    pub fn coverage_ms(&self) -> u64 {
        let first = self.outcomes.iter().map(|a| a.sent_ms).min();
        let last = self.outcomes.iter().map(|a| a.sent_ms).max();
        match (first, last) {
            (Some(first), Some(last)) => last - first,
            _ => 0,
        }
    }

    /// The longest time without an evaluated alert, between two consecutive ones. A long gap
    /// means the sender was down and that stretch was not measured.
    pub fn max_gap_ms(&self) -> u64 {
        self.outcomes
            .windows(2)
            .map(|pair| pair[1].sent_ms - pair[0].sent_ms)
            .max()
            .unwrap_or(0)
    }

    /// Latencies of every acknowledged alert, in time or late, sorted.
    pub fn latencies_ms(&self) -> Vec<u64> {
        let mut latencies: Vec<u64> = self
            .outcomes
            .iter()
            .filter_map(|a| match a.outcome {
                Outcome::InTime { latency_ms } | Outcome::Late { latency_ms } => Some(latency_ms),
                Outcome::Missing | Outcome::Unpublished => None,
            })
            .collect();
        latencies.sort_unstable();
        latencies
    }

    /// The in-time rate in hundredths of a percent, rounded down.
    pub fn rate_bp(&self) -> u64 {
        match self.evaluated() {
            0 => 0,
            n => self.in_time() * 10_000 / n,
        }
    }
}

/// Nearest-rank percentile of a sorted slice.
pub fn percentile(sorted: &[u64], percent: u64) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = (percent * sorted.len() as u64).div_ceil(100).max(1);
    sorted.get(usize::try_from(rank - 1).ok()?).copied()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub criterion: Criterion,
    pub at_ms: u64,
    pub targets: Vec<TargetStats>,
    pub servers: Vec<(ServerKind, Verdict)>,
    /// E13 follows the default self-hosted server (D118).
    pub e13: Verdict,
    /// Acknowledgements whose id matches no recorded send.
    pub unknown_acks: u64,
}

impl Report {
    pub fn server_verdict(&self, server: ServerKind) -> Verdict {
        self.servers
            .iter()
            .find(|(kind, _)| *kind == server)
            .map_or(Verdict::Incomplete, |(_, verdict)| *verdict)
    }

    pub fn target(&self, phone: &PhoneLabel, server: ServerKind) -> Option<&TargetStats> {
        self.targets
            .iter()
            .find(|t| &t.phone == phone && t.server == server)
    }
}

/// Computes the report at `at_ms` for the configured `targets` from the recorded events.
pub fn compute(
    targets: &[(PhoneLabel, ServerKind)],
    records: &[Record],
    criterion: Criterion,
    night: Night,
    at_ms: u64,
) -> Report {
    let mut sends: BTreeMap<(PhoneLabel, ServerKind), Vec<&SendRecord>> = targets
        .iter()
        .map(|target| (target.clone(), Vec::new()))
        .collect();
    let mut sent_ids: HashSet<&str> = HashSet::new();
    // First arrival per id; later ones are duplicates.
    let mut acks: HashMap<&str, (u64, Option<u64>)> = HashMap::new();
    let mut duplicates: HashMap<&str, u64> = HashMap::new();
    for record in records {
        match record {
            Record::Send(send) => {
                sent_ids.insert(&send.id);
                if let Some(list) = sends.get_mut(&(send.phone.clone(), send.server)) {
                    list.push(send);
                }
            }
            Record::Ack(ack) => match acks.get_mut(ack.id.as_str()) {
                Some(first) => {
                    *duplicates.entry(&ack.id).or_default() += 1;
                    if ack.arrival_ms < first.0 {
                        *first = (ack.arrival_ms, ack.phone_ms);
                    }
                }
                None => {
                    acks.insert(&ack.id, (ack.arrival_ms, ack.phone_ms));
                }
            },
        }
    }
    let unknown_acks = acks.keys().filter(|id| !sent_ids.contains(*id)).count() as u64;

    let target_stats: Vec<TargetStats> = sends
        .into_iter()
        .map(|((phone, server), list)| {
            target_stats(
                phone,
                server,
                &list,
                &acks,
                &duplicates,
                criterion,
                night,
                at_ms,
            )
        })
        .collect();

    let servers: Vec<(ServerKind, Verdict)> = ServerKind::ALL
        .into_iter()
        .map(|kind| {
            let verdicts: Vec<Verdict> = target_stats
                .iter()
                .filter(|t| t.server == kind)
                .map(|t| t.verdict)
                .collect();
            let verdict = if verdicts.is_empty() {
                Verdict::Incomplete
            } else if verdicts.contains(&Verdict::Fail) {
                Verdict::Fail
            } else if verdicts.contains(&Verdict::Incomplete) {
                Verdict::Incomplete
            } else {
                Verdict::Pass
            };
            (kind, verdict)
        })
        .collect();
    let e13 = servers
        .iter()
        .find(|(kind, _)| *kind == ServerKind::SelfHosted)
        .map_or(Verdict::Incomplete, |(_, verdict)| *verdict);

    Report {
        criterion,
        at_ms,
        targets: target_stats,
        servers,
        e13,
        unknown_acks,
    }
}

#[allow(clippy::too_many_arguments)] // one call site; a parameter struct would only rename them
fn target_stats(
    phone: PhoneLabel,
    server: ServerKind,
    sends: &[&SendRecord],
    acks: &HashMap<&str, (u64, Option<u64>)>,
    duplicates: &HashMap<&str, u64>,
    criterion: Criterion,
    night: Night,
    at_ms: u64,
) -> TargetStats {
    let mut pending = 0;
    let mut outcomes = Vec::new();
    let mut phone_reported = Vec::new();
    let mut duplicate_acks = 0;
    let mut night_evaluated = 0;
    let mut night_in_time = 0;
    for send in sends {
        duplicate_acks += duplicates.get(send.id.as_str()).copied().unwrap_or(0);
        if send.sent_ms.saturating_add(criterion.deadline_ms) > at_ms {
            pending += 1;
            continue;
        }
        let ack = acks.get(send.id.as_str());
        let outcome = match ack {
            _ if !send.published => Outcome::Unpublished,
            None => Outcome::Missing,
            Some((arrival_ms, _)) => {
                let latency_ms = arrival_ms.saturating_sub(send.sent_ms);
                if latency_ms <= criterion.deadline_ms {
                    Outcome::InTime { latency_ms }
                } else {
                    Outcome::Late { latency_ms }
                }
            }
        };
        if let Some((_, Some(phone_ms))) = ack {
            phone_reported.push(*phone_ms as i64 - send.sent_ms as i64);
        }
        if night.contains(send.sent_ms) {
            night_evaluated += 1;
            if matches!(outcome, Outcome::InTime { .. }) {
                night_in_time += 1;
            }
        }
        outcomes.push(AlertOutcome {
            id: send.id.clone(),
            sent_ms: send.sent_ms,
            outcome,
        });
    }
    outcomes.sort_by_key(|a| a.sent_ms);
    phone_reported.sort_unstable();
    let phone_reported_p50_ms =
        (!phone_reported.is_empty()).then(|| phone_reported[(phone_reported.len() - 1) / 2]);

    let mut stats = TargetStats {
        phone,
        server,
        pending,
        outcomes,
        duplicate_acks,
        phone_reported_p50_ms,
        night_evaluated,
        night_in_time,
        verdict: Verdict::Incomplete,
    };
    stats.verdict = target_verdict(&stats, criterion);
    stats
}

fn target_verdict(stats: &TargetStats, criterion: Criterion) -> Verdict {
    // One night per full day of the window must have been measured (idle nights included).
    let nights_required = criterion.window_ms / DAY_MS;
    let complete = stats.evaluated() >= criterion.min_alerts
        && stats.coverage_ms() >= criterion.window_ms
        && stats.night_evaluated >= nights_required;
    let rate_met = stats.in_time() * 10_000 >= criterion.threshold_bp * stats.evaluated();
    match (complete, rate_met) {
        (true, true) => Verdict::Pass,
        (true, false) => Verdict::Fail,
        (false, _) => Verdict::Incomplete,
    }
}

fn percent(bp: u64) -> String {
    format!("{}.{:02}", bp / 100, bp % 100)
}

fn optional(value: Option<impl fmt::Display>) -> String {
    value.map_or_else(|| "-".to_owned(), |v| v.to_string())
}

impl fmt::Display for Report {
    /// One `key=value` line per phone and server, one per server, then the E13 line. A report
    /// computed with any criterion other than D105's says so on every verdict line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c = self.criterion;
        let criterion = if c.is_d105() { "d105" } else { "simulation" };
        writeln!(
            f,
            "criterion name={criterion} deadline_ms={} window_ms={} threshold_percent={} min_alerts={} at_ms={}",
            c.deadline_ms,
            c.window_ms,
            percent(c.threshold_bp),
            c.min_alerts,
            self.at_ms
        )?;
        for t in &self.targets {
            let latencies = t.latencies_ms();
            let buckets: Vec<String> = BUCKETS_MS
                .iter()
                .map(|(bound, name)| {
                    let n = latencies.iter().filter(|l| **l <= *bound).count();
                    format!("{name}:{n}")
                })
                .collect();
            writeln!(
                f,
                "target phone={} server={} evaluated={} in_time={} late={} missing={} unpublished={} pending={} rate_percent={} p50_ms={} p90_ms={} p99_ms={} max_ms={} cumulative={} night_evaluated={} night_in_time={} coverage_ms={} max_gap_ms={} duplicate_acks={} phone_reported_p50_ms={} verdict={} criterion={criterion}",
                t.phone,
                t.server,
                t.evaluated(),
                t.in_time(),
                t.late(),
                t.missing(),
                t.unpublished(),
                t.pending,
                percent(t.rate_bp()),
                optional(percentile(&latencies, 50)),
                optional(percentile(&latencies, 90)),
                optional(percentile(&latencies, 99)),
                optional(latencies.last()),
                buckets.join(","),
                t.night_evaluated,
                t.night_in_time,
                t.coverage_ms(),
                t.max_gap_ms(),
                t.duplicate_acks,
                optional(t.phone_reported_p50_ms),
                t.verdict,
            )?;
        }
        for (kind, verdict) in &self.servers {
            let note = match (kind, verdict) {
                (ServerKind::Public, Verdict::Fail) => " status=not-recommended",
                _ => "",
            };
            writeln!(
                f,
                "server server={kind} verdict={verdict}{note} criterion={criterion}"
            )?;
        }
        writeln!(f, "unknown_acks count={}", self.unknown_acks)?;
        write!(
            f,
            "e13 verdict={} self_hosted={} public={} criterion={criterion}",
            self.e13,
            self.server_verdict(ServerKind::SelfHosted),
            self.server_verdict(ServerKind::Public),
        )?;
        if !c.is_d105() {
            write!(
                f,
                "\nnote: computed with simulation parameters, not the D105 criterion; this is not an E13 result"
            )?;
        }
        Ok(())
    }
}

/// One line per late, missing or unpublished alert of a target, for investigation.
pub fn explain(stats: &TargetStats) -> String {
    stats
        .outcomes
        .iter()
        .filter_map(|a| {
            let what = match a.outcome {
                Outcome::InTime { .. } => return None,
                Outcome::Late { latency_ms } => format!("late latency_ms={latency_ms}"),
                Outcome::Missing => "missing".to_owned(),
                Outcome::Unpublished => "unpublished".to_owned(),
            };
            Some(format!(
                "alert phone={} server={} sent_ms={} outcome={what}\n",
                stats.phone, stats.server, a.sent_ms
            ))
        })
        .collect()
}
