//! Latency samples per label and their percentiles (nearest rank).

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How many of the slowest samples [`Recorder::record_detailed`] keeps.
pub const SLOWEST_KEPT: usize = 10;

#[derive(Clone, Copy, Default)]
struct Window {
    start: Option<Instant>,
    end: Option<Instant>,
}

/// Collects the samples whose operation started inside the measured window (after the
/// warm-up, before the stop), whenever they complete, so a slow operation that finishes
/// during the drain is kept and one that started during the warm-up is not.
#[derive(Default)]
pub struct Recorder {
    window: Mutex<Window>,
    samples: Mutex<BTreeMap<String, Vec<Duration>>>,
    slowest: Mutex<Vec<(Duration, String)>>,
    errors: Mutex<BTreeMap<String, Vec<String>>>,
}

impl Recorder {
    /// Opens the window now.
    pub fn start(&self) {
        self.window.lock().expect("window").start = Some(Instant::now());
    }

    /// Closes the window now; operations started before keep being recorded.
    pub fn stop(&self) {
        self.window.lock().expect("window").end = Some(Instant::now());
    }

    /// Whether an operation started at `started` belongs to the window.
    pub fn in_window(&self, started: Instant) -> bool {
        let window = *self.window.lock().expect("window");
        window.start.is_some_and(|start| started >= start)
            && window.end.is_none_or(|end| started < end)
    }

    /// Records `elapsed` under `label` if the operation started inside the window.
    pub fn record(&self, label: &str, started: Instant, elapsed: Duration) {
        if self.in_window(started) {
            self.samples
                .lock()
                .expect("samples")
                .entry(label.to_owned())
                .or_default()
                .push(elapsed);
        }
    }

    /// [`Recorder::record`], and keeps `detail` if the sample is among the slowest so far.
    pub fn record_detailed(
        &self,
        label: &str,
        started: Instant,
        elapsed: Duration,
        detail: String,
    ) {
        if !self.in_window(started) {
            return;
        }
        self.record(label, started, elapsed);
        let mut slowest = self.slowest.lock().expect("slowest");
        slowest.push((elapsed, detail));
        slowest.sort_by_key(|sample| std::cmp::Reverse(sample.0));
        slowest.truncate(SLOWEST_KEPT);
    }

    /// The slowest detailed samples, slowest first.
    pub fn slowest(&self) -> Vec<(Duration, String)> {
        self.slowest.lock().expect("slowest").clone()
    }

    /// Errors are kept whether or not the window is open: a failed call is never discarded.
    pub fn error(&self, label: &str, message: String) {
        self.errors
            .lock()
            .expect("errors")
            .entry(label.to_owned())
            .or_default()
            .push(message);
    }

    pub fn summaries(&self) -> Vec<Summary> {
        self.samples
            .lock()
            .expect("samples")
            .iter()
            .map(|(label, samples)| Summary::of(label, samples))
            .collect()
    }

    pub fn errors(&self) -> BTreeMap<String, Vec<String>> {
        self.errors.lock().expect("errors").clone()
    }
}

/// Percentiles of one label.
#[derive(Clone, Debug)]
pub struct Summary {
    pub label: String,
    pub count: usize,
    pub p50: Duration,
    pub p95: Duration,
    pub p99: Duration,
    pub max: Duration,
}

impl Summary {
    pub fn of(label: &str, samples: &[Duration]) -> Self {
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        Self {
            label: label.to_owned(),
            count: sorted.len(),
            p50: percentile(&sorted, 0.50),
            p95: percentile(&sorted, 0.95),
            p99: percentile(&sorted, 0.99),
            max: sorted.last().copied().unwrap_or_default(),
        }
    }
}

/// Nearest-rank percentile of sorted samples: the smallest sample with at least `q` of the
/// samples at or below it. Zero for no samples.
pub fn percentile(sorted: &[Duration], q: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let rank = (q * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

fn ms(duration: Duration) -> String {
    format!("{:.2}", duration.as_secs_f64() * 1_000.0)
}

/// A Markdown table of summaries, milliseconds.
pub fn table(summaries: &[Summary]) -> String {
    let mut out = String::from(
        "| label | samples | p50 ms | p95 ms | p99 ms | max ms |\n|---|---|---|---|---|---|\n",
    );
    for summary in summaries {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            summary.label,
            summary.count,
            ms(summary.p50),
            ms(summary.p95),
            ms(summary.p99),
            ms(summary.max)
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn millis(values: &[u64]) -> Vec<Duration> {
        values.iter().map(|v| Duration::from_millis(*v)).collect()
    }

    #[test]
    fn nearest_rank_percentiles() {
        let samples: Vec<u64> = (1..=100).collect();
        let sorted = millis(&samples);
        assert_eq!(percentile(&sorted, 0.50), Duration::from_millis(50));
        assert_eq!(percentile(&sorted, 0.99), Duration::from_millis(99));
        assert_eq!(percentile(&sorted, 1.0), Duration::from_millis(100));
        assert_eq!(percentile(&millis(&[7]), 0.99), Duration::from_millis(7));
        assert_eq!(percentile(&[], 0.99), Duration::ZERO);
    }

    #[test]
    fn summary_sorts_and_keeps_samples_by_start_time() {
        let recorder = Recorder::default();
        let before = Instant::now();
        recorder.start();
        let inside = Instant::now();
        for value in [30, 10, 20] {
            recorder.record("a", inside, Duration::from_millis(value));
        }
        recorder.record("a", before, Duration::from_millis(1));
        recorder.stop();
        // Completes after the stop but started inside: kept.
        recorder.record("a", inside, Duration::from_millis(25));
        // Started after the stop: dropped.
        recorder.record("a", Instant::now(), Duration::from_millis(500));
        let summaries = recorder.summaries();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].count, 4);
        assert_eq!(summaries[0].p50, Duration::from_millis(20));
        assert_eq!(summaries[0].max, Duration::from_millis(30));
    }
}
