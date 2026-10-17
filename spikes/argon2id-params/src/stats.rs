//! Latency summaries in milliseconds, nearest-rank percentiles.

use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Summary {
    pub samples: usize,
    pub median_ms: f64,
    pub p95_ms: f64,
    pub max_ms: f64,
}

/// Nearest-rank percentile of sorted values, `pct` in (0, 100].
fn nearest_rank(sorted: &[f64], pct: f64) -> f64 {
    let rank = ((pct / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// Summarises `durations`; `None` when there is nothing to summarise.
pub fn summarise(durations: &[Duration]) -> Option<Summary> {
    if durations.is_empty() {
        return None;
    }
    let mut ms: Vec<f64> = durations.iter().map(|d| d.as_secs_f64() * 1e3).collect();
    ms.sort_by(f64::total_cmp);
    Some(Summary {
        samples: ms.len(),
        median_ms: nearest_rank(&ms, 50.0),
        p95_ms: nearest_rank(&ms, 95.0),
        max_ms: ms[ms.len() - 1],
    })
}
