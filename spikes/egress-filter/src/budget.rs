//! Per-host budgets shared by every caller (spine AD-16, PRD FR-105).
//!
//! The proxy sees tunnels, not requests: what a client sends inside a CONNECT tunnel is
//! encrypted end to end, so a budget here counts tunnels opened per sliding window, per
//! hostname whatever the port. Every host has a budget: its own line or the default one. Part of
//! each budget is reserved for the Core and the backup caller, so plugins and AI processes
//! cannot exhaust it for them. The budget is taken after the address check, so a refused tunnel
//! costs nothing.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Instant;

use crate::config::{BudgetLimit, Config};

/// The budget state of every host seen.
#[derive(Debug)]
pub struct Budgets {
    limits: HashMap<String, BudgetLimit>,
    default: BudgetLimit,
    opened: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl Budgets {
    /// Builds the state from the configured budgets.
    #[must_use]
    pub fn new(config: &Config) -> Self {
        Self {
            limits: config.budgets.iter().cloned().collect(),
            default: config.default_budget,
            opened: Mutex::new(HashMap::new()),
        }
    }

    /// Takes one tunnel from `host`'s budget at `now`; true when allowed. A caller that is not
    /// Core-side may not use the reserve.
    pub fn try_take(&self, host: &str, core_side: bool, now: Instant) -> bool {
        let limit = self.limits.get(host).copied().unwrap_or(self.default);
        // A poisoned lock only means another task panicked mid-update; the counters stay usable.
        let mut opened = self
            .opened
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let times = opened.entry(host.to_owned()).or_default();
        while times
            .front()
            .is_some_and(|t| now.duration_since(*t) >= limit.window)
        {
            times.pop_front();
        }
        let ceiling = if core_side {
            limit.tunnels
        } else {
            limit.tunnels - limit.reserve
        };
        if u32::try_from(times.len()).unwrap_or(u32::MAX) >= ceiling {
            return false;
        }
        times.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn budgets() -> Budgets {
        let config = Config::parse(
            "budget budget.test tunnels=3 window=60 reserve=1\n\
             budget-default tunnels=2 window=60 reserve=1\n",
        )
        .unwrap();
        Budgets::new(&config)
    }

    #[test]
    fn plugins_stop_at_the_reserve_and_the_core_uses_it() {
        let budgets = budgets();
        let start = Instant::now();
        assert!(budgets.try_take("budget.test", false, start));
        assert!(budgets.try_take("budget.test", false, start));
        assert!(!budgets.try_take("budget.test", false, start));
        assert!(budgets.try_take("budget.test", true, start));
        assert!(!budgets.try_take("budget.test", true, start));
    }

    #[test]
    fn the_window_slides() {
        let budgets = budgets();
        let start = Instant::now();
        assert!(budgets.try_take("budget.test", false, start));
        assert!(budgets.try_take("budget.test", false, start + Duration::from_secs(30)));
        assert!(!budgets.try_take("budget.test", false, start + Duration::from_secs(59)));
        // Only the first tunnel has left the window: one slot, not a fresh window of two.
        assert!(budgets.try_take("budget.test", false, start + Duration::from_secs(60)));
        assert!(!budgets.try_take("budget.test", false, start + Duration::from_secs(61)));
    }

    #[test]
    fn unlisted_hosts_take_the_default_budget_each() {
        let budgets = budgets();
        let start = Instant::now();
        assert!(budgets.try_take("a.test", false, start));
        assert!(!budgets.try_take("a.test", false, start));
        assert!(budgets.try_take("b.test", false, start));
        assert!(budgets.try_take("a.test", true, start));
    }
}
