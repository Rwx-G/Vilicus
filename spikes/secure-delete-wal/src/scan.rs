//! Searches decoded bytes for any surviving run of known content.

use std::collections::{BTreeSet, HashMap};

/// A needle counts as found when any run of this many of its bytes appears.
pub const WINDOW: usize = 16;
/// The finer second pass. Needles are random bytes, so an 8-byte match (64 bits) is
/// still never accidental at the sizes scanned here.
pub const SHORT_WINDOW: usize = 8;

/// Every 16-byte and every 8-byte window of every needle, mapped to the needle it came from.
#[derive(Default)]
pub struct NeedleSet {
    windows: HashMap<[u8; WINDOW], usize>,
    short_windows: HashMap<[u8; SHORT_WINDOW], usize>,
    count: usize,
}

impl NeedleSet {
    pub fn add(&mut self, needle: &[u8]) {
        assert!(needle.len() >= WINDOW, "needle shorter than the window");
        let id = self.count;
        self.count += 1;
        for window in needle.windows(WINDOW) {
            self.windows
                .insert(window.try_into().expect("window length"), id);
        }
        for window in needle.windows(SHORT_WINDOW) {
            self.short_windows
                .insert(window.try_into().expect("window length"), id);
        }
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Number of needles of which at least 16 contiguous bytes occur in `haystack`.
    pub fn found_in(&self, haystack: &[u8]) -> usize {
        count_hits(&self.windows, haystack)
    }

    /// Number of needles of which at least 8 contiguous bytes occur in `haystack`.
    pub fn found_in_short(&self, haystack: &[u8]) -> usize {
        count_hits(&self.short_windows, haystack)
    }
}

fn count_hits<const N: usize>(windows: &HashMap<[u8; N], usize>, haystack: &[u8]) -> usize {
    let mut hits = BTreeSet::new();
    for window in haystack.windows(N) {
        if let Some(id) = windows.get(window) {
            hits.insert(*id);
        }
    }
    hits.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::Rng;

    #[test]
    fn a_surviving_fragment_of_one_window_is_found() {
        let mut rng = Rng::new(1);
        let needle = rng.bytes(200);
        let mut set = NeedleSet::default();
        set.add(&needle);
        let mut haystack = rng.bytes(4096);
        haystack[1000..1000 + WINDOW].copy_from_slice(&needle[77..77 + WINDOW]);
        assert_eq!(set.found_in(&haystack), 1);
    }

    #[test]
    fn a_fragment_shorter_than_the_window_is_not_found() {
        let mut rng = Rng::new(2);
        let needle = rng.bytes(200);
        let mut set = NeedleSet::default();
        set.add(&needle);
        let mut haystack = vec![0u8; 4096];
        haystack[1000..1000 + WINDOW - 1].copy_from_slice(&needle[10..10 + WINDOW - 1]);
        assert_eq!(set.found_in(&haystack), 0);
        assert_eq!(set.found_in_short(&haystack), 1);
    }

    #[test]
    fn a_fragment_shorter_than_the_short_window_is_not_found() {
        let mut rng = Rng::new(4);
        let needle = rng.bytes(200);
        let mut set = NeedleSet::default();
        set.add(&needle);
        let mut haystack = vec![0u8; 4096];
        haystack[1000..1000 + SHORT_WINDOW - 1].copy_from_slice(&needle[10..10 + SHORT_WINDOW - 1]);
        assert_eq!(set.found_in_short(&haystack), 0);
    }

    #[test]
    fn needles_are_counted_once_each() {
        let mut rng = Rng::new(3);
        let first = rng.bytes(64);
        let second = rng.bytes(64);
        let mut set = NeedleSet::default();
        set.add(&first);
        set.add(&second);
        let haystack = [first.clone(), first, second].concat();
        assert_eq!(set.found_in(&haystack), 2);
    }
}
