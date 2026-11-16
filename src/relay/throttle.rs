//! At most one log line per distinct condition per interval.
//!
//! A relay and a device both turn away or lose data connections in bursts: a
//! device that cannot reach its relay retries on every request, and each retry
//! fails the same way. Reporting every one buries the single line that explains
//! all of them; reporting none — which is what a `debug!` does at the default
//! level — leaves an operator with a device that reads as attached and answers
//! `503`, and nothing saying why. This is the middle: the first
//! occurrence is reported at once, repeats inside the interval are counted, and
//! the next report says how many it stood for.
//!
//! It is used for an audit-trail entry as well as for log lines
//! (`api::router`'s refusal by the host check). That use has a reason beyond
//! tidiness: a refusal that anyone able to reach the server can cause for free
//! would, entry per request, let them fill the trail and rotate real history
//! out of it, so the trail records the first one and a count of the rest. Before
//! writing any new entry for something a caller can trigger without cost to
//! themselves, ask who pays for each one — and use this if the answer is the
//! operator.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a condition stays quiet after it was reported.
pub(crate) const REPORT_INTERVAL: Duration = Duration::from_secs(60);

/// Distinct conditions remembered at once. Two failures that alternate would
/// each be reported every time if only the last one were kept; a handful of
/// slots covers every way a connection fails, and a full table drops the entry
/// reported longest ago.
const SLOTS: usize = 8;

/// What to do with one occurrence.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Report {
    /// Say it now. `suppressed` is how many identical occurrences were held back
    /// since this condition was last reported.
    Now { suppressed: u64 },
    /// Already reported inside the interval; counted, not said.
    Held,
}

struct Slot {
    key: String,
    reported: Instant,
    suppressed: u64,
}

pub(crate) struct Throttle {
    interval: Duration,
    slots: Mutex<Vec<Slot>>,
}

impl Throttle {
    pub(crate) const fn new(interval: Duration) -> Self {
        Throttle {
            interval,
            slots: Mutex::new(Vec::new()),
        }
    }

    /// Decide whether the condition named by `key` is reported now.
    ///
    /// `key` must be stable across occurrences of the same condition: leave out
    /// anything that changes each time (a timestamp, a counter, a request id).
    pub(crate) fn admit(&self, key: &str, now: Instant) -> Report {
        // A panic elsewhere while the lock was held must not stop a log line
        // being decided: the table holds nothing that can be left inconsistent.
        let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(slot) = slots.iter_mut().find(|slot| slot.key == key) {
            if now.saturating_duration_since(slot.reported) < self.interval {
                slot.suppressed += 1;
                return Report::Held;
            }
            let suppressed = std::mem::take(&mut slot.suppressed);
            slot.reported = now;
            return Report::Now { suppressed };
        }
        if slots.len() >= SLOTS {
            if let Some(oldest) = slots
                .iter()
                .enumerate()
                .min_by_key(|(_, slot)| slot.reported)
                .map(|(index, _)| index)
            {
                slots.swap_remove(oldest);
            }
        }
        slots.push(Slot {
            key: key.to_string(),
            reported: now,
            suppressed: 0,
        });
        Report::Now { suppressed: 0 }
    }

    /// [`Self::admit`] against the clock.
    pub(crate) fn admit_now(&self, key: &str) -> Report {
        self.admit(key, Instant::now())
    }
}

/// The suffix a report carries when it stands for more than itself.
pub(crate) fn repeats_note(suppressed: u64) -> String {
    match suppressed {
        0 => String::new(),
        1 => " (1 more like it since the last report)".to_string(),
        n => format!(" ({n} more like it since the last report)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTERVAL: Duration = Duration::from_secs(60);

    #[test]
    fn the_first_occurrence_is_reported_and_repeats_inside_the_interval_are_counted() {
        let throttle = Throttle::new(INTERVAL);
        let t0 = Instant::now();
        assert_eq!(throttle.admit("a", t0), Report::Now { suppressed: 0 });
        assert_eq!(
            throttle.admit("a", t0 + Duration::from_secs(1)),
            Report::Held
        );
        assert_eq!(
            throttle.admit("a", t0 + Duration::from_secs(59)),
            Report::Held
        );
        // The interval counts from the last *report*, not from the last
        // occurrence: a condition that never stops is still said once a minute.
        assert_eq!(
            throttle.admit("a", t0 + Duration::from_secs(60)),
            Report::Now { suppressed: 2 }
        );
        assert_eq!(
            throttle.admit("a", t0 + Duration::from_secs(61)),
            Report::Held
        );
    }

    #[test]
    fn alternating_conditions_are_each_throttled() {
        let throttle = Throttle::new(INTERVAL);
        let t0 = Instant::now();
        assert_eq!(throttle.admit("a", t0), Report::Now { suppressed: 0 });
        assert_eq!(throttle.admit("b", t0), Report::Now { suppressed: 0 });
        // A table that kept only the last key would report both again here.
        assert_eq!(
            throttle.admit("a", t0 + Duration::from_secs(1)),
            Report::Held
        );
        assert_eq!(
            throttle.admit("b", t0 + Duration::from_secs(1)),
            Report::Held
        );
    }

    #[test]
    fn a_full_table_forgets_the_condition_reported_longest_ago() {
        let throttle = Throttle::new(INTERVAL);
        let t0 = Instant::now();
        for i in 0..SLOTS {
            let key = format!("k{i}");
            assert_eq!(
                throttle.admit(&key, t0 + Duration::from_millis(i as u64)),
                Report::Now { suppressed: 0 }
            );
        }
        // One more distinct condition evicts k0, the oldest report …
        assert_eq!(
            throttle.admit("new", t0 + Duration::from_secs(1)),
            Report::Now { suppressed: 0 }
        );
        // … so k0 is reported again (as new), while a later key is still held.
        assert_eq!(
            throttle.admit("k0", t0 + Duration::from_secs(2)),
            Report::Now { suppressed: 0 }
        );
        assert_eq!(
            throttle.admit("k5", t0 + Duration::from_secs(2)),
            Report::Held
        );
    }

    #[test]
    fn the_note_says_how_many_a_report_stands_for() {
        assert_eq!(repeats_note(0), "");
        assert_eq!(repeats_note(1), " (1 more like it since the last report)");
        assert_eq!(repeats_note(7), " (7 more like it since the last report)");
    }
}
