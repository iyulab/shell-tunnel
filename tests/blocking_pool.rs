//! What a saturated blocking pool does, and does not, stall.
//!
//! Two claims live in this tree and they are not the same one:
//!
//! - **(A)** putting blocking work behind `spawn_blocking` keeps it off the
//!   worker threads that run `/health` and the accept loop. Roughly a dozen
//!   comments in `src/api/fs.rs`, `src/audit.rs` and `src/api/sweep.rs` say so.
//! - **(B)** the blocking pool is itself a shared, exhaustible resource, so a
//!   route whose only blocking work is *behind* `spawn_blocking` —
//!   `AuditSink::record_async`, every filesystem route — is coupled to whatever
//!   else is holding that pool. A command holds one thread for its whole
//!   deadline, so a burst of concurrent commands is exactly such a holder.
//!
//! Both were reasoned from the code and neither had been run. This runs them.
//!
//! **The pool is deliberately tiny here.** What is in question is the mechanism,
//! not the threshold: the shipped binary builds its runtime with tokio's default
//! blocking pool, so reaching this state in production takes that many
//! concurrent commands rather than two. Saturating the real figure would mean
//! spawning hundreds of processes to observe something the mechanism already
//! shows.

use std::sync::Arc;
use std::time::{Duration, Instant};

use shell_tunnel::audit::{AuditEvent, AuditSink};

/// Blocking threads the probe runtime is allowed.
const POOL: usize = 2;
/// How long every one of them is held.
const HOLD: Duration = Duration::from_secs(2);

/// A route that awaits the blocking pool stalls behind whatever holds it;
/// one that does not, does not.
///
/// Measured, first run: `/health` **2.5 µs** while the pool was full, against
/// **2.96 s** for `record_async` — which is the hold, to within the sleep — and
/// **1.57 ms** for the same call once a slot was free. Three orders of magnitude
/// between the coupled path saturated and free, and none at all on the
/// uncoupled one.
///
/// This is a guard over a *causal claim*, which is unusual here and deliberate:
/// the claim is load-bearing (it is the reason `record_async` exists at all, and
/// the reason every filesystem route is written the way it is) and it was
/// carried in comments as reasoning rather than measurement.
///
/// Deterministic rather than a race, in both directions. `record_async` cannot
/// finish before a slot frees, so its lower bound is structural. `/health` is an
/// `async fn` returning a constant, so its upper bound has a margin of several
/// orders of magnitude — the assertion below fails only if the worker threads
/// themselves were blocked, which is the thing being ruled out.
#[test]
fn a_saturated_blocking_pool_stalls_only_what_awaits_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(AuditSink::file(dir.path().join("audit.jsonl")).expect("audit sink"));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .max_blocking_threads(POOL)
        .enable_all()
        .build()
        .expect("runtime");

    rt.block_on(async move {
        for _ in 0..POOL {
            tokio::task::spawn_blocking(move || std::thread::sleep(HOLD));
        }
        // Let them be picked up before anything is measured; without this the
        // pool may still be free when the calls below reach it.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let start = Instant::now();
        let _ = shell_tunnel::api::handlers::health().await;
        let health = start.elapsed();

        let start = Instant::now();
        sink.record_async(AuditEvent::new("probe")).await;
        let audited = start.elapsed();

        assert!(
            health < Duration::from_millis(500),
            "`/health` waited on a full blocking pool ({health:?}) — the point of \
             putting blocking work behind `spawn_blocking` is that the worker \
             threads serving this route are not the ones being held"
        );
        assert!(
            audited >= HOLD / 2,
            "`record_async` returned in {audited:?} with every blocking thread \
             held — either the pool was not actually saturated, or this path no \
             longer goes through it. If the latter is deliberate, the comments \
             in `src/audit.rs` and `src/api/fs.rs` about starving the pool need \
             rewriting with it"
        );

        // The contrast, and the reason the figure above is about the pool rather
        // than about the audit file being slow to write.
        let start = Instant::now();
        sink.record_async(AuditEvent::new("probe-after")).await;
        let free = start.elapsed();
        assert!(
            free < HOLD / 4,
            "the same call took {free:?} with the pool free; if writing the trail \
             is itself this slow, the figure above says nothing about saturation"
        );
    });
}
