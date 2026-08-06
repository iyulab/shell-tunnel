//! How many concurrent commands it takes to saturate the blocking pool.
//!
//! `tests/blocking_pool.rs` established the *mechanism*: a route that awaits the
//! blocking pool stalls behind whatever holds it, and one that does not, does
//! not. What that left open was the *threshold* — the figure an operator would
//! actually need — and extrapolating it from a two-thread probe would be
//! inventing a number.
//!
//! The threshold is a product of two terms, so it is measured as two terms:
//!
//! 1. **How many slots there are.** Read off, not measured: `src/main.rs` builds
//!    its runtime with `tokio::runtime::Builder::new_multi_thread()` and sets
//!    neither `worker_threads` nor `max_blocking_threads`, so both are tokio's
//!    defaults — 512 blocking threads at the time of writing. A guard below
//!    pins that the binary still declines to override it, because the arithmetic
//!    stops holding the day it does.
//! 2. **How many slots a command takes, and for how long.** That is this repo's
//!    own behaviour and nothing had measured it. It is what the test below does.
//!
//! Multiplying gives the threshold without any extrapolated latency: 512
//! concurrent commands, each holding its slot for up to `execution::MAX_TIMEOUT`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use shell_tunnel::{Command, CommandExecutor, SessionStore};

/// Blocking threads the probe runtime is allowed.
const POOL: usize = 4;

/// A command that runs long enough to be timed against a loaded machine's noise.
fn slow_command() -> &'static str {
    if cfg!(windows) {
        // `ping -n 3` sends three echoes a second apart: about two seconds.
        "ping -n 3 127.0.0.1"
    } else {
        "sleep 2"
    }
}

/// One in-flight command occupies one blocking thread for its whole run.
///
/// This is the term that turns "the pool has 512 slots" into "512 concurrent
/// commands saturate it", and it was assumed rather than measured. `execute`
/// hands the whole blocking core to a single `spawn_blocking`, which holds its
/// thread until the command exits or its deadline passes — so commands beyond
/// the pool's size do not run late, they do not *start*.
///
/// **Measured against a control on the same machine at the same time**, which is
/// what makes the figure mean anything here: this workstation's process spawn
/// varies by an order of magnitude with load (`kill_tree` alone was measured at
/// 6.1 s under it), so an absolute duration would be meaningless. What is
/// asserted is a *ratio* between runs taken seconds apart on that same host.
///
/// **Three points, not two**, because two would not have been an experiment.
/// Timing `POOL + 1` commands against one alone gives a ratio near two — but so
/// would any fixed per-command serialisation that has nothing to do with the
/// pool. The discriminating point is the one *at* the limit: `POOL` commands
/// must overlap (ratio near one) and `POOL + 1` must not (ratio near two). The
/// step has to land exactly on the pool boundary, and that is what pins the
/// count to the pool rather than to the commands.
///
/// Measured, first clean run with a pool of four: one command alone **2.69 s**,
/// four together **2.94 s** (ratio **1.09** — they overlap), five **5.50 s**
/// (ratio **2.04** — the fifth waits a whole round). The step is on the
/// boundary, so a command holds exactly one slot for exactly its run.
///
/// A first attempt got this wrong and is worth recording: it raised the pool
/// from 2 to 8 as a control while still running `POOL + 1` commands, and read
/// the resulting 2.26 as a failure to reproduce. It was not — nine commands
/// through eight slots is still two rounds, so the ratio is near two *by
/// construction*. Changing both terms together controls for nothing.
#[test]
fn a_command_holds_one_blocking_thread_for_its_whole_run() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .max_blocking_threads(POOL)
        .enable_all()
        .build()
        .expect("runtime");

    rt.block_on(async {
        let exec = Arc::new(CommandExecutor::new(Arc::new(SessionStore::new())));

        async fn run_concurrently(exec: &Arc<CommandExecutor>, n: usize) -> Duration {
            let start = Instant::now();
            let mut running = Vec::new();
            for _ in 0..n {
                let exec = Arc::clone(exec);
                running.push(tokio::spawn(async move {
                    exec.execute(&Command::new(slow_command()).timeout(Duration::from_secs(30)))
                        .await
                        .expect("execute")
                }));
            }
            for handle in running {
                handle.await.expect("join");
            }
            start.elapsed()
        }

        // Control: one command, alone, on this machine right now. Everything
        // below is a ratio against this, because an absolute duration on this
        // host means nothing — process spawn here varies by an order of
        // magnitude with load.
        let solo = run_concurrently(&exec, 1).await;
        // At the limit: every command gets a slot, so they overlap.
        let fits = run_concurrently(&exec, POOL).await;
        // One past it: the extra command cannot start until a slot frees.
        let over = run_concurrently(&exec, POOL + 1).await;

        let fits_ratio = fits.as_secs_f64() / solo.as_secs_f64();
        let over_ratio = over.as_secs_f64() / solo.as_secs_f64();

        assert!(
            fits_ratio < 1.5,
            "{POOL} commands through {POOL} blocking threads took {fits:?} against \
             {solo:?} for one alone (ratio {fits_ratio:.2}). They should overlap \
             almost entirely; if they do not, this is measuring contention for \
             something other than the pool and the rest of the figure is unsafe"
        );
        assert!(
            over_ratio >= fits_ratio * 1.5,
            "{} commands took {over:?} where {POOL} took {fits:?} (ratios \
             {over_ratio:.2} vs {fits_ratio:.2}). The step must land exactly on \
             the pool boundary: if it does not, a command is not holding a slot \
             for its whole run, and the arithmetic that turns the pool's size \
             into a concurrency threshold does not hold",
            POOL + 1
        );
    });
}

/// The shipped binary does not narrow the blocking pool.
///
/// The threshold above is `pool size × one slot per command`, and the first term
/// is read off `src/main.rs` rather than measured: it builds its runtime without
/// naming `max_blocking_threads`, so the pool is tokio's default. That is a fact
/// about a source file, so it is checked against the source file — the day the
/// binary starts sizing its own pool, the figure quoted to operators changes
/// with it, and nothing else here would notice.
///
/// Same shape as the other structural guards in this suite. It pins where the
/// number comes from, not what the number is; the number belongs to tokio.
#[test]
fn the_binary_leaves_the_blocking_pool_at_the_runtime_default() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    let source = std::fs::read_to_string(&path).expect("source file is readable");

    assert!(
        !source.contains("max_blocking_threads"),
        "src/main.rs now sizes the blocking pool itself. That is the first term \
         of the concurrency threshold documented for operators, so update the \
         figure wherever it is quoted — and say what the new size is and why"
    );
}
