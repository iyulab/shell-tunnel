//! What this server is doing right now, and the latch that stops it taking more.
//!
//! A device that replaces its own binary has to pick a moment when nobody is
//! mid-request, and then keep that moment true until the process is gone. The
//! two halves live here together because they cannot be built apart: an idle
//! check followed by a separate "stop accepting" step leaves a gap, and a
//! request that lands in the gap is cut off by the restart.
//!
//! Idleness is deliberately narrower than "a session exists". A consumer that
//! keeps one session and uses it every few minutes would otherwise hold an
//! update off forever, and an idle session has nothing to lose to a restart —
//! each command already gets a fresh shell. What is counted is work that a
//! restart would destroy: a request being served, a command running in a
//! session, an upload being assembled, and an open WebSocket.
//!
//! Only the request count lives in the latch word. A session command and an
//! upload are live *between* requests, holding no guard, so [`Activity::latch`]
//! alone cannot see them: an upload created and acknowledged just before the
//! latch leaves the count at zero. The primitive to latch with is
//! [`latch_if_idle`], which closes the door and then checks those two.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use super::handlers::AppState;

/// The top bit of the counter is the latch; the rest counts guards.
const LATCHED: usize = 1 << (usize::BITS - 1);

/// The body of the refusal a latched server answers with.
pub const LATCHED_BODY: &str = "this device is restarting to finish an update; retry shortly";

/// A count of work in flight, and a latch that closes the door on more.
///
/// One `AtomicUsize` holds both, rather than an atomic count beside a latch
/// flag. Taking a guard and latching are then each a single compare-and-swap
/// on the same word, so `latch` can only succeed from a count of exactly zero
/// and a guard can only be taken while the latch is open. Two separate
/// variables would admit the interleaving "count read as 0, request admitted,
/// latch set" — the very request the latch exists to keep out.
#[derive(Debug, Default)]
pub struct Activity {
    state: AtomicUsize,
}

impl Activity {
    pub fn new() -> Self {
        Self::default()
    }

    /// Count one unit of work until the returned guard drops. Never refuses.
    ///
    /// For a holder that is already inside a counted request: the WebSocket
    /// handlers move a second guard into the socket task, which outlives the
    /// upgrade request's own. The latch cannot close while that request holds
    /// its guard, so this increment cannot race it. Everything else goes
    /// through [`Self::try_guard`], which respects the latch.
    pub fn guard(self: &Arc<Self>) -> ActivityGuard {
        self.state.fetch_add(1, Ordering::AcqRel);
        ActivityGuard {
            activity: Arc::clone(self),
        }
    }

    /// Count one unit of work, or `None` if the latch is closed.
    pub fn try_guard(self: &Arc<Self>) -> Option<ActivityGuard> {
        let mut current = self.state.load(Ordering::Acquire);
        loop {
            if current & LATCHED != 0 {
                return None;
            }
            match self.state.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(ActivityGuard {
                        activity: Arc::clone(self),
                    })
                }
                Err(seen) => current = seen,
            }
        }
    }

    /// Units of work in flight right now.
    pub fn in_flight(&self) -> usize {
        self.state.load(Ordering::Acquire) & !LATCHED
    }

    /// Close the door, if and only if nothing is in flight at this instant.
    ///
    /// `false` means work was running and the latch was **not** set; the
    /// caller waits for idleness again rather than latching anyway. Latching
    /// an already-latched server succeeds.
    pub fn latch(&self) -> bool {
        match self
            .state
            .compare_exchange(0, LATCHED, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => true,
            Err(seen) => seen == LATCHED,
        }
    }

    /// Reopen the door. An update that could not be applied leaves the
    /// process running, and it has to go back to serving.
    pub fn unlatch(&self) {
        self.state.fetch_and(!LATCHED, Ordering::AcqRel);
    }

    pub fn is_latched(&self) -> bool {
        self.state.load(Ordering::Acquire) & LATCHED != 0
    }
}

/// One unit of counted work; ends when dropped.
#[derive(Debug)]
pub struct ActivityGuard {
    activity: Arc<Activity>,
}

impl Drop for ActivityGuard {
    fn drop(&mut self) {
        self.activity.state.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Whether nothing this server is doing would be lost to a restart.
///
/// Sessions count only while a command runs in them, not while they merely
/// exist; see the module comment for why.
pub fn is_idle(state: &AppState) -> bool {
    state.activity.in_flight() == 0
        && state.store.count_active() == 0
        && state.uploads.live_count() == 0
}

/// Close the latch only if the whole server is idle, and leave it open if not.
///
/// The one function an updater should latch with. [`Activity::latch`] proves
/// only that no request is in flight; a live upload or a running session
/// command holds no guard between requests. So this latches first and
/// re-checks afterwards, undoing the latch if either is non-zero.
///
/// Re-checking *after* latching is what makes it sound. Once the latch is
/// closed and the request count was zero, no request is being served and none
/// can be admitted, and a session command or an upload can only begin through
/// a request. So the two counts read next cannot rise, and a zero is final.
/// Checking before latching would leave a window for one to begin in between.
pub fn latch_if_idle(state: &AppState) -> bool {
    if !state.activity.latch() {
        return false;
    }
    if state.store.count_active() == 0 && state.uploads.live_count() == 0 {
        return true;
    }
    state.activity.unlatch();
    false
}

/// Count every request while it is served, and refuse all of them once latched.
///
/// Sits just inside the body-drain guard and outside authentication and rate
/// limiting: a latched server answers `503` to everyone, whatever they hold,
/// and the refusal never costs a caller rate-limit budget or an audit line.
///
/// `/health` is neither refused nor counted. A load balancer or the relay
/// probing it must keep seeing the process as alive while it restarts, and a
/// probe that counted would hold idleness off for as long as it polled.
///
/// The guard lives until the handler has produced its response. No route
/// streams a body from this process (every response is built in memory), so
/// that is the whole of the request; a streamed body would need the guard
/// moved into it.
pub(crate) async fn activity_middleware(
    State(activity): State<Arc<Activity>>,
    request: Request,
    next: Next,
) -> Response {
    if request.uri().path() == "/health" {
        return next.run(request).await;
    }
    match activity.try_guard() {
        Some(_guard) => next.run(request).await,
        None => {
            let mut response = (StatusCode::SERVICE_UNAVAILABLE, LATCHED_BODY).into_response();
            // 30 s: long enough for a swap and a restart, short enough that a
            // caller retrying on the hint reconnects promptly afterwards.
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("30"));
            response
        }
    }
}
