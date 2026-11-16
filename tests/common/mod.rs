//! Helpers shared by the integration tests.

#![allow(dead_code)]

use std::net::SocketAddr;

use axum::{extract::ConnectInfo, extract::Request, middleware, middleware::Next, Router};
use shell_tunnel::api::{create_secure_router, AppState, SecurityConfig};

/// The server's whole route table with authentication off and the rate limit
/// relaxed — what these tests exercise when they are about a handler and not
/// about who may call it.
///
/// Built through the same constructor a real server uses. The library used to
/// export a second one with no security layers at all for this, which was also
/// available to anyone embedding it: a router that runs commands for whoever
/// can reach it, one `use` away from the secure one.
///
/// A request driven straight into a router (`oneshot`) has no socket, and the
/// rate limiter keys on the peer address, so one is supplied here — the same
/// loopback peer a real connection to a loopback server has.
pub fn plain_app(state: AppState) -> Router {
    let (router, _keys, _limiter) = create_secure_router(state, SecurityConfig::development());
    router.layer(middleware::from_fn(peer_is_loopback))
}

async fn peer_is_loopback(mut request: Request, next: Next) -> axum::response::Response {
    if request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .is_none()
    {
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    }
    next.run(request).await
}
