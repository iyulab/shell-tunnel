#![cfg(feature = "relay-client")]
//! A WebSocket crossing the relay to a device's local server, with the device's
//! real relay client in the middle.
//!
//! What is pinned: the caller's `Sec-WebSocket-Extensions` offer does not reach
//! the local server. The relay answers the caller's upgrade without any
//! extension, and the device's own client implements none; a local server that
//! was offered compression and accepted it produced frames nothing on that leg
//! could read, and the connection closed the moment it opened. The relay-leg
//! behaviour has no other test — the fake devices in `relay_data_e2e` do not run
//! this code.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use shell_tunnel::relay::client::{run, AttachEvent, RelayClientConfig};
use shell_tunnel::relay::{relay_router, RelayConfig, RelayState};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;

async fn start_relay() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = RelayConfig::new(addr, "secret").with_public_base("https://relay.test");
    let router = relay_router(RelayState::new(config));
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

/// A local WebSocket server that echoes, and records the header names the
/// device's client sent it.
async fn local_echo_server() -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let recorded = Arc::clone(&recorded);
            tokio::spawn(async move {
                #[allow(clippy::result_large_err)]
                let callback = |request: &Request, response: Response| {
                    *recorded.lock().unwrap() = request
                        .headers()
                        .keys()
                        .map(|name| name.as_str().to_ascii_lowercase())
                        .collect();
                    Ok(response)
                };
                let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(socket, callback).await else {
                    return;
                };
                while let Some(Ok(message)) = ws.next().await {
                    if message.is_close() || ws.send(message).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (addr, seen)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_callers_extension_offer_is_not_passed_to_the_local_server() {
    let relay = start_relay().await;
    let (local, seen) = local_echo_server().await;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(run(
        RelayClientConfig {
            relay_url: format!("ws://{relay}"),
            enroll_token: "secret".to_string(),
            local,
            label: None,
            device_name: Some("wsdev".to_string()),
            fingerprint: None,
            ca_file: None,
            events: Some(tx),
            serve_direct_requests: false,
            direct_events: None,
            local_hop_token: None,
            activity: None,
        },
        None,
    ));
    let event = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(event, AttachEvent::Enrolled { .. }), "{event:?}");
    // The pool fills right after enrolment.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut request = format!("ws://{relay}/d/wsdev/socket")
        .into_client_request()
        .unwrap();
    // What most WebSocket libraries send by default.
    request.headers_mut().insert(
        "sec-websocket-extensions",
        HeaderValue::from_static("permessage-deflate; client_max_window_bits"),
    );
    let (mut caller, _) = tokio::time::timeout(
        Duration::from_secs(10),
        tokio_tungstenite::connect_async(request),
    )
    .await
    .expect("the upgrade completes")
    .expect("the relay accepts the upgrade");

    caller
        .send(Message::Text("through two hops".into()))
        .await
        .unwrap();
    let echoed = tokio::time::timeout(Duration::from_secs(10), caller.next())
        .await
        .expect("the echo arrives")
        .expect("the connection stays open")
        .unwrap();
    assert_eq!(echoed, Message::Text("through two hops".into()));
    caller.close(None).await.ok();

    let headers = seen.lock().unwrap().clone();
    assert!(
        headers.iter().any(|name| name == "sec-websocket-key"),
        "the device made its own handshake: {headers:?}"
    );
    assert!(
        !headers
            .iter()
            .any(|name| name == "sec-websocket-extensions"),
        "the caller's extension offer reached the local server: {headers:?}"
    );
}
