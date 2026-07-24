//! End-to-end tests for the self-hosted relay's control channel.
//!
//! These stand in for a device: they dial the relay over a real WebSocket and
//! speak the wire protocol, so the enrollment contract is verified against a
//! running server rather than against the handler in isolation.

use std::net::SocketAddr;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

use shell_tunnel::relay::protocol::{reject, DeviceMessage, RelayMessage, PROTOCOL_VERSION};
use shell_tunnel::relay::{relay_router, RelayConfig, RelayState};

/// Start a relay on an ephemeral port; returns its address and shared state.
async fn start_relay(enroll_token: &str) -> (SocketAddr, RelayState) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = RelayConfig::new(addr, enroll_token).with_public_base("https://relay.test");
    let state = RelayState::new(config);

    let router = relay_router(state.clone());
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    // Let the listener become ready before the first dial.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, state)
}

type Device =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Dial the relay's control endpoint as a device would.
async fn connect(addr: SocketAddr) -> Device {
    let (socket, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/relay/v1/control"))
        .await
        .expect("control endpoint should accept the upgrade");
    socket
}

async fn send(device: &mut Device, message: &DeviceMessage) {
    device
        .send(Message::Text(serde_json::to_string(message).unwrap()))
        .await
        .unwrap();
}

async fn recv(device: &mut Device) -> RelayMessage {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(5), device.next())
            .await
            .expect("relay should answer")
            .expect("stream should stay open")
            .expect("frame should be readable");
        if let Message::Text(text) = message {
            return serde_json::from_str(&text).expect("relay frames are protocol messages");
        }
    }
}

fn enroll(token: &str) -> DeviceMessage {
    DeviceMessage::Enroll {
        enroll_token: token.to_string(),
        version: PROTOCOL_VERSION,
        label: Some("test-device".to_string()),
        device_name: None,
    }
}

fn enroll_as(token: &str, name: &str) -> DeviceMessage {
    DeviceMessage::Enroll {
        enroll_token: token.to_string(),
        version: PROTOCOL_VERSION,
        label: None,
        device_name: Some(name.to_string()),
    }
}

#[tokio::test]
async fn a_device_enrolls_and_is_registered() {
    let (addr, state) = start_relay("secret").await;
    let mut device = connect(addr).await;

    send(&mut device, &enroll("secret")).await;
    let RelayMessage::Enrolled {
        device_id,
        public_url,
    } = recv(&mut device).await
    else {
        panic!("expected an enrolled message");
    };

    assert!(!device_id.is_empty());
    // The port-less --public-base inherits this relay's ephemeral listen port.
    assert_eq!(
        public_url,
        format!("https://relay.test:{}/d/{device_id}", addr.port())
    );
    assert_eq!(state.devices().count(), 1);
    assert_eq!(
        state.devices().get(&device_id).unwrap().label.as_deref(),
        Some("test-device")
    );
}

#[tokio::test]
async fn a_bad_token_is_refused_without_detail() {
    let (addr, state) = start_relay("secret").await;
    let mut device = connect(addr).await;

    send(&mut device, &enroll("wrong")).await;
    let RelayMessage::Rejected { code, message } = recv(&mut device).await else {
        panic!("expected a rejection");
    };

    assert_eq!(code, reject::BAD_TOKEN);
    // The refusal must not hint at what the real token looks like.
    assert!(!message.contains("secret"), "{message}");
    assert_eq!(state.devices().count(), 0);
}

#[tokio::test]
async fn a_mismatched_protocol_version_is_refused() {
    let (addr, state) = start_relay("secret").await;
    let mut device = connect(addr).await;

    send(
        &mut device,
        &DeviceMessage::Enroll {
            enroll_token: "secret".to_string(),
            version: PROTOCOL_VERSION + 99,
            label: None,
            device_name: None,
        },
    )
    .await;

    let RelayMessage::Rejected { code, .. } = recv(&mut device).await else {
        panic!("expected a rejection");
    };
    assert_eq!(code, reject::UNSUPPORTED_VERSION);
    assert_eq!(state.devices().count(), 0);
}

#[tokio::test]
async fn a_non_enroll_first_frame_is_refused() {
    let (addr, _state) = start_relay("secret").await;
    let mut device = connect(addr).await;

    // Heartbeat before enrolling: the connection has no identity yet.
    send(&mut device, &DeviceMessage::Heartbeat).await;

    let RelayMessage::Rejected { code, .. } = recv(&mut device).await else {
        panic!("expected a rejection");
    };
    assert_eq!(code, reject::BAD_HANDSHAKE);
}

#[tokio::test]
async fn heartbeats_are_acknowledged() {
    let (addr, state) = start_relay("secret").await;
    let mut device = connect(addr).await;

    send(&mut device, &enroll("secret")).await;
    let RelayMessage::Enrolled { device_id, .. } = recv(&mut device).await else {
        panic!("expected an enrolled message");
    };

    // Enrollment is followed by a pool-fill request, so skip past it.
    assert!(matches!(
        recv(&mut device).await,
        RelayMessage::OpenData { .. }
    ));

    send(&mut device, &DeviceMessage::Heartbeat).await;
    assert_eq!(recv(&mut device).await, RelayMessage::HeartbeatAck);
    assert!(state.devices().get(&device_id).is_some());
}

#[tokio::test]
async fn a_disconnecting_device_is_detached() {
    let (addr, state) = start_relay("secret").await;
    let mut device = connect(addr).await;

    send(&mut device, &enroll("secret")).await;
    let RelayMessage::Enrolled { device_id, .. } = recv(&mut device).await else {
        panic!("expected an enrolled message");
    };
    assert_eq!(state.devices().count(), 1);

    device.close(None).await.unwrap();

    // Detach happens when the control session ends, so allow a moment for it.
    for _ in 0..50 {
        if state.devices().get(&device_id).is_none() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("device should be detached once its control connection closes");
}

#[tokio::test]
async fn two_devices_get_distinct_ids() {
    let (addr, state) = start_relay("secret").await;

    let mut first = connect(addr).await;
    send(&mut first, &enroll("secret")).await;
    let RelayMessage::Enrolled { device_id: id1, .. } = recv(&mut first).await else {
        panic!("expected an enrolled message");
    };

    let mut second = connect(addr).await;
    send(&mut second, &enroll("secret")).await;
    let RelayMessage::Enrolled { device_id: id2, .. } = recv(&mut second).await else {
        panic!("expected an enrolled message");
    };

    assert_ne!(id1, id2);
    assert_eq!(state.devices().count(), 2);
}

// ===========================================================================
// Stable device names
// ===========================================================================

#[tokio::test]
async fn a_named_device_keeps_that_name_as_its_routing_key() {
    let (addr, state) = start_relay("secret").await;
    let mut device = connect(addr).await;

    send(&mut device, &enroll_as("secret", "build-box")).await;
    let RelayMessage::Enrolled {
        device_id,
        public_url,
    } = recv(&mut device).await
    else {
        panic!("expected an enrolled message");
    };

    assert_eq!(device_id, "build-box");
    assert_eq!(
        public_url,
        format!("https://relay.test:{}/d/build-box", addr.port())
    );
    assert!(state.devices().get("build-box").is_some());
}

#[tokio::test]
async fn a_name_survives_a_reconnect() {
    let (addr, _state) = start_relay("secret").await;

    let mut first = connect(addr).await;
    send(&mut first, &enroll_as("secret", "build-box")).await;
    let RelayMessage::Enrolled { device_id: id1, .. } = recv(&mut first).await else {
        panic!("expected an enrolled message");
    };
    drop(first);

    // Reconnecting must land on the same URL — that is the whole point of a
    // name, and refusing here would lock the device out until the heartbeat
    // timeout expired.
    let mut second = connect(addr).await;
    send(&mut second, &enroll_as("secret", "build-box")).await;
    let RelayMessage::Enrolled { device_id: id2, .. } = recv(&mut second).await else {
        panic!("expected an enrolled message");
    };

    assert_eq!(
        id1, id2,
        "a named device must keep its URL across reconnects"
    );
}

#[tokio::test]
async fn an_unusable_device_name_is_refused() {
    let (addr, state) = start_relay("secret").await;

    for bad in ["../escape", "has space", "slash/inside", ""] {
        let mut device = connect(addr).await;
        send(&mut device, &enroll_as("secret", bad)).await;
        let RelayMessage::Rejected { code, .. } = recv(&mut device).await else {
            panic!("expected a rejection for {bad:?}");
        };
        assert_eq!(code, reject::BAD_DEVICE_NAME, "for {bad:?}");
    }
    assert_eq!(state.devices().count(), 0);
}

#[tokio::test]
async fn an_unnamed_device_still_gets_a_random_id() {
    let (addr, _state) = start_relay("secret").await;
    let mut device = connect(addr).await;

    send(&mut device, &enroll("secret")).await;
    let RelayMessage::Enrolled { device_id, .. } = recv(&mut device).await else {
        panic!("expected an enrolled message");
    };
    assert!(device_id.starts_with("st_"), "{device_id}");
}
