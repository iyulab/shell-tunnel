//! The relay serving HTTPS on its own, with no reverse proxy in front.
//!
//! Certificates are generated per test rather than committed, so nothing here
//! depends on a fixture key living in the repository.

#![cfg(feature = "tls")]

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use tokio::net::TcpListener;

use shell_tunnel::relay::{relay_router, RelayConfig, RelayState};
use shell_tunnel::tls::TlsFiles;

/// Write a self-signed certificate for `localhost`, returning its paths and the
/// DER bytes a client needs in order to trust it.
fn self_signed(dir: &Path) -> (TlsFiles, Vec<u8>) {
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, issued.cert.pem()).unwrap();
    std::fs::write(&key_path, issued.signing_key.serialize_pem()).unwrap();
    (
        TlsFiles::new(cert_path, key_path),
        issued.cert.der().to_vec(),
    )
}

/// Start a relay that terminates TLS itself.
async fn start_tls_relay(dir: &Path) -> (SocketAddr, Vec<u8>) {
    let (files, cert_der) = self_signed(dir);

    // Bind first so the test knows the port, then hand the listener over.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let config = RelayConfig::new(addr, "secret").with_tls(files.clone());
    let service =
        relay_router(RelayState::new(config)).into_make_service_with_connect_info::<SocketAddr>();
    let rustls_config = shell_tunnel::tls::acceptor(files.load().expect("certificate should load"));

    let std_listener = listener.into_std().unwrap();
    tokio::spawn(async move {
        axum_server::from_tcp_rustls(std_listener, rustls_config)
            .unwrap()
            .serve(service)
            .await
            .unwrap();
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    (addr, cert_der)
}

/// A TLS client that trusts exactly the certificate we just generated.
fn client_config(cert_der: Vec<u8>) -> tokio_rustls::rustls::ClientConfig {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    roots.add(cert_der.into()).unwrap();

    tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

#[tokio::test]
async fn the_relay_serves_https_without_a_proxy() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = tempfile::tempdir().unwrap();
    let (addr, cert_der) = start_tls_relay(dir.path()).await;

    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config(cert_der)));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut tls = connector
        .connect("localhost".try_into().unwrap(), tcp)
        .await
        .expect("the handshake should complete against our own certificate");

    tls.write_all(
        format!(
            "GET /health HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
            addr.port()
        )
        .as_bytes(),
    )
    .await
    .unwrap();

    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), tls.read_to_end(&mut raw))
        .await
        .expect("the relay should answer over TLS")
        .unwrap();

    let text = String::from_utf8_lossy(&raw);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.trim_end().ends_with("OK"), "{text}");
}

#[tokio::test]
async fn plaintext_is_refused_once_tls_is_on() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = tempfile::tempdir().unwrap();
    let (addr, _cert) = start_tls_relay(dir.path()).await;

    // Speaking HTTP to an HTTPS port must not accidentally work: a caller that
    // forgot the scheme should fail loudly rather than send a token in clear.
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tcp.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut raw)).await;

    let text = String::from_utf8_lossy(&raw);
    assert!(
        !text.starts_with("HTTP/1.1 200"),
        "plaintext must not be served on a TLS port: {text}"
    );
}

#[tokio::test]
async fn a_device_attaches_over_wss() {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    use shell_tunnel::relay::protocol::{DeviceMessage, RelayMessage, PROTOCOL_VERSION};

    let dir = tempfile::tempdir().unwrap();
    let (addr, cert_der) = start_tls_relay(dir.path()).await;

    let connector =
        tokio_tungstenite::Connector::Rustls(std::sync::Arc::new(client_config(cert_der)));
    let (mut socket, _) = tokio_tungstenite::connect_async_tls_with_config(
        format!("wss://localhost:{}/relay/v1/control", addr.port()),
        None,
        false,
        Some(connector),
    )
    .await
    .expect("the control channel should upgrade over TLS");

    let enroll = DeviceMessage::Enroll {
        enroll_token: "secret".to_string(),
        version: PROTOCOL_VERSION,
        label: None,
        device_name: Some("tls-box".to_string()),
    };
    socket
        .send(Message::Text(serde_json::to_string(&enroll).unwrap()))
        .await
        .unwrap();

    use futures_util::StreamExt;
    let reply = loop {
        let message = tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("the relay should answer")
            .expect("stream open")
            .expect("frame readable");
        if let Message::Text(text) = message {
            break serde_json::from_str::<RelayMessage>(&text).unwrap();
        }
    };

    let RelayMessage::Enrolled { device_id, .. } = reply else {
        panic!("expected an enrolled message, got {reply:?}");
    };
    assert_eq!(device_id, "tls-box");
}
