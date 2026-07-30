//! Forwarding public requests down a device's data connection.
//!
//! One in-flight request owns one data connection for its lifetime. That is the
//! whole reason this relay needs no stream multiplexer: with a connection per
//! request there are no interleaved streams to demultiplex, so there is no
//! framing format of our own to design, version, and defend. The cost — a pool
//! of idle connections to keep refilled — is the same trade frp makes with
//! `pool_count`, and it is bounded work rather than a protocol.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// How long a request waits for a free data connection before giving up.
pub const POOL_WAIT: Duration = Duration::from_secs(5);

/// How long a proxied request may take before the relay gives up on the device.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Request metadata sent to the device ahead of the body.
///
/// Sent once per connection rather than per frame: this is a header, not a
/// multiplexing envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyRequest {
    /// HTTP method.
    pub method: String,
    /// Path and query, relative to the device's local server.
    pub path: String,
    /// Headers to replay, including `Authorization` — which the relay forwards
    /// verbatim and never inspects.
    pub headers: Vec<(String, String)>,
    /// Whether this is a WebSocket upgrade.
    ///
    /// Carried as a field rather than as `Upgrade`/`Connection` headers: those
    /// are hop-by-hop and describe the *client's* connection to the relay, so
    /// replaying them would contradict the filtering everything else goes
    /// through. The device performs its own local handshake instead.
    #[serde(default)]
    pub websocket: bool,
}

/// Response metadata returned by the device ahead of the body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers.
    pub headers: Vec<(String, String)>,
}

/// Headers that must not be replayed onto the device's local request.
///
/// Hop-by-hop headers describe *this* connection, not the message; forwarding
/// them makes the device answer about a connection it is not part of.
///
/// `expect` is here for the same reason, and it is not merely tidy — leaving it
/// in produced a 500 for every body-carrying request a normal client made.
/// The relay buffers the entire body before it forwards anything (see
/// `MAX_BODY`), so by the time the device sees the request the expectation has
/// already been met: there is nothing left for the device to decide. Replaying
/// `Expect: 100-continue` onto the device's own local HTTP call instead made
/// that server answer with an interim `100 Continue`, which the device
/// reported back as the response, which the relay then tried to return as a
/// final status — and hyper cannot write a 1xx as a final response, so it
/// substituted an empty `500`.
///
/// The request itself always succeeded. The device ran the command or wrote the
/// chunk and answered 200; only the status the caller saw was wrong, which is
/// the worst way for this to fail — a non-idempotent `execute` reported as
/// failed after it had already run. `curl` adds this header automatically for
/// bodies over about a kilobyte, so every upload chunk tripped it while small
/// `execute` payloads did not, which is why it stayed hidden until the file
/// API made large bodies ordinary.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "expect",
];

/// Whether a header may be forwarded across the relay boundary.
pub fn is_forwardable(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    !HOP_BY_HOP.contains(&name.as_str())
}

/// Strip the `/d/<device-id>` prefix, returning the device id and the remainder.
///
/// The remainder always starts with `/` so it can be appended to the device's
/// local base URL unchanged.
pub fn split_device_path(path: &str) -> Option<(&str, String)> {
    let rest = path.strip_prefix("/d/")?;
    let (device_id, tail) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    };
    if device_id.is_empty() {
        return None;
    }
    let tail = if tail.is_empty() { "/" } else { tail };
    Some((device_id, tail.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_path_is_split_from_the_remainder() {
        assert_eq!(
            split_device_path("/d/dev-1/api/v1/execute"),
            Some(("dev-1", "/api/v1/execute".to_string()))
        );
    }

    #[test]
    fn a_bare_device_path_maps_to_the_root() {
        assert_eq!(
            split_device_path("/d/dev-1"),
            Some(("dev-1", "/".to_string()))
        );
        assert_eq!(
            split_device_path("/d/dev-1/"),
            Some(("dev-1", "/".to_string()))
        );
    }

    #[test]
    fn non_device_paths_are_rejected() {
        assert!(split_device_path("/health").is_none());
        assert!(split_device_path("/d/").is_none());
        assert!(split_device_path("/api/v1/execute").is_none());
    }

    #[test]
    fn the_websocket_flag_defaults_to_false_for_older_peers() {
        let json = r#"{"method":"GET","path":"/","headers":[]}"#;
        let request: ProxyRequest = serde_json::from_str(json).unwrap();
        assert!(!request.websocket);
    }

    #[test]
    fn hop_by_hop_headers_are_not_forwarded() {
        assert!(!is_forwardable("Connection"));
        assert!(!is_forwardable("transfer-encoding"));
        assert!(!is_forwardable("Host"));
    }

    #[test]
    fn end_to_end_headers_are_forwarded() {
        // Authorization in particular: the relay is a router, and the capability
        // token has to reach the device unchanged.
        assert!(is_forwardable("Authorization"));
        assert!(is_forwardable("content-type"));
    }

    #[test]
    fn proxy_messages_roundtrip() {
        let request = ProxyRequest {
            method: "POST".into(),
            path: "/api/v1/execute".into(),
            headers: vec![("authorization".into(), "Bearer st_x".into())],
            websocket: false,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(
            serde_json::from_str::<ProxyRequest>(&json).unwrap(),
            request
        );

        let response = ProxyResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(
            serde_json::from_str::<ProxyResponse>(&json).unwrap(),
            response
        );
    }
}
