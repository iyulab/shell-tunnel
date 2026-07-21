//! Wire protocol between a device and a relay.
//!
//! Messages are JSON text frames over one long-lived WebSocket ("control"
//! connection). The device always dials *out*, which is what makes a machine
//! behind NAT reachable without any inbound firewall change.
//!
//! Scope discipline: the relay decides only whether a device may attach and
//! where its traffic goes. It never inspects or stores the `Authorization`
//! header of proxied requests — capability tokens stay end-to-end between the
//! client and the device, so attaching a relay does not widen the trust
//! boundary.

use serde::{Deserialize, Serialize};

/// Protocol version. Bumped only on a breaking change to these messages.
pub const PROTOCOL_VERSION: u32 = 1;

/// Device → relay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DeviceMessage {
    /// First message: ask to attach to this relay.
    Enroll {
        /// Shared secret proving the device may attach.
        enroll_token: String,
        /// Protocol version the device speaks.
        version: u32,
        /// Free-form label to make the device recognisable in relay logs.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
        /// Requested stable identifier, becoming this device's routing key.
        ///
        /// Without it the relay assigns a random id, which changes on every
        /// reconnect — fine when whoever calls the device can read its console,
        /// useless when they cannot. A name keeps one URL valid across restarts.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_name: Option<String>,
    },
    /// First frame on a *data* connection: claim a slot in a device's pool.
    ///
    /// The secret travels in the frame body, never in the URL. Query strings are
    /// written to access logs by default by the reverse proxies this relay is
    /// meant to sit behind, so a token in the URL would end up on disk in
    /// plaintext on every deployment that follows our own TLS advice.
    Attach {
        /// Which device's pool this connection joins.
        device_id: String,
        /// Same secret the control channel presented.
        enroll_token: String,
    },
    /// Liveness heartbeat.
    ///
    /// Sent by the device rather than relied upon from the transport: a proxy
    /// or load balancer between the two closes idle connections (60s is the
    /// common default), and tungstenite answers pings but never originates
    /// them.
    Heartbeat,
}

/// Relay → device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayMessage {
    /// Enrollment accepted.
    Enrolled {
        /// Identifier the relay assigned. Relay-generated, never device-chosen,
        /// so one device cannot claim or guess another's address.
        device_id: String,
        /// Public URL prefix that now routes to this device.
        public_url: String,
    },
    /// Enrollment refused; the connection closes afterwards.
    Rejected {
        /// Machine-readable reason (`bad-token`, `unsupported-version`).
        code: String,
        /// Human-readable detail.
        message: String,
    },
    /// Heartbeat acknowledgement.
    HeartbeatAck,
    /// Open `count` more data connections.
    ///
    /// Sent when the pool is short: at enrollment (to fill it) and whenever a
    /// request consumes a connection. The device dials out for each one, so the
    /// relay can ask but never initiate.
    OpenData {
        /// How many connections to open.
        count: usize,
    },
}

/// Reason codes used in [`RelayMessage::Rejected`].
pub mod reject {
    /// The enrollment token did not match.
    pub const BAD_TOKEN: &str = "bad-token";
    /// The device speaks a protocol version this relay does not support.
    pub const UNSUPPORTED_VERSION: &str = "unsupported-version";
    /// The first frame was not a valid enrollment.
    pub const BAD_HANDSHAKE: &str = "bad-handshake";
    /// The requested device name cannot be used as a routing key.
    pub const BAD_DEVICE_NAME: &str = "bad-device-name";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enroll_roundtrips() {
        let msg = DeviceMessage::Enroll {
            enroll_token: "secret".into(),
            version: PROTOCOL_VERSION,
            label: Some("build-box".into()),
            device_name: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"enroll\""));
        assert_eq!(serde_json::from_str::<DeviceMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn label_is_optional() {
        let json = r#"{"type":"enroll","enroll_token":"s","version":1}"#;
        let msg: DeviceMessage = serde_json::from_str(json).unwrap();
        assert_eq!(
            msg,
            DeviceMessage::Enroll {
                enroll_token: "s".into(),
                version: 1,
                label: None,
                device_name: None,
            }
        );
    }

    #[test]
    fn relay_messages_roundtrip() {
        for msg in [
            RelayMessage::Enrolled {
                device_id: "d-1".into(),
                public_url: "https://relay.example/d/d-1".into(),
            },
            RelayMessage::Rejected {
                code: reject::BAD_TOKEN.into(),
                message: "no".into(),
            },
            RelayMessage::HeartbeatAck,
            RelayMessage::OpenData { count: 4 },
        ] {
            let json = serde_json::to_string(&msg).unwrap();
            assert_eq!(serde_json::from_str::<RelayMessage>(&json).unwrap(), msg);
        }
    }

    #[test]
    fn a_requested_device_name_survives_the_wire() {
        let msg = DeviceMessage::Enroll {
            enroll_token: "s".into(),
            version: PROTOCOL_VERSION,
            label: None,
            device_name: Some("build-box".into()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<DeviceMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn attach_roundtrips() {
        let msg = DeviceMessage::Attach {
            device_id: "dev-1".into(),
            enroll_token: "secret".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"attach\""));
        assert_eq!(serde_json::from_str::<DeviceMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn unknown_message_types_are_rejected() {
        // A future message type must not silently deserialize as something else.
        assert!(serde_json::from_str::<DeviceMessage>(r#"{"type":"teleport"}"#).is_err());
    }
}
