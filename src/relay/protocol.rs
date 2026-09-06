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
    /// Ask the relay to forward a direct-connect request to another attached
    /// device.
    ///
    /// Only meaningful between two devices — an ordinary HTTP caller has no
    /// control channel to receive the forwarded request on. The relay does
    /// not require anything special of `target`; if it is not attached, the
    /// sender gets `RelayMessage::DirectUnavailable` back.
    RequestDirect {
        /// Device id of the peer to attempt a direct connection to.
        target: String,
    },
    /// Tell the relay this device is ready to be connected to directly by
    /// `to`, in response to a `RelayMessage::DirectRequested`.
    ///
    /// The relay does not track which devices have an outstanding
    /// `RequestDirect`: it does not remember who asked whom, so any attached
    /// device may send this at any time and `to` receives `PeerReady`
    /// regardless of whether it ever sent a matching `RequestDirect`. Not a
    /// privilege issue — every attached device already shares the enrollment
    /// secret — but a future consumer must not assume request/response
    /// pairing is enforced by the relay.
    DirectReady {
        /// Device id of the peer that requested this direct connection.
        to: String,
        /// SHA-256 fingerprint of the self-signed certificate this device will
        /// present on the direct socket, so `to` can pin it before dialling.
        ///
        /// `None` only when this device predates Phase 3 direct-connect and has
        /// no certificate to offer — a relay carrying that absence through must
        /// never be read as "connect anyway": the requester's only correct
        /// response to a missing fingerprint is to skip the direct attempt and
        /// stay on the relay path (see `RelayMessage::PeerReady`'s doc comment).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fingerprint: Option<String>,
    },
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
        /// This device's address as the relay observed it on the control
        /// connection's TCP socket — a STUN-style reflexive address. The NAT
        /// mapping it names was created *toward the relay*, not toward a
        /// future peer, so it is a hint a direct-connect attempt starts from,
        /// not a guarantee a peer can reach it. `None` when talking to a
        /// relay that predates this field — the absence is itself
        /// information (no hint available), which is why this is `Option`
        /// rather than defaulting to an empty string.
        ///
        /// Behind this relay's own documented reverse-proxy TLS-termination
        /// deployment mode (see `observed_base()` in `mod.rs`), the address
        /// this relay observes is the proxy's own address, not a usable STUN
        /// hint for a real peer — the connection info axum sees is the
        /// proxy's socket, not the device's. This field can be structurally
        /// useless in that deployment mode, and a later phase building a
        /// direct-connect attempt on top of it needs to account for that.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reflexive_addr: Option<String>,
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
    /// Another device asked to connect to this one directly.
    DirectRequested {
        /// Device id of the peer that wants to connect directly.
        from: String,
        /// That peer's address, as the relay observed it on its own control
        /// connection — never self-reported by the peer.
        from_addr: String,
    },
    /// A `RequestDirect` could not be forwarded.
    DirectUnavailable {
        /// Device id that was requested.
        target: String,
        /// Why the request could not be forwarded. One of the constants in
        /// [`direct_unavailable`].
        reason: String,
    },
    /// The peer this device asked to reach is ready.
    PeerReady {
        /// Device id of the peer that is ready.
        from: String,
        /// That peer's address, as the relay observed it on its own control
        /// connection — never self-reported by the peer.
        from_addr: String,
        /// Carried straight from the peer's `DeviceMessage::DirectReady` —
        /// the relay does not generate or inspect this value.
        ///
        /// `None` means either the peer predates this field or an
        /// intermediate relay in the path dropped it on re-serialize (an old
        /// relay's `RelayMessage` has no such variant field to carry it).
        /// Either way, **the receiver must treat a missing fingerprint as "do
        /// not attempt direct" and go straight to the relay path** — nothing
        /// here should ever open a direct socket it cannot pin.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fingerprint: Option<String>,
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

/// Reason codes used in [`RelayMessage::DirectUnavailable`].
pub mod direct_unavailable {
    /// The requested target device is not attached.
    pub const NO_SUCH_DEVICE: &str = "no-such-device";
    /// The target's control session could not accept the signal right now.
    pub const PEER_BUSY: &str = "peer-busy";
    /// The target's control session ended before the signal was delivered.
    pub const PEER_GONE: &str = "peer-gone";
    /// A device asked to connect directly to itself.
    pub const SELF_TARGET: &str = "self-target";
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
                reflexive_addr: Some("203.0.113.5:51820".into()),
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
    fn an_old_relays_enrolled_message_has_no_reflexive_addr() {
        // A relay that predates this field omits it entirely; a new device
        // must still be able to enroll against it rather than hard-failing
        // deserialization on a missing field.
        let json =
            r#"{"type":"enrolled","device_id":"d-1","public_url":"https://relay.example/d/d-1"}"#;
        let msg: RelayMessage = serde_json::from_str(json).unwrap();
        assert_eq!(
            msg,
            RelayMessage::Enrolled {
                device_id: "d-1".into(),
                public_url: "https://relay.example/d/d-1".into(),
                reflexive_addr: None,
            }
        );
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

    #[test]
    fn request_direct_roundtrips() {
        let msg = DeviceMessage::RequestDirect {
            target: "device-b".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"request_direct\""));
        assert_eq!(serde_json::from_str::<DeviceMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn direct_ready_roundtrips() {
        let msg = DeviceMessage::DirectReady {
            to: "device-a".into(),
            fingerprint: Some("aa:bb:cc".into()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"direct_ready\""));
        assert_eq!(serde_json::from_str::<DeviceMessage>(&json).unwrap(), msg);
    }

    #[test]
    fn direct_ready_without_a_fingerprint_deserializes_as_none() {
        // A pre-Phase-3 device's `direct_ready` carries no such field at all.
        let json = r#"{"type":"direct_ready","to":"device-a"}"#;
        let msg: DeviceMessage = serde_json::from_str(json).unwrap();
        assert_eq!(
            msg,
            DeviceMessage::DirectReady {
                to: "device-a".into(),
                fingerprint: None,
            }
        );
    }

    #[test]
    fn direct_connect_relay_messages_roundtrip() {
        for msg in [
            RelayMessage::DirectRequested {
                from: "device-a".into(),
                from_addr: "203.0.113.5:51820".into(),
            },
            RelayMessage::DirectUnavailable {
                target: "ghost".into(),
                reason: "no such device".into(),
            },
            RelayMessage::PeerReady {
                from: "device-b".into(),
                from_addr: "203.0.113.9:41230".into(),
                fingerprint: Some("dd:ee:ff".into()),
            },
        ] {
            let json = serde_json::to_string(&msg).unwrap();
            assert_eq!(serde_json::from_str::<RelayMessage>(&json).unwrap(), msg);
        }
    }

    #[test]
    fn peer_ready_without_a_fingerprint_deserializes_as_none() {
        // An old relay's `RelayMessage::PeerReady` predates this field and
        // drops it on re-serialize even if the originating device sent one.
        let json = r#"{"type":"peer_ready","from":"device-b","from_addr":"203.0.113.9:41230"}"#;
        let msg: RelayMessage = serde_json::from_str(json).unwrap();
        assert_eq!(
            msg,
            RelayMessage::PeerReady {
                from: "device-b".into(),
                from_addr: "203.0.113.9:41230".into(),
                fingerprint: None,
            }
        );
    }
}
