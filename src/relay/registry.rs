//! Which devices are attached, and the idle connections that reach them.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use axum::extract::ws::WebSocket;
use tokio::sync::mpsc;

/// How many idle data connections a device is asked to keep ready.
///
/// Pre-opened so a request does not pay a WebSocket handshake (2–3 RTT) before
/// it can be forwarded; small because each one is a real socket on both ends.
pub const POOL_TARGET: usize = 4;

/// A device attached to the relay.
///
/// Held behind an `Arc`: the control session, the pool, and every in-flight
/// request all refer to the same entry, and the data connections cannot be
/// cloned.
#[derive(Debug)]
pub struct Device {
    /// Relay-assigned identifier; also the routing key in `/d/<id>/…`.
    pub id: String,
    /// Optional label the device supplied, for operator-facing logs.
    pub label: Option<String>,
    attached_at: Instant,
    last_seen: Mutex<Instant>,
    exchanges: Mutex<Exchanges>,
    pool_tx: mpsc::Sender<WebSocket>,
    pool_rx: tokio::sync::Mutex<mpsc::Receiver<WebSocket>>,
    refill_tx: mpsc::Sender<()>,
}

/// How long this device has been taking to answer proxied requests.
///
/// **What one measurement covers, exactly**: from the moment the relay hands a
/// request to the device's socket to the moment it has finished reading the
/// answer. That is transfer time and the device's own processing *added
/// together*, and it does not come apart here — `send` returns as soon as the
/// socket buffer accepts the frame, so the relay never observes the two
/// separately. A number from this says how long the device took to answer, not
/// how fast the link to it is.
///
/// Waiting for a free connection from the pool is deliberately outside it: that
/// is the relay's own queueing, not the device's.
#[derive(Debug, Default, Clone, Copy)]
struct Exchanges {
    count: u64,
    total_ms: u64,
    last_ms: u64,
    slowest_ms: u64,
}

impl Device {
    /// Record how long one proxied exchange with this device took.
    pub fn record_exchange(&self, elapsed: Duration) {
        let ms = elapsed.as_millis().min(u64::MAX as u128) as u64;
        if let Ok(mut exchanges) = self.exchanges.lock() {
            exchanges.count = exchanges.count.saturating_add(1);
            exchanges.total_ms = exchanges.total_ms.saturating_add(ms);
            exchanges.last_ms = ms;
            exchanges.slowest_ms = exchanges.slowest_ms.max(ms);
        }
    }

    /// Whether the device has missed heartbeats for longer than `timeout`.
    pub fn is_stale(&self, timeout: Duration) -> bool {
        self.last_seen
            .lock()
            .map(|seen| seen.elapsed() > timeout)
            .unwrap_or(false)
    }

    /// Record that the device is alive.
    pub fn touch(&self) {
        if let Ok(mut seen) = self.last_seen.lock() {
            *seen = Instant::now();
        }
    }

    /// Offer a freshly opened data connection to the pool.
    ///
    /// Returns the connection back if the pool is full, so the caller can close
    /// it rather than leak it.
    pub async fn offer(&self, conn: WebSocket) -> Option<WebSocket> {
        match self.pool_tx.try_send(conn) {
            Ok(()) => None,
            Err(mpsc::error::TrySendError::Full(conn)) => Some(conn),
            Err(mpsc::error::TrySendError::Closed(conn)) => Some(conn),
        }
    }

    /// Take an idle data connection, waiting up to `timeout` for one.
    ///
    /// Asks the device to open a replacement first: the request that consumes a
    /// connection is exactly the event that makes the pool one short.
    pub async fn take(&self, timeout: Duration) -> Option<WebSocket> {
        let _ = self.refill_tx.try_send(());
        let mut rx = self.pool_rx.lock().await;
        tokio::time::timeout(timeout, rx.recv())
            .await
            .ok()
            .flatten()
    }
}

/// A point-in-time view of an attached device.
///
/// Separate from [`Device`] because a device owns its data connections and
/// therefore cannot be cloned or serialized; this is what an operator asking
/// "what is attached right now?" actually needs.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DeviceSummary {
    /// Routing key used in `/d/<id>/…`.
    pub id: String,
    /// Label the device supplied, if any.
    pub label: Option<String>,
    /// Seconds since the device attached.
    pub attached_secs: u64,
    /// Seconds since its last heartbeat.
    pub last_seen_secs: u64,
    /// Proxied exchanges measured so far, absent until there has been one.
    ///
    /// Absent rather than zero: a device nothing has called yet has no timing,
    /// and a `0` there reads as "answers instantly".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exchanges: Option<u64>,
    /// How long the most recent exchange took, in milliseconds.
    ///
    /// Transfer *and* the device's own processing together — see [`Exchanges`].
    /// Splitting them is not possible from the relay's side.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_exchange_ms: Option<u64>,
    /// Mean over every exchange since this device attached, in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mean_exchange_ms: Option<u64>,
    /// The slowest single exchange since this device attached, in milliseconds.
    ///
    /// Kept alongside the mean because the mean hides exactly the case an
    /// operator is looking for: an occasional very slow answer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slowest_exchange_ms: Option<u64>,
}

/// Handles handed to the control session that owns a device.
#[derive(Debug)]
pub struct DeviceHandles {
    /// The registered device.
    pub device: Arc<Device>,
    /// Fires whenever the pool wants another data connection.
    pub refill_rx: mpsc::Receiver<()>,
}

/// Thread-safe set of attached devices.
///
/// Mirrors [`crate::session::SessionStore`]: an `RwLock<HashMap<_, _>>` rather
/// than a concurrent-map dependency, since reads dominate and the map is small.
#[derive(Debug, Clone, Default)]
pub struct DeviceRegistry {
    devices: Arc<RwLock<HashMap<String, Arc<Device>>>>,
}

impl DeviceRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a device under `id`, replacing any previous entry for it.
    pub fn attach(&self, id: impl Into<String>, label: Option<String>) -> DeviceHandles {
        let id = id.into();
        let (pool_tx, pool_rx) = mpsc::channel(POOL_TARGET);
        let (refill_tx, refill_rx) = mpsc::channel(POOL_TARGET);

        let device = Arc::new(Device {
            id: id.clone(),
            label,
            attached_at: Instant::now(),
            last_seen: Mutex::new(Instant::now()),
            exchanges: Mutex::new(Exchanges::default()),
            pool_tx,
            pool_rx: tokio::sync::Mutex::new(pool_rx),
            refill_tx,
        });

        if let Ok(mut devices) = self.devices.write() {
            devices.insert(id, Arc::clone(&device));
        }
        DeviceHandles { device, refill_rx }
    }

    /// Detach a device, e.g. when its control connection closes.
    pub fn detach(&self, id: &str) -> bool {
        self.devices
            .write()
            .map(|mut devices| devices.remove(id).is_some())
            .unwrap_or(false)
    }

    /// Look up an attached device.
    pub fn get(&self, id: &str) -> Option<Arc<Device>> {
        Some(Arc::clone(self.devices.read().ok()?.get(id)?))
    }

    /// Record a heartbeat. Returns `false` if the device is not attached.
    pub fn touch(&self, id: &str) -> bool {
        match self.get(id) {
            Some(device) => {
                device.touch();
                true
            }
            None => false,
        }
    }

    /// Snapshot of every attached device, newest attachment first.
    pub fn list(&self) -> Vec<DeviceSummary> {
        let mut devices: Vec<DeviceSummary> = match self.devices.read() {
            Ok(devices) => devices
                .values()
                .map(|device| {
                    let measured = device
                        .exchanges
                        .lock()
                        .ok()
                        .map(|exchanges| *exchanges)
                        .filter(|exchanges| exchanges.count > 0);
                    DeviceSummary {
                        id: device.id.clone(),
                        label: device.label.clone(),
                        attached_secs: device.attached_at.elapsed().as_secs(),
                        last_seen_secs: device
                            .last_seen
                            .lock()
                            .map(|seen| seen.elapsed().as_secs())
                            .unwrap_or_default(),
                        exchanges: measured.map(|e| e.count),
                        last_exchange_ms: measured.map(|e| e.last_ms),
                        mean_exchange_ms: measured.map(|e| e.total_ms / e.count),
                        slowest_exchange_ms: measured.map(|e| e.slowest_ms),
                    }
                })
                .collect(),
            Err(_) => Vec::new(),
        };
        devices.sort_by_key(|device| device.attached_secs);
        devices
    }

    /// Number of attached devices.
    pub fn count(&self) -> usize {
        self.devices.read().map(|d| d.len()).unwrap_or(0)
    }

    /// Drop devices that have not been heard from within `timeout`.
    ///
    /// A half-open connection (the peer vanished without a close frame) is
    /// indistinguishable from an idle one at the socket level, so staleness is
    /// judged from heartbeats.
    pub fn evict_stale(&self, timeout: Duration) -> Vec<String> {
        let mut evicted = Vec::new();
        if let Ok(mut devices) = self.devices.write() {
            devices.retain(|id, device| {
                let keep = !device.is_stale(timeout);
                if !keep {
                    evicted.push(id.clone());
                }
                keep
            });
        }
        evicted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn attach_and_get() {
        let registry = DeviceRegistry::new();
        let handles = registry.attach("dev-1", Some("build-box".into()));

        assert_eq!(handles.device.id, "dev-1");
        assert_eq!(registry.count(), 1);
        assert_eq!(
            registry.get("dev-1").unwrap().label.as_deref(),
            Some("build-box")
        );
        assert!(registry.get("nope").is_none());
    }

    #[tokio::test]
    async fn detach_removes_the_device() {
        let registry = DeviceRegistry::new();
        registry.attach("dev-1", None);

        assert!(registry.detach("dev-1"));
        assert!(!registry.detach("dev-1"));
        assert_eq!(registry.count(), 0);
    }

    #[tokio::test]
    async fn touch_only_succeeds_for_attached_devices() {
        let registry = DeviceRegistry::new();
        registry.attach("dev-1", None);

        assert!(registry.touch("dev-1"));
        assert!(!registry.touch("dev-2"));
    }

    #[tokio::test]
    async fn stale_devices_are_evicted() {
        let registry = DeviceRegistry::new();
        registry.attach("fresh", None);

        // Zero timeout: everything already attached counts as stale.
        let evicted = registry.evict_stale(Duration::ZERO);
        assert_eq!(evicted, vec!["fresh".to_string()]);
        assert_eq!(registry.count(), 0);
    }

    #[tokio::test]
    async fn a_heartbeat_keeps_a_device_attached() {
        let registry = DeviceRegistry::new();
        registry.attach("dev-1", None);
        registry.touch("dev-1");

        assert!(registry.evict_stale(Duration::from_secs(60)).is_empty());
        assert_eq!(registry.count(), 1);
    }

    #[tokio::test]
    async fn reattaching_replaces_the_previous_entry() {
        let registry = DeviceRegistry::new();
        registry.attach("dev-1", Some("old".into()));
        registry.attach("dev-1", Some("new".into()));

        assert_eq!(registry.count(), 1);
        assert_eq!(registry.get("dev-1").unwrap().label.as_deref(), Some("new"));
    }

    #[tokio::test]
    async fn taking_from_an_empty_pool_times_out_and_asks_for_a_refill() {
        let registry = DeviceRegistry::new();
        let mut handles = registry.attach("dev-1", None);

        let taken = handles.device.take(Duration::from_millis(50)).await;
        assert!(taken.is_none(), "an empty pool must not hand out a socket");
        assert!(
            handles.refill_rx.try_recv().is_ok(),
            "the device should have been asked to open a connection"
        );
    }

    #[tokio::test]
    async fn listing_reports_attached_devices() {
        let registry = DeviceRegistry::new();
        registry.attach("dev-1", Some("build-box".into()));
        registry.attach("dev-2", None);

        let listed = registry.list();
        assert_eq!(listed.len(), 2);
        let first = listed.iter().find(|d| d.id == "dev-1").unwrap();
        assert_eq!(first.label.as_deref(), Some("build-box"));
        assert!(first.attached_secs < 5);
    }

    #[tokio::test]
    async fn listing_an_empty_registry_is_empty() {
        assert!(DeviceRegistry::new().list().is_empty());
    }

    #[tokio::test]
    async fn registry_is_shared_across_clones() {
        let registry = DeviceRegistry::new();
        let clone = registry.clone();
        clone.attach("dev-1", None);

        assert_eq!(registry.count(), 1);
    }
}
