//! Terminating TLS in-process.
//!
//! Compiled only with the `tls` feature. Without it the binary links no TLS
//! server stack, and an operator fronts it with a reverse proxy instead — which
//! is a perfectly good answer, just not the only one. With it, a relay on a
//! public address can serve HTTPS on its own, and the secrets that travel over
//! that connection (enrolment tokens, capability tokens) stop being readable by
//! anyone on the path.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::ServerConfig;

use crate::error::ShellTunnelError;
use crate::Result;

/// Where to find the certificate chain and private key.
#[derive(Debug, Clone)]
pub struct TlsFiles {
    /// PEM certificate chain, leaf first.
    pub cert: PathBuf,
    /// PEM private key (PKCS#8, PKCS#1, or SEC1).
    pub key: PathBuf,
}

/// Default certificate path when the operator names none.
pub const DEFAULT_CERT: &str = "shell-tunnel-cert.pem";

/// Default private key path when the operator names none.
pub const DEFAULT_KEY: &str = "shell-tunnel-key.pem";

impl TlsFiles {
    /// Point at a certificate and key on disk.
    pub fn new(cert: impl Into<PathBuf>, key: impl Into<PathBuf>) -> Self {
        Self {
            cert: cert.into(),
            key: key.into(),
        }
    }

    /// The conventional paths, so `--tls-self-signed` needs no arguments.
    pub fn default_paths() -> Self {
        Self::new(DEFAULT_CERT, DEFAULT_KEY)
    }

    /// Whether both files already exist.
    pub fn exist(&self) -> bool {
        self.cert.exists() && self.key.exists()
    }

    /// Write a self-signed certificate for `names`, unless one is already here.
    ///
    /// Reuse is the point of checking first: a relay that minted a fresh
    /// certificate on every restart would invalidate the trust every device was
    /// configured with, turning a restart into a fleet-wide reconfiguration.
    ///
    /// Returns whether a certificate was generated, so the caller can tell an
    /// operator what just happened.
    pub fn ensure_self_signed(&self, names: &[String]) -> Result<bool> {
        if self.exist() {
            return Ok(false);
        }
        if names.is_empty() {
            return Err(ShellTunnelError::Tls(
                "a self-signed certificate needs at least one name to be valid for".to_string(),
            ));
        }

        let issued = rcgen::generate_simple_self_signed(names.to_vec())
            .map_err(|e| ShellTunnelError::Tls(format!("cannot generate a certificate: {e}")))?;

        write_new(&self.cert, issued.cert.pem().as_bytes())?;
        // Written after the certificate and with restricted permissions where
        // the platform has them: a private key readable by every local account
        // is the kind of default that is discovered much later.
        write_new(&self.key, issued.signing_key.serialize_pem().as_bytes())?;
        restrict(&self.key);

        Ok(true)
    }

    /// The SHA-256 fingerprint of the certificate on disk.
    pub fn fingerprint(&self) -> Result<String> {
        let certs = read_certs(&self.cert)?;
        let leaf = certs
            .first()
            .ok_or_else(|| ShellTunnelError::Tls("certificate file is empty".to_string()))?;
        Ok(crate::fingerprint::of_certificate(leaf.as_ref()))
    }

    /// Load them into a server configuration.
    pub fn load(&self) -> Result<ServerConfig> {
        install_crypto_provider();

        let certs = read_certs(&self.cert)?;
        let key = read_key(&self.key)?;

        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| ShellTunnelError::Tls(format!("certificate and key do not match: {e}")))
    }
}

/// Write a file that must not already exist, creating parent directories.
fn write_new(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                ShellTunnelError::Tls(format!("cannot create {}: {e}", parent.display()))
            })?;
        }
    }
    std::fs::write(path, contents)
        .map_err(|e| ShellTunnelError::Tls(format!("cannot write {}: {e}", path.display())))
}

/// Restrict a private key to its owner, where the platform expresses that.
fn restrict(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Names a generated certificate should be valid for.
///
/// A certificate is only useful at the address devices actually dial, so the
/// public base — when the operator stated one — matters more than anything this
/// machine knows about itself.
pub fn certificate_names(public_base: Option<&str>, bind: std::net::SocketAddr) -> Vec<String> {
    let mut names = Vec::new();

    if let Some(base) = public_base {
        let after_scheme = base.split_once("://").map_or(base, |(_, rest)| rest);
        if let Some(host) = after_scheme
            .split('/')
            .next()
            .map(|host| host.rsplit_once(':').map_or(host, |(h, _)| h))
        {
            if !host.is_empty() {
                names.push(host.to_string());
            }
        }
    }

    if let Ok(hostname) = std::env::var(if cfg!(windows) {
        "COMPUTERNAME"
    } else {
        "HOSTNAME"
    }) {
        let hostname = hostname.trim();
        if !hostname.is_empty() && !names.iter().any(|n| n == hostname) {
            names.push(hostname.to_string());
        }
    }

    if !bind.ip().is_unspecified() {
        let ip = bind.ip().to_string();
        if !names.contains(&ip) {
            names.push(ip);
        }
    }

    // Always usable from the machine itself, which is where an operator checks
    // first.
    for fallback in ["localhost", "127.0.0.1"] {
        if !names.iter().any(|n| n == fallback) {
            names.push(fallback.to_string());
        }
    }

    names
}

/// Select the TLS backend once, before any handshake.
///
/// rustls 0.23 will not choose a provider implicitly; without this the first
/// connection panics inside the library rather than returning an error.
fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // An error here means a provider was already installed, which is fine.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Read a PEM certificate chain.
fn read_certs(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let pem = std::fs::read(path).map_err(|e| {
        ShellTunnelError::Tls(format!("cannot read certificate {}: {e}", path.display()))
    })?;

    let certs: std::result::Result<Vec<_>, _> =
        rustls_pemfile::certs(&mut pem.as_slice()).collect();
    let certs = certs.map_err(|e| {
        ShellTunnelError::Tls(format!("{} is not a PEM certificate: {e}", path.display()))
    })?;

    if certs.is_empty() {
        return Err(ShellTunnelError::Tls(format!(
            "{} contains no certificate",
            path.display()
        )));
    }
    Ok(certs)
}

/// Read a PEM private key, accepting the three encodings in common use.
fn read_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let pem = std::fs::read(path)
        .map_err(|e| ShellTunnelError::Tls(format!("cannot read key {}: {e}", path.display())))?;

    rustls_pemfile::private_key(&mut pem.as_slice())
        .map_err(|e| ShellTunnelError::Tls(format!("{} is not a PEM key: {e}", path.display())))?
        .ok_or_else(|| ShellTunnelError::Tls(format!("{} contains no private key", path.display())))
}

/// Turn a loaded configuration into an acceptor for `axum-server`.
pub fn acceptor(config: ServerConfig) -> axum_server::tls_rustls::RustlsConfig {
    axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(config))
}

/// How often the certificate files are checked for replacement.
const RELOAD_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Watch `files` and hand new certificates to `acceptor` as they appear.
///
/// Certificates expire, and the ones that expire soonest are renewed most often
/// — a server that needs restarting for each renewal turns routine maintenance
/// into downtime. Existing connections keep the certificate they started with;
/// new handshakes get the new one.
///
/// Polling rather than filesystem notification: renewal tools replace files by
/// rename, atomic writes look different on every platform, and a minute of
/// staleness costs nothing against a certificate measured in weeks.
pub fn watch(files: TlsFiles, acceptor: axum_server::tls_rustls::RustlsConfig) {
    tokio::spawn(async move {
        let mut last = modified_at(&files);

        loop {
            tokio::time::sleep(RELOAD_INTERVAL).await;

            let current = modified_at(&files);
            if current == last {
                continue;
            }
            last = current;

            // A half-written file mid-renewal parses as garbage; keeping the
            // previous certificate is better than serving none, and the next
            // poll picks it up once the writer finishes.
            match files.load() {
                Ok(config) => {
                    acceptor.reload_from_config(Arc::new(config));
                    tracing::info!(target: "tls", "reloaded {}", files.cert.display());
                }
                Err(e) => {
                    tracing::warn!(target: "tls", "keeping the previous certificate: {e}");
                }
            }
        }
    });
}

/// Modification times of both files, as the change signal.
fn modified_at(files: &TlsFiles) -> (Option<std::time::SystemTime>, Option<std::time::SystemTime>) {
    let stamp = |path: &Path| std::fs::metadata(path).and_then(|m| m.modified()).ok();
    (stamp(&files.cert), stamp(&files.key))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write a self-signed certificate and key, returning their paths.
    fn self_signed(dir: &Path) -> TlsFiles {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();
        TlsFiles::new(cert_path, key_path)
    }

    #[test]
    fn a_generated_certificate_is_immediately_usable() {
        let dir = tempfile::tempdir().unwrap();
        let files = TlsFiles::new(dir.path().join("c.pem"), dir.path().join("k.pem"));

        assert!(files
            .ensure_self_signed(&["localhost".to_string()])
            .unwrap());
        assert!(files.exist());
        // Generating something that then fails to load would be worse than not
        // generating at all.
        assert!(files.load().is_ok());
    }

    #[test]
    fn an_existing_certificate_is_reused_not_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let files = TlsFiles::new(dir.path().join("c.pem"), dir.path().join("k.pem"));
        files
            .ensure_self_signed(&["localhost".to_string()])
            .unwrap();
        let original = std::fs::read_to_string(&files.cert).unwrap();

        // A restart must not invalidate the trust every device was configured
        // with, which is what minting a fresh certificate each time would do.
        assert!(!files
            .ensure_self_signed(&["localhost".to_string()])
            .unwrap());
        assert_eq!(original, std::fs::read_to_string(&files.cert).unwrap());
    }

    #[test]
    fn generating_creates_missing_directories() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("deep").join("deeper");
        let files = TlsFiles::new(nested.join("c.pem"), nested.join("k.pem"));

        files
            .ensure_self_signed(&["localhost".to_string()])
            .unwrap();
        assert!(files.load().is_ok());
    }

    #[test]
    fn a_certificate_needs_a_name() {
        let dir = tempfile::tempdir().unwrap();
        let files = TlsFiles::new(dir.path().join("c.pem"), dir.path().join("k.pem"));
        let err = files.ensure_self_signed(&[]).unwrap_err().to_string();
        assert!(err.contains("at least one name"), "{err}");
    }

    #[test]
    fn the_public_base_is_the_first_name_a_certificate_gets() {
        let bind = "0.0.0.0:8443".parse().unwrap();
        let names = certificate_names(Some("https://relay.example.com:8443"), bind);

        // Devices dial the public base, so a certificate that is not valid for
        // it is valid for nothing that matters.
        assert_eq!(names.first().map(String::as_str), Some("relay.example.com"));
        assert!(names.iter().any(|n| n == "localhost"));
    }

    #[test]
    fn without_a_public_base_the_local_names_still_work() {
        let bind = "192.0.2.10:8443".parse().unwrap();
        let names = certificate_names(None, bind);

        assert!(names.iter().any(|n| n == "192.0.2.10"), "{names:?}");
        assert!(names.iter().any(|n| n == "127.0.0.1"), "{names:?}");
    }

    #[test]
    fn a_wildcard_bind_contributes_no_address() {
        let bind = "0.0.0.0:8443".parse().unwrap();
        let names = certificate_names(None, bind);
        // `0.0.0.0` is not an address anyone dials.
        assert!(!names.iter().any(|n| n == "0.0.0.0"), "{names:?}");
    }

    #[test]
    fn a_certificate_and_key_pair_loads() {
        let dir = tempfile::tempdir().unwrap();
        let files = self_signed(dir.path());
        assert!(files.load().is_ok());
    }

    #[test]
    fn a_missing_file_names_itself() {
        let files = TlsFiles::new("nope-cert.pem", "nope-key.pem");
        let err = files.load().unwrap_err().to_string();
        // The operator has to be told *which* path failed, not just "TLS error".
        assert!(err.contains("nope-cert.pem"), "{err}");
    }

    #[test]
    fn a_non_pem_file_is_reported_as_such() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("garbage.pem");
        std::fs::write(&cert_path, b"this is not a certificate").unwrap();

        let files = TlsFiles::new(&cert_path, &cert_path);
        let err = files.load().unwrap_err().to_string();
        assert!(err.contains("no certificate"), "{err}");
    }

    #[test]
    fn replacing_a_certificate_changes_the_modification_signal() {
        let dir = tempfile::tempdir().unwrap();
        let files = self_signed(dir.path());
        let before = modified_at(&files);

        // Filesystem timestamps are coarse on some platforms, so make the write
        // unambiguous rather than relying on sub-millisecond resolution.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let replacement =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        std::fs::write(&files.cert, replacement.cert.pem()).unwrap();
        std::fs::write(&files.key, replacement.signing_key.serialize_pem()).unwrap();

        assert_ne!(before, modified_at(&files), "a replacement must be noticed");
        assert!(files.load().is_ok(), "the replacement should load");
    }

    #[test]
    fn a_missing_file_reports_no_timestamp_rather_than_panicking() {
        // Mid-renewal the file can be absent for an instant; the watcher must
        // survive that rather than taking the server down.
        let files = TlsFiles::new("no-such-cert.pem", "no-such-key.pem");
        assert_eq!(modified_at(&files), (None, None));
    }

    #[test]
    fn a_mismatched_key_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let first = self_signed(dir.path());

        let second_dir = tempfile::tempdir().unwrap();
        let second = self_signed(second_dir.path());

        // A cert with someone else's key would fail at handshake time; catching
        // it at startup is the difference between "refused to start" and
        // "started and then refused every connection".
        let mixed = TlsFiles::new(&first.cert, &second.key);
        let err = mixed.load().unwrap_err().to_string();
        assert!(err.contains("do not match"), "{err}");
    }
}
