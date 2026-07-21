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

impl TlsFiles {
    /// Point at a certificate and key on disk.
    pub fn new(cert: impl Into<PathBuf>, key: impl Into<PathBuf>) -> Self {
        Self {
            cert: cert.into(),
            key: key.into(),
        }
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
