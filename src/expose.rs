//! Exposed services: HTTP services on this machine's loopback that the device's
//! owner names at startup, reachable through this server under the same
//! authorization, audit trail and relay path as everything else it serves.
//!
//! A machine reachable only through this server — behind NAT, through a relay —
//! has no other way in for an inference API, a notebook or a dashboard running
//! beside it, and the usual workarounds (a second tunnel, a port forward) sit
//! outside both the authorization and the audit trail. `--expose name=url`
//! puts one such service at `/x/<name>/…`.
//!
//! Three properties carry the design:
//!
//! - **Loopback only, named only at startup.** The upstream must be on this
//!   machine's loopback, and the set is fixed by the operator's flags. No
//!   request chooses a destination, and nothing at runtime widens the set: this
//!   is not a general proxy.
//! - **A key of its own header.** A service behind it usually has its own
//!   `Authorization` (an OpenAI-style API, for one), so this server's key
//!   travels in `X-Shell-Tunnel-Key` and `Authorization` reaches the service
//!   untouched. The key header never reaches the service.
//! - **Granted by name.** `expose:<name>`, or `expose:*` for every exposed
//!   service. The `operator` preset does not hold `expose:*`: exposing a
//!   service opens a door that a key scoped before the service existed should
//!   not open by itself.

use std::collections::BTreeMap;

/// The capability that grants every exposed service.
pub const ANY_EXPOSE: &str = "expose:*";

/// The header a caller sends this server's key in, on an exposed service's
/// path. `Authorization` there belongs to the service.
pub const KEY_HEADER: &str = "x-shell-tunnel-key";

/// The capability that grants the exposed service `name`.
pub fn capability_for(name: &str) -> String {
    format!("expose:{name}")
}

/// One exposed service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exposure {
    /// The name it is reached by: `/x/<name>/…`.
    pub name: String,
    /// The host as the operator wrote it — `127.0.0.1`, `[::1]` or
    /// `localhost` — which is also what the service is told in `Host`.
    pub host: String,
    pub port: u16,
    /// A path prefix the service lives under, without a trailing `/`; empty
    /// for the root.
    pub base_path: String,
}

impl Exposure {
    /// Parse one `--expose` value, `<name>=<url>`.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let (name, url) = spec
            .split_once('=')
            .ok_or_else(|| format!("`{spec}` is not <name>=<url>"))?;
        if !valid_name(name) {
            return Err(format!(
                "`{name}` cannot name an exposed service: use 1–32 characters of a–z, 0–9 and `-`, starting with a letter or digit"
            ));
        }
        let rest = url.strip_prefix("http://").ok_or_else(|| {
            if url.starts_with("https://") {
                format!("`{url}`: an exposed service is reached over this machine's loopback, so plain http:// — https upstreams are not supported")
            } else {
                format!("`{url}` must be an http:// URL")
            }
        })?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        if path.contains('?') || path.contains('#') {
            return Err(format!(
                "`{url}`: give a path prefix only, without a query or fragment"
            ));
        }
        let (host, port) = split_host_port(authority)
            .ok_or_else(|| format!("`{url}`: the host and port could not be read"))?;
        if !matches!(host, "127.0.0.1" | "[::1]" | "localhost") {
            return Err(format!(
                "`{url}`: an exposed service must be on this machine's loopback — 127.0.0.1, [::1] or localhost. Reaching other machines is not what --expose is for"
            ));
        }
        Ok(Self {
            name: name.to_string(),
            host: host.to_string(),
            port,
            base_path: path.trim_end_matches('/').to_string(),
        })
    }

    /// The `host:port` this server connects to.
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// The URL as an operator reads it back.
    pub fn url(&self) -> String {
        format!("http://{}{}", self.authority(), self.base_path)
    }
}

fn valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 32
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// `host[:port]`, with an IPv6 literal in brackets; the port defaults to 80.
fn split_host_port(authority: &str) -> Option<(&str, u16)> {
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        let host = &authority[..=end];
        return match &authority[end + 1..] {
            "" => Some((host, 80)),
            port => Some((host, port.strip_prefix(':')?.parse().ok()?)),
        };
    }
    match authority.split_once(':') {
        Some((host, port)) => Some((host, port.parse().ok()?)),
        None if !authority.is_empty() => Some((authority, 80)),
        None => None,
    }
}

/// Every service this server exposes, by name.
#[derive(Debug, Clone, Default)]
pub struct ExposeSet {
    by_name: BTreeMap<String, Exposure>,
}

impl ExposeSet {
    /// Parse every `--expose` value, refusing the whole set on the first bad
    /// one or a name given twice.
    pub fn parse<S: AsRef<str>>(specs: &[S]) -> Result<Self, String> {
        let mut by_name = BTreeMap::new();
        for spec in specs {
            let exposure = Exposure::parse(spec.as_ref())?;
            if by_name.contains_key(&exposure.name) {
                return Err(format!(
                    "`{}` is exposed twice; each name may be given once",
                    exposure.name
                ));
            }
            by_name.insert(exposure.name.clone(), exposure);
        }
        Ok(Self { by_name })
    }

    pub fn get(&self, name: &str) -> Option<&Exposure> {
        self.by_name.get(name)
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Exposure> {
        self.by_name.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_loopback_url_is_taken_apart() {
        let e = Exposure::parse("llm=http://127.0.0.1:8080/v1/").unwrap();
        assert_eq!(
            (
                e.name.as_str(),
                e.host.as_str(),
                e.port,
                e.base_path.as_str()
            ),
            ("llm", "127.0.0.1", 8080, "/v1")
        );
        let e = Exposure::parse("nb=http://[::1]:8888").unwrap();
        assert_eq!(
            (e.host.as_str(), e.port, e.base_path.as_str()),
            ("[::1]", 8888, "")
        );
        let e = Exposure::parse("dash=http://localhost").unwrap();
        assert_eq!((e.host.as_str(), e.port), ("localhost", 80));
    }

    #[test]
    fn anything_but_a_loopback_http_url_is_refused() {
        for spec in [
            "llm=http://10.0.0.5:8080",
            "llm=http://example.com",
            "llm=http://127.0.0.2:80",
            "llm=https://127.0.0.1:443",
            "llm=127.0.0.1:8080",
            "llm=http://127.0.0.1:8080/v1?x=1",
            "llm=http://127.0.0.1:notaport",
            "llm",
        ] {
            assert!(Exposure::parse(spec).is_err(), "{spec} should be refused");
        }
    }

    #[test]
    fn a_name_is_short_lowercase_and_url_safe() {
        for name in ["llm", "a", "gpu-0", "0x"] {
            assert!(
                Exposure::parse(&format!("{name}=http://127.0.0.1:1")).is_ok(),
                "{name}"
            );
        }
        let long = "a".repeat(33);
        for name in ["", "-a", "LLM", "a_b", "a/b", "a.b", long.as_str()] {
            assert!(
                Exposure::parse(&format!("{name}=http://127.0.0.1:1")).is_err(),
                "{name:?}"
            );
        }
    }

    #[test]
    fn a_name_given_twice_is_refused() {
        let err = ExposeSet::parse(&["a=http://127.0.0.1:1", "a=http://127.0.0.1:2"]).unwrap_err();
        assert!(err.contains("twice"), "{err}");
    }
}
