//! Certificate fingerprints.
//!
//! A fingerprint identifies one exact certificate, which is what makes it
//! useful for a self-signed relay: the device is told *which* certificate to
//! expect rather than which authority to believe. That is the SSH model, and it
//! removes both chores the certificate-file route imposes — copying a file to
//! every device, and making sure the certificate names the address they dial.
//!
//! It is the wrong tool for a publicly-signed certificate, which is replaced on
//! every renewal; there the authority is the stable thing, not the certificate.

/// Render the SHA-256 fingerprint of a DER certificate.
///
/// Formatted `sha256:<hex>` so the algorithm travels with the value and a
/// future change is not silently mistaken for the old one.
pub fn of_certificate(der: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    let mut hex = String::with_capacity(7 + digest.as_ref().len() * 2);
    hex.push_str("sha256:");
    for byte in digest.as_ref() {
        use std::fmt::Write;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Parse a fingerprint into the raw digest it names.
///
/// Accepts what an operator is likely to paste: with or without the `sha256:`
/// prefix, upper or lower case, and with the colons some tools print between
/// bytes.
pub fn parse(value: &str) -> Result<Vec<u8>, String> {
    let body = value
        .trim()
        .strip_prefix("sha256:")
        .or_else(|| value.trim().strip_prefix("SHA256:"))
        .unwrap_or(value.trim());
    let hex: String = body.chars().filter(|c| !matches!(c, ':' | ' ')).collect();

    if hex.len() != 64 {
        return Err(format!(
            "a sha256 fingerprint is 64 hex characters; got {}",
            hex.len()
        ));
    }

    (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| "not hexadecimal".to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fingerprint_names_its_algorithm() {
        let fp = of_certificate(b"pretend this is a certificate");
        assert!(fp.starts_with("sha256:"), "{fp}");
        assert_eq!(fp.len(), 7 + 64);
    }

    #[test]
    fn the_same_certificate_always_gives_the_same_fingerprint() {
        assert_eq!(of_certificate(b"same"), of_certificate(b"same"));
        assert_ne!(of_certificate(b"same"), of_certificate(b"other"));
    }

    #[test]
    fn a_rendered_fingerprint_parses_back() {
        let fp = of_certificate(b"round trip");
        let digest = parse(&fp).unwrap();
        assert_eq!(of_certificate(b"round trip"), {
            let mut s = String::from("sha256:");
            for b in &digest {
                s.push_str(&format!("{b:02x}"));
            }
            s
        });
    }

    #[test]
    fn the_shapes_an_operator_might_paste_all_work() {
        let canonical = of_certificate(b"x");
        let bare = canonical.trim_start_matches("sha256:").to_string();

        assert_eq!(parse(&canonical).unwrap(), parse(&bare).unwrap());
        assert_eq!(
            parse(&canonical).unwrap(),
            parse(&bare.to_uppercase()).unwrap()
        );

        // Some tools print a colon between every byte.
        let spaced: String = bare
            .as_bytes()
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(parse(&canonical).unwrap(), parse(&spaced).unwrap());
    }

    #[test]
    fn a_truncated_or_malformed_fingerprint_is_refused() {
        assert!(parse("sha256:abcd").is_err());
        assert!(parse(&"z".repeat(64)).is_err());
        assert!(parse("").is_err());
    }
}
