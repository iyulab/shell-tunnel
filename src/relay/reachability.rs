//! Whether two devices the relay has observed could ever punch to each other.
//!
//! The relay signals a direct attempt by handing each side the address it
//! observed the *other* on. That address is only useful if it means something
//! from where the other side stands, and the relay is the one process that can
//! see both — so it is the only place the impossible cases can be recognised
//! at all.
//!
//! **This module answers "never", not "will it work".** Hole punching fails
//! for reasons no observer can predict — a firewall, a NAT that will not open,
//! a peer that stopped answering — and none of those belong here. What belongs
//! here is the narrower question the relay can settle with certainty: is the
//! address one side would be told to open *routable from the other side at
//! all*. When it is not, the attempt is not unlikely, it is meaningless, and
//! spending the punch deadline on it buys nothing, once or a thousand times.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

/// Whether `ip` is an address only reachable from inside the network that
/// assigned it.
///
/// Deliberately built from explicit ranges rather than the inverse of "is
/// global": the standard library's `is_global` is unstable, and an
/// under-approximation is the safe direction here. A range this does not know
/// is treated as routable, which costs a pointless punch attempt — the status
/// quo. Getting it wrong the other way would refuse a direct connection that
/// would have worked.
fn is_private_to_its_own_network(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()          // 10/8, 172.16/12, 192.168/16
                || v4.is_loopback()  // 127/8
                || v4.is_link_local()// 169.254/16
                || v4.is_unspecified()
                // 100.64/10, carrier-grade NAT (RFC 6598). Not private and not
                // globally routable — the one range that is neither.
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 unique-local and fe80::/10 link-local. Spelled out
                // because `is_unique_local`/`is_unicast_link_local` are both
                // unstable.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || is_mapped_private_v4(v6)
        }
    }
}

/// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) carries a v4 address, and a
/// dual-stack listener reports every v4 peer in this form — so the v4 ranges
/// above have to be reachable through it or the check silently never fires on
/// such a relay.
fn is_mapped_private_v4(v6: Ipv6Addr) -> bool {
    match v6.to_ipv4_mapped() {
        Some(v4) => is_private_to_its_own_network(IpAddr::V4(v4)),
        None => false,
    }
}

/// Whether a direct connection between two observed addresses cannot succeed,
/// whatever the NATs in between are willing to do.
///
/// True for exactly one shape: **one side is private to its own network and
/// the other is not**. The private address is then meaningless to the peer
/// outside it, no punch from that side ever arrives, and so the mapping the
/// other direction needs is never opened either.
///
/// Everything else answers false, including two cases that look like they
/// belong here and do not:
///
/// - **Both private.** Two devices on one LAN, with the relay on it too, are
///   each observed at their own address and punch perfectly well. Refusing
///   this pair would break the deployment direct-connect works best in.
/// - **Both private and identical** (two devices behind one gateway, seen at
///   the one outbound address). Whether that opens is up to the gateway's
///   hairpinning, which this cannot see — some do it, some do not. An
///   unanswerable question is not the same as a settled "no", and this module
///   only answers the settled ones.
pub(crate) fn direct_is_impossible(a: SocketAddr, b: SocketAddr) -> bool {
    is_private_to_its_own_network(a.ip()) != is_private_to_its_own_network(b.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("test address")
    }

    #[test]
    fn a_private_address_paired_with_a_public_one_is_impossible() {
        // The measured case: a relay inside one participant's network observes
        // that side at the network's own address, and a peer outside it is
        // handed an address that does not route from where it stands.
        assert!(direct_is_impossible(
            addr("10.1.2.3:40000"),
            addr("198.51.100.7:40000")
        ));
        assert!(direct_is_impossible(
            addr("198.51.100.7:40000"),
            addr("172.20.0.9:40000")
        ));
        assert!(direct_is_impossible(
            addr("192.168.1.1:40000"),
            addr("203.0.113.5:40000")
        ));
    }

    #[test]
    fn two_public_addresses_are_not_refused() {
        // The deployment direct-connect exists for. Whether the punch actually
        // opens is the NATs' business, not this module's.
        assert!(!direct_is_impossible(
            addr("198.51.100.7:40000"),
            addr("203.0.113.5:40000")
        ));
    }

    #[test]
    fn two_private_addresses_are_not_refused() {
        // Both on one LAN with the relay beside them: each is observed at its
        // own address and the punch works. This is the pair a wider rule would
        // wrongly kill.
        assert!(!direct_is_impossible(
            addr("192.168.1.10:40000"),
            addr("192.168.1.11:40000")
        ));
        // Different private ranges, which this still does not judge: the
        // relay cannot tell one routing domain from another, and guessing
        // would refuse a working pair.
        assert!(!direct_is_impossible(
            addr("10.0.0.5:40000"),
            addr("192.168.1.11:40000")
        ));
    }

    #[test]
    fn one_gateway_seen_twice_is_not_refused() {
        // Two devices behind one NAT, observed at the one outbound address.
        // Measured not to work on the gateway that produced this module — but
        // that is hairpinning, which varies by gateway and is not visible from
        // here. Only settled impossibility is refused.
        assert!(!direct_is_impossible(
            addr("172.30.9.9:1000"),
            addr("172.30.9.9:2000")
        ));
    }

    #[test]
    fn loopback_pairs_are_not_refused() {
        // Every test in this repository that drives a relay does it over
        // loopback. Both sides are private here, so nothing is refused and
        // those tests keep exercising the path they were written for.
        assert!(!direct_is_impossible(
            addr("127.0.0.1:40000"),
            addr("127.0.0.1:40001")
        ));
        // A loopback device and a public one is still the impossible shape.
        assert!(direct_is_impossible(
            addr("127.0.0.1:40000"),
            addr("198.51.100.7:40000")
        ));
    }

    #[test]
    fn carrier_grade_nat_counts_as_private() {
        // 100.64/10 is neither private nor globally routable. A relay inside a
        // carrier's network is the only way to observe one, and the address is
        // as useless to an outside peer as any RFC1918 one.
        assert!(direct_is_impossible(
            addr("100.64.0.1:40000"),
            addr("198.51.100.7:40000")
        ));
        // The neighbouring ranges are ordinary public space and must not be
        // caught by the same check.
        assert!(!direct_is_impossible(
            addr("100.63.255.255:40000"),
            addr("198.51.100.7:40000")
        ));
        assert!(!direct_is_impossible(
            addr("100.128.0.0:40000"),
            addr("198.51.100.7:40000")
        ));
    }

    #[test]
    fn ipv6_is_judged_by_the_same_rule() {
        assert!(direct_is_impossible(
            addr("[fd00::1]:40000"),
            addr("[2001:db8::1]:40000")
        ));
        assert!(direct_is_impossible(
            addr("[fe80::1]:40000"),
            addr("[2001:db8::1]:40000")
        ));
        assert!(!direct_is_impossible(
            addr("[2001:db8::1]:40000"),
            addr("[2001:db8::2]:40000")
        ));
        assert!(!direct_is_impossible(
            addr("[fd00::1]:40000"),
            addr("[fd00::2]:40000")
        ));
    }

    #[test]
    fn a_v4_mapped_address_is_read_as_the_v4_it_carries() {
        // A dual-stack relay reports every v4 peer as `::ffff:a.b.c.d`. Read
        // naively that is neither loopback nor unique-local, so every check
        // above would answer "routable" and this module would never fire on
        // exactly the relays most likely to run it.
        assert!(direct_is_impossible(
            addr("[::ffff:10.1.2.3]:40000"),
            addr("198.51.100.7:40000")
        ));
        assert!(!direct_is_impossible(
            addr("[::ffff:198.51.100.7]:40000"),
            addr("203.0.113.5:40000")
        ));
        // And the mixed spelling of one pair still agrees with itself.
        assert!(!direct_is_impossible(
            addr("[::ffff:192.168.1.10]:40000"),
            addr("192.168.1.11:40000")
        ));
    }

    #[test]
    fn the_relation_does_not_depend_on_which_side_is_asking() {
        // The relay calls this with (requester, target); nothing should change
        // if a later caller passes them the other way round.
        let private = addr("10.0.0.1:1234");
        let public = addr("198.51.100.7:1234");
        assert_eq!(
            direct_is_impossible(private, public),
            direct_is_impossible(public, private)
        );
    }
}
