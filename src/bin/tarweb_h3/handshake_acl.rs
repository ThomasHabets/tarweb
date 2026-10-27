//! Source networks allowed to create new connections. Established QUIC
//! connections remain eligible for migration from other addresses.

use std::net::IpAddr;
use std::sync::Arc;

use ipnet::{IpNet, Ipv4Net};

#[derive(Clone)]
pub(super) struct HandshakeAcl {
    prefixes: Arc<[IpNet]>,
}

impl HandshakeAcl {
    pub(super) fn new(prefixes: Vec<IpNet>) -> Self {
        let prefixes = prefixes
            .into_iter()
            .map(|prefix| {
                // Treat IPv4-mapped IPv6 networks and source addresses as
                // IPv4, including when receiving on a dual-stack socket.
                if let IpNet::V6(net) = prefix
                    && net.prefix_len() >= 96
                    && let Some(ip) = net.addr().to_ipv4_mapped()
                {
                    return IpNet::V4(
                        Ipv4Net::new(ip, net.prefix_len() - 96)
                            .expect("mapped IPv4 prefix length is at most 32"),
                    );
                }
                prefix
            })
            .collect::<Vec<_>>()
            .into();
        Self { prefixes }
    }

    pub(super) fn allows(&self, source: IpAddr) -> bool {
        let source = source.to_canonical();
        self.prefixes.is_empty() || self.prefixes.iter().any(|prefix| prefix.contains(&source))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_acl_allows_both_address_families() {
        let acl = HandshakeAcl::new(Vec::new());
        for ip in ["192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1"] {
            assert!(acl.allows(ip.parse().unwrap()));
        }
    }

    #[test]
    fn prefixes_match_boundaries_and_either_allowed_network() {
        let acl = HandshakeAcl::new(
            [
                "192.0.2.0/24",
                "198.51.100.7/32",
                "2001:db8:1::/64",
                "::1/128",
            ]
            .map(|prefix| prefix.parse().unwrap())
            .to_vec(),
        );
        for ip in [
            "192.0.2.0",
            "192.0.2.255",
            "198.51.100.7",
            "2001:db8:1::",
            "2001:db8:1:0:ffff:ffff:ffff:ffff",
            "::1",
            "::ffff:192.0.2.42",
        ] {
            assert!(acl.allows(ip.parse().unwrap()), "denied {ip}");
        }
        for ip in [
            "192.0.1.255",
            "192.0.3.0",
            "198.51.100.6",
            "198.51.100.8",
            "2001:db8:0:ffff:ffff:ffff:ffff:ffff",
            "2001:db8:1:1::",
            "::2",
            "::ffff:192.0.3.1",
        ] {
            assert!(!acl.allows(ip.parse().unwrap()), "allowed {ip}");
        }
    }

    #[test]
    fn mapped_prefixes_and_ipv6_catch_all_have_consistent_families() {
        let mapped = HandshakeAcl::new(vec!["::ffff:192.0.2.0/120".parse().unwrap()]);
        for ip in ["192.0.2.7", "::ffff:192.0.2.7"] {
            assert!(mapped.allows(ip.parse().unwrap()));
        }
        assert!(!mapped.allows("192.0.3.7".parse().unwrap()));
        let v6 = HandshakeAcl::new(vec!["::/0".parse().unwrap()]);
        assert!(v6.allows("2001:db8::1".parse().unwrap()));
        assert!(!v6.allows("192.0.2.7".parse().unwrap()));
        assert!(!v6.allows("::ffff:192.0.2.7".parse().unwrap()));
        let v4 = HandshakeAcl::new(vec!["0.0.0.0/0".parse().unwrap()]);
        assert!(v4.allows("::ffff:192.0.2.7".parse().unwrap()));
        assert!(!v4.allows("2001:db8::1".parse().unwrap()));
    }
}
