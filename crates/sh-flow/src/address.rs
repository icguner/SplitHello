use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Canonical binary peer address. IPv4 is stored in IPv4-mapped IPv6 form, so
/// `1.2.3.4` and `::ffff:1.2.3.4` compare equal and no text is built on the
/// packet hot path.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct PeerAddr(pub [u8; 16]);

impl PeerAddr {
    pub fn from_v4_bytes(bytes: [u8; 4]) -> Self {
        Self(Ipv4Addr::from(bytes).to_ipv6_mapped().octets())
    }

    pub fn from_v6_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Parses `inet_ntop`-style text (dotted quad or IPv6).
    pub fn parse(text: &str) -> Option<Self> {
        text.parse::<IpAddr>().ok().map(Self::from)
    }

    pub fn to_ip(self) -> IpAddr {
        let v6 = Ipv6Addr::from(self.0);
        v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)
    }
}

impl From<IpAddr> for PeerAddr {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::from_v4_bytes(v4.octets()),
            IpAddr::V6(v6) => Self(v6.octets()),
        }
    }
}

impl fmt::Debug for PeerAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_ip())
    }
}

impl fmt::Display for PeerAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_ip())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> PeerAddr {
        PeerAddr::parse(text).expect("valid address")
    }

    #[test]
    fn addresses_are_canonical_across_text_forms() {
        assert_eq!(addr("1.2.3.4"), addr("::ffff:1.2.3.4"));
        assert_eq!(addr("2001:DB8::1"), addr("2001:db8:0:0:0:0:0:1"));
        assert_ne!(addr("1.2.3.4"), addr("1.2.3.5"));
        assert_eq!(PeerAddr::from_v4_bytes([1, 2, 3, 4]), addr("1.2.3.4"));
        assert!(PeerAddr::parse("not an address").is_none());
        assert!(PeerAddr::parse("").is_none());
        assert_eq!(addr("1.2.3.4").to_string(), "1.2.3.4");
    }
}
