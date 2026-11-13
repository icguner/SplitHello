#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramRoute {
    Pass,
    ReflectDnsToProxy,
    ReflectProxyToClient,
}

/// Pure routing decision by port (host byte order).
pub fn route_datagram(
    outbound: bool,
    source_port: u16,
    destination_port: u16,
    dns_port: u16,
    proxy_port: u16,
) -> DatagramRoute {
    if !outbound {
        DatagramRoute::Pass
    } else if source_port == proxy_port {
        DatagramRoute::ReflectProxyToClient
    } else if destination_port == dns_port {
        DatagramRoute::ReflectDnsToProxy
    } else {
        DatagramRoute::Pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_route_reflects_queries_and_answers() {
        assert_eq!(
            route_datagram(true, 54000, 53, 53, 1053),
            DatagramRoute::ReflectDnsToProxy
        );
        assert_eq!(
            route_datagram(true, 1053, 54000, 53, 1053),
            DatagramRoute::ReflectProxyToClient
        );
        assert_eq!(
            route_datagram(false, 53, 54000, 53, 1053),
            DatagramRoute::Pass
        );
    }
}
