#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketRoute {
    Pass,
    ReflectClientToProxy,
    ReflectProxyToClient,
    RedirectProxyToTarget,
    RedirectTargetToProxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramRoute {
    Pass,
    ReflectDnsToProxy,
    ReflectProxyToClient,
}

/// Pure routing decision by port (host byte order). The caller must still check
/// that the tuple is a tracked flow (`TcpFlowTable`) before rewriting.
///
/// shortcut: classification is by port only. A foreign local program that
/// dials the private connect port or sends from the relay port is
/// indistinguishable here; the SYN-seen check narrows it, and an owner-PID
/// check on those SYNs is the upgrade if collisions are ever reported.
pub fn route_packet(
    outbound: bool,
    source_port: u16,
    destination_port: u16,
    target_port: u16,
    proxy_port: u16,
    connect_port: u16,
) -> PacketRoute {
    if outbound {
        if source_port == proxy_port {
            PacketRoute::ReflectProxyToClient
        } else if destination_port == connect_port {
            PacketRoute::RedirectProxyToTarget
        } else if destination_port == target_port {
            PacketRoute::ReflectClientToProxy
        } else {
            PacketRoute::Pass
        }
    } else if source_port == target_port {
        PacketRoute::RedirectTargetToProxy
    } else {
        PacketRoute::Pass
    }
}

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
    fn reflects_application_https_to_proxy() {
        assert_eq!(
            route_packet(true, 52000, 443, 443, 1080, 65534),
            PacketRoute::ReflectClientToProxy
        );
    }

    #[test]
    fn reflects_proxy_replies_back_to_application() {
        assert_eq!(
            route_packet(true, 1080, 52000, 443, 1080, 65534),
            PacketRoute::ReflectProxyToClient
        );
    }

    #[test]
    fn maps_private_connect_port_to_https() {
        assert_eq!(
            route_packet(true, 53000, 65534, 443, 1080, 65534),
            PacketRoute::RedirectProxyToTarget
        );
        assert_eq!(
            route_packet(false, 443, 53000, 443, 1080, 65534),
            PacketRoute::RedirectTargetToProxy
        );
    }

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
