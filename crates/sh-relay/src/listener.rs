//! Accept loop and session ownership (port of `SocksProxy::run`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use sh_flow::{FlowRegistry, PeerAddr};
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

use crate::direct::{RelayContext, relay};
use crate::negotiate::negotiate;

/// Live connection cap; beyond it the client is reset at once.
pub const MAX_CONNECTIONS: usize = 1024;

pub enum ListenerMode {
    /// Accepts only connections whose SYN the packet loop reflected
    /// (`FlowRegistry`); the listener is never an open proxy.
    Transparent(Arc<FlowRegistry>),
    /// SOCKS5 / HTTP CONNECT on loopback.
    Manual,
}

pub struct Listener {
    listener: TcpListener,
    mode: ListenerMode,
    context: Arc<RelayContext>,
    running: AtomicBool,
}

impl Listener {
    /// Transparent: `[::]` dual-stack; manual: 127.0.0.1.
    pub fn bind(
        port: u16,
        mode: ListenerMode,
        context: Arc<RelayContext>,
    ) -> std::io::Result<Arc<Self>> {
        let (domain, address) = match mode {
            ListenerMode::Transparent(_) => (
                Domain::IPV6,
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
            ),
            ListenerMode::Manual => (
                Domain::IPV4,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            ),
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        if domain == Domain::IPV6 {
            socket.set_only_v6(false)?;
        }
        socket.bind(&address.into())?;
        socket.listen(1024)?;
        socket.set_nonblocking(true)?;
        let listener = TcpListener::from_std(socket.into())?;
        Ok(Arc::new(Self {
            listener,
            mode,
            context,
            running: AtomicBool::new(false),
        }))
    }

    pub fn local_port(&self) -> u16 {
        self.listener.local_addr().map(|a| a.port()).unwrap_or(0)
    }

    pub fn running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Serves until `shutdown` turns true; then every session is ended and
    /// awaited before returning (no session outlives the listener).
    pub async fn run(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let mut sessions = JoinSet::new();
        let mut consecutive_errors = 0u32;
        self.running.store(true, Ordering::SeqCst);
        tracing::info!("Relay dinliyor: {:?}", self.listener.local_addr().ok());

        loop {
            let accepted = tokio::select! {
                accepted = self.listener.accept() => accepted,
                _ = shutdown.changed() => break,
                Some(_) = sessions.join_next(), if !sessions.is_empty() => continue,
            };
            let (stream, peer) = match accepted {
                Ok(value) => {
                    consecutive_errors = 0;
                    value
                }
                Err(error) => {
                    // Transient errors back off; a long unbroken run ends the
                    // accept loop (the engine then fails open).
                    consecutive_errors += 1;
                    if consecutive_errors >= 100 {
                        tracing::error!("Accept hatasi tekrarlandi, relay duruyor: {error}");
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(
                        (10u64 << consecutive_errors.min(7)).min(1000),
                    ))
                    .await;
                    continue;
                }
            };
            let Ok(permit) = slots.clone().try_acquire_owned() else {
                tracing::warn!("Baglanti siniri ({MAX_CONNECTIONS}) asildi, istemci sifirlandi");
                let _ = SockRef::from(&stream).set_linger(Some(Duration::ZERO));
                continue;
            };
            let this = self.clone();
            sessions.spawn(async move {
                this.serve(stream, peer).await;
                drop(permit);
            });
        }

        self.running.store(false, Ordering::SeqCst);
        // Dropping the futures closes their sockets; then wait for them all.
        sessions.abort_all();
        while sessions.join_next().await.is_some() {}
    }

    async fn serve(&self, mut stream: TcpStream, peer: SocketAddr) {
        match &self.mode {
            ListenerMode::Transparent(flows) => {
                let peer_ip = PeerAddr::from(peer.ip());
                match flows.claim(peer_ip, peer.port(), sh_core::clock::now_ms()) {
                    Some(target) => {
                        let address = target.address.to_ip();
                        relay(
                            stream,
                            &self.context,
                            address.to_string(),
                            target.target_port,
                            Some(address),
                            target.connect_port,
                            Vec::new(),
                        )
                        .await;
                    }
                    None => tracing::warn!("Yetkisiz transparent relay baglantisi reddedildi"),
                }
            }
            ListenerMode::Manual => {
                if let Some(negotiated) =
                    negotiate(&mut stream, self.context.handshake_timeout).await
                {
                    relay(
                        stream,
                        &self.context,
                        negotiated.host,
                        negotiated.port,
                        None,
                        0,
                        negotiated.leftover,
                    )
                    .await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sh_strategy::Store;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn context() -> Arc<RelayContext> {
        Arc::new(RelayContext {
            resolver: None,
            strategies: Arc::new(Store::new("")),
            packet_policies: None,
            telemetry: None,
            live_stats: None,
            network_id: Arc::new(|| "test-network".into()),
            split_delay_ms: 0,
            probe_timeout: Duration::from_millis(1500),
            tunnel: None,
            idle_timeout: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(2),
            forced_profile: String::new(),
        })
    }

    #[tokio::test]
    async fn transparent_listener_refuses_unannounced_connections() {
        let flows = Arc::new(FlowRegistry::default());
        let listener = Listener::bind(0, ListenerMode::Transparent(flows), context()).unwrap();
        let port = listener.local_port();
        let (stop, shutdown) = watch::channel(false);
        let server = tokio::spawn(listener.clone().run(shutdown));

        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut buffer = [0u8; 1];
        // Closed without a byte: no FlowRegistry entry for this peer.
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), client.read(&mut buffer))
                .await
                .unwrap()
                .unwrap_or(0),
            0
        );
        stop.send(true).unwrap();
        server.await.unwrap();
        assert!(!listener.running());
    }

    #[tokio::test]
    async fn manual_listener_relays_http_connect_to_an_echo_origin() {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut socket, _) = origin.accept().await.unwrap();
            let mut buffer = [0u8; 64];
            let n = socket.read(&mut buffer).await.unwrap();
            socket.write_all(&buffer[..n]).await.unwrap();
        });

        let listener = Listener::bind(0, ListenerMode::Manual, context()).unwrap();
        let port = listener.local_port();
        let (stop, shutdown) = watch::channel(false);
        let server = tokio::spawn(listener.run(shutdown));

        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client
            .write_all(format!("CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut status = [0u8; 39];
        client.read_exact(&mut status).await.unwrap();
        assert!(status.starts_with(b"HTTP/1.1 200"));
        // Not TLS: forwarded untouched after the first-byte wait.
        client.write_all(b"plain").await.unwrap();
        let mut echo = [0u8; 5];
        tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut echo))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&echo, b"plain");
        drop(client);
        stop.send(true).unwrap();
        server.await.unwrap();
    }
}
