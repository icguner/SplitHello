//! Worker WebSocket tunnel: the last-resort path when every bypass profile
//! failed (port of `src/Relay.cpp` + `src/WsClient.cpp`).
//!
//! Connects to `<worker>/tunnel` through the private connect port, sends
//! `{"cmd":"connect","host":..,"port":..}`, requires a reply containing
//! `"connected"`, replays the bytes already read from the client, then pumps
//! binary frames both ways. Text frames from the Worker are logged and dropped:
//! written to the client they would corrupt the TLS stream.

use std::net::IpAddr;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Bytes, Message};

/// Largest message accepted from the Worker.
const MAX_MESSAGE: usize = 1024 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct TunnelTarget {
    pub worker_host: String,
    pub worker_addresses: Vec<IpAddr>,
    pub connect_port: u16,
    pub shared_secret: String,
}

fn quote(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| "\"\"".into())
}

/// Runs the tunnel for one client connection until either side closes.
/// Returns false when the tunnel could not be established.
pub async fn run(
    client: &mut TcpStream,
    target: &TunnelTarget,
    host: &str,
    port: u16,
    initial: &[u8],
) -> bool {
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, open(target, host, port, initial)).await {
        Ok(Ok(mut socket)) => {
            tracing::info!("Tunel kuruldu: {host}:{port}");
            pump(client, &mut socket).await;
            let _ = socket.close(None).await;
            tracing::debug!("Tunel kapandi: {host}:{port}");
            true
        }
        Ok(Err(reason)) => {
            tracing::error!("Tunel hatasi ({reason}): {host}:{port}");
            false
        }
        Err(_) => {
            tracing::error!("Tunel hatasi (zaman asimi): {host}:{port}");
            false
        }
    }
}

type Socket = tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

async fn open(
    target: &TunnelTarget,
    host: &str,
    port: u16,
    initial: &[u8],
) -> Result<Socket, String> {
    let (tcp, _) = crate::connect::connect_with_timeout(
        &target.worker_addresses,
        target.connect_port,
        HANDSHAKE_TIMEOUT,
    )
    .await
    .ok_or("baglanti")?;
    let _ = tcp.set_nodelay(true);
    let server_name = rustls::pki_types::ServerName::try_from(target.worker_host.clone())
        .map_err(|_| "worker adi")?;
    let tls = TlsConnector::from(crate::tls::client_config())
        .connect(server_name, tcp)
        .await
        .map_err(|_| "TLS")?;

    let mut request = format!("wss://{}/tunnel", target.worker_host)
        .into_client_request()
        .map_err(|_| "istek")?;
    if !target.shared_secret.is_empty() {
        let value = format!("Bearer {}", target.shared_secret)
            .parse()
            .map_err(|_| "yetki")?;
        request.headers_mut().insert("Authorization", value);
    }
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE))
        .max_frame_size(Some(MAX_MESSAGE));
    let (mut socket, response) =
        tokio_tungstenite::client_async_with_config(request, tls, Some(config))
            .await
            .map_err(|_| "websocket")?;
    if response.status().as_u16() != 101 {
        return Err("websocket".into());
    }

    let command = format!(
        "{{\"cmd\":\"connect\",\"host\":{},\"port\":{port}}}",
        quote(host)
    );
    socket
        .send(Message::text(command))
        .await
        .map_err(|_| "connect komutu")?;
    match socket.next().await {
        Some(Ok(reply))
            if reply
                .to_text()
                .is_ok_and(|text| text.contains("\"connected\"")) => {}
        Some(Ok(reply)) => {
            tracing::error!("Tunel reddedildi: {}", reply.to_text().unwrap_or("<ikili>"));
            return Err("reddedildi".into());
        }
        _ => return Err("yanit yok".into()),
    }
    // Replay what the client already sent before the fallback.
    if !initial.is_empty() {
        socket
            .send(Message::Binary(Bytes::copy_from_slice(initial)))
            .await
            .map_err(|_| "ilk veri")?;
    }
    Ok(socket)
}

async fn pump(client: &mut TcpStream, socket: &mut Socket) {
    let (mut client_read, mut client_write) = client.split();
    let mut buffer = vec![0u8; 32 * 1024];
    loop {
        tokio::select! {
            read = client_read.read(&mut buffer) => match read {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if socket.send(Message::Binary(Bytes::copy_from_slice(&buffer[..n]))).await.is_err() {
                        break;
                    }
                }
            },
            message = socket.next() => match message {
                Some(Ok(Message::Binary(data))) => {
                    if client_write.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Text(text))) => {
                    let shown: String = text.chars().take(256).collect();
                    tracing::warn!("Tunel mesaji: {shown}");
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(_)) => {} // ping/pong handled by tungstenite
            },
        }
    }
}
