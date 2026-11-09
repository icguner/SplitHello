//! Target negotiation for manual mode: SOCKS5 and HTTP CONNECT (port of
//! `SocksProxy::negotiate`). The transparent path lives in the listener.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::Instant;

const SOCKS_VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const AUTH_REJECT: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const MAX_HEADER_LINES: usize = 100;
const MAX_LINE: usize = 8192;

/// Negotiated destination plus any bytes the handshake read past its end.
pub struct Negotiated {
    pub host: String,
    pub port: u16,
    pub leftover: Vec<u8>,
}

async fn within<T>(
    deadline: Instant,
    future: impl Future<Output = std::io::Result<T>>,
) -> Option<T> {
    tokio::time::timeout_at(deadline, future).await.ok()?.ok()
}

/// One budget for the whole handshake: a silent or dribbling local client must
/// not pin a connection slot.
pub async fn negotiate(stream: &mut TcpStream, budget: Duration) -> Option<Negotiated> {
    let deadline = Instant::now() + budget;
    let mut first = [0u8; 1];
    let peeked = within(deadline, stream.peek(&mut first)).await?;
    if peeked == 0 {
        return None;
    }
    let negotiated = if first[0] == SOCKS_VERSION {
        socks5(stream, deadline).await
    } else if first[0].is_ascii_uppercase() {
        http_connect(stream, deadline).await
    } else {
        tracing::warn!("Bilinmeyen protokol: ilk byte=0x{:02x}", first[0]);
        None
    }?;
    tracing::info!("CONNECT {}:{}", negotiated.host, negotiated.port);
    Some(negotiated)
}

async fn read_line<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    deadline: Instant,
) -> Option<String> {
    let mut line = Vec::new();
    let read = within(deadline, async {
        let mut limited = (&mut *reader).take(MAX_LINE as u64 + 1);
        limited.read_until(b'\n', &mut line).await
    })
    .await?;
    if read == 0 || line.len() > MAX_LINE || line.last() != Some(&b'\n') {
        return None;
    }
    while matches!(line.last(), Some(b'\n' | b'\r')) {
        line.pop();
    }
    String::from_utf8(line).ok()
}

async fn http_connect(stream: &mut TcpStream, deadline: Instant) -> Option<Negotiated> {
    let mut reader = BufReader::new(&mut *stream);
    let request_line = read_line(&mut reader, deadline).await?;
    let mut parts = request_line.split(' ');
    let method = parts.next()?;
    if method != "CONNECT" {
        // Plain-HTTP proxying is not implemented (no ClientHello on port 80).
        // Drain the headers first: closing with unread data would reset the
        // socket and the client would never see the status.
        tracing::debug!("HTTP {method} istegi reddedildi (sadece CONNECT desteklenir)");
        for _ in 0..MAX_HEADER_LINES {
            match read_line(&mut reader, deadline).await {
                Some(line) if !line.is_empty() => {}
                _ => break,
            }
        }
        drop(reader);
        let _ = stream
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        let _ = stream.shutdown().await;
        return None;
    }
    let host_port = parts.next()?;
    let (host, port) = host_port.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port: u16 = port.parse().ok().filter(|&p| p != 0)?;
    if host.is_empty() {
        tracing::debug!("Gecersiz CONNECT hedefi: {host_port}");
        return None;
    }
    // A timeout, a closed socket or a header flood is a broken client.
    let mut end_of_headers = false;
    for _ in 0..MAX_HEADER_LINES {
        if read_line(&mut reader, deadline).await?.is_empty() {
            end_of_headers = true;
            break;
        }
    }
    if !end_of_headers {
        return None;
    }
    let leftover = reader.buffer().to_vec();
    drop(reader);
    within(
        deadline,
        stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n"),
    )
    .await?;
    Some(Negotiated {
        host: host.to_owned(),
        port,
        leftover,
    })
}

async fn socks5(stream: &mut TcpStream, deadline: Instant) -> Option<Negotiated> {
    let mut header = [0u8; 2];
    within(deadline, stream.read_exact(&mut header)).await?;
    if header[0] != SOCKS_VERSION || header[1] == 0 {
        return None;
    }
    let mut methods = vec![0u8; usize::from(header[1])];
    within(deadline, stream.read_exact(&mut methods)).await?;
    let no_auth = methods.contains(&AUTH_NONE);
    within(
        deadline,
        stream.write_all(&[SOCKS_VERSION, if no_auth { AUTH_NONE } else { AUTH_REJECT }]),
    )
    .await?;
    if !no_auth {
        return None;
    }

    let mut request = [0u8; 4];
    within(deadline, stream.read_exact(&mut request)).await?;
    if request[0] != SOCKS_VERSION {
        return None;
    }
    if request[1] != CMD_CONNECT {
        let _ = stream
            .write_all(&[
                SOCKS_VERSION,
                REP_CMD_NOT_SUPPORTED,
                0,
                ATYP_IPV4,
                0,
                0,
                0,
                0,
                0,
                0,
            ])
            .await;
        return None;
    }
    let host = match request[3] {
        ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            within(deadline, stream.read_exact(&mut ip)).await?;
            Ipv4Addr::from(ip).to_string()
        }
        ATYP_DOMAIN => {
            let mut length = [0u8; 1];
            within(deadline, stream.read_exact(&mut length)).await?;
            if length[0] == 0 {
                return None;
            }
            let mut domain = vec![0u8; usize::from(length[0])];
            within(deadline, stream.read_exact(&mut domain)).await?;
            String::from_utf8(domain).ok()?
        }
        ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            within(deadline, stream.read_exact(&mut ip)).await?;
            Ipv6Addr::from(ip).to_string()
        }
        _ => return None,
    };
    let mut port = [0u8; 2];
    within(deadline, stream.read_exact(&mut port)).await?;
    within(
        deadline,
        stream.write_all(&[SOCKS_VERSION, REP_SUCCESS, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0]),
    )
    .await?;
    Some(Negotiated {
        host,
        port: u16::from_be_bytes(port),
        leftover: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let connect = TcpStream::connect(listener.local_addr().unwrap());
        let (accepted, connected) = tokio::join!(listener.accept(), connect);
        (accepted.unwrap().0, connected.unwrap())
    }

    #[tokio::test]
    async fn socks5_domain_connect() {
        let (mut server, mut client) = pair().await;
        let client_side = tokio::spawn(async move {
            client.write_all(&[5, 1, 0]).await.unwrap();
            let mut auth = [0u8; 2];
            client.read_exact(&mut auth).await.unwrap();
            assert_eq!(auth, [5, 0]);
            let mut request = vec![5, 1, 0, 3, 11];
            request.extend(b"discord.com");
            request.extend(443u16.to_be_bytes());
            client.write_all(&request).await.unwrap();
            let mut reply = [0u8; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[1], 0);
        });
        let negotiated = negotiate(&mut server, Duration::from_secs(5))
            .await
            .expect("negotiated");
        assert_eq!(
            (negotiated.host.as_str(), negotiated.port),
            ("discord.com", 443)
        );
        client_side.await.unwrap();
    }

    #[tokio::test]
    async fn http_connect_keeps_pipelined_bytes() {
        let (mut server, mut client) = pair().await;
        client
            .write_all(
                b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n\x16\x03\x01",
            )
            .await
            .unwrap();
        let negotiated = negotiate(&mut server, Duration::from_secs(5))
            .await
            .expect("negotiated");
        assert_eq!(
            (negotiated.host.as_str(), negotiated.port),
            ("example.com", 443)
        );
        assert_eq!(negotiated.leftover, b"\x16\x03\x01");
        let mut reply = [0u8; 39];
        client.read_exact(&mut reply).await.unwrap();
        assert!(reply.starts_with(b"HTTP/1.1 200"));
    }

    #[tokio::test]
    async fn plain_http_gets_405_and_silent_clients_time_out() {
        let (mut server, mut client) = pair().await;
        client
            .write_all(b"GET http://x/ HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        assert!(
            negotiate(&mut server, Duration::from_secs(5))
                .await
                .is_none()
        );
        let mut reply = String::new();
        client.read_to_string(&mut reply).await.unwrap();
        assert!(reply.starts_with("HTTP/1.1 405"));

        let (mut server, _quiet) = pair().await;
        let started = std::time::Instant::now();
        assert!(
            negotiate(&mut server, Duration::from_millis(300))
                .await
                .is_none()
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn rejects_unknown_protocols_and_auth_only_socks() {
        let (mut server, mut client) = pair().await;
        client.write_all(&[0x16, 0x03, 0x01]).await.unwrap();
        assert!(
            negotiate(&mut server, Duration::from_secs(5))
                .await
                .is_none()
        );

        let (mut server, mut client) = pair().await;
        client.write_all(&[5, 1, 2]).await.unwrap(); // username/password only
        assert!(
            negotiate(&mut server, Duration::from_secs(5))
                .await
                .is_none()
        );
        let mut auth = [0u8; 2];
        client.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, [5, 0xFF]);
    }
}
