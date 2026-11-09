//! Happy Eyeballs connector (port of `tcp::connectAny`, `src/TcpConnect.cpp`).
//!
//! Attempts start 250 ms apart (RFC 8305), at most eight in flight, inside one
//! total budget. Only a live attempt earns the stagger: an address that fails
//! at once (no IPv6 route) does not delay the next one, and any failure starts
//! the next attempt immediately.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep_until, timeout_at};

pub const ATTEMPT_DELAY: Duration = Duration::from_millis(250);
pub const MAX_PARALLEL_ATTEMPTS: usize = 8;

pub fn is_ip_literal(value: &str) -> bool {
    value.parse::<IpAddr>().is_ok()
}

/// Races connections to `addresses` (in the given order). Returns the first
/// stream that connects and the address it reached.
pub async fn connect_any(
    addresses: &[IpAddr],
    port: u16,
    attempt_delay: Duration,
    total_timeout: Duration,
) -> Option<(TcpStream, IpAddr)> {
    let deadline = Instant::now() + total_timeout;
    let mut pending = addresses.iter().copied();
    let mut in_flight: JoinSet<(IpAddr, std::io::Result<TcpStream>)> = JoinSet::new();
    let mut next_start = Instant::now();
    let mut exhausted = addresses.is_empty();

    loop {
        if !exhausted && in_flight.len() < MAX_PARALLEL_ATTEMPTS && Instant::now() >= next_start {
            match pending.next() {
                Some(address) => {
                    in_flight.spawn(async move {
                        (
                            address,
                            TcpStream::connect(SocketAddr::new(address, port)).await,
                        )
                    });
                    next_start = Instant::now() + attempt_delay;
                    continue;
                }
                None => exhausted = true,
            }
        }
        if in_flight.is_empty() && exhausted {
            return None;
        }

        let can_start_more = !exhausted && in_flight.len() < MAX_PARALLEL_ATTEMPTS;
        let wake = if can_start_more {
            next_start.min(deadline)
        } else {
            deadline
        };
        tokio::select! {
            joined = in_flight.join_next(), if !in_flight.is_empty() => {
                match joined {
                    Some(Ok((address, Ok(stream)))) => return Some((stream, address)),
                    Some(Ok((address, Err(error)))) => {
                        tracing::debug!("Baglanti basarisiz: {address} ({error})");
                        next_start = Instant::now(); // a failure starts the next attempt now
                    }
                    _ => {}
                }
            }
            () = sleep_until(wake) => {
                if Instant::now() >= deadline {
                    return None;
                }
            }
        }
        if Instant::now() >= deadline {
            return None;
        }
    }
}

/// `connect_any` with the engine's defaults, bounded by `total_timeout`.
pub async fn connect_with_timeout(
    addresses: &[IpAddr],
    port: u16,
    total_timeout: Duration,
) -> Option<(TcpStream, IpAddr)> {
    let deadline = Instant::now() + total_timeout;
    timeout_at(
        deadline,
        connect_any(addresses, port, ATTEMPT_DELAY, total_timeout),
    )
    .await
    .ok()
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn reaches_a_live_listener_after_a_dead_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Nobody listens on ::1:port. Windows retries a refused loopback SYN
        // for ~2 s, so the race must start the live address after the stagger
        // instead of waiting for that attempt to fail.
        let started = std::time::Instant::now();
        let (stream, address) = connect_any(
            &["::1".parse().unwrap(), "127.0.0.1".parse().unwrap()],
            port,
            Duration::from_millis(300),
            Duration::from_secs(5),
        )
        .await
        .expect("connects");
        assert_eq!(address, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert!(stream.peer_addr().is_ok());
        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "the second attempt did not start after the stagger"
        );
    }

    #[tokio::test]
    async fn gives_up_when_nothing_connects() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        assert!(
            connect_any(
                &["127.0.0.1".parse().unwrap()],
                port,
                ATTEMPT_DELAY,
                Duration::from_secs(3)
            )
            .await
            .is_none()
        );
        assert!(
            connect_any(&[], port, ATTEMPT_DELAY, Duration::from_secs(1))
                .await
                .is_none()
        );
    }

    #[test]
    fn recognises_ip_literals() {
        assert!(is_ip_literal("1.2.3.4"));
        assert!(is_ip_literal("2001:db8::1"));
        assert!(!is_ip_literal("example.com"));
        assert!(!is_ip_literal(""));
    }
}
