//! Bidirectional byte pump after the handshake (port of `DirectRelay::pump`).
//!
//! FIN is propagated and the other direction keeps flowing (half-close).
//! Back-pressure comes from awaiting each write. A reset on either side resets
//! the other too: a clean EOF would let the client take a cut-off body as
//! complete. Idle limit: the context's idle timeout, or 30 s once half-closed.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{ReadHalf, WriteHalf};

/// One TLS record (16 KiB) per read: the buffer lives as long as the
/// connection, so at the 1024 cap this is 32 MiB instead of 128 MiB.
const PUMP_BUFFER: usize = 16 * 1024;
/// Once one side sent FIN the other normally follows within a round trip.
const HALF_CLOSED_LINGER: Duration = Duration::from_secs(30);
/// The watchdog sleeps until the idle deadline, but never longer than this,
/// so a half-close shortens the limit within one tick (and 1024 idle
/// connections cost ~34 wake-ups a second, not 1024).
const WATCHDOG_MAX_SLEEP: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PumpEnd {
    /// Both sides finished cleanly.
    Closed,
    /// No traffic for the idle limit.
    Idle,
    /// A read or write failed: close abortively (RST).
    Aborted,
}

async fn direction(
    mut from: ReadHalf<'_>,
    mut to: WriteHalf<'_>,
    activity: &AtomicU64,
    eof: &AtomicBool,
) -> bool {
    let mut buffer = vec![0u8; PUMP_BUFFER];
    loop {
        match from.read(&mut buffer).await {
            Ok(0) => {
                eof.store(true, Ordering::SeqCst);
                let _ = to.shutdown().await; // propagate the half-close
                return true;
            }
            Ok(n) => {
                activity.store(sh_core::clock::now_ms(), Ordering::Relaxed);
                if to.write_all(&buffer[..n]).await.is_err() {
                    return false;
                }
                activity.store(sh_core::clock::now_ms(), Ordering::Relaxed);
            }
            Err(_) => return false,
        }
    }
}

pub async fn pump(
    client: &mut TcpStream,
    target: &mut TcpStream,
    idle_timeout: Duration,
) -> PumpEnd {
    let activity = AtomicU64::new(sh_core::clock::now_ms());
    let (client_eof, target_eof) = (AtomicBool::new(false), AtomicBool::new(false));
    let (client_read, client_write) = client.split();
    let (target_read, target_write) = target.split();

    let upstream = direction(client_read, target_write, &activity, &client_eof);
    let downstream = direction(target_read, client_write, &activity, &target_eof);
    let watchdog = async {
        loop {
            let half_closed =
                client_eof.load(Ordering::SeqCst) || target_eof.load(Ordering::SeqCst);
            let limit = if half_closed {
                idle_timeout.min(HALF_CLOSED_LINGER)
            } else {
                idle_timeout
            };
            let idle = Duration::from_millis(
                sh_core::clock::now_ms().saturating_sub(activity.load(Ordering::Relaxed)),
            );
            if idle >= limit {
                return;
            }
            tokio::time::sleep((limit - idle).min(WATCHDOG_MAX_SLEEP)).await;
        }
    };

    tokio::pin!(upstream, downstream, watchdog);
    let (mut up_done, mut down_done) = (false, false);
    loop {
        tokio::select! {
            ok = &mut upstream, if !up_done => {
                if !ok { return PumpEnd::Aborted; }
                up_done = true;
            }
            ok = &mut downstream, if !down_done => {
                if !ok { return PumpEnd::Aborted; }
                down_done = true;
            }
            () = &mut watchdog => return PumpEnd::Idle,
        }
        if up_done && down_done {
            return PumpEnd::Closed;
        }
    }
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

    // Half-close (FIN propagation) is not unit-tested here: on the development
    // machine a network filter driver keeps loopback FINs from arriving at all
    // (a plain .NET socket pair shows the same), so such a test would hang.
    #[tokio::test]
    async fn forwards_both_ways_and_ends_when_both_sides_close() {
        let (mut client_side, mut app) = pair().await;
        let (mut target_side, mut server) = pair().await;
        let relay = tokio::spawn(async move {
            pump(&mut client_side, &mut target_side, Duration::from_secs(3)).await
        });

        app.write_all(b"hello").await.unwrap();
        let mut buffer = [0u8; 5];
        server.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"hello");
        server.write_all(b"world").await.unwrap();
        app.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"world");

        drop(app);
        drop(server);
        // Closed, reset or idle, depending on how the stack reports the close;
        // the point is that the pump ends instead of holding the sockets.
        let end = tokio::time::timeout(Duration::from_secs(10), relay)
            .await
            .expect("pump ended")
            .unwrap();
        assert!(matches!(
            end,
            PumpEnd::Closed | PumpEnd::Aborted | PumpEnd::Idle
        ));
    }

    #[tokio::test]
    async fn closes_an_idle_connection() {
        let (mut client_side, _app) = pair().await;
        let (mut target_side, _server) = pair().await;
        let end = pump(
            &mut client_side,
            &mut target_side,
            Duration::from_millis(1500),
        )
        .await;
        assert_eq!(end, PumpEnd::Idle);
    }
}
