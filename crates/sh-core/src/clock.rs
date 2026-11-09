//! The engine's monotonic clock (the role GetTickCount64 plays in the C++
//! build). Registries filled by the packet loop and read by the relay must use
//! the same scale, so everything takes its "now" from here.

use std::sync::OnceLock;
use std::time::Instant;

/// Milliseconds since the first call in this process; never 0, so 0 can keep
/// meaning "unset".
pub fn now_ms() -> u64 {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    1 + ORIGIN.get_or_init(Instant::now).elapsed().as_millis() as u64
}

#[cfg(test)]
mod tests {
    #[test]
    fn is_monotonic_and_never_zero() {
        let first = super::now_ms();
        assert!(first >= 1);
        assert!(super::now_ms() >= first);
    }
}
