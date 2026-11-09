//! Fail-open and back-off policy (port of `src/RecoveryPolicy.cpp`).

use std::collections::VecDeque;
use std::sync::Mutex;

pub const MAX_WINDIVERT_READ_RETRIES: u32 = 3;
pub const RESTART_WINDOW_MS: u64 = 10 * 60 * 1000;
pub const MAX_AUTOMATIC_RESTARTS: u32 = 3;
pub const WORKER_UNAVAILABLE_EXIT_CODE: i32 = 3;

/// A transport error, 401/403 or 5xx is a failure; HTTP 429 is not (the Worker
/// is alive and asks us to slow down). The Worker only latches as unavailable
/// after this many failures with no success in between, each within
/// `WORKER_FAILURE_GAP_MS` of the previous, spread over `WORKER_MIN_STREAK_MS`:
/// a burst of timeouts during a short blip must not shut the engine down.
pub const WORKER_FAILURE_THRESHOLD: u32 = 5;
pub const WORKER_FAILURE_GAP_MS: u64 = 60_000;
pub const WORKER_MIN_STREAK_MS: u64 = 15_000;
pub const RATE_LIMIT_DEFAULT_BACKOFF_MS: u64 = 5_000;
pub const RATE_LIMIT_MAX_BACKOFF_MS: u64 = 30_000;

// Win32 / Winsock error codes (stable ABI values).
const WSAEWOULDBLOCK: i32 = 10035;
const WSAEMSGSIZE: i32 = 10040;
const WSAECONNRESET: i32 = 10054;
const WSAETIMEDOUT: i32 = 10060;
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
const ERROR_NO_SYSTEM_RESOURCES: u32 = 1450;
const ERROR_WORKING_SET_QUOTA: u32 = 1453;
const ERROR_COMMITMENT_LIMIT: u32 = 1455;
const ERROR_NOT_ENOUGH_QUOTA: u32 = 1816;

pub fn should_continue_dns_receive(error: i32) -> bool {
    matches!(
        error,
        WSAEMSGSIZE | WSAETIMEDOUT | WSAEWOULDBLOCK | WSAECONNRESET
    )
}

pub fn is_transient_windivert_read_error(error: u32) -> bool {
    matches!(
        error,
        ERROR_NOT_ENOUGH_MEMORY
            | ERROR_NO_SYSTEM_RESOURCES
            | ERROR_WORKING_SET_QUOTA
            | ERROR_COMMITMENT_LIMIT
            | ERROR_NOT_ENOUGH_QUOTA
    )
}

pub fn should_retry_windivert_read(error: u32, completed_retries: u32) -> bool {
    is_transient_windivert_read_error(error) && completed_retries < MAX_WINDIVERT_READ_RETRIES
}

pub fn windivert_retry_delay_ms(completed_retries: u32) -> u32 {
    (50u32 << completed_retries.min(3)).min(500)
}

pub fn automatic_restart_delay_ms(attempt_number: u32) -> u32 {
    if attempt_number == 0 {
        0
    } else {
        (1000u32 << (attempt_number - 1).min(3)).min(8000)
    }
}

#[derive(Default)]
struct HealthState {
    failures: u32,
    streak_start_ms: u64,
    last_failure_ms: u64,
    backoff_until_ms: u64,
    unavailable: bool,
}

/// Latches after a sustained run of Worker failures; a successful response
/// clears the streak, so an old failure cannot poison a healthy run.
#[derive(Default)]
pub struct WorkerHealth {
    state: Mutex<HealthState>,
}

impl WorkerHealth {
    fn lock(&self) -> std::sync::MutexGuard<'_, HealthState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// `http_status < 0` is a transport failure; `retry_after_seconds` is the
    /// Retry-After of a 429 (0 = absent). Returns whether the Worker is latched.
    pub fn observe(&self, http_status: i32, now_ms: u64, retry_after_seconds: u32) -> bool {
        let mut s = self.lock();
        if s.unavailable {
            return true;
        }
        if http_status == 429 {
            // Alive but rate limiting us: neither a failure nor proof of recovery.
            let requested = if retry_after_seconds != 0 {
                u64::from(retry_after_seconds) * 1000
            } else {
                RATE_LIMIT_DEFAULT_BACKOFF_MS
            };
            s.backoff_until_ms = s
                .backoff_until_ms
                .max(now_ms + requested.min(RATE_LIMIT_MAX_BACKOFF_MS));
            return false;
        }
        let failed =
            http_status < 0 || http_status == 401 || http_status == 403 || http_status >= 500;
        if !failed {
            s.failures = 0;
            return false;
        }
        if s.failures == 0 || now_ms - s.last_failure_ms > WORKER_FAILURE_GAP_MS {
            s.failures = 0;
            s.streak_start_ms = now_ms;
        }
        s.last_failure_ms = now_ms;
        s.failures += 1;
        s.unavailable = s.failures >= WORKER_FAILURE_THRESHOLD
            && now_ms - s.streak_start_ms >= WORKER_MIN_STREAK_MS;
        s.unavailable
    }

    pub fn unavailable(&self) -> bool {
        self.lock().unavailable
    }

    /// True while a 429 told us to hold off; callers should not hit the Worker.
    pub fn backing_off(&self, now_ms: u64) -> bool {
        now_ms < self.lock().backoff_until_ms
    }
}

/// Sliding-window restart budget. `consume` returns a one-based attempt
/// number, or 0 when another automatic restart would create a crash loop.
#[derive(Debug)]
pub struct RestartBudget {
    max_attempts: u32,
    window_ms: u64,
    attempts: VecDeque<u64>,
}

impl Default for RestartBudget {
    fn default() -> Self {
        Self::new(MAX_AUTOMATIC_RESTARTS, RESTART_WINDOW_MS)
    }
}

impl RestartBudget {
    pub fn new(max_attempts: u32, window_ms: u64) -> Self {
        Self {
            max_attempts: max_attempts.max(1),
            window_ms: window_ms.max(1),
            attempts: VecDeque::new(),
        }
    }

    pub fn consume(&mut self, now_ms: u64) -> u32 {
        while self
            .attempts
            .front()
            .is_some_and(|&first| now_ms - first >= self.window_ms)
        {
            self.attempts.pop_front();
        }
        if self.attempts.len() as u32 >= self.max_attempts {
            return 0;
        }
        self.attempts.push_back(now_ms);
        self.attempts.len() as u32
    }

    pub fn reset(&mut self) {
        self.attempts.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ERROR_INVALID_HANDLE: u32 = 6;

    #[test]
    fn retries_transient_windivert_errors_only() {
        assert!(should_retry_windivert_read(ERROR_NO_SYSTEM_RESOURCES, 0));
        assert!(should_retry_windivert_read(ERROR_NO_SYSTEM_RESOURCES, 2));
        assert!(!should_retry_windivert_read(ERROR_NO_SYSTEM_RESOURCES, 3));
        assert!(!should_retry_windivert_read(ERROR_INVALID_HANDLE, 0));
    }

    #[test]
    fn uses_bounded_backoff() {
        assert_eq!(windivert_retry_delay_ms(0), 50);
        assert_eq!(windivert_retry_delay_ms(1), 100);
        assert_eq!(windivert_retry_delay_ms(2), 200);
        assert_eq!(windivert_retry_delay_ms(20), 400);
        assert_eq!(automatic_restart_delay_ms(1), 1000);
        assert_eq!(automatic_restart_delay_ms(2), 2000);
        assert_eq!(automatic_restart_delay_ms(3), 4000);
    }

    #[test]
    fn stops_restart_loops_inside_window() {
        let mut budget = RestartBudget::new(3, 1000);
        assert_eq!(budget.consume(100), 1);
        assert_eq!(budget.consume(200), 2);
        assert_eq!(budget.consume(300), 3);
        assert_eq!(budget.consume(400), 0);
        assert_eq!(budget.consume(1100), 3);
        budget.reset();
        assert_eq!(budget.consume(1101), 1);
    }

    #[test]
    fn worker_health_trips_on_sustained_failures_and_stays_open() {
        let health = WorkerHealth::default();
        // A burst of failures inside a short blip is not enough...
        for (status, at) in [
            (-1, 1000),
            (503, 1100),
            (-1, 1200),
            (401, 1300),
            (-1, 1400),
            (-1, 1500),
        ] {
            assert!(!health.observe(status, at, 0));
        }
        assert!(!health.unavailable());
        // ...it has to persist for WORKER_MIN_STREAK_MS without a success.
        assert!(health.observe(-1, 1000 + WORKER_MIN_STREAK_MS, 0));
        assert!(health.unavailable());
        assert!(health.observe(200, 40_000, 0));
    }

    #[test]
    fn worker_health_resets_after_success_or_quiet_period() {
        let health = WorkerHealth::default();
        for at in (100..500).step_by(100) {
            assert!(!health.observe(-1, at, 0));
        }
        assert!(!health.observe(200, 600, 0)); // success clears the streak
        for at in (700..1100).step_by(100) {
            assert!(!health.observe(-1, at, 0));
        }
        // A long quiet gap starts a fresh streak instead of extending the old one.
        let later = 1000 + WORKER_FAILURE_GAP_MS + 1;
        for i in 0..4 {
            assert!(!health.observe(-1, later + i, 0));
        }
        assert!(!health.unavailable());
        // 404 is a healthy answer (NXDOMAIN-style), not a failure.
        assert!(!health.observe(404, later + 10, 0));
        for i in 0..4 {
            assert!(!health.observe(500, later + 20 + i, 0));
        }
        assert!(!health.unavailable());
    }

    #[test]
    fn worker_health_treats_rate_limiting_as_backoff_not_failure() {
        let health = WorkerHealth::default();
        // 429s never latch, however many arrive.
        for i in 0..50 {
            assert!(!health.observe(429, 1000 + i * 1000, 0));
        }
        assert!(!health.unavailable());

        let backoff = WorkerHealth::default();
        assert!(!backoff.backing_off(0));
        assert!(!backoff.observe(429, 10_000, 7));
        assert!(backoff.backing_off(10_000));
        assert!(backoff.backing_off(16_999));
        assert!(!backoff.backing_off(17_000));

        // Default when Retry-After is absent, and a hostile value is capped.
        let defaults = WorkerHealth::default();
        defaults.observe(429, 0, 0);
        assert!(defaults.backing_off(RATE_LIMIT_DEFAULT_BACKOFF_MS - 1));
        assert!(!defaults.backing_off(RATE_LIMIT_DEFAULT_BACKOFF_MS));
        let capped = WorkerHealth::default();
        capped.observe(429, 0, 86_400);
        assert!(capped.backing_off(RATE_LIMIT_MAX_BACKOFF_MS - 1));
        assert!(!capped.backing_off(RATE_LIMIT_MAX_BACKOFF_MS));
    }

    #[test]
    fn dns_receive_continues_only_on_benign_errors() {
        assert!(should_continue_dns_receive(WSAEMSGSIZE));
        assert!(should_continue_dns_receive(WSAECONNRESET));
        assert!(!should_continue_dns_receive(10038)); // WSAENOTSOCK
    }
}
