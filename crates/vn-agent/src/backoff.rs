//! Exponential reconnect backoff with jitter.

use std::time::Duration;

/// Shortest reconnect delay.
pub const MIN_DELAY: Duration = Duration::from_secs(1);

/// Longest reconnect delay.
pub const MAX_DELAY: Duration = Duration::from_secs(60);

/// Delays that double from `min` up to `max`. Each delay is drawn uniformly from the
/// upper half of its step ("equal jitter"), so agents that lost the server at the same
/// moment spread out, while no delay is shorter than `min`.
#[derive(Debug, Clone)]
pub struct Backoff {
    min: Duration,
    max: Duration,
    attempt: u32,
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new(MIN_DELAY, MAX_DELAY)
    }
}

impl Backoff {
    pub fn new(min: Duration, max: Duration) -> Self {
        assert!(!min.is_zero() && min <= max);
        Self {
            min,
            max,
            attempt: 0,
        }
    }

    /// The next delay, using the operating system's random number generator.
    pub fn next_delay(&mut self) -> Duration {
        let mut bytes = [0u8; 8];
        // Without randomness the delay is still bounded; it just loses its jitter.
        let unit = match getrandom::fill(&mut bytes) {
            Ok(()) => (u64::from_le_bytes(bytes) >> 11) as f64 / (1u64 << 53) as f64,
            Err(_) => 1.0,
        };
        self.next_delay_with(unit)
    }

    /// The next delay for a random `unit` in `[0, 1]`.
    pub fn next_delay_with(&mut self, unit: f64) -> Duration {
        let step = self
            .min
            .checked_mul(1u32.checked_shl(self.attempt).unwrap_or(u32::MAX))
            .unwrap_or(self.max)
            .min(self.max);
        self.attempt = self.attempt.saturating_add(1);
        step.mul_f64(0.5 + 0.5 * unit.clamp(0.0, 1.0)).max(self.min)
    }

    /// Starts again from `min`, after a connection that worked.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(s: f64) -> Duration {
        Duration::from_secs_f64(s)
    }

    #[test]
    fn delays_double_up_to_the_maximum() {
        let mut backoff = Backoff::default();
        let delays: Vec<Duration> = (0..9).map(|_| backoff.next_delay_with(1.0)).collect();
        assert_eq!(
            delays,
            [1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 60.0, 60.0, 60.0].map(secs)
        );
    }

    #[test]
    fn jitter_stays_in_the_upper_half_and_above_the_minimum() {
        let mut low = Backoff::default();
        let delays: Vec<Duration> = (0..8).map(|_| low.next_delay_with(0.0)).collect();
        assert_eq!(
            delays,
            [1.0, 1.0, 2.0, 4.0, 8.0, 16.0, 30.0, 30.0].map(secs)
        );
        let mut backoff = Backoff::default();
        for _ in 0..100 {
            let delay = backoff.next_delay();
            assert!(delay >= MIN_DELAY && delay <= MAX_DELAY, "{delay:?}");
        }
    }

    #[test]
    fn reset_starts_over_and_many_attempts_do_not_overflow() {
        let mut backoff = Backoff::default();
        for _ in 0..1000 {
            assert!(backoff.next_delay_with(1.0) <= MAX_DELAY);
        }
        backoff.reset();
        assert_eq!(backoff.next_delay_with(1.0), MIN_DELAY);
    }
}
