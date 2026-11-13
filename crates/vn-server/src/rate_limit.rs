//! In-process rate limiting by client address.
//!
//! A token bucket per client: each attempt takes a token up front, and the caller hands it
//! back when the attempt succeeds, so only failures count against the limit while
//! concurrent attempts still cannot exceed it. IPv6 clients are grouped by /64, because a
//! single host commonly controls a whole /64. State lives in this process, which matches
//! the single-replica first release; with several replicas each enforces its own limit.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Clients tracked at once. When full, buckets that have refilled completely are
/// forgotten; if none have, new clients are refused until some do.
const MAX_CLIENTS: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RateLimit {
    /// Attempts allowed in a burst.
    pub(crate) burst: u32,
    /// Time to regain one attempt.
    pub(crate) refill: Duration,
}

/// Key for a client: an IPv4 address, an IPv6 /64, or unknown (no connection info).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ClientKey {
    V4(u32),
    V6(u64),
    Unknown,
}

impl ClientKey {
    fn of(addr: Option<IpAddr>) -> Self {
        match addr.map(|addr| addr.to_canonical()) {
            Some(IpAddr::V4(v4)) => ClientKey::V4(v4.to_bits()),
            Some(IpAddr::V6(v6)) => ClientKey::V6((v6.to_bits() >> 64) as u64),
            None => ClientKey::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    updated: Instant,
}

/// The outcome of [`RateLimiter::acquire`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Acquire {
    Allowed,
    /// Refused; retry after this long.
    Limited {
        retry_after: Duration,
    },
}

#[derive(Debug)]
pub(crate) struct RateLimiter {
    limit: RateLimit,
    buckets: Mutex<HashMap<ClientKey, Bucket>>,
}

impl RateLimiter {
    pub(crate) fn new(limit: RateLimit) -> Self {
        assert!(limit.burst > 0 && !limit.refill.is_zero());
        Self {
            limit,
            buckets: Mutex::default(),
        }
    }

    /// Takes one attempt for `addr`.
    pub(crate) fn acquire(&self, addr: Option<IpAddr>) -> Acquire {
        self.acquire_at(ClientKey::of(addr), Instant::now())
    }

    /// Returns the attempt taken by a successful [`RateLimiter::acquire`].
    pub(crate) fn refund(&self, addr: Option<IpAddr>) {
        self.refund_at(ClientKey::of(addr), Instant::now());
    }

    fn acquire_at(&self, key: ClientKey, now: Instant) -> Acquire {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if !buckets.contains_key(&key) && buckets.len() >= MAX_CLIENTS {
            buckets.retain(|_, bucket| self.refilled(*bucket, now) < f64::from(self.limit.burst));
            if buckets.len() >= MAX_CLIENTS {
                return Acquire::Limited {
                    retry_after: self.limit.refill,
                };
            }
        }
        let burst = f64::from(self.limit.burst);
        let bucket = buckets.entry(key).or_insert(Bucket {
            tokens: burst,
            updated: now,
        });
        bucket.tokens = self.refilled(*bucket, now);
        bucket.updated = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Acquire::Allowed
        } else {
            let missing = 1.0 - bucket.tokens;
            Acquire::Limited {
                retry_after: self.limit.refill.mul_f64(missing),
            }
        }
    }

    fn refund_at(&self, key: ClientKey, now: Instant) {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(bucket) = buckets.get_mut(&key) {
            bucket.tokens = (self.refilled(*bucket, now) + 1.0).min(f64::from(self.limit.burst));
            bucket.updated = now;
        }
    }

    /// Tokens in `bucket` at `now`, after refilling.
    fn refilled(&self, bucket: Bucket, now: Instant) -> f64 {
        let elapsed = now.saturating_duration_since(bucket.updated);
        let gained = elapsed.as_secs_f64() / self.limit.refill.as_secs_f64();
        (bucket.tokens + gained).min(f64::from(self.limit.burst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: RateLimit = RateLimit {
        burst: 3,
        refill: Duration::from_secs(10),
    };

    fn key(s: &str) -> ClientKey {
        ClientKey::of(Some(s.parse().unwrap()))
    }

    #[test]
    fn allows_a_burst_then_limits() {
        let limiter = RateLimiter::new(LIMIT);
        let now = Instant::now();
        for _ in 0..3 {
            assert_eq!(limiter.acquire_at(key("192.0.2.1"), now), Acquire::Allowed);
        }
        assert_eq!(
            limiter.acquire_at(key("192.0.2.1"), now),
            Acquire::Limited {
                retry_after: Duration::from_secs(10)
            }
        );
        // Other clients have their own bucket.
        assert_eq!(limiter.acquire_at(key("192.0.2.2"), now), Acquire::Allowed);
    }

    #[test]
    fn refills_over_time() {
        let limiter = RateLimiter::new(LIMIT);
        let start = Instant::now();
        for _ in 0..3 {
            limiter.acquire_at(key("192.0.2.1"), start);
        }
        let later = start + Duration::from_secs(5);
        assert_eq!(
            limiter.acquire_at(key("192.0.2.1"), later),
            Acquire::Limited {
                retry_after: Duration::from_secs(5)
            }
        );
        let later = start + Duration::from_secs(10);
        assert_eq!(
            limiter.acquire_at(key("192.0.2.1"), later),
            Acquire::Allowed
        );
    }

    #[test]
    fn refunds_successful_attempts() {
        let limiter = RateLimiter::new(LIMIT);
        let now = Instant::now();
        for _ in 0..10 {
            assert_eq!(limiter.acquire_at(key("192.0.2.1"), now), Acquire::Allowed);
            limiter.refund_at(key("192.0.2.1"), now);
        }
        // Refunds never raise a bucket above its burst.
        limiter.refund_at(key("192.0.2.1"), now);
        for _ in 0..3 {
            assert_eq!(limiter.acquire_at(key("192.0.2.1"), now), Acquire::Allowed);
        }
        assert!(matches!(
            limiter.acquire_at(key("192.0.2.1"), now),
            Acquire::Limited { .. }
        ));
    }

    #[test]
    fn groups_ipv6_by_slash_64() {
        assert_eq!(key("2001:db8:1:2::1"), key("2001:db8:1:2:ffff::9"));
        assert_ne!(key("2001:db8:1:2::1"), key("2001:db8:1:3::1"));
        assert_eq!(key("::ffff:192.0.2.1"), key("192.0.2.1"));
    }
}
