//! Server-side browser sessions.
//!
//! The browser holds a random 256-bit token in an HttpOnly cookie. PostgreSQL stores only
//! its SHA-256 hash, so a database leak does not reveal usable session tokens.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, TimeDelta, Utc};
use sha2::{Digest, Sha256};

/// Activity is written back at most this often, to keep reads from turning into writes.
pub(crate) const TOUCH_INTERVAL: TimeDelta = TimeDelta::seconds(60);

/// Longest cookie value accepted as a session or login token. Real tokens are 43 bytes.
const MAX_TOKEN_LEN: usize = 128;

/// A newly generated secret token, for a session or a login attempt.
pub(crate) struct Token(String);

impl Token {
    /// Generates 32 bytes from the operating system's CSPRNG.
    pub(crate) fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)?;
        Ok(Self(URL_SAFE_NO_PAD.encode(bytes)))
    }

    /// The cookie value. Do not log it.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }

    pub(crate) fn hash(&self) -> Vec<u8> {
        hash_token(&self.0)
    }
}

/// SHA-256 of a token as stored in the database.
pub(crate) fn hash_token(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// Returns the cookie value when it could be a token, so oversized input is not hashed.
pub(crate) fn plausible_token(value: &str) -> Option<&str> {
    (!value.is_empty() && value.len() <= MAX_TOKEN_LEN).then_some(value)
}

/// Timestamps that decide whether a stored session is still usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionTimes {
    pub(crate) last_seen_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionStatus {
    Active,
    /// Ended by sign-out.
    Revoked,
    /// Past its absolute lifetime.
    Expired,
    /// No request within the idle timeout.
    Idle,
}

impl SessionTimes {
    pub(crate) fn status(&self, now: DateTime<Utc>, idle_timeout: TimeDelta) -> SessionStatus {
        if self.revoked_at.is_some() {
            SessionStatus::Revoked
        } else if now >= self.expires_at {
            SessionStatus::Expired
        } else if now >= self.last_seen_at + idle_timeout {
            SessionStatus::Idle
        } else {
            SessionStatus::Active
        }
    }

    /// Whether `last_seen_at` is old enough to be worth updating.
    pub(crate) fn needs_touch(&self, now: DateTime<Utc>) -> bool {
        now - self.last_seen_at >= TOUCH_INTERVAL
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(minutes: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000, 0).unwrap() + TimeDelta::minutes(minutes)
    }

    fn times(last_seen: i64, expires: i64) -> SessionTimes {
        SessionTimes {
            last_seen_at: at(last_seen),
            expires_at: at(expires),
            revoked_at: None,
        }
    }

    const IDLE: TimeDelta = TimeDelta::minutes(30);

    #[test]
    fn active_within_idle_and_absolute_limits() {
        assert_eq!(times(0, 720).status(at(29), IDLE), SessionStatus::Active);
    }

    #[test]
    fn idle_timeout_ends_session() {
        assert_eq!(times(0, 720).status(at(30), IDLE), SessionStatus::Idle);
        assert_eq!(times(100, 720).status(at(129), IDLE), SessionStatus::Active);
    }

    #[test]
    fn absolute_expiry_wins_over_recent_activity() {
        assert_eq!(
            times(715, 720).status(at(720), IDLE),
            SessionStatus::Expired
        );
        assert_eq!(times(715, 720).status(at(719), IDLE), SessionStatus::Active);
    }

    #[test]
    fn revocation_ends_session_immediately() {
        let revoked = SessionTimes {
            revoked_at: Some(at(1)),
            ..times(0, 720)
        };
        assert_eq!(revoked.status(at(2), IDLE), SessionStatus::Revoked);
    }

    #[test]
    fn touches_at_most_once_per_interval() {
        let session = times(0, 720);
        assert!(!session.needs_touch(at(0) + TimeDelta::seconds(59)));
        assert!(session.needs_touch(at(1)));
    }

    #[test]
    fn tokens_are_random_and_stored_only_as_hashes() {
        let a = Token::generate().unwrap();
        let b = Token::generate().unwrap();
        assert_ne!(a.expose(), b.expose());
        assert_eq!(a.expose().len(), 43);
        assert_eq!(a.hash().len(), 32);
        assert_eq!(a.hash(), hash_token(a.expose()));
        assert_ne!(a.hash(), a.expose().as_bytes());
    }

    #[test]
    fn rejects_implausible_cookie_values() {
        assert_eq!(plausible_token(""), None);
        assert_eq!(plausible_token(&"x".repeat(129)), None);
        assert_eq!(plausible_token("abc"), Some("abc"));
    }
}
