//! Enrollment token strings.
//!
//! A token reads `vn_enroll_<token ID>_<secret>`: the prefix makes it recognizable (for
//! example to secret scanners), the token ID is the public ID as 32 lowercase hex digits,
//! and the secret is 256 random bits in URL-safe base64 without padding. Only the
//! SHA-256 of the secret is stored.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use uuid::Uuid;
use vn_core::ENROLLMENT_TOKEN_PREFIX;

use crate::auth::hash_token;

/// Length of the encoded secret: 32 bytes in base64 without padding.
const SECRET_LEN: usize = 43;

/// Formats the token string for `id` and `secret`. The result is secret: do not log it.
pub(crate) fn format(id: Uuid, secret: &str) -> String {
    format!("{ENROLLMENT_TOKEN_PREFIX}{}_{secret}", id.simple())
}

/// A token string split into its parts.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ParsedToken<'a> {
    pub(crate) id: Uuid,
    secret: &'a str,
}

impl ParsedToken<'_> {
    /// SHA-256 of the secret, as stored.
    pub(crate) fn secret_hash(&self) -> Vec<u8> {
        hash_token(self.secret)
    }
}

/// Splits a token string, or returns `None` when it is not shaped like one.
pub(crate) fn parse(token: &str) -> Option<ParsedToken<'_>> {
    let rest = token.strip_prefix(ENROLLMENT_TOKEN_PREFIX)?;
    let (id, secret) = rest.split_once('_')?;
    let id_is_hex = id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !id_is_hex || secret.len() != SECRET_LEN {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(secret).ok()?;
    if decoded.len() != 32 {
        return None;
    }
    Some(ParsedToken {
        id: Uuid::try_parse(id).ok()?,
        secret,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Token;

    #[test]
    fn formatted_tokens_parse_back() {
        let secret = Token::generate().unwrap();
        let id = Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
        let token = format(id, secret.expose());
        assert!(token.starts_with("vn_enroll_0123456789abcdef0123456789abcdef_"));
        let parsed = parse(&token).unwrap();
        assert_eq!(parsed.id, id);
        assert_eq!(parsed.secret_hash(), secret.hash());
    }

    #[test]
    fn secrets_may_contain_underscores() {
        let id = Uuid::from_u128(1);
        let secret = format!("_{}", "A".repeat(42));
        let token = format(id, &secret);
        let parsed = parse(&token).unwrap();
        assert_eq!(parsed.id, id);
        assert_eq!(parsed.secret, secret);
    }

    #[test]
    fn rejects_malformed_tokens() {
        let good = format(Uuid::from_u128(1), &"A".repeat(43));
        assert!(parse(&good).is_some());
        for bad in [
            String::new(),
            good.replacen("vn_enroll_", "vn_enrol_", 1),
            good.replacen("vn_enroll_0", "vn_enroll_G", 1),
            good.replacen("vn_enroll_0", "vn_enroll_A", 1),
            format!("{good}A"),
            good[..good.len() - 1].to_owned(),
            good.replace('A', "+"),
            format!("vn_enroll_{}", "0".repeat(32)),
        ] {
            assert_eq!(parse(&bad), None, "{bad}");
        }
    }
}
