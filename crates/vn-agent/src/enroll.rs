//! Enrollment: trading a single-use enrollment token for a registered identity.

use anyhow::{Context, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use uuid::Uuid;
use vn_core::{
    AGENT_PROTOCOL_VERSIONS, AgentKind, ENROLLMENT_TOKEN_PREFIX, EnrollRequest,
    enrollment_signing_message,
};

use crate::client::ServerClient;
use crate::identity::{Identity, key_id};

/// The token ID inside an enrollment token string (`vn_enroll_<token ID>_<secret>`).
pub fn token_id(token: &str) -> anyhow::Result<Uuid> {
    let id = token
        .strip_prefix(ENROLLMENT_TOKEN_PREFIX)
        .and_then(|rest| rest.get(..32))
        .filter(|id| id.bytes().all(|b| b.is_ascii_hexdigit()))
        .context("the enrollment token is malformed: expected `vn_enroll_<token ID>_<secret>`")?;
    Ok(Uuid::try_parse(id)?)
}

/// Generates a key pair and enrolls it with `token`. The returned identity is not
/// stored yet.
pub async fn enroll(
    server: &ServerClient,
    token: &str,
    cluster_fingerprint: &str,
) -> anyhow::Result<Identity> {
    let token_id = token_id(token)?;
    let info = server.info().await?;
    if !info
        .protocol_versions
        .iter()
        .any(|v| AGENT_PROTOCOL_VERSIONS.contains(v))
    {
        bail!(
            "the server supports agent protocol versions {:?}, this agent {:?}",
            info.protocol_versions,
            AGENT_PROTOCOL_VERSIONS
        );
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).context("failed to generate a key")?;
    let key = SigningKey::from_bytes(&seed);
    let public_key = key.verifying_key().to_bytes();
    let message = enrollment_signing_message(info.installation_id, token_id, &public_key);
    let request = EnrollRequest {
        token: token.to_owned(),
        installation_id: info.installation_id,
        kind: AgentKind::Kubernetes,
        public_key: URL_SAFE_NO_PAD.encode(public_key),
        signature: URL_SAFE_NO_PAD.encode(key.sign(&message).to_bytes()),
        agent_version: crate::VERSION.to_owned(),
        protocol_versions: AGENT_PROTOCOL_VERSIONS.to_vec(),
        cluster_fingerprint: cluster_fingerprint.to_owned(),
    };
    let enrolled = server.enroll(&request).await?;
    if enrolled.key_id != key_id(&key) || enrolled.installation_id != info.installation_id {
        bail!("the server's enrollment response does not match the request");
    }
    Ok(Identity::new(&enrolled, &key, server.base().as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_token_id() {
        let id = token_id(&format!(
            "vn_enroll_0123456789abcdef0123456789abcdef_{}",
            "A".repeat(43)
        ))
        .unwrap();
        assert_eq!(
            id,
            Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef)
        );
        for bad in ["", "vn_enroll_", "vn_enroll_xyz", "token"] {
            assert!(token_id(bad).is_err(), "{bad}");
        }
    }
}
