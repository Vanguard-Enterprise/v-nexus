//! The agent's identity: the IDs it received at enrollment and its Ed25519 private key.
//!
//! In a cluster the identity lives in the Secret [`SECRET_NAME`] in the agent's own
//! namespace, one data key per field. On a development host it lives in a JSON file with
//! mode 0600. Either way an identity is created once and never overwritten: creating one
//! where one exists fails, so two agent processes cannot silently replace each other's
//! keys.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, ObjectMeta, PostParams};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Name of the identity Secret in the agent's namespace.
pub const SECRET_NAME: &str = "vn-agent-identity";

/// Everything the agent needs to authenticate. `Debug` redacts the private key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub agent_id: Uuid,
    pub installation_id: Uuid,
    pub cluster_id: Uuid,
    pub source_id: Uuid,
    /// URL-safe base64 of the SHA-256 of the public key, without padding.
    pub key_id: String,
    /// Standard base64 of the 32-byte Ed25519 seed.
    private_key: String,
    /// The server the agent enrolled with.
    pub server_url: String,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("agent_id", &self.agent_id)
            .field("installation_id", &self.installation_id)
            .field("cluster_id", &self.cluster_id)
            .field("source_id", &self.source_id)
            .field("key_id", &self.key_id)
            .field("private_key", &"<redacted>")
            .field("server_url", &self.server_url)
            .finish()
    }
}

/// Key ID of an Ed25519 public key, as the server computes it.
pub fn key_id(key: &SigningKey) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(key.verifying_key().as_bytes()))
}

impl Identity {
    pub fn new(
        enrolled: &vn_core::EnrollResponse,
        key: &SigningKey,
        server_url: impl Into<String>,
    ) -> Self {
        Self {
            agent_id: enrolled.agent_id,
            installation_id: enrolled.installation_id,
            cluster_id: enrolled.cluster_id,
            source_id: enrolled.source_id,
            key_id: enrolled.key_id.clone(),
            private_key: STANDARD.encode(key.to_bytes()),
            server_url: server_url.into(),
        }
    }

    /// The private key. Do not log it.
    pub fn signing_key(&self) -> anyhow::Result<SigningKey> {
        let seed: [u8; 32] = STANDARD
            .decode(&self.private_key)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .context("`private_key` is not base64 of a 32-byte Ed25519 seed")?;
        Ok(SigningKey::from_bytes(&seed))
    }

    /// Checks that the stored key matches the stored key ID.
    fn validate(&self) -> anyhow::Result<()> {
        let key = self.signing_key()?;
        if key_id(&key) != self.key_id {
            bail!("`key_id` does not match `private_key`");
        }
        Ok(())
    }

    fn to_fields(&self) -> anyhow::Result<BTreeMap<String, String>> {
        let value = serde_json::to_value(self)?;
        let fields = value
            .as_object()
            .context("identity serializes to an object")?
            .iter()
            .map(|(name, value)| {
                let text = value.as_str().context("identity fields are strings")?;
                Ok((name.clone(), text.to_owned()))
            })
            .collect::<anyhow::Result<_>>()?;
        Ok(fields)
    }

    fn from_fields(fields: BTreeMap<String, String>) -> anyhow::Result<Self> {
        let object: serde_json::Map<String, serde_json::Value> = fields
            .into_iter()
            .map(|(name, value)| (name, value.into()))
            .collect();
        let identity: Identity = serde_json::from_value(object.into())?;
        identity.validate()?;
        Ok(identity)
    }
}

/// Where the identity is kept.
pub enum IdentityStore {
    /// A JSON file, for running outside a cluster.
    File(PathBuf),
    /// The Secret [`SECRET_NAME`] in `namespace`.
    Secret {
        api: Box<Api<Secret>>,
        namespace: String,
    },
}

impl fmt::Display for IdentityStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityStore::File(path) => write!(f, "file {}", path.display()),
            IdentityStore::Secret { namespace, .. } => {
                write!(f, "Secret {namespace}/{SECRET_NAME}")
            }
        }
    }
}

impl IdentityStore {
    pub fn secret(client: kube::Client, namespace: &str) -> Self {
        Self::Secret {
            api: Box::new(Api::namespaced(client, namespace)),
            namespace: namespace.to_owned(),
        }
    }

    /// The stored identity, or `None` when none has been stored yet.
    pub async fn load(&self) -> anyhow::Result<Option<Identity>> {
        let loaded = match self {
            IdentityStore::File(path) => load_file(path),
            IdentityStore::Secret { api, .. } => load_secret(api).await,
        };
        loaded.with_context(|| format!("failed to load the agent identity from {self}"))
    }

    /// Stores a new identity. Fails if one is already stored.
    pub async fn create(&self, identity: &Identity) -> anyhow::Result<()> {
        let created = match self {
            IdentityStore::File(path) => create_file(path, identity),
            IdentityStore::Secret { api, .. } => create_secret(api, identity).await,
        };
        created.with_context(|| format!("failed to store the agent identity in {self}"))
    }
}

fn load_file(path: &Path) -> anyhow::Result<Option<Identity>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            tracing::warn!(
                path = %path.display(),
                mode = format!("{:o}", mode & 0o777),
                "the identity file is readable by other users; restrict it to mode 0600"
            );
        }
    }
    let identity: Identity = serde_json::from_str(&text).context("invalid identity file")?;
    identity.validate()?;
    Ok(Some(identity))
}

fn create_file(path: &Path, identity: &Identity) -> anyhow::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            bail!("the file already exists; refusing to overwrite another identity")
        }
        Err(err) => return Err(err.into()),
    };
    let mut text = serde_json::to_string_pretty(identity)?;
    text.push('\n');
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

async fn load_secret(api: &Api<Secret>) -> anyhow::Result<Option<Identity>> {
    let Some(secret) = api.get_opt(SECRET_NAME).await? else {
        return Ok(None);
    };
    let fields = secret
        .data
        .unwrap_or_default()
        .into_iter()
        .map(|(name, ByteString(bytes))| {
            let value = String::from_utf8(bytes)
                .map_err(|_| anyhow::anyhow!("field `{name}` is not UTF-8"))?;
            Ok((name, value))
        })
        .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
    Identity::from_fields(fields).map(Some)
}

async fn create_secret(api: &Api<Secret>, identity: &Identity) -> anyhow::Result<()> {
    let data = identity
        .to_fields()?
        .into_iter()
        .map(|(name, value)| (name, ByteString(value.into_bytes())))
        .collect();
    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(SECRET_NAME.to_owned()),
            labels: Some(BTreeMap::from([(
                "app.kubernetes.io/name".to_owned(),
                "vn-agent".to_owned(),
            )])),
            ..ObjectMeta::default()
        },
        type_: Some("Opaque".to_owned()),
        data: Some(data),
        ..Secret::default()
    };
    match api.create(&PostParams::default(), &secret).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(status)) if status.code == 409 => {
            bail!("the Secret already exists; refusing to overwrite another identity")
        }
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Identity {
        let key = SigningKey::from_bytes(&[5; 32]);
        let enrolled = vn_core::EnrollResponse {
            agent_id: Uuid::from_u128(1),
            installation_id: Uuid::from_u128(2),
            cluster_id: Uuid::from_u128(3),
            source_id: Uuid::from_u128(4),
            key_id: key_id(&key),
        };
        Identity::new(&enrolled, &key, "https://vn.example.com")
    }

    fn store(dir: &tempfile::TempDir) -> (IdentityStore, PathBuf) {
        let path = dir.path().join("identity.json");
        (IdentityStore::File(path.clone()), path)
    }

    #[tokio::test]
    async fn a_file_identity_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let (store, path) = store(&dir);
        assert_eq!(store.load().await.unwrap(), None);
        store.create(&identity()).await.unwrap();
        let loaded = store.load().await.unwrap().unwrap();
        assert_eq!(loaded, identity());
        assert_eq!(
            loaded.signing_key().unwrap().to_bytes(),
            [5; 32],
            "the key survives the round trip"
        );
        let text = std::fs::read_to_string(&path).unwrap();
        for field in [
            "agent_id",
            "installation_id",
            "cluster_id",
            "source_id",
            "key_id",
            "private_key",
            "server_url",
        ] {
            assert!(text.contains(&format!("\"{field}\"")), "{text}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_identity_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let (store, path) = store(&dir);
        store.create(&identity()).await.unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[tokio::test]
    async fn an_existing_identity_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let (store, path) = store(&dir);
        store.create(&identity()).await.unwrap();
        let before = std::fs::read(&path).unwrap();
        let mut other = identity();
        other.agent_id = Uuid::from_u128(99);
        let err = store.create(&other).await.unwrap_err();
        assert!(format!("{err:#}").contains("already exists"), "{err:#}");
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[tokio::test]
    async fn a_corrupt_identity_is_an_error_not_a_missing_one() {
        let dir = tempfile::tempdir().unwrap();
        let (store, path) = store(&dir);
        std::fs::write(&path, "{").unwrap();
        assert!(store.load().await.is_err());

        // A key that does not match the key ID.
        let mut value = serde_json::to_value(identity()).unwrap();
        value["key_id"] = "x".repeat(43).into();
        std::fs::write(&path, value.to_string()).unwrap();
        let err = store.load().await.unwrap_err();
        assert!(format!("{err:#}").contains("does not match"), "{err:#}");

        let mut value = serde_json::to_value(identity()).unwrap();
        value["private_key"] = "c2hvcnQ=".into();
        std::fs::write(&path, value.to_string()).unwrap();
        assert!(store.load().await.is_err());
    }

    #[test]
    fn debug_output_redacts_the_private_key() {
        let identity = identity();
        let debug = format!("{identity:?}");
        assert!(debug.contains("<redacted>"), "{debug}");
        assert!(!debug.contains(&identity.private_key), "{debug}");
    }

    #[test]
    fn secret_fields_round_trip() {
        let fields = identity().to_fields().unwrap();
        assert_eq!(fields.len(), 7);
        assert_eq!(fields["server_url"], "https://vn.example.com");
        assert_eq!(Identity::from_fields(fields).unwrap(), identity());
    }
}
