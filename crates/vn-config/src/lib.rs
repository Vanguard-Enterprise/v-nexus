//! Loads and validates the Vanguard Nexus configuration file.
//!
//! The file is YAML with an explicit schema `version`. Unknown fields are rejected so that
//! typos fail loudly instead of being ignored. Secrets are never stored in the file: the
//! database connection URL is read from the environment variable named by
//! `database.url_env`, and the OIDC client secret from the one named by
//! `auth.client_secret_env`.

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Schema version understood by this build.
pub const SUPPORTED_VERSION: u32 = 1;

/// Environment variable that overrides the config file path.
pub const CONFIG_PATH_ENV: &str = "VN_CONFIG";

/// Config file path used when neither `--config` nor `VN_CONFIG` is given.
pub const DEFAULT_CONFIG_PATH: &str = "vn.yaml";

const DEFAULT_MAX_CONNECTIONS: u32 = 10;
const DEFAULT_IDLE_TIMEOUT_MINUTES: u32 = 60;
const DEFAULT_ABSOLUTE_TIMEOUT_MINUTES: u32 = 12 * 60;
/// Upper bound on `auth.session.absolute_timeout_minutes` (30 days).
pub const MAX_ABSOLUTE_TIMEOUT_MINUTES: u32 = 30 * 24 * 60;

/// The `admin.claim` value that matches users by their ID token subject.
pub const SUBJECT_CLAIM: &str = "sub";

/// Claims the OIDC client parses into dedicated fields (the registered ID token claims
/// and the OpenID Connect standard profile claims). They never reach the admin lookup,
/// and the profile claims are user-editable at many providers, so `admin.claim` rejects
/// them. Matched on the name before any `#` language tag, as the client does.
const NON_ADMIN_CLAIMS: &[&str] = &[
    "iss",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
    "acr",
    "amr",
    "azp",
    "at_hash",
    "c_hash",
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "email",
    "email_verified",
    "gender",
    "birthday",
    "birthdate",
    "zoneinfo",
    "locale",
    "phone_number",
    "phone_number_verified",
    "address",
    "updated_at",
];

/// Top-level configuration file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    /// User sign-in. When omitted, nobody can sign in and every API route except health
    /// answers 401.
    #[serde(default)]
    pub auth: Option<AuthConfig>,
}

/// HTTP server settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Socket address to listen on, for example `0.0.0.0:8080`.
    pub listen: SocketAddr,
    /// Directory holding the built web UI. Relative paths resolve against the working
    /// directory. When unset or missing on disk, UI routes return 404.
    #[serde(default)]
    pub static_dir: Option<PathBuf>,
    /// Reverse proxies whose `X-Forwarded-For` header is believed, as addresses or CIDR
    /// networks. Requests from other peers use the peer address as the client address,
    /// which rate limiting and audit records use. Defaults to none.
    #[serde(default, deserialize_with = "deserialize_networks")]
    pub trusted_proxies: Vec<ipnet::IpNet>,
}

/// Reads a list of CIDR networks, accepting a bare address as a single-host network.
fn deserialize_networks<'de, D>(deserializer: D) -> Result<Vec<ipnet::IpNet>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let values = Vec::<String>::deserialize(deserializer)?;
    values
        .iter()
        .map(|value| {
            value
                .parse::<ipnet::IpNet>()
                .or_else(|_| value.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
                .map_err(|_| {
                    serde::de::Error::custom(format!(
                        "`{value}` is not an IP address or CIDR network"
                    ))
                })
        })
        .collect()
}

/// PostgreSQL settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    /// Name of the environment variable holding the connection URL.
    pub url_env: String,
    /// Upper bound on pooled connections.
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
}

fn default_max_connections() -> u32 {
    DEFAULT_MAX_CONNECTIONS
}

/// OpenID Connect sign-in settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// OIDC issuer URL, exactly as the provider reports it in its `issuer` metadata (a
    /// trailing slash matters). Provider metadata is discovered from
    /// `<issuer_url>/.well-known/openid-configuration`.
    pub issuer_url: String,
    /// Client ID registered with the provider.
    pub client_id: String,
    /// Name of the environment variable holding the client secret.
    pub client_secret_env: String,
    /// Origin browsers use to reach VN, for example `https://vn.example.com`. The OIDC
    /// redirect URI is `<public_url>/api/v1/auth/callback`, session cookies are marked
    /// `Secure` when it uses https, and state-changing requests must come from this origin.
    pub public_url: url::Url,
    /// Scopes requested at sign-in. `openid` is always requested.
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// How installation administrators are recognized.
    pub admin: AdminMapping,
    #[serde(default)]
    pub session: SessionConfig,
    /// Allows `issuer_url` and `public_url` to use plain http. Only for development over a
    /// trusted network (loopback, or a VPN such as NetBird): over http, provider metadata
    /// and signing keys can be tampered with in transit, and session cookies are sent
    /// without the `Secure` flag.
    #[serde(default)]
    pub allow_insecure_http: bool,
}

/// Maps an OIDC claim to the installation `admin` role.
///
/// A user is an administrator when the claim named by `claim`, read from the ID token or
/// (when absent there) the userinfo response, contains any of `values`. The claim may be a
/// string, a list of strings (a groups claim), or an object whose keys are role names (the
/// Zitadel project roles claim).
///
/// `claim: sub` instead compares the verified ID token subject against `values`, which
/// suits bootstrapping the first administrator. The other registered and standard
/// profile claims (`email`, `preferred_username`, and so on) are rejected.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminMapping {
    pub claim: String,
    pub values: Vec<String>,
}

/// Browser session lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConfig {
    /// A session ends after this many minutes without a request.
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_minutes: u32,
    /// A session ends this many minutes after sign-in, regardless of activity.
    #[serde(default = "default_absolute_timeout")]
    pub absolute_timeout_minutes: u32,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            idle_timeout_minutes: DEFAULT_IDLE_TIMEOUT_MINUTES,
            absolute_timeout_minutes: DEFAULT_ABSOLUTE_TIMEOUT_MINUTES,
        }
    }
}

fn default_scopes() -> Vec<String> {
    ["openid", "profile", "email"].map(String::from).to_vec()
}

fn default_idle_timeout() -> u32 {
    DEFAULT_IDLE_TIMEOUT_MINUTES
}

fn default_absolute_timeout() -> u32 {
    DEFAULT_ABSOLUTE_TIMEOUT_MINUTES
}

/// Errors from loading, validating, or resolving configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Syntax, type, missing-field, and unknown-field errors. The message names the
    /// offending field path and its line.
    #[error("invalid config: {0}")]
    Parse(serde_norway::Error),
    #[error("missing required field `version`")]
    MissingVersion,
    #[error("unsupported config version {found}; this build supports version {SUPPORTED_VERSION}")]
    UnsupportedVersion { found: String },
    #[error("invalid value for `{field}`: {message}")]
    Invalid {
        field: &'static str,
        message: String,
    },
    #[error("environment variable `{var}` named by `{field}` is not set")]
    EnvVarMissing { field: &'static str, var: String },
    #[error("environment variable `{var}` named by `{field}` is empty")]
    EnvVarEmpty { field: &'static str, var: String },
    /// The message never includes the URL or any parameter value, since they may hold
    /// credentials.
    #[error("database URL in environment variable `{var}` is invalid: {message}")]
    DatabaseUrlInvalid { var: String, message: String },
}

impl Config {
    /// Reads, parses, and validates the config file at `path`.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_yaml(&text)
    }

    /// Parses and validates config from YAML text.
    pub fn from_yaml(text: &str) -> Result<Self, ConfigError> {
        check_version(text)?;
        let config: Config = serde_norway::from_str(text).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    /// Checks constraints that the type system does not express.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version != SUPPORTED_VERSION {
            return Err(ConfigError::UnsupportedVersion {
                found: self.version.to_string(),
            });
        }
        if let Some(dir) = &self.server.static_dir
            && dir.as_os_str().is_empty()
        {
            return Err(ConfigError::Invalid {
                field: "server.static_dir",
                message: "must not be empty; omit the field to disable UI serving".into(),
            });
        }
        if !is_env_var_name(&self.database.url_env) {
            return Err(ConfigError::Invalid {
                field: "database.url_env",
                message: format!(
                    "`{}` is not a valid environment variable name \
                     (use letters, digits, and underscores, not starting with a digit)",
                    self.database.url_env
                ),
            });
        }
        if self.database.max_connections == 0 {
            return Err(ConfigError::Invalid {
                field: "database.max_connections",
                message: "must be at least 1".into(),
            });
        }
        if let Some(auth) = &self.auth {
            auth.validate()?;
        }
        Ok(())
    }
}

impl AuthConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |field, message: &str| ConfigError::Invalid {
            field,
            message: message.into(),
        };
        let issuer = url::Url::parse(&self.issuer_url).map_err(|err| ConfigError::Invalid {
            field: "auth.issuer_url",
            message: format!("not a valid URL ({err})"),
        })?;
        if !matches!(issuer.scheme(), "http" | "https") {
            return Err(invalid(
                "auth.issuer_url",
                "scheme must be `http` or `https`",
            ));
        }
        if issuer.scheme() == "http" && !self.allow_insecure_http {
            return Err(invalid(
                "auth.issuer_url",
                "must use https, because provider metadata and signing keys are fetched \
                 from it. For development over a trusted network (loopback, or a VPN such \
                 as NetBird), set `auth.allow_insecure_http: true`.",
            ));
        }
        if issuer.query().is_some() || issuer.fragment().is_some() {
            return Err(invalid(
                "auth.issuer_url",
                "must not have a query string or fragment",
            ));
        }
        if self.client_id.trim().is_empty() {
            return Err(invalid("auth.client_id", "must not be empty"));
        }
        if !is_env_var_name(&self.client_secret_env) {
            return Err(ConfigError::Invalid {
                field: "auth.client_secret_env",
                message: format!(
                    "`{}` is not a valid environment variable name \
                     (use letters, digits, and underscores, not starting with a digit)",
                    self.client_secret_env
                ),
            });
        }
        let public = &self.public_url;
        if !matches!(public.scheme(), "http" | "https") {
            return Err(invalid(
                "auth.public_url",
                "scheme must be `http` or `https`",
            ));
        }
        if public.scheme() == "http" && !self.allow_insecure_http {
            return Err(invalid(
                "auth.public_url",
                "must use https, because session cookies are sent without the Secure flag \
                 over http. For development over a trusted network (loopback, or a VPN \
                 such as NetBird), set `auth.allow_insecure_http: true`.",
            ));
        }
        if public.path() != "/"
            || public.query().is_some()
            || public.fragment().is_some()
            || !public.username().is_empty()
            || public.password().is_some()
        {
            return Err(invalid(
                "auth.public_url",
                "must be an origin such as `https://vn.example.com`, without a path, \
                 query, fragment, or credentials",
            ));
        }
        for scope in &self.scopes {
            if scope.is_empty() || scope.chars().any(|c| c.is_whitespace() || c == '"') {
                return Err(ConfigError::Invalid {
                    field: "auth.scopes",
                    message: format!("`{scope}` is not a valid scope"),
                });
            }
        }
        if self.admin.claim.trim().is_empty() {
            return Err(invalid("auth.admin.claim", "must not be empty"));
        }
        let claim = self.admin.claim.as_str();
        let base = claim.split_once('#').map_or(claim, |(base, _)| base);
        if claim != SUBJECT_CLAIM && (base == SUBJECT_CLAIM || NON_ADMIN_CLAIMS.contains(&base)) {
            return Err(ConfigError::Invalid {
                field: "auth.admin.claim",
                message: format!(
                    "`{claim}` cannot be used for the admin mapping because it is mutable \
                     or not an authorization claim; use a role or groups claim, or `sub` \
                     to match the user's subject"
                ),
            });
        }
        if self.admin.values.is_empty() {
            return Err(invalid(
                "auth.admin.values",
                "must list at least one value that grants the admin role",
            ));
        }
        if self.admin.values.iter().any(|v| v.is_empty()) {
            return Err(invalid("auth.admin.values", "values must not be empty"));
        }
        let session = &self.session;
        if session.idle_timeout_minutes == 0 {
            return Err(invalid(
                "auth.session.idle_timeout_minutes",
                "must be at least 1",
            ));
        }
        if session.absolute_timeout_minutes > MAX_ABSOLUTE_TIMEOUT_MINUTES {
            return Err(ConfigError::Invalid {
                field: "auth.session.absolute_timeout_minutes",
                message: format!("must be at most {MAX_ABSOLUTE_TIMEOUT_MINUTES} (30 days)"),
            });
        }
        if session.absolute_timeout_minutes < session.idle_timeout_minutes {
            return Err(invalid(
                "auth.session.absolute_timeout_minutes",
                "must be at least `auth.session.idle_timeout_minutes`",
            ));
        }
        Ok(())
    }

    /// Origin of [`AuthConfig::public_url`] in the form browsers send in `Origin` headers,
    /// for example `https://vn.example.com`.
    pub fn public_origin(&self) -> String {
        self.public_url.origin().ascii_serialization()
    }

    /// Redirect URI registered with the provider.
    pub fn redirect_url(&self) -> String {
        format!("{}/api/v1/auth/callback", self.public_origin())
    }

    /// Whether the public URL uses https, so cookies must be marked `Secure`.
    pub fn is_https(&self) -> bool {
        self.public_url.scheme() == "https"
    }

    /// Whether the issuer URL uses plain http, which validation allows only with
    /// [`AuthConfig::allow_insecure_http`].
    pub fn issuer_uses_http(&self) -> bool {
        url::Url::parse(&self.issuer_url).is_ok_and(|issuer| issuer.scheme() == "http")
    }

    /// Reads the client secret from the process environment.
    pub fn resolve_client_secret(&self) -> Result<Secret, ConfigError> {
        self.resolve_client_secret_with(|name| {
            std::env::var_os(name).map(|v| v.to_string_lossy().into())
        })
    }

    /// Resolves the client secret using `lookup` in place of the process environment.
    pub fn resolve_client_secret_with(
        &self,
        lookup: impl FnOnce(&str) -> Option<String>,
    ) -> Result<Secret, ConfigError> {
        let field = "auth.client_secret_env";
        let var = &self.client_secret_env;
        match lookup(var) {
            None => Err(ConfigError::EnvVarMissing {
                field,
                var: var.clone(),
            }),
            Some(value) if value.trim().is_empty() => Err(ConfigError::EnvVarEmpty {
                field,
                var: var.clone(),
            }),
            Some(value) => Ok(Secret(value)),
        }
    }
}

/// A secret read from the environment. `Debug` and `Display` redact it.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Returns the secret value. Do not log it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl DatabaseConfig {
    /// Reads the connection URL from the process environment.
    pub fn resolve_url(&self) -> Result<DatabaseUrl, ConfigError> {
        self.resolve_url_with(|name| std::env::var_os(name).map(|v| v.to_string_lossy().into()))
    }

    /// Resolves the connection URL using `lookup` in place of the process environment.
    pub fn resolve_url_with(
        &self,
        lookup: impl FnOnce(&str) -> Option<String>,
    ) -> Result<DatabaseUrl, ConfigError> {
        let field = "database.url_env";
        let var = &self.url_env;
        match lookup(var) {
            None => Err(ConfigError::EnvVarMissing {
                field,
                var: var.clone(),
            }),
            Some(value) if value.trim().is_empty() => Err(ConfigError::EnvVarEmpty {
                field,
                var: var.clone(),
            }),
            Some(value) => {
                check_database_url(&value).map_err(|message| ConfigError::DatabaseUrlInvalid {
                    var: var.clone(),
                    message,
                })?;
                Ok(DatabaseUrl(value))
            }
        }
    }
}

/// Query parameters the PostgreSQL driver understands. The driver logs unrecognized
/// parameters together with their values, which could expose secrets such as
/// `sslpassword`, so anything else is rejected here, before the driver sees it.
const DATABASE_URL_PARAMS: &[&str] = &[
    "sslmode",
    "ssl-mode",
    "sslrootcert",
    "ssl-root-cert",
    "ssl-ca",
    "sslcert",
    "ssl-cert",
    "sslkey",
    "ssl-key",
    "statement-cache-capacity",
    "host",
    "hostaddr",
    "port",
    "dbname",
    "user",
    "password",
    "application_name",
    "options",
];

/// Checks the URL shape and its query parameter names. Error messages name parameter keys
/// only, never values.
fn check_database_url(value: &str) -> Result<(), String> {
    let url = url::Url::parse(value.trim()).map_err(|err| format!("not a valid URL ({err})"))?;
    if !matches!(url.scheme(), "postgres" | "postgresql") {
        return Err("scheme must be `postgres` or `postgresql`".into());
    }
    for (key, _) in url.query_pairs() {
        let known = DATABASE_URL_PARAMS.contains(&key.as_ref())
            || (key.starts_with("options[") && key.ends_with(']'));
        if !known {
            return Err(format!("unsupported query parameter `{key}`"));
        }
    }
    Ok(())
}

/// Database connection URL. May contain credentials, so `Debug` and `Display` redact it.
#[derive(Clone, PartialEq, Eq)]
pub struct DatabaseUrl(String);

impl DatabaseUrl {
    /// Returns the URL for handing to the database driver. Do not log it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DatabaseUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DatabaseUrl(<redacted>)")
    }
}

impl fmt::Display for DatabaseUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Checks `version` before the full parse, so a file written for another schema version
/// reports the version mismatch rather than whichever field changed first.
fn check_version(text: &str) -> Result<(), ConfigError> {
    #[derive(Deserialize)]
    #[serde(rename = "Config")]
    struct VersionOnly {
        version: Option<serde_norway::Value>,
    }

    let probe: VersionOnly = serde_norway::from_str(text).map_err(ConfigError::Parse)?;
    match probe.version {
        None | Some(serde_norway::Value::Null) => Err(ConfigError::MissingVersion),
        Some(serde_norway::Value::Number(n))
            if n.as_u64() == Some(u64::from(SUPPORTED_VERSION)) =>
        {
            Ok(())
        }
        Some(serde_norway::Value::Number(n)) => Err(ConfigError::UnsupportedVersion {
            found: n.to_string(),
        }),
        Some(other) => Err(ConfigError::Invalid {
            field: "version",
            message: format!("expected an integer, found {}", describe(&other)),
        }),
    }
}

fn describe(value: &serde_norway::Value) -> &'static str {
    use serde_norway::Value;
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Sequence(_) => "a list",
        Value::Mapping(_) => "a mapping",
        Value::Tagged(_) => "a tagged value",
    }
}

fn is_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = "\
version: 1
server:
  listen: 0.0.0.0:8080
  static_dir: web/dist
database:
  url_env: VN_DATABASE_URL
  max_connections: 5
";

    const WITH_AUTH: &str = "\
version: 1
server:
  listen: 0.0.0.0:8080
database:
  url_env: VN_DATABASE_URL
auth:
  issuer_url: https://id.example.com
  client_id: \"1234@vn\"
  client_secret_env: VN_OIDC_CLIENT_SECRET
  public_url: https://vn.example.com
  scopes: [openid, profile, email, groups]
  admin:
    claim: groups
    values: [vn-admins]
  session:
    idle_timeout_minutes: 30
    absolute_timeout_minutes: 480
";

    fn err(text: &str) -> String {
        Config::from_yaml(text).unwrap_err().to_string()
    }

    fn auth(text: &str) -> AuthConfig {
        Config::from_yaml(text).unwrap().auth.unwrap()
    }

    #[test]
    fn parses_valid_config() {
        let config = Config::from_yaml(VALID).unwrap();
        assert_eq!(config.version, 1);
        assert_eq!(config.server.listen, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(config.server.static_dir, Some(PathBuf::from("web/dist")));
        assert_eq!(config.database.url_env, "VN_DATABASE_URL");
        assert_eq!(config.database.max_connections, 5);
    }

    #[test]
    fn optional_fields_have_defaults() {
        let config = Config::from_yaml(
            "version: 1\nserver:\n  listen: 127.0.0.1:9000\ndatabase:\n  url_env: DB\n",
        )
        .unwrap();
        assert_eq!(config.server.static_dir, None);
        assert!(config.server.trusted_proxies.is_empty());
        assert_eq!(config.database.max_connections, DEFAULT_MAX_CONNECTIONS);
    }

    #[test]
    fn parses_trusted_proxies_as_networks_or_addresses() {
        let config = Config::from_yaml(&VALID.replace(
            "  static_dir: web/dist\n",
            "  static_dir: web/dist\n  trusted_proxies: [10.0.0.0/8, 192.0.2.7, \"::1\"]\n",
        ))
        .unwrap();
        let proxies: Vec<String> = config
            .server
            .trusted_proxies
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(proxies, ["10.0.0.0/8", "192.0.2.7/32", "::1/128"]);

        let message = err(&VALID.replace(
            "  static_dir: web/dist\n",
            "  static_dir: web/dist\n  trusted_proxies: [proxy.local]\n",
        ));
        assert!(
            message.contains("`proxy.local` is not an IP address"),
            "{message}"
        );
    }

    #[test]
    fn example_config_is_valid() {
        let example = include_str!("../../../config/vn.example.yaml");
        Config::from_yaml(example).unwrap();
    }

    #[test]
    fn rejects_unknown_nested_field() {
        let message = err(&VALID.replace("  max_connections: 5", "  max_conections: 5"));
        assert!(message.contains("database: "), "{message}");
        assert!(
            message.contains("unknown field `max_conections`"),
            "{message}"
        );
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let message = err(&format!("{VALID}telemetry: {{}}\n"));
        assert!(message.contains("unknown field `telemetry`"), "{message}");
    }

    #[test]
    fn rejects_unsupported_version() {
        let message = err(&VALID.replace("version: 1", "version: 2"));
        assert!(
            message.contains("unsupported config version 2"),
            "{message}"
        );
    }

    #[test]
    fn version_mismatch_wins_over_unknown_fields() {
        let message = err("version: 2\nsomething_new: true\n");
        assert!(
            message.contains("unsupported config version 2"),
            "{message}"
        );
    }

    #[test]
    fn rejects_missing_and_non_integer_version() {
        assert!(matches!(
            Config::from_yaml(&VALID.replace("version: 1\n", "")),
            Err(ConfigError::MissingVersion)
        ));
        let message = err(&VALID.replace("version: 1", "version: one"));
        assert!(message.contains("`version`"), "{message}");
    }

    #[test]
    fn names_field_with_bad_value() {
        let message = err(&VALID.replace("0.0.0.0:8080", "not-an-address"));
        assert!(message.contains("server.listen: "), "{message}");

        let message = err(&VALID.replace("max_connections: 5", "max_connections: 0"));
        assert!(message.contains("`database.max_connections`"), "{message}");

        let message = err(&VALID.replace("VN_DATABASE_URL", "VN-DATABASE-URL"));
        assert!(message.contains("`database.url_env`"), "{message}");
    }

    #[test]
    fn names_missing_field() {
        let message = err(&VALID.replace("  url_env: VN_DATABASE_URL\n", ""));
        assert!(message.contains("database: "), "{message}");
        assert!(message.contains("missing field `url_env`"), "{message}");
    }

    #[test]
    fn resolves_database_url_from_env() {
        let config = Config::from_yaml(VALID).unwrap();
        let url = config
            .database
            .resolve_url_with(|name| {
                assert_eq!(name, "VN_DATABASE_URL");
                Some("postgres://vn:secret@db/vn".into())
            })
            .unwrap();
        assert_eq!(url.expose(), "postgres://vn:secret@db/vn");
        assert!(!format!("{url:?} {url}").contains("secret"));
    }

    #[test]
    fn errors_when_env_var_missing_or_empty() {
        let config = Config::from_yaml(VALID).unwrap();

        let missing = config.database.resolve_url_with(|_| None).unwrap_err();
        assert!(
            matches!(missing, ConfigError::EnvVarMissing { ref var, .. } if var == "VN_DATABASE_URL")
        );
        assert!(missing.to_string().contains("VN_DATABASE_URL"));

        let empty = config
            .database
            .resolve_url_with(|_| Some("  ".into()))
            .unwrap_err();
        assert!(matches!(empty, ConfigError::EnvVarEmpty { .. }));
    }

    #[test]
    fn rejects_unsupported_url_parameters_without_echoing_values() {
        let config = Config::from_yaml(VALID).unwrap();
        let resolve = |url: &'static str| config.database.resolve_url_with(|_| Some(url.into()));

        let err = resolve("postgres://vn:hunter2@db/vn?sslpassword=TOPSECRET").unwrap_err();
        let message = err.to_string();
        assert!(matches!(err, ConfigError::DatabaseUrlInvalid { .. }));
        assert!(message.contains("`sslpassword`"), "{message}");
        assert!(!message.contains("TOPSECRET"), "{message}");
        assert!(!message.contains("hunter2"), "{message}");

        let message = resolve("mysql://vn:hunter2@db/vn").unwrap_err().to_string();
        assert!(message.contains("scheme"), "{message}");
        assert!(!message.contains("hunter2"), "{message}");

        let message = resolve("not a url hunter2").unwrap_err().to_string();
        assert!(!message.contains("hunter2"), "{message}");

        resolve("postgresql://vn:pw@db:5432/vn?sslmode=require&application_name=vn&options[search_path]=vn")
            .unwrap();
    }

    #[test]
    fn auth_is_optional() {
        assert_eq!(Config::from_yaml(VALID).unwrap().auth, None);
    }

    #[test]
    fn parses_auth_section() {
        let auth = auth(WITH_AUTH);
        assert_eq!(auth.issuer_url, "https://id.example.com");
        assert_eq!(auth.client_id, "1234@vn");
        assert_eq!(auth.client_secret_env, "VN_OIDC_CLIENT_SECRET");
        assert_eq!(auth.public_origin(), "https://vn.example.com");
        assert_eq!(
            auth.redirect_url(),
            "https://vn.example.com/api/v1/auth/callback"
        );
        assert!(auth.is_https());
        assert_eq!(auth.scopes, ["openid", "profile", "email", "groups"]);
        assert_eq!(
            auth.admin,
            AdminMapping {
                claim: "groups".into(),
                values: vec!["vn-admins".into()],
            }
        );
        assert_eq!(
            auth.session,
            SessionConfig {
                idle_timeout_minutes: 30,
                absolute_timeout_minutes: 480,
            }
        );
    }

    #[test]
    fn auth_optional_fields_have_defaults() {
        let text = WITH_AUTH
            .replace("  scopes: [openid, profile, email, groups]\n", "")
            .replace(
                "  session:\n    idle_timeout_minutes: 30\n    absolute_timeout_minutes: 480\n",
                "",
            );
        let auth = auth(&text);
        assert_eq!(auth.scopes, ["openid", "profile", "email"]);
        assert_eq!(auth.session, SessionConfig::default());
        assert!(!auth.allow_insecure_http);
        assert!(!auth.issuer_uses_http());
    }

    fn allowing_insecure_http(text: &str) -> String {
        text.replace(
            "  public_url:",
            "  allow_insecure_http: true\n  public_url:",
        )
    }

    #[test]
    fn http_issuer_requires_allow_insecure_http() {
        let text = WITH_AUTH.replace("https://id.example.com", "http://id.example.com");
        let message = err(&text);
        assert!(message.contains("`auth.issuer_url`"), "{message}");
        assert!(message.contains("must use https"), "{message}");
        assert!(
            message.contains("`auth.allow_insecure_http: true`"),
            "{message}"
        );

        let auth = auth(&allowing_insecure_http(&text));
        assert_eq!(auth.issuer_url, "http://id.example.com");
        assert!(auth.is_https());
        assert!(auth.issuer_uses_http());
    }

    #[test]
    fn http_public_url_requires_allow_insecure_http() {
        let text = WITH_AUTH.replace("https://vn.example.com", "http://100.64.0.5:5173");
        let message = err(&text);
        assert!(message.contains("`auth.public_url`"), "{message}");
        assert!(message.contains("must use https"), "{message}");
        assert!(
            message.contains("`auth.allow_insecure_http: true`"),
            "{message}"
        );

        let auth = auth(&allowing_insecure_http(&text));
        assert_eq!(auth.public_origin(), "http://100.64.0.5:5173");
        assert!(!auth.is_https());
        assert!(!auth.issuer_uses_http());
    }

    #[test]
    fn https_urls_do_not_need_allow_insecure_http() {
        let auth = auth(&allowing_insecure_http(WITH_AUTH));
        assert!(auth.allow_insecure_http);
        assert!(auth.is_https());
        assert!(!auth.issuer_uses_http());
    }

    #[test]
    fn issuer_url_is_kept_verbatim() {
        let auth = auth(&WITH_AUTH.replace("https://id.example.com", "https://id.example.com/"));
        assert_eq!(auth.issuer_url, "https://id.example.com/");
    }

    #[test]
    fn rejects_unknown_auth_fields() {
        let message =
            err(&WITH_AUTH.replace("  client_id:", "  client_secret: oops\n  client_id:"));
        assert!(
            message.contains("unknown field `client_secret`"),
            "{message}"
        );

        let message =
            err(&WITH_AUTH.replace("    claim: groups", "    claim: groups\n    role: x"));
        assert!(message.contains("unknown field `role`"), "{message}");
    }

    #[test]
    fn requires_admin_mapping() {
        let message =
            err(&WITH_AUTH.replace("  admin:\n    claim: groups\n    values: [vn-admins]\n", ""));
        assert!(message.contains("missing field `admin`"), "{message}");
    }

    #[test]
    fn names_invalid_auth_field() {
        let cases = [
            ("https://id.example.com", "not a url", "`auth.issuer_url`"),
            (
                "https://id.example.com",
                "ftp://id.example.com",
                "`auth.issuer_url`",
            ),
            (
                "https://id.example.com",
                "https://id.example.com/?x=1",
                "`auth.issuer_url`",
            ),
            ("\"1234@vn\"", "\" \"", "`auth.client_id`"),
            (
                "VN_OIDC_CLIENT_SECRET",
                "1SECRET",
                "`auth.client_secret_env`",
            ),
            (
                "https://vn.example.com",
                "https://vn.example.com/vn",
                "`auth.public_url`",
            ),
            (
                "https://vn.example.com",
                "https://u:p@vn.example.com",
                "`auth.public_url`",
            ),
            (
                "https://vn.example.com",
                "ws://vn.example.com",
                "`auth.public_url`",
            ),
            (
                "[openid, profile, email, groups]",
                "[openid, \"two words\"]",
                "`auth.scopes`",
            ),
            ("claim: groups", "claim: \"\"", "`auth.admin.claim`"),
            ("values: [vn-admins]", "values: []", "`auth.admin.values`"),
            (
                "values: [vn-admins]",
                "values: [\"\"]",
                "`auth.admin.values`",
            ),
            (
                "idle_timeout_minutes: 30",
                "idle_timeout_minutes: 0",
                "`auth.session.idle_timeout_minutes`",
            ),
            (
                "absolute_timeout_minutes: 480",
                "absolute_timeout_minutes: 10",
                "`auth.session.absolute_timeout_minutes`",
            ),
            (
                "absolute_timeout_minutes: 480",
                "absolute_timeout_minutes: 50000",
                "`auth.session.absolute_timeout_minutes`",
            ),
        ];
        for (from, to, field) in cases {
            let text = WITH_AUTH.replace(from, to);
            assert_ne!(text, WITH_AUTH, "{from} not found");
            let message = err(&text);
            assert!(message.contains(field), "{to}: {message}");
        }
    }

    #[test]
    fn admin_claim_rejects_standard_claims() {
        for claim in [
            "email",
            "preferred_username",
            "name",
            "name#en",
            "email_verified",
            "iss",
            "aud",
            "amr",
            "sub#en",
        ] {
            let text = WITH_AUTH.replace("claim: groups", &format!("claim: \"{claim}\""));
            let message = err(&text);
            assert!(message.contains("`auth.admin.claim`"), "{claim}: {message}");
            assert!(
                message.contains("cannot be used for the admin mapping"),
                "{claim}: {message}"
            );
            assert!(message.contains("`sub`"), "{claim}: {message}");
        }
    }

    #[test]
    fn admin_claim_accepts_sub_and_custom_claims() {
        for claim in [
            "sub",
            "groups",
            "roles",
            "urn:zitadel:iam:org:project:roles",
        ] {
            let text = WITH_AUTH.replace("claim: groups", &format!("claim: \"{claim}\""));
            assert_eq!(auth(&text).admin.claim, claim);
        }
    }

    #[test]
    fn resolves_client_secret_from_env_without_revealing_it() {
        let auth = auth(WITH_AUTH);
        let secret = auth
            .resolve_client_secret_with(|name| {
                assert_eq!(name, "VN_OIDC_CLIENT_SECRET");
                Some("s3cr3t-value".into())
            })
            .unwrap();
        assert_eq!(secret.expose(), "s3cr3t-value");
        assert!(!format!("{secret:?} {secret} {auth:?}").contains("s3cr3t"));

        let missing = auth.resolve_client_secret_with(|_| None).unwrap_err();
        assert!(matches!(
            missing,
            ConfigError::EnvVarMissing {
                field: "auth.client_secret_env",
                ..
            }
        ));
        assert!(missing.to_string().contains("VN_OIDC_CLIENT_SECRET"));
        assert!(matches!(
            auth.resolve_client_secret_with(|_| Some(" ".into())),
            Err(ConfigError::EnvVarEmpty { .. })
        ));
    }

    #[test]
    fn load_reports_unreadable_path() {
        let message = Config::load("/nonexistent/vn.yaml")
            .unwrap_err()
            .to_string();
        assert!(message.contains("/nonexistent/vn.yaml"), "{message}");
    }
}
