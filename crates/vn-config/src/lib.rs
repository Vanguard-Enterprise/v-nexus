//! Loads and validates the Vanguard Nexus configuration file.
//!
//! The file is YAML with an explicit schema `version`. Unknown fields are rejected so that
//! typos fail loudly instead of being ignored. Secrets are never stored in the file: the
//! database connection URL is read from the environment variable named by
//! `database.url_env`.

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

/// Top-level configuration file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub server: ServerConfig,
    pub database: DatabaseConfig,
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
    #[error("environment variable `{var}` named by `database.url_env` is not set")]
    EnvVarMissing { var: String },
    #[error("environment variable `{var}` named by `database.url_env` is empty")]
    EnvVarEmpty { var: String },
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
        Ok(())
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
        let var = &self.url_env;
        match lookup(var) {
            None => Err(ConfigError::EnvVarMissing { var: var.clone() }),
            Some(value) if value.trim().is_empty() => {
                Err(ConfigError::EnvVarEmpty { var: var.clone() })
            }
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

    fn err(text: &str) -> String {
        Config::from_yaml(text).unwrap_err().to_string()
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
        assert_eq!(config.database.max_connections, DEFAULT_MAX_CONNECTIONS);
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
            matches!(missing, ConfigError::EnvVarMissing { ref var } if var == "VN_DATABASE_URL")
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
    fn load_reports_unreadable_path() {
        let message = Config::load("/nonexistent/vn.yaml")
            .unwrap_err()
            .to_string();
        assert!(message.contains("/nonexistent/vn.yaml"), "{message}");
    }
}
