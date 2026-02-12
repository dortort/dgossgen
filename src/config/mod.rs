use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Policy configuration loaded from .dgossgen.yml or defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Port assertion policy: required, optional, off
    #[serde(default = "default_optional")]
    pub assert_ports: AssertionPolicy,

    /// Process assertion policy: required, optional, off
    #[serde(default = "default_optional")]
    pub assert_process: AssertionPolicy,

    /// Whether to assert file modes
    #[serde(default)]
    pub assert_file_modes: bool,

    /// Whether to enable HTTP checks
    #[serde(default)]
    pub http_checks: bool,

    /// Known service pattern mappings
    #[serde(default)]
    pub service_patterns: Vec<ServicePattern>,

    /// Paths to ignore in assertions
    #[serde(default)]
    pub ignore_paths: Vec<String>,

    /// Volume paths to ignore unless mounted
    #[serde(default)]
    pub ignore_volumes: bool,

    /// Wait configuration
    #[serde(default)]
    pub wait: WaitConfig,

    /// Secret key patterns to redact
    #[serde(default = "default_secret_patterns")]
    pub secret_patterns: Vec<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            assert_ports: AssertionPolicy::Optional,
            assert_process: AssertionPolicy::Optional,
            assert_file_modes: false,
            http_checks: false,
            service_patterns: Vec::new(),
            ignore_paths: Vec::new(),
            ignore_volumes: true,
            wait: WaitConfig::default(),
            secret_patterns: default_secret_patterns(),
        }
    }
}

impl PolicyConfig {
    /// Load from a file path (YAML).
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let config: PolicyConfig =
            serde_yml::from_str(&content).with_context(|| "parsing config file")?;
        Ok(config)
    }

    /// Try to load from default locations, falling back to defaults.
    pub fn load_or_default(dir: &Path) -> Self {
        let candidates = [".dgossgen.yml", ".dgossgen.yaml"];
        for name in &candidates {
            let path = dir.join(name);
            if path.exists() {
                if let Ok(config) = Self::load(&path) {
                    return config;
                }
            }
        }
        Self::default()
    }

    pub fn assert_ports_enabled(&self) -> bool {
        !matches!(self.assert_ports, AssertionPolicy::Off)
    }

    pub fn assert_process_enabled(&self) -> bool {
        !matches!(self.assert_process, AssertionPolicy::Off)
    }

    /// Check if a key name looks like a secret.
    pub fn is_secret_key(&self, key: &str) -> bool {
        let upper = key.to_uppercase();
        self.secret_patterns
            .iter()
            .any(|pattern| upper.contains(&pattern.to_uppercase()))
    }
}

/// Assertion policy: how strictly to enforce a type of assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AssertionPolicy {
    Required,
    Optional,
    Off,
}

/// Wait configuration for goss_wait.yml.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaitConfig {
    /// Number of retries before giving up
    #[serde(default = "default_retries")]
    pub retries: u32,

    /// Sleep duration between retries (e.g., "1s")
    #[serde(default = "default_sleep")]
    pub sleep: String,

    /// Total timeout (e.g., "60s")
    #[serde(default = "default_timeout")]
    pub timeout: String,
}

impl Default for WaitConfig {
    fn default() -> Self {
        Self {
            retries: 60,
            sleep: "1s".to_string(),
            timeout: "60s".to_string(),
        }
    }
}

/// A known service pattern mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicePattern {
    /// Service name to match (e.g., "nginx")
    pub name: String,

    /// Expected process name
    pub process: Option<String>,

    /// Config file path to check
    pub config_path: Option<String>,

    /// Version command to verify
    pub version_cmd: Option<String>,
}

fn default_optional() -> AssertionPolicy {
    AssertionPolicy::Optional
}

fn default_retries() -> u32 {
    60
}

fn default_sleep() -> String {
    "1s".to_string()
}

fn default_timeout() -> String {
    "60s".to_string()
}

fn default_secret_patterns() -> Vec<String> {
    vec![
        "SECRET".to_string(),
        "TOKEN".to_string(),
        "PASSWORD".to_string(),
        "KEY".to_string(),
        "PRIVATE".to_string(),
        "CREDENTIAL".to_string(),
        "AUTH".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PolicyConfig::default();
        assert_eq!(config.assert_ports, AssertionPolicy::Optional);
        assert!(!config.assert_file_modes);
        assert!(!config.http_checks);
        assert!(config.assert_ports_enabled());
    }

    #[test]
    fn test_secret_detection() {
        let config = PolicyConfig::default();
        assert!(config.is_secret_key("DB_PASSWORD"));
        assert!(config.is_secret_key("API_TOKEN"));
        assert!(config.is_secret_key("SECRET_KEY"));
        assert!(!config.is_secret_key("APP_PORT"));
        assert!(!config.is_secret_key("LOG_LEVEL"));
    }

    #[test]
    fn test_parse_config() {
        let yaml = r#"
assert_ports: required
assert_process: off
assert_file_modes: true
http_checks: true
wait:
  retries: 30
  sleep: "2s"
  timeout: "120s"
secret_patterns:
  - SECRET
  - TOKEN
"#;
        let config: PolicyConfig = serde_yml::from_str(yaml).unwrap();
        assert_eq!(config.assert_ports, AssertionPolicy::Required);
        assert_eq!(config.assert_process, AssertionPolicy::Off);
        assert!(config.assert_file_modes);
        assert!(config.http_checks);
        assert_eq!(config.wait.retries, 30);
    }
}
