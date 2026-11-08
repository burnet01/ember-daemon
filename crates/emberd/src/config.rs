use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG: &str = "/etc/ember/config.toml";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Tailscale login names allowed to administer this node.
    pub owners: Vec<String>,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default = "default_socket")]
    pub tailscale_socket: PathBuf,
    /// Public resolvers, because sandboxes cannot reach private addresses.
    #[serde(default = "default_dns")]
    pub dns: Vec<String>,
    #[serde(default = "default_tmp_mb")]
    pub tmp_mb: u64,
    #[serde(default = "default_stop_timeout")]
    pub stop_timeout_secs: u64,
}

fn default_port() -> u16 {
    ember_proto::DEFAULT_PORT
}
fn default_data_dir() -> PathBuf {
    "/var/lib/ember".into()
}
fn default_socket() -> PathBuf {
    "/var/run/tailscale/tailscaled.sock".into()
}
fn default_dns() -> Vec<String> {
    vec!["1.1.1.1".into(), "8.8.8.8".into()]
}
fn default_tmp_mb() -> u64 {
    1024
}
fn default_stop_timeout() -> u64 {
    60
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        Self::parse(&raw).with_context(|| format!("parse {}", path.display()))
    }

    pub fn parse(raw: &str) -> Result<Self> {
        let cfg: Config = toml::from_str(raw)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        if self.owners.is_empty() {
            bail!("`owners` must list at least one Tailscale login");
        }
        // Every tagged device shares this pseudo-login, so it can never identify a person.
        if self.owners.iter().any(|o| o.trim().is_empty() || o.eq_ignore_ascii_case("tagged-devices")) {
            bail!("`owners` contains an entry that cannot identify a person");
        }
        if !self.data_dir.is_absolute() {
            bail!("`data_dir` must be an absolute path");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_defaults() {
        let c = Config::parse(r#"owners = ["me@example.com"]"#).unwrap();
        assert_eq!(c.port, ember_proto::DEFAULT_PORT);
        assert_eq!(c.data_dir, PathBuf::from("/var/lib/ember"));
    }

    #[test]
    fn rejects_configs_that_fail_open() {
        assert!(Config::parse("owners = []").is_err());
        assert!(Config::parse(r#"owners = ["tagged-devices"]"#).is_err());
        assert!(Config::parse(r#"owners = ["a@b"]
bind = "0.0.0.0""#).is_err(), "unknown keys such as a bind address must be refused");
    }
}
