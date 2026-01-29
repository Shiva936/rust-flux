use anyhow::{anyhow, Context, Result};
use notify::{recommended_watcher, EventKind, RecursiveMode, Watcher};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen_addr: String,
    #[serde(default = "default_shutdown_grace_period_secs")]
    pub shutdown_grace_period_secs: u64,
}

fn default_shutdown_grace_period_secs() -> u64 {
    30
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum JwtAlgorithm {
    HS256,
    RS256,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthPolicy {
    pub name: String,
    pub algorithm: JwtAlgorithm,
    pub issuer: String,
    #[serde(default)]
    pub audiences: Vec<String>,
    #[serde(default)]
    pub required_scopes: Vec<String>,
    /// Reference to key material; actual secret/public key is sourced from env or external store.
    #[serde(default)]
    pub key_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RetryConfig {
    #[serde(default = "default_retry_attempts")]
    pub attempts: u32,
    #[serde(default = "default_retry_backoff_ms")]
    pub backoff_ms: u64,
}

fn default_retry_attempts() -> u32 {
    1
}

fn default_retry_backoff_ms() -> u64 {
    100
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    pub name: String,
    pub base_url: String,
    #[serde(default = "default_upstream_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub retry: Option<RetryConfig>,
}

fn default_upstream_timeout_ms() -> u64 {
    5_000
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitKey {
    ClientIp,
    JwtSubject,
    RoutePath,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitPolicy {
    pub name: String,
    pub limit_per_minute: u64,
    #[serde(default = "default_rate_limit_burst")]
    pub burst: u64,
    #[serde(default)]
    pub key: Vec<RateLimitKey>,
}

fn default_rate_limit_burst() -> u64 {
    0
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathMatch {
    Exact(String),
    Prefix(String),
}

#[derive(Debug, Clone, Deserialize)]
pub struct RouteConfig {
    pub id: String,
    pub match_path: PathMatch,
    #[serde(default)]
    pub methods: Vec<String>,
    pub upstream: String,
    #[serde(default)]
    pub rewrite_path: Option<String>,
    #[serde(default)]
    pub auth_policy: Option<String>,
    #[serde(default)]
    pub rate_limit: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MetricsConfig {
    #[serde(default = "default_metrics_path")]
    pub path: String,
}

fn default_metrics_path() -> String {
    "/metrics".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    pub server: ServerConfig,
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
    #[serde(default)]
    pub auth_policies: Vec<AuthPolicy>,
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    #[serde(default)]
    pub rate_limits: Vec<RateLimitPolicy>,
}

impl GatewayConfig {
    pub fn validate(&self) -> Result<()> {
        if self.upstreams.is_empty() {
            return Err(anyhow!("at least one upstream must be defined"));
        }

        for route in &self.routes {
            if !self
                .upstreams
                .iter()
                .any(|u| u.name == route.upstream)
            {
                return Err(anyhow!(
                    "route '{}' references unknown upstream '{}'",
                    route.id,
                    route.upstream
                ));
            }

            if let Some(ref auth_name) = route.auth_policy {
                if !self.auth_policies.iter().any(|p| &p.name == auth_name) {
                    return Err(anyhow!(
                        "route '{}' references unknown auth_policy '{}'",
                        route.id,
                        auth_name
                    ));
                }
            }

            if let Some(ref rl_name) = route.rate_limit {
                if !self.rate_limits.iter().any(|p| &p.name == rl_name) {
                    return Err(anyhow!(
                        "route '{}' references unknown rate_limit '{}'",
                        route.id,
                        rl_name
                    ));
                }
            }
        }

        Ok(())
    }
}

pub struct ConfigManager {
    shared: Arc<RwLock<GatewayConfig>>,
    path: PathBuf,
}

impl ConfigManager {
    pub fn load_initial(path: &str) -> Result<Self> {
        let path_buf = PathBuf::from(path);
        let cfg = load_config_file(&path_buf)?;
        cfg.validate()?;
        let shared = Arc::new(RwLock::new(cfg));
        Ok(Self {
            shared,
            path: path_buf,
        })
    }

    pub fn shared_config(&self) -> Arc<RwLock<GatewayConfig>> {
        self.shared.clone()
    }

    pub fn spawn_watcher(&self) {
        let path = self.path.clone();
        let shared = self.shared.clone();
        if !path.exists() {
            warn!(path = ?path, "config file does not exist, skipping watcher");
            return;
        }

        tokio::spawn(async move {
            if let Err(err) = watch_config(path, shared).await {
                error!(error = ?err, "config watcher terminated with error");
            }
        });
    }
}

fn load_config_file(path: &Path) -> Result<GatewayConfig> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file at {}", path.display()))?;

    // Try YAML first, then TOML as a fallback.
    let cfg: GatewayConfig = if path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("toml"))
        .unwrap_or(false)
    {
        toml::from_str(&raw).context("failed to parse config as TOML")?
    } else {
        match serde_yaml::from_str(&raw) {
            Ok(c) => c,
            Err(yaml_err) => {
                // Try TOML second.
                toml::from_str(&raw)
                    .map_err(|toml_err| anyhow!("YAML error: {yaml_err}; TOML error: {toml_err}"))
                    .context("failed to parse config as TOML")?
            }
        }
    };

    Ok(cfg)
}

async fn watch_config(path: PathBuf, shared: Arc<RwLock<GatewayConfig>>) -> Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    let mut watcher = recommended_watcher(move |res| {
        if let Err(err) = tx.send(res) {
            error!(error = ?err, "failed to send config watch event");
        }
    })?;

    watcher
        .watch(&path, RecursiveMode::NonRecursive)
        .with_context(|| format!("failed to watch config path {}", path.display()))?;

    info!(path = ?path, "started config watcher");

    while let Some(event_res) = rx.recv().await {
        match event_res {
            Ok(event) => {
                if matches!(
                    event.kind,
                    EventKind::Modify(_)
                        | EventKind::Create(_)
                        | EventKind::Remove(_)
                        | EventKind::Any
                ) {
                    info!(?event, "config file changed, reloading");
                    match load_config_file(&path).and_then(|cfg| {
                        cfg.validate()?;
                        Ok(cfg)
                    }) {
                        Ok(new_cfg) => {
                            let mut guard = shared.write().await;
                            *guard = new_cfg;
                            info!("config reloaded successfully");
                        }
                        Err(err) => {
                            error!(error = ?err, "failed to reload config, keeping previous");
                        }
                    }
                }
            }
            Err(err) => {
                warn!(error = ?err, "config watch error");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_unknown_upstream_fails() {
        let cfg = GatewayConfig {
            server: ServerConfig {
                listen_addr: "127.0.0.1:0".to_string(),
                shutdown_grace_period_secs: 30,
            },
            metrics: None,
            auth_policies: vec![],
            upstreams: vec![],
            routes: vec![RouteConfig {
                id: "r1".to_string(),
                match_path: PathMatch::Exact("/".to_string()),
                methods: vec!["GET".to_string()],
                upstream: "missing".to_string(),
                rewrite_path: None,
                auth_policy: None,
                rate_limit: None,
            }],
            rate_limits: vec![],
        };

        assert!(cfg.validate().is_err());
    }
}

