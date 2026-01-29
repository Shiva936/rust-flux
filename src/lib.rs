pub mod auth;
pub mod config;
pub mod observability;
pub mod proxy;
pub mod rate_limit;
pub mod server;

use crate::rate_limit::RateLimitStore;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct AppState<S: RateLimitStore> {
    pub config: Arc<RwLock<config::GatewayConfig>>,
    pub rate_limit_store: Arc<S>,
    pub http_client: reqwest::Client,
}

