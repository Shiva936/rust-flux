use async_trait::async_trait;
use axum::response::IntoResponse;
use axum::http::StatusCode;
use axum::response::Response;
use axum::body::Body;
use redis::AsyncCommands;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{error, warn};

#[async_trait]
pub trait RateLimitStore: Send + Sync {
    async fn check_rate_limit(
        &self,
        key: &str,
        limit: u64,
        window_seconds: u64,
    ) -> Result<RateLimitResult, RateLimitError>;
}

impl IntoResponse for RateLimitError {
    fn into_response(self) -> Response<Body> {
        let (status, body) = match self {
            RateLimitError::Timeout | RateLimitError::Redis(_) => {
                (StatusCode::SERVICE_UNAVAILABLE, "Rate limit service unavailable")
            }
            RateLimitError::Limited => {
                (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded")
            }
            RateLimitError::Internal => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Rate limiting error")
            }
        };

        Response::builder()
            .status(status)
            .body(Body::from(body))
            .unwrap()
    }
}

#[derive(Debug, Clone)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub remaining: u64,
    pub reset_after: Option<Duration>,
}

#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("timeout")]
    Timeout,
    #[error("rate limited")]
    Limited,
    #[error("internal error")]
    Internal,
}

/// Redis-backed fixed-window counter (reliable + simple).
pub struct RedisRateLimitStore {
    client: redis::Client,
}

impl RedisRateLimitStore {
    pub fn new(url: String) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(url)?;
        Ok(Self { client })
    }
}

#[async_trait]
impl RateLimitStore for RedisRateLimitStore {
    async fn check_rate_limit(
        &self,
        key: &str,
        limit: u64,
        window_seconds: u64,
    ) -> Result<RateLimitResult, RateLimitError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(RateLimitError::Redis)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let window_start = (now / window_seconds) * window_seconds;
        let redis_key = format!("ratelimit:{}:{}", key, window_start);

        let count: u64 = conn.incr(&redis_key, 1_u64).await?;
        // ensure TTL is set (best effort)
        let _: () = conn.expire(&redis_key, window_seconds as i64).await?;

        if count > limit {
            let reset_after = Duration::from_secs((window_start + window_seconds).saturating_sub(now));
            return Ok(RateLimitResult {
                allowed: false,
                remaining: 0,
                reset_after: Some(reset_after),
            });
        }

        Ok(RateLimitResult {
            allowed: true,
            remaining: limit.saturating_sub(count),
            reset_after: Some(Duration::from_secs((window_start + window_seconds).saturating_sub(now))),
        })
    }
}

/// In-memory rate limit store for testing
pub struct MemoryRateLimitStore {
    store: Arc<RwLock<std::collections::HashMap<String, Vec<u64>>>>,
}

impl MemoryRateLimitStore {
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }
}

#[async_trait]
impl RateLimitStore for MemoryRateLimitStore {
    async fn check_rate_limit(
        &self,
        key: &str,
        limit: u64,
        window_seconds: u64,
    ) -> Result<RateLimitResult, RateLimitError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut store = self.store.write().await;
        let entries = store.entry(key.to_string()).or_insert_with(Vec::new);

        // Remove old entries
        entries.retain(|&ts| ts > now.saturating_sub(window_seconds));

        if entries.len() as u64 >= limit {
            let oldest = entries.first().copied().unwrap_or(now);
            let reset_after = Duration::from_secs(
                (oldest + window_seconds).saturating_sub(now),
            );

            return Ok(RateLimitResult {
                allowed: false,
                remaining: 0,
                reset_after: Some(reset_after),
            });
        }

        entries.push(now);
        let remaining = limit - entries.len() as u64;

        Ok(RateLimitResult {
            allowed: true,
            remaining,
            reset_after: Some(Duration::from_secs(window_seconds)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_rate_limit_allows_under_limit() {
        let store = MemoryRateLimitStore::new();
        let result = store
            .check_rate_limit("test-key", 10, 60)
            .await
            .unwrap();

        assert!(result.allowed);
        assert_eq!(result.remaining, 9);
    }

    #[tokio::test]
    async fn test_memory_rate_limit_blocks_over_limit() {
        let store = MemoryRateLimitStore::new();
        let key = "test-key";

        // Fill up to limit
        for _ in 0..10 {
            store.check_rate_limit(key, 10, 60).await.unwrap();
        }

        // Next request should be blocked
        let result = store.check_rate_limit(key, 10, 60).await.unwrap();
        assert!(!result.allowed);
        assert_eq!(result.remaining, 0);
    }
}
