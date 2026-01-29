use crate::observability::{metrics_handler, Metrics};
use crate::proxy::proxy_handler;
use crate::rate_limit::RateLimitStore;
use crate::AppState;
use axum::http::StatusCode;
use axum::routing::{get, any};
use axum::Router;
use std::sync::Arc;
use tower_http::trace::TraceLayer;

pub fn build_router<S: RateLimitStore + Send + Sync + 'static>(
    state: Arc<AppState<S>>,
) -> Router {
    let metrics = Metrics::new();

    // Default metrics path - will be read from config at runtime if needed
    // For now, use default since we can't block in this function
    let metrics_path = "/metrics".to_string();

    let metrics_clone = metrics.clone();

    let router = Router::new()
        .route(
            "/healthz",
            get(|| async { StatusCode::OK }),
        )
        .route(
            "/readyz",
            get(|| async { StatusCode::OK }),
        )
        .route(
            &metrics_path,
            get(move || {
                let metrics = metrics_clone.clone();
                async move {
                    match metrics_handler(metrics).await {
                        Ok(body) => (StatusCode::OK, body),
                        Err((status, msg)) => (status, msg),
                    }
                }
            }),
        )
        .fallback(any(proxy_handler::<S>))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    router
}

