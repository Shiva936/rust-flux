use prometheus::{Encoder, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder};
use tracing::info;
use tracing_subscriber::fmt::format::FmtSpan;

pub fn init_tracing() {
    let env_filter =
        std::env::var("RUST_LOG").unwrap_or_else(|_| "info,rust_flux=debug,axum::rejection=trace".into());

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_span_events(FmtSpan::CLOSE)
        .with_line_number(true)
        .with_level(true)
        .init();
}

/// Simple metrics registry for Prometheus exposure.
#[derive(Clone)]
pub struct Metrics {
    pub registry: Registry,
    pub http_requests_total: IntCounterVec,
    pub http_request_duration_seconds: HistogramVec,
}

impl Metrics {
    pub fn new() -> Self {
        let registry = Registry::new();

        let http_requests_total = IntCounterVec::new(
            Opts::new("http_requests_total", "Total number of HTTP requests"),
            &["method", "path", "status"],
        )
        .expect("failed to create http_requests_total");

        let http_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "http_request_duration_seconds",
                "HTTP request latencies in seconds",
            ),
            &["method", "path"],
        )
        .expect("failed to create http_request_duration_seconds");

        registry
            .register(Box::new(http_requests_total.clone()))
            .expect("failed to register http_requests_total");
        registry
            .register(Box::new(http_request_duration_seconds.clone()))
            .expect("failed to register http_request_duration_seconds");

        Self {
            registry,
            http_requests_total,
            http_request_duration_seconds,
        }
    }
}

pub async fn metrics_handler(metrics: Metrics) -> Result<String, (axum::http::StatusCode, String)> {
    let encoder = TextEncoder::new();
    let metric_families = metrics
        .registry
        .gather();
    let mut buffer = Vec::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    String::from_utf8(buffer)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

