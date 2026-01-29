use rust_flux::config::{GatewayConfig, PathMatch, RouteConfig, ServerConfig, UpstreamConfig};
use rust_flux::rate_limit::MemoryRateLimitStore;
use rust_flux::AppState;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

async fn create_test_gateway() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    // Create a simple mock upstream server
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    
    let upstream_handle = tokio::spawn(async move {
        let app = axum::Router::new()
            .route("/test", axum::routing::get(|| async { "OK" }))
            .route("/echo", axum::routing::post(|body: axum::body::Body| async move {
                let bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
                format!("Echo: {}", String::from_utf8_lossy(&bytes))
            }));
        
        axum::serve(upstream_listener, app.into_make_service())
            .await
            .unwrap();
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let test_config = GatewayConfig {
        server: ServerConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            shutdown_grace_period_secs: 5,
        },
        metrics: None,
        auth_policies: vec![],
        upstreams: vec![UpstreamConfig {
            name: "test-upstream".to_string(),
            base_url: format!("http://{}", upstream_addr),
            timeout_ms: 5000,
            retry: None,
        }],
        routes: vec![RouteConfig {
            id: "test-route".to_string(),
            match_path: PathMatch::Prefix("/".to_string()),
            methods: vec![],
            upstream: "test-upstream".to_string(),
            rewrite_path: None,
            auth_policy: None,
            rate_limit: None,
        }],
        rate_limits: vec![],
    };

    let shared_config = Arc::new(RwLock::new(test_config));
    let rate_limit_store = Arc::new(MemoryRateLimitStore::new());
    let http_client = reqwest::Client::new();

    let state = Arc::new(AppState {
        config: shared_config,
        rate_limit_store,
        http_client,
    });

    let app = rust_flux::server::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Keep upstream handle alive
    tokio::spawn(async move {
        upstream_handle.await.ok();
    });

    (addr, handle)
}

#[tokio::test]
async fn test_health_endpoint() {
    let (addr, _handle) = create_test_gateway().await;

    let client = reqwest::Client::new();
    let response = client
        .get(&format!("http://{}/healthz", addr))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
}

#[tokio::test]
async fn test_proxy_flow() {
    let (addr, _handle) = create_test_gateway().await;

    let client = reqwest::Client::new();
    let response = client
        .get(&format!("http://{}/test", addr))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.text().await.unwrap();
    assert_eq!(body, "OK");
}
