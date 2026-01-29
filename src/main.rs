use rust_flux::config::ConfigManager;
use rust_flux::observability::init_tracing;
use rust_flux::server::build_router;
use anyhow::Context;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::RwLock;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    init_tracing();

    let config_path =
        std::env::var("GATEWAY_CONFIG_PATH").unwrap_or_else(|_| "config/config.yaml".into());

    let manager = ConfigManager::load_initial(&config_path)
        .with_context(|| format!("failed to load initial config from {}", config_path))?;

    let shared_config = manager.shared_config();
    manager.spawn_watcher();

    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379/".to_string());
    let rate_limit_store = rust_flux::rate_limit::RedisRateLimitStore::new(redis_url.clone())
        .context("failed to create Redis rate limit store")?;

    let http_client = reqwest::Client::builder()
        .user_agent("rust-flux/0.1")
        .build()
        .context("failed to build reqwest client")?;

    let state = Arc::new(rust_flux::AppState {
        config: shared_config,
        rate_limit_store: Arc::new(rate_limit_store),
        http_client,
    });

    let cfg_read = state.config.read().await;
    let addr: SocketAddr = cfg_read
        .server
        .listen_addr
        .parse()
        .context("invalid listen_addr in config")?;
    drop(cfg_read);

    let app = build_router(state.clone());

    info!(%addr, "starting gateway server");

    let listener = tokio::net::TcpListener::bind(&addr).await
        .context("failed to bind to address")?;
    
    let graceful = axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal());

    if let Err(err) = graceful.await {
        error!(error = ?err, "server error");
    }

    info!("gateway shut down");
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sig_int =
            signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");
        let mut sig_term =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");

        tokio::select! {
            _ = sig_int.recv() => {
                info!("received SIGINT, starting graceful shutdown");
            }
            _ = sig_term.recv() => {
                info!("received SIGTERM, starting graceful shutdown");
            }
        }
    }

    #[cfg(not(unix))]
    {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
        info!("received Ctrl+C, starting graceful shutdown");
    }
}

