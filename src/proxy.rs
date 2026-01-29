use crate::auth::{extract_token, get_key_for_policy, validate_token, AuthError};
use crate::config::{GatewayConfig, PathMatch, RateLimitKey, UpstreamConfig};
use crate::rate_limit::{RateLimitError, RateLimitStore};
use crate::AppState;
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, Request, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use reqwest::Url;
use std::sync::Arc;
use tracing::{error, instrument, warn};

/// Metadata attached to each request after routing resolution.
#[derive(Clone, Debug)]
pub struct ResolvedRoute {
    pub route_id: String,
    pub upstream: UpstreamConfig,
    pub rewrite_path: Option<String>,
    pub auth_policy: Option<String>,
    pub rate_limit: Option<String>,
}

fn strip_hop_by_hop_headers(headers: &mut HeaderMap) {
    headers.remove(header::CONNECTION);
    headers.remove(header::PROXY_AUTHENTICATE);
    headers.remove(header::PROXY_AUTHORIZATION);
    headers.remove(header::TE);
    headers.remove(header::TRAILER);
    headers.remove(header::TRANSFER_ENCODING);
    headers.remove(header::UPGRADE);
}

fn resolve_route<'a>(
    cfg: &'a GatewayConfig,
    method: &axum::http::Method,
    path: &str,
) -> Option<ResolvedRoute> {
    for route in &cfg.routes {
        let method_match = if route.methods.is_empty() {
            true
        } else {
            route
                .methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(method.as_str()))
        };
        if !method_match {
            continue;
        }

        let path_match = match &route.match_path {
            PathMatch::Exact(p) => p == path,
            PathMatch::Prefix(p) => path.starts_with(p),
        };
        if !path_match {
            continue;
        }

        let upstream = cfg
            .upstreams
            .iter()
            .find(|u| u.name == route.upstream)?
            .clone();

        return Some(ResolvedRoute {
            route_id: route.id.clone(),
            upstream,
            rewrite_path: route.rewrite_path.clone(),
            auth_policy: route.auth_policy.clone(),
            rate_limit: route.rate_limit.clone(),
        });
    }

    None
}

fn build_upstream_uri(
    upstream: &UpstreamConfig,
    original_uri: &Uri,
    rewrite_path: &Option<String>,
) -> Result<Url, anyhow::Error> {
    let mut base = upstream.base_url.clone();
    if base.ends_with('/') {
        base.pop();
    }

    let path_and_query = if let Some(rewrite) = rewrite_path {
        if let Some(q) = original_uri.query() {
            format!("{}?{}", rewrite, q)
        } else {
            rewrite.clone()
        }
    } else {
        original_uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string())
    };

    let full = format!("{}{}", base, path_and_query);
    Url::parse(&full).map_err(|e| anyhow::anyhow!(e))
}

fn to_reqwest_method(method: &axum::http::Method) -> Result<reqwest::Method, ()> {
    reqwest::Method::from_bytes(method.as_str().as_bytes()).map_err(|_| ())
}

async fn check_auth<S: RateLimitStore + Send + Sync>(
    state: &Arc<AppState<S>>,
    req: &mut Request<Body>,
    policy_name: &str,
) -> Result<(), AuthError> {
    let token = extract_token(req).ok_or(AuthError::MissingAuth)?;

    let cfg = state.config.read().await;
    let policy = cfg
        .auth_policies
        .iter()
        .find(|p| p.name == policy_name)
        .ok_or(AuthError::PolicyNotFound)?;

    let key = get_key_for_policy(policy).ok_or(AuthError::KeyNotFound)?;
    let claims = validate_token(&token, policy, &key)?;

    // Attach claims to request extensions for downstream use
    req.extensions_mut().insert(crate::auth::AuthContext {
        claims,
        policy_name: policy_name.to_string(),
    });

    Ok(())
}

fn build_rate_limit_key(
    policy: &crate::config::RateLimitPolicy,
    req: &Request<Body>,
    resolved: &ResolvedRoute,
) -> String {
    let mut parts = Vec::new();
    for key_type in &policy.key {
        match key_type {
            RateLimitKey::ClientIp => {
                if let Some(ip) = req
                    .headers()
                    .get("x-forwarded-for")
                    .or_else(|| req.headers().get("x-real-ip"))
                    .and_then(|h| h.to_str().ok())
                {
                    parts.push(format!("ip:{}", ip.split(',').next().unwrap_or(ip).trim()));
                }
            }
            RateLimitKey::JwtSubject => {
                if let Some(auth_ctx) = req.extensions().get::<crate::auth::AuthContext>() {
                    if let Some(sub) = &auth_ctx.claims.sub {
                        parts.push(format!("sub:{}", sub));
                    }
                } else {
                    // Fallback to IP if no JWT subject
                    if let Some(ip) = req
                        .headers()
                        .get("x-forwarded-for")
                        .or_else(|| req.headers().get("x-real-ip"))
                        .and_then(|h| h.to_str().ok())
                    {
                        parts.push(format!("ip:{}", ip.split(',').next().unwrap_or(ip).trim()));
                    }
                }
            }
            RateLimitKey::RoutePath => {
                parts.push(format!("route:{}", resolved.route_id));
            }
        }
    }
    if parts.is_empty() {
        format!("default:{}", resolved.route_id)
    } else {
        parts.join(":")
    }
}

async fn check_rate_limit<S: RateLimitStore + Send + Sync>(
    state: &Arc<AppState<S>>,
    req: &mut Request<Body>,
    resolved: &ResolvedRoute,
) -> Result<(), RateLimitError> {
    let policy_name = match &resolved.rate_limit {
        Some(name) => name,
        None => return Ok(()),
    };

    let cfg = state.config.read().await;
    let policy = cfg
        .rate_limits
        .iter()
        .find(|p| &p.name == policy_name)
        .ok_or_else(|| {
            error!(policy = %policy_name, "rate limit policy not found");
            RateLimitError::Internal
        })?;

    let key = build_rate_limit_key(policy, req, resolved);
    let limit = policy.limit_per_minute;
    let window = 60; // 1 minute

    drop(cfg);

    let result = state
        .rate_limit_store
        .check_rate_limit(&key, limit, window)
        .await?;

    if !result.allowed {
        return Err(RateLimitError::Limited);
    }

    Ok(())
}

#[instrument(skip_all, fields(route_id = tracing::field::Empty, upstream = tracing::field::Empty))]
pub async fn proxy_handler<S: RateLimitStore + Send + Sync + 'static>(
    State(state): State<Arc<AppState<S>>>,
    mut req: Request<Body>,
) -> impl IntoResponse {
    let cfg_guard = state.config.read().await;
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    let resolved = match resolve_route(&cfg_guard, &method, &path) {
        Some(r) => r,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    tracing::Span::current().record("route_id", tracing::field::display(&resolved.route_id));
    tracing::Span::current().record("upstream", tracing::field::display(&resolved.upstream.name));

    // Check authentication if required
    if let Some(ref auth_policy) = resolved.auth_policy {
        match check_auth(&state, &mut req, auth_policy).await {
            Ok(_) => {
                // Auth passed, continue
            }
            Err(err) => return err.into_response(),
        }
    }

    // Check rate limiting
    if let Err(e) = check_rate_limit(&state, &mut req, &resolved).await {
        match e {
            RateLimitError::Redis(_) | RateLimitError::Timeout => {
                warn!(error = ?e, "rate limit check failed, allowing request");
            }
            _ => {
                return e.into_response();
            }
        }
    }

    drop(cfg_guard);

    let upstream_uri = match build_upstream_uri(&resolved.upstream, req.uri(), &resolved.rewrite_path) {
        Ok(uri) => uri,
        Err(err) => {
            error!(error = ?err, "failed to build upstream URI");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let (parts, body) = req.into_parts();
    let mut headers = parts.headers.clone();
    strip_hop_by_hop_headers(&mut headers);

    const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;
    let body_bytes = match axum::body::to_bytes(body, MAX_BODY_BYTES).await {
        Ok(b) => b,
        Err(e) => {
            error!(error = ?e, "failed to read request body");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    let method = match to_reqwest_method(&parts.method) {
        Ok(m) => m,
        Err(_) => return StatusCode::METHOD_NOT_ALLOWED.into_response(),
    };

    let mut upstream_req = state
        .http_client
        .request(method, upstream_uri)
        .body(body_bytes);

    for (name, value) in headers.iter() {
        upstream_req = upstream_req.header(name, value);
    }

    let upstream_resp = match upstream_req.send().await {
        Ok(r) => r,
        Err(err) => {
            error!(error = ?err, "upstream request failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let resp_body = match upstream_resp.bytes().await {
        Ok(b) => b,
        Err(err) => {
            error!(error = ?err, "failed to read upstream response body");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let mut response = Response::new(Body::from(resp_body));
    *response.status_mut() = StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    for (k, v) in resp_headers.iter() {
        response.headers_mut().insert(k, v.clone());
    }
    response.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GatewayConfig, MetricsConfig, RouteConfig, ServerConfig};

    #[test]
    fn resolve_route_exact_match() {
        let cfg = GatewayConfig {
            server: ServerConfig {
                listen_addr: "127.0.0.1:0".into(),
                shutdown_grace_period_secs: 30,
            },
            metrics: Some(MetricsConfig { path: "/metrics".into() }),
            auth_policies: vec![],
            upstreams: vec![UpstreamConfig {
                name: "u1".into(),
                base_url: "http://example.com".into(),
                timeout_ms: 1000,
                retry: None,
            }],
            routes: vec![RouteConfig {
                id: "r1".into(),
                match_path: PathMatch::Exact("/foo".into()),
                methods: vec!["GET".into()],
                upstream: "u1".into(),
                rewrite_path: None,
                auth_policy: None,
                rate_limit: None,
            }],
            rate_limits: vec![],
        };

        let resolved = resolve_route(&cfg, &axum::http::Method::GET, "/foo").expect("route should resolve");
        assert_eq!(resolved.route_id, "r1");
        assert_eq!(resolved.upstream.name, "u1");
    }
}

