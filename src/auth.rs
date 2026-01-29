use crate::config::{AuthPolicy, JwtAlgorithm};
use axum::http::{header::AUTHORIZATION, StatusCode};
use axum::response::{IntoResponse, Response};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Option<String>,
    pub iss: String,
    pub aud: Option<String>,
    pub exp: i64,
    pub iat: Option<i64>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Clone)]
pub struct AuthContext {
    pub claims: Claims,
    pub policy_name: String,
}

/// Extract JWT token from Authorization header
pub fn extract_token(req: &axum::http::Request<axum::body::Body>) -> Option<String> {
    req.headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| {
            if s.starts_with("Bearer ") {
                Some(s[7..].to_string())
            } else {
                None
            }
        })
}

/// Get key material for a policy from environment variables
pub fn get_key_for_policy(policy: &AuthPolicy) -> Option<Vec<u8>> {
    let key_env = policy.key_id.as_ref().map(|kid| {
        format!("JWT_KEY_{}", kid.to_uppercase().replace("-", "_"))
    }).unwrap_or_else(|| {
        format!("JWT_KEY_{}", policy.name.to_uppercase().replace("-", "_"))
    });

    std::env::var(&key_env)
        .ok()
        .map(|s| s.into_bytes())
        .or_else(|| {
            // Fallback to generic JWT_SECRET
            std::env::var("JWT_SECRET").ok().map(|s| s.into_bytes())
        })
}

/// Validate JWT token against a policy
pub fn validate_token(
    token: &str,
    policy: &AuthPolicy,
    key: &[u8],
) -> Result<Claims, AuthError> {
    let header = decode_header(token).map_err(|e| {
        error!(error = ?e, "failed to decode JWT header");
        AuthError::InvalidToken
    })?;

    let alg = match policy.algorithm {
        JwtAlgorithm::HS256 => Algorithm::HS256,
        JwtAlgorithm::RS256 => Algorithm::RS256,
    };

    if header.alg != alg {
        return Err(AuthError::InvalidAlgorithm);
    }

    let decoding_key = match policy.algorithm {
        JwtAlgorithm::HS256 => DecodingKey::from_secret(key),
        JwtAlgorithm::RS256 => {
            // For RS256, expect PEM-encoded public key
            DecodingKey::from_rsa_pem(key)
                .map_err(|e| {
                    error!(error = ?e, "failed to parse RSA public key");
                    AuthError::InvalidKey
                })?
        }
    };

    let mut validation = Validation::new(alg);
    validation.set_issuer(&[policy.issuer.clone()]);
    if !policy.audiences.is_empty() {
        validation.set_audience(&policy.audiences);
    }
    validation.validate_exp = true;

    let token_data = decode::<Claims>(token, &decoding_key, &validation)
        .map_err(|e| {
            error!(error = ?e, "JWT validation failed");
            match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::ExpiredToken,
                jsonwebtoken::errors::ErrorKind::InvalidIssuer => AuthError::InvalidIssuer,
                jsonwebtoken::errors::ErrorKind::InvalidAudience => AuthError::InvalidAudience,
                _ => AuthError::InvalidToken,
            }
        })?;

    let mut claims = token_data.claims;

    // Check required scopes if specified
    if !policy.required_scopes.is_empty() {
        let scopes: Vec<String> = claims
            .extra
            .get("scope")
            .and_then(|v| v.as_str())
            .map(|s| s.split(' ').map(String::from).collect())
            .unwrap_or_default();

        for required in &policy.required_scopes {
            if !scopes.contains(required) {
                return Err(AuthError::InsufficientScope);
            }
        }
    }

    Ok(claims)
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing authorization header")]
    MissingAuth,
    #[error("invalid token")]
    InvalidToken,
    #[error("invalid algorithm")]
    InvalidAlgorithm,
    #[error("invalid key")]
    InvalidKey,
    #[error("expired token")]
    ExpiredToken,
    #[error("invalid issuer")]
    InvalidIssuer,
    #[error("invalid audience")]
    InvalidAudience,
    #[error("insufficient scope")]
    InsufficientScope,
    #[error("policy not found")]
    PolicyNotFound,
    #[error("key not found")]
    KeyNotFound,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response<axum::body::Body> {
        let (status, body) = match self {
            AuthError::MissingAuth | AuthError::InvalidToken | AuthError::InvalidAlgorithm
            | AuthError::InvalidKey => (StatusCode::UNAUTHORIZED, "Unauthorized"),
            AuthError::ExpiredToken => (StatusCode::UNAUTHORIZED, "Token expired"),
            AuthError::InvalidIssuer | AuthError::InvalidAudience => {
                (StatusCode::UNAUTHORIZED, "Invalid token claims")
            }
            AuthError::InsufficientScope => (StatusCode::FORBIDDEN, "Insufficient permissions"),
            AuthError::PolicyNotFound | AuthError::KeyNotFound => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Configuration error")
            }
        };

        Response::builder()
            .status(status)
            .body(axum::body::Body::from(body))
            .unwrap()
    }
}

// Auth middleware functionality is integrated directly into proxy handler
// This module provides the core auth validation functions

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthPolicy;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn create_test_policy() -> AuthPolicy {
        AuthPolicy {
            name: "test".to_string(),
            algorithm: JwtAlgorithm::HS256,
            issuer: "test-issuer".to_string(),
            audiences: vec!["test-audience".to_string()],
            required_scopes: vec![],
            key_id: None,
        }
    }

    fn create_test_token(issuer: &str, audience: &str, exp: i64) -> String {
        let claims = Claims {
            sub: Some("test-user".to_string()),
            iss: issuer.to_string(),
            aud: Some(audience.to_string()),
            exp,
            iat: Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64,
            ),
            extra: HashMap::new(),
        };

        let key = b"test-secret";
        encode(&Header::default(), &claims, &EncodingKey::from_secret(key)).unwrap()
    }

    #[test]
    fn test_extract_token() {
        let req = axum::http::Request::builder()
            .uri("http://example.com")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap();

        assert_eq!(extract_token(&req), Some("test-token".to_string()));

        let req_no_auth = axum::http::Request::builder()
            .uri("http://example.com")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(extract_token(&req_no_auth), None);
    }

    #[test]
    fn test_validate_token_success() {
        std::env::set_var("JWT_KEY_TEST", "test-secret");
        let policy = create_test_policy();
        let token = create_test_token("test-issuer", "test-audience", i64::MAX);
        let key = get_key_for_policy(&policy).unwrap();

        let result = validate_token(&token, &policy, &key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_token_wrong_issuer() {
        std::env::set_var("JWT_KEY_TEST", "test-secret");
        let policy = create_test_policy();
        let token = create_test_token("wrong-issuer", "test-audience", i64::MAX);
        let key = get_key_for_policy(&policy).unwrap();

        let result = validate_token(&token, &policy, &key);
        assert!(matches!(result, Err(AuthError::InvalidIssuer)));
    }
}
