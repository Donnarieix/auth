//! Provider discovery is deliberately unavailable until the authorization
//! and token endpoints pass full interoperability tests.
use axum::{Json, extract::State, http::StatusCode};
use serde::Serialize;

use crate::state::AppState;

#[derive(Serialize)]
pub struct ProviderMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    response_types_supported: Vec<&'static str>,
    subject_types_supported: Vec<&'static str>,
    id_token_signing_alg_values_supported: Vec<&'static str>,
    scopes_supported: Vec<&'static str>,
    grant_types_supported: Vec<&'static str>,
    token_endpoint_auth_methods_supported: Vec<&'static str>,
    code_challenge_methods_supported: Vec<&'static str>,
}

impl ProviderMetadata {
    pub fn new(origin: &str) -> Result<Self, &'static str> {
        if !origin.starts_with("https://")
            || origin.ends_with('/')
            || origin.contains('?')
            || origin.contains('#')
            || origin.contains('@')
        {
            return Err("An exact HTTPS issuer origin is required");
        }
        Ok(Self {
            issuer: origin.to_owned(),
            authorization_endpoint: format!("{origin}/authorize"),
            token_endpoint: format!("{origin}/token"),
            jwks_uri: format!("{origin}/.well-known/jwks.json"),
            response_types_supported: vec!["code"],
            subject_types_supported: vec!["public"],
            id_token_signing_alg_values_supported: vec!["RS256"],
            scopes_supported: vec!["openid", "profile", "email"],
            grant_types_supported: vec!["authorization_code"],
            token_endpoint_auth_methods_supported: vec!["none"],
            code_challenge_methods_supported: vec!["S256"],
        })
    }
}

/// This route is NOT wired into the HTTP router until /authorize and /token
/// are implemented and tested. Misleading metadata would be dangerous.
#[expect(
    dead_code,
    reason = "Provider discovery is gated on end-to-end OIDC readiness"
)]
pub async fn discovery(
    State(state): State<AppState>,
) -> Result<Json<ProviderMetadata>, StatusCode> {
    if state.oidc_keys.is_none() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    ProviderMetadata::new(&state.security.origin)
        .map(Json)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

#[cfg(test)]
mod tests {
    use super::ProviderMetadata;

    #[test]
    fn metadata_is_https_only_and_advertises_pkce_for_public_clients() {
        assert!(ProviderMetadata::new("http://127.0.0.1:3000").is_err());
        assert!(ProviderMetadata::new("https://bad.example/path/").is_err());
        assert!(ProviderMetadata::new("https://evil@trusted.example").is_err());
        let metadata = ProviderMetadata::new("https://auth.example.test").unwrap();
        let json = serde_json::to_value(metadata).unwrap();
        assert_eq!(json["issuer"], "https://auth.example.test");
        assert_eq!(
            json["jwks_uri"],
            "https://auth.example.test/.well-known/jwks.json"
        );
        assert_eq!(
            json["authorization_endpoint"],
            "https://auth.example.test/authorize"
        );
        assert_eq!(json["token_endpoint_auth_methods_supported"][0], "none");
        assert_eq!(json["code_challenge_methods_supported"][0], "S256");
        assert_eq!(json["response_types_supported"][0], "code");
    }
}
