//! Fail-closed validation of OIDC Authorization Code + S256 PKCE requests.
//! No authorization endpoint is exposed until issuing codes and signing tokens
//! are fully implemented and tested.
pub mod authorization;
pub mod consent;
pub mod discovery;
pub mod grants;
pub mod introspection;
pub mod signing;
pub mod token;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, DbErr, Statement};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::services::client::{get_client, is_redirect_uri_allowed};

#[derive(Debug, Deserialize)]
pub struct AuthorizationRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    #[serde(default)]
    pub resource: Option<String>,
    pub state: String,
    pub nonce: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthorizationError {
    InvalidClient,
    InvalidRedirect,
    UnsupportedResponseType,
    InvalidScope,
    InvalidState,
    InvalidNonce,
    InvalidPkce,
    Database,
}

impl From<DbErr> for AuthorizationError {
    fn from(_: DbErr) -> Self {
        Self::Database
    }
}

fn opaque(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len())
        && value.is_ascii()
        && value.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

pub fn valid_code_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

pub fn s256_challenge(verifier: &str) -> Option<String> {
    valid_code_verifier(verifier)
        .then(|| URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())))
}

pub fn matches_s256(challenge: &str, verifier: &str) -> bool {
    s256_challenge(verifier).is_some_and(|computed| computed == challenge)
}

pub async fn validate_authorization_request(
    db: &DatabaseConnection,
    request: &AuthorizationRequest,
) -> Result<(), AuthorizationError> {
    let app = get_client(db, &request.client_id)
        .await?
        .ok_or(AuthorizationError::InvalidClient)?;

    // Never redirect protocol errors to an unvalidated URI.
    if !is_redirect_uri_allowed(db, &app, &request.redirect_uri).await? {
        return Err(AuthorizationError::InvalidRedirect);
    }
    if let Some(resource) = &request.resource {
        if resource.len() > 256 { return Err(AuthorizationError::InvalidClient); }
        let allowed = db.query_one_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT 1 FROM oauth_client_resources cr JOIN oauth_resources r ON cr.resource_id = r.id WHERE cr.client_id = ? AND r.audience = ? AND r.active = 1",
            [app.id.to_string().into(), resource.clone().into()],
        )).await?;
        if allowed.is_none() { return Err(AuthorizationError::InvalidClient); }
    }
    if request.response_type != "code" {
        return Err(AuthorizationError::UnsupportedResponseType);
    }
    let scopes: Vec<_> = request.scope.split_whitespace().collect();
    if !scopes.contains(&"openid")
        || scopes.is_empty()
        || scopes
            .iter()
            .any(|scope| !matches!(*scope, "openid" | "profile" | "email"))
        || scopes
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != scopes.len()
    {
        return Err(AuthorizationError::InvalidScope);
    }
    if !opaque(&request.state, 16, 512) {
        return Err(AuthorizationError::InvalidState);
    }
    if !opaque(&request.nonce, 16, 256) {
        return Err(AuthorizationError::InvalidNonce);
    }
    if request.code_challenge_method != "S256" {
        return Err(AuthorizationError::InvalidPkce);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(&request.code_challenge)
        .map_err(|_| AuthorizationError::InvalidPkce)?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(decoded) != request.code_challenge {
        return Err(AuthorizationError::InvalidPkce);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::Database;

    use super::{
        AuthorizationError, AuthorizationRequest, matches_s256, s256_challenge,
        valid_code_verifier, validate_authorization_request,
    };
    use crate::{
        schema,
        services::client::{ClientType, disable_client, register_client},
    };

    #[test]
    fn pkce_rfc7636_s256_vector_and_invalid_verifiers() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(valid_code_verifier(verifier));
        assert_eq!(s256_challenge(verifier).as_deref(), Some(challenge));
        assert!(matches_s256(challenge, verifier));
        assert!(!matches_s256(challenge, "otherverifier"));
        assert!(!valid_code_verifier("short"));
        assert!(!valid_code_verifier(&"A".repeat(129)));
        assert!(!valid_code_verifier(
            &"A".repeat(42).to_string().replace("A", " ")
        ));
        assert!(!valid_code_verifier(&("A".repeat(42) + "!")));
    }

    #[tokio::test]
    async fn valid_request_binds_registered_client_redirect_scope_and_s256() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        schema::apply(&db).await.unwrap();
        let redirect = "https://client.example.com/callback".to_owned();
        let client_id = register_client(
            &db,
            "Client",
            ClientType::Web,
            std::slice::from_ref(&redirect),
        )
        .await
        .unwrap();

        let mut request = AuthorizationRequest {
            response_type: "code".into(),
            client_id: client_id.clone(),
            redirect_uri: redirect,
            scope: "openid profile email".into(),
            resource: None,
            state: "opaque_state_123456789".into(),
            nonce: "opaque_nonce_123456789".into(),
            code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into(),
            code_challenge_method: "S256".into(),
        };
        assert_eq!(validate_authorization_request(&db, &request).await, Ok(()));

        request.redirect_uri = "https://attacker.example/callback".into();
        assert_eq!(
            validate_authorization_request(&db, &request).await,
            Err(AuthorizationError::InvalidRedirect)
        );
        request.redirect_uri = "https://client.example.com/callback".into();
        request.code_challenge_method = "plain".into();
        assert_eq!(
            validate_authorization_request(&db, &request).await,
            Err(AuthorizationError::InvalidPkce)
        );
        request.code_challenge_method = "S256".into();
        // Reject malformed PKCE rather than trying to guess client entropy.
        request.code_challenge = "0".repeat(42);
        assert_eq!(
            validate_authorization_request(&db, &request).await,
            Err(AuthorizationError::InvalidPkce)
        );
        request.code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into();
        request.response_type = "token".into();
        assert_eq!(
            validate_authorization_request(&db, &request).await,
            Err(AuthorizationError::UnsupportedResponseType)
        );
        request.response_type = "code".into();
        request.scope = "profile email".into();
        assert_eq!(
            validate_authorization_request(&db, &request).await,
            Err(AuthorizationError::InvalidScope)
        );
        request.scope = "openid".into();
        request.nonce = "short".into();
        assert_eq!(
            validate_authorization_request(&db, &request).await,
            Err(AuthorizationError::InvalidNonce)
        );
        request.nonce = "opaque_nonce_123456789".into();
        assert_eq!(validate_authorization_request(&db, &request).await, Ok(()));
        disable_client(&db, &client_id).await.unwrap();
        assert_eq!(
            validate_authorization_request(&db, &request).await,
            Err(AuthorizationError::InvalidClient)
        );
    }
}
