//! Public-client Authorization Code + PKCE token exchange and UserInfo.
//! Bearer access tokens are opaque, short-lived and hashed at rest.
use axum::{
    Form, Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{Duration, Utc};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    entities::{client, oidc_access_token, user},
    oidc::{consent, grants},
    services::session::generate_token,
    state::AppState,
};

#[derive(Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code: String,
    pub code_verifier: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    id_token: String,
    scope: String,
}

#[derive(Serialize)]
struct OAuthError {
    error: &'static str,
}

fn invalid_grant() -> (StatusCode, Json<OAuthError>) {
    (
        StatusCode::BAD_REQUEST,
        Json(OAuthError {
            error: "invalid_grant",
        }),
    )
}

fn invalid_request() -> (StatusCode, Json<OAuthError>) {
    (
        StatusCode::BAD_REQUEST,
        Json(OAuthError {
            error: "invalid_request",
        }),
    )
}

/// Accepts public PKCE clients without credentials and web clients
/// only with a separately configured confidential client secret over HTTP Basic.
fn valid_web_client_secret(headers: &HeaderMap, id: &str, hash: &[u8]) -> bool {
    let Some(encoded) = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Basic "))
    else {
        return false;
    };
    let Ok(decoded) = STANDARD.decode(encoded) else {
        return false;
    };
    let Ok(credentials) = std::str::from_utf8(&decoded) else {
        return false;
    };
    let Some((username, password)) = credentials.split_once(':') else {
        return false;
    };
    if username != id || password.len() != 43 || !password.is_ascii() || hash.len() != 32 {
        return false;
    }
    let digest = Sha256::digest(password.as_bytes());
    digest
        .iter()
        .zip(hash)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Public clients must never present client credentials; confidential web
/// clients must authenticate before an authorization code can be consumed.
pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<TokenRequest>,
) -> impl IntoResponse {
    let Some(keys) = &state.oidc_keys else {
        return invalid_request().into_response();
    };
    if form.grant_type != "authorization_code"
        || form.client_id.len() > 256
        || form.code.len() > 256
        || form.redirect_uri.len() > 2048
        || form.code_verifier.len() > 128
    {
        return invalid_request().into_response();
    }
    if !state
        .abuse
        .allow("oidc_token", &form.client_id, 80, 20)
        .await
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(OAuthError { error: "slow_down" }),
        )
            .into_response();
    }

    let app = match client::Entity::find()
        .filter(client::COLUMN.client_id.eq(&form.client_id))
        .filter(client::COLUMN.active.eq(true))
        .one(&state.db)
        .await
    {
        Ok(Some(app)) => app,
        _ => return invalid_grant().into_response(),
    };
    let client_authenticated = match app.client_type.as_str() {
        "desktop" => !headers.contains_key(header::AUTHORIZATION),
        "web" => app
            .client_secret_hash
            .as_deref()
            .is_some_and(|hash| valid_web_client_secret(&headers, &form.client_id, hash)),
        _ => false,
    };
    if !client_authenticated {
        return (
            StatusCode::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                "Basic realm=\"Donnarieix Auth token\"",
            )],
            Json(OAuthError {
                error: "invalid_client",
            }),
        )
            .into_response();
    }

    let grant = match grants::redeem(
        &state.db,
        &form.code,
        &form.client_id,
        &form.redirect_uri,
        &form.code_verifier,
    )
    .await
    {
        Ok(grant) => grant,
        Err(_) => return invalid_grant().into_response(),
    };
    let account = match user::Entity::find_by_id(grant.user_id).one(&state.db).await {
        Ok(Some(account)) if account.active && account.email_verified => account,
        _ => return invalid_grant().into_response(),
    };
    let id_token = match keys.sign_id_token(&grant, &account, grant.auth_time) {
        Ok(jwt) => jwt,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OAuthError {
                    error: "server_error",
                }),
            )
                .into_response();
        }
    };
    let app = match client::Entity::find()
        .filter(client::COLUMN.client_id.eq(&grant.client_id))
        .filter(client::COLUMN.active.eq(true))
        .one(&state.db)
        .await
    {
        Ok(Some(app)) => app,
        _ => return invalid_grant().into_response(),
    };

    let (access_token, hash) = generate_token();
    let now = Utc::now();
    let access = oidc_access_token::ActiveModel {
        id: Set(Uuid::new_v4()),
        token_hash: Set(hash),
        user_id: Set(account.id),
        client_id: Set(app.id),
        scope: Set(grant.scope.clone()),
        created_at: Set(now),
        expires_at: Set(now + Duration::minutes(5)),
        revoked: Set(false),
    };
    if access.insert(&state.db).await.is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(OAuthError {
                error: "server_error",
            }),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in: 300,
            id_token,
            scope: grant.scope,
        }),
    )
        .into_response()
}

#[derive(Serialize)]
pub struct UserInfo {
    sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    picture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email_verified: Option<bool>,
}

pub async fn userinfo(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));
    let Some(token) = bearer.filter(|t| t.len() == 43 && t.is_ascii()) else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    let hash = Sha256::digest(token.as_bytes()).to_vec();
    let access = oidc_access_token::Entity::find()
        .filter(oidc_access_token::COLUMN.token_hash.eq(hash))
        .filter(oidc_access_token::COLUMN.revoked.eq(false))
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if access.expires_at <= Utc::now() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let account = user::Entity::find_by_id(access.user_id)
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .filter(|account| account.active && account.email_verified)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let app = client::Entity::find_by_id(access.client_id)
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .filter(|client| client.active)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if !consent::approved(&state.db, account.id, app.id, &access.scope)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let scopes = consent::Scopes::parse(&access.scope).map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(UserInfo {
            sub: account.id.to_string(),
            preferred_username: scopes.profile.then(|| account.username.clone()),
            name: if scopes.profile {
                account.display_name
            } else {
                None
            },
            picture: if scopes.profile {
                account.avatar_url
            } else {
                None
            },
            email: scopes.email.then_some(account.email),
            email_verified: scopes.email.then_some(account.email_verified),
        }),
    ))
}

#[cfg(test)]
mod confidential_client_tests {
    use super::valid_web_client_secret;
    use axum::http::{HeaderMap, header};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use sha2::{Digest, Sha256};

    #[test]
    fn basic_client_authentication_requires_correct_id_and_secret() {
        let id = "test-client";
        let secret = "x".repeat(43);
        let digest = Sha256::digest(secret.as_bytes()).to_vec();
        let mut headers = HeaderMap::new();
        let encoded = STANDARD.encode(format!("{id}:{secret}"));
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {encoded}").parse().unwrap(),
        );
        assert!(valid_web_client_secret(&headers, id, &digest));
        assert!(!valid_web_client_secret(&headers, "other-client", &digest));
        assert!(!valid_web_client_secret(&headers, id, &Sha256::digest(b"wrong").to_vec()));
        assert!(!valid_web_client_secret(&HeaderMap::new(), id, &digest));
    }
}
