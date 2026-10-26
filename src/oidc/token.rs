//! Public-client Authorization Code + PKCE token exchange and UserInfo.
//! Bearer access tokens are opaque, short-lived and hashed at rest.
use axum::{
    Form, Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};
use chrono::{Duration, Utc};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    entities::{client, oidc_access_token, user},
    oidc::{consent, grants, signing::SigningKeys},
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

/// For public clients only; no confidential client credentials are accepted.
pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<TokenRequest>,
) -> impl IntoResponse {
    let Some(keys) = &state.oidc_keys else {
        return invalid_request().into_response();
    };
    if headers.contains_key(header::AUTHORIZATION)
        || form.grant_type != "authorization_code"
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
            email: scopes.email.then(|| account.email),
            email_verified: scopes.email.then_some(account.email_verified),
        }),
    ))
}

/// The current Authorization Code profile only permits PKCE public clients.
#[expect(
    dead_code,
    reason = "Signer exposed only when OIDC endpoints are enabled"
)]
fn _requires_signer(_: &SigningKeys) {}
