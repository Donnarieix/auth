//! OIDC Discovery, Authorization Code exchange, and scoped UserInfo.
use axum::{
    Form, Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    entities::{client, oidc_access_token, session, user},
    oidc::{consent::Scopes, grants},
    services::{client::get_client, session::generate_token},
    state::AppState,
};

#[derive(Serialize)]
pub struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    userinfo_endpoint: String,
    response_types_supported: Vec<&'static str>,
    subject_types_supported: Vec<&'static str>,
    id_token_signing_alg_values_supported: Vec<&'static str>,
    scopes_supported: Vec<&'static str>,
    claims_supported: Vec<&'static str>,
    grant_types_supported: Vec<&'static str>,
    token_endpoint_auth_methods_supported: Vec<&'static str>,
    code_challenge_methods_supported: Vec<&'static str>,
}

pub async fn discovery(State(state): State<AppState>) -> impl IntoResponse {
    let issuer = &state.security.origin;
    (
        [(header::CACHE_CONTROL, "public, max-age=300")],
        Json(Discovery {
            issuer: issuer.clone(),
            authorization_endpoint: format!("{issuer}/authorize"),
            token_endpoint: format!("{issuer}/token"),
            jwks_uri: format!("{issuer}/.well-known/jwks.json"),
            userinfo_endpoint: format!("{issuer}/userinfo"),
            response_types_supported: vec!["code"],
            subject_types_supported: vec!["public"],
            id_token_signing_alg_values_supported: vec!["RS256"],
            scopes_supported: vec!["openid", "profile", "email"],
            claims_supported: vec![
                "sub",
                "preferred_username",
                "name",
                "picture",
                "email",
                "email_verified",
                "auth_time",
            ],
            grant_types_supported: vec!["authorization_code"],
            token_endpoint_auth_methods_supported: vec!["none"],
            code_challenge_methods_supported: vec!["S256"],
        }),
    )
}

#[derive(Deserialize)]
pub struct Exchange {
    grant_type: String,
    code: String,
    redirect_uri: String,
    client_id: String,
    code_verifier: String,
    client_secret: Option<String>,
}

#[derive(Serialize)]
pub struct TokenResult {
    access_token: String,
    token_type: &'static str,
    expires_in: u32,
    scope: String,
    id_token: String,
}

#[derive(Serialize)]
struct OAuthError {
    error: &'static str,
}

fn error(status: StatusCode, kind: &'static str) -> Response {
    (
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(OAuthError { error: kind }),
    )
        .into_response()
}

pub async fn token(State(state): State<AppState>, Form(form): Form<Exchange>) -> Response {
    let Some(keys) = state.oidc_keys.as_ref() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    if form.grant_type != "authorization_code"
        || form.client_secret.is_some()
        || form.code.len() != 43
        || form.code_verifier.len() > 128
        || form.client_id.len() > 256
        || form.redirect_uri.len() > 2048
    {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    if !state
        .abuse
        .allow("oidc_token", &form.client_id, 160, 40)
        .await
    {
        return error(StatusCode::TOO_MANY_REQUESTS, "slow_down");
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
        Err(grants::GrantError::Database) => {
            return error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_grant"),
    };

    let account = match user::Entity::find_by_id(grant.user_id).one(&state.db).await {
        Ok(Some(u)) => u,
        _ => return error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
    let app = match get_client(&state.db, &grant.client_id).await {
        Ok(Some(app)) => app,
        _ => return error(StatusCode::BAD_REQUEST, "invalid_grant"),
    };
    let jwt = match keys.sign_id_token(&grant, &account, grant.authenticated_at) {
        Ok(jwt) => jwt,
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };

    let (access_token, hash) = generate_token();
    let now = Utc::now();
    let model = oidc_access_token::ActiveModel {
        id: Set(Uuid::new_v4()),
        token_hash: Set(hash),
        client_id: Set(app.id),
        user_id: Set(account.id),
        session_id: Set(grant.session_id),
        scope: Set(grant.scope.clone()),
        created_at: Set(now),
        expires_at: Set(now + Duration::minutes(5)),
    };
    if model.insert(&state.db).await.is_err() {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    }
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(TokenResult {
            access_token,
            token_type: "Bearer",
            expires_in: 300,
            scope: grant.scope,
            id_token: jwt,
        }),
    )
        .into_response()
}

#[derive(Serialize)]
struct Profile {
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

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [
            (header::WWW_AUTHENTICATE, "Bearer error=\"invalid_token\""),
            (header::CACHE_CONTROL, "no-store"),
        ],
    )
        .into_response()
}

pub async fn userinfo(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return unauthorized();
    };
    let Some(bearer) = value.strip_prefix("Bearer ") else {
        return unauthorized();
    };
    if bearer.len() != 43
        || URL_SAFE_NO_PAD.decode(bearer).is_err()
        || headers.get_all(header::AUTHORIZATION).iter().count() != 1
    {
        return unauthorized();
    }

    let hash = Sha256::digest(bearer.as_bytes()).to_vec();
    let record = match oidc_access_token::Entity::find()
        .filter(oidc_access_token::COLUMN.token_hash.eq(hash))
        .one(&state.db)
        .await
    {
        Ok(Some(token)) if token.expires_at > Utc::now() => token,
        _ => return unauthorized(),
    };
    let account = match user::Entity::find_by_id(record.user_id)
        .one(&state.db)
        .await
    {
        Ok(Some(account)) if account.active && account.email_verified => account,
        _ => return unauthorized(),
    };
    let browser = match session::Entity::find_by_id(record.session_id)
        .one(&state.db)
        .await
    {
        Ok(Some(s)) if s.active && s.user_id == record.user_id && s.expires_at > Utc::now() => s,
        _ => return unauthorized(),
    };
    let app = match client::Entity::find_by_id(record.client_id)
        .one(&state.db)
        .await
    {
        Ok(Some(c)) if c.active => c,
        _ => return unauthorized(),
    };
    let _ = (browser, app);
    let scopes = match Scopes::parse(&record.scope) {
        Ok(scopes) => scopes,
        _ => return unauthorized(),
    };
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(Profile {
            sub: account.id.to_string(),
            preferred_username: scopes.profile.then(|| account.username),
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
    ).into_response()
}
