//! RFC 7662-style introspection for confidential clients.
//! A caller only learns about tokens issued for its own client_id.
//! Public/native clients cannot call this endpoint.
use axum::{
    Form, Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use chrono::Utc;
use sea_orm::{EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    entities::{client, oidc_access_token, user},
    oidc::{consent, token::valid_web_client_secret},
    state::AppState,
};

#[derive(Deserialize)]
pub struct IntrospectionRequest {
    token: String,
    token_type_hint: Option<String>,
}

#[derive(Serialize)]
pub struct IntrospectionResponse {
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_type: Option<&'static str>,
}

impl IntrospectionResponse {
    fn inactive() -> Self {
        Self {
            active: false,
            scope: None,
            client_id: None,
            sub: None,
            exp: None,
            iat: None,
            token_type: None,
        }
    }
}

/// Authenticate the confidential caller before looking up any token.
pub async fn introspect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<IntrospectionRequest>,
) -> Result<Json<IntrospectionResponse>, StatusCode> {
    let Some(encoded) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
    else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let decoded = STANDARD.decode(encoded).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let credentials = std::str::from_utf8(&decoded).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let (client_id, _) = credentials.split_once(':').ok_or(StatusCode::UNAUTHORIZED)?;
    if client_id.len() > 256 {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let app = client::Entity::find()
        .filter(client::Column::ClientId.eq(client_id))
        .filter(client::Column::Active.eq(true))
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .filter(|app| app.client_type == "web")
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if !app.client_secret_hash.as_deref().is_some_and(|hash| {
        valid_web_client_secret(&headers, client_id, hash)
    }) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if form.token.len() != 43 || !form.token.is_ascii()
        || form.token_type_hint.as_deref().is_some_and(|hint| hint.len() > 64)
    {
        return Ok(Json(IntrospectionResponse::inactive()));
    }
    let hash = Sha256::digest(form.token.as_bytes()).to_vec();
    let Some(access) = oidc_access_token::Entity::find()
        .filter(oidc_access_token::Column::TokenHash.eq(hash))
        .filter(oidc_access_token::Column::ClientId.eq(app.id))
        .filter(oidc_access_token::Column::Revoked.eq(false))
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    else {
        return Ok(Json(IntrospectionResponse::inactive()));
    };
    if access.expires_at <= Utc::now() {
        return Ok(Json(IntrospectionResponse::inactive()));
    }
    let Some(account) = user::Entity::find_by_id(access.user_id)
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .filter(|account| account.active && account.email_verified)
    else {
        return Ok(Json(IntrospectionResponse::inactive()));
    };
    if !consent::approved(&state.db, account.id, app.id, &access.scope)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        return Ok(Json(IntrospectionResponse::inactive()));
    }
    Ok(Json(IntrospectionResponse {
        active: true,
        scope: Some(access.scope),
        client_id: Some(app.client_id),
        sub: Some(account.id.to_string()),
        exp: Some(access.expires_at.timestamp()),
        iat: Some(access.created_at.timestamp()),
        token_type: Some("Bearer"),
    }))
}
