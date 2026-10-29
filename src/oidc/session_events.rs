//! Durable, cursor-based logout feed for confidential relying parties.
//! Consumers poll with client_secret_basic and invalidate local sessions for
//! the returned subjects. Public clients must not embed a shared secret.
use axum::{
    Form, Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sea_orm::{ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, QueryFilter, Statement};
use serde::{Deserialize, Serialize};

use crate::{entities::client, oidc::token::valid_web_client_secret, state::AppState};

#[derive(Deserialize)]
pub struct Poll {
    #[serde(default)]
    after: Option<i64>,
}

#[derive(Serialize)]
pub struct RevocationEvent {
    id: i64,
    sub: String,
    reason: String,
}

#[derive(Serialize)]
pub struct Revocations {
    events: Vec<RevocationEvent>,
    next_cursor: i64,
}

pub async fn events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<Poll>,
) -> Result<Json<Revocations>, StatusCode> {
    let raw = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let decoded = STANDARD.decode(raw).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let credentials = std::str::from_utf8(&decoded).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let (client_id, _) = credentials
        .split_once(':')
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if client_id.is_empty() || client_id.len() > 256 {
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
    if !app
        .client_secret_hash
        .as_deref()
        .is_some_and(|hash| valid_web_client_secret(&headers, client_id, hash))
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let after = form.after.unwrap_or(0);
    if after < 0 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let rows = state.db.query_all_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "SELECT id,user_id,reason FROM oauth_session_events WHERE client_id = ? AND id > ? ORDER BY id ASC LIMIT 100",
        [app.id.into(),after.into()],
    )).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut cursor = after;
    let mut events = Vec::with_capacity(rows.len());
    for row in rows {
        let id: i64 = row
            .try_get("", "id")
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let sub: uuid::Uuid = row
            .try_get("", "user_id")
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let reason: String = row
            .try_get("", "reason")
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        cursor = id;
        events.push(RevocationEvent {
            id,
            sub: sub.to_string(),
            reason,
        });
    }
    Ok(Json(Revocations {
        events,
        next_cursor: cursor,
    }))
}
