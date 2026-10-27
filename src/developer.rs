//! Separate developer administration identity. No end-user session or cookie
//! grants access to developer endpoints. Tokens are created offline.
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
};
use sea_orm::{ConnectionTrait, DbBackend, EntityTrait, Statement};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{entities::client, state::AppState};

async fn authenticated_administrator(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Uuid, StatusCode> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .filter(|token| token.len() == 43 && token.is_ascii())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let digest = Sha256::digest(token.as_bytes()).to_vec();
    let result = state
        .db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT id FROM developer_administrators WHERE token_hash = ? AND active = 1",
            [digest.into()],
        ))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let id: String = result
        .try_get("", "id")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Uuid::parse_str(&id).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[derive(Serialize)]
pub struct DeveloperClient {
    client_id: String,
    name: String,
    client_type: String,
    active: bool,
    confidential: bool,
}

/// Read-only first slice of the developer API: no secrets or credentials
/// are disclosed. Explicit credentials are mandatory, not Auth user cookies.
pub async fn list_clients(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<DeveloperClient>>, StatusCode> {
    authenticated_administrator(&state, &headers).await?;
    let clients = client::Entity::find()
        .all(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(
        clients
            .into_iter()
            .map(|app| DeveloperClient {
                client_id: app.client_id,
                name: app.name,
                client_type: app.client_type,
                active: app.active,
                confidential: app.client_secret_hash.is_some(),
            })
            .collect(),
    ))
}
