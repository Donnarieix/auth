//! End-user, self-service view and revocation of previously approved OIDC clients.
//! The user is set by the existing session-authentication middleware, never
//! supplied by a request body or query parameter.
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::Utc;
use sea_orm::{EntityTrait, QueryFilter, TransactionTrait, ActiveModelTrait, ActiveValue::Set, sea_query::Expr};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    entities::{client, oidc_access_token, oidc_consent, user},
    state::AppState,
};

#[derive(Serialize)]
pub struct ConsentView {
    client_id: String,
    name: String,
    scope: String,
    approved_at: chrono::DateTime<Utc>,
}

pub async fn list(
    State(state): State<AppState>,
    Extension(account): Extension<user::Model>,
) -> Result<Json<Vec<ConsentView>>, StatusCode> {
    let consents = oidc_consent::Entity::find()
        .filter(oidc_consent::COLUMN.user_id.eq(account.id))
        .filter(oidc_consent::COLUMN.revoked_at.is_null())
        .all(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut entries = Vec::with_capacity(consents.len());
    for consent in consents {
        if let Some(app) = client::Entity::find_by_id(consent.client_id)
            .one(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        {
            entries.push(ConsentView {
                client_id: app.client_id,
                name: app.name,
                scope: consent.scope,
                approved_at: consent.approved_at,
            });
        }
    }
    Ok(Json(entries))
}

/// Immediately invalidate the consent and every outstanding access token for
/// that user/client. Only the authenticated user's own grants can be revoked.
pub async fn revoke(
    State(state): State<AppState>,
    Extension(account): Extension<user::Model>,
    Path(public_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let app = client::Entity::find()
        .filter(client::COLUMN.client_id.eq(&public_id))
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let tx = state.db.begin().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let now = Utc::now();
    let affected = oidc_consent::Entity::update_many()
        .col_expr(oidc_consent::COLUMN.revoked_at, Expr::value(now))
        .filter(oidc_consent::COLUMN.user_id.eq(account.id))
        .filter(oidc_consent::COLUMN.client_id.eq(app.id))
        .filter(oidc_consent::COLUMN.revoked_at.is_null())
        .exec(&tx)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if affected.rows_affected == 0 {
        return Err(StatusCode::NOT_FOUND);
    }
    oidc_access_token::Entity::update_many()
        .col_expr(oidc_access_token::COLUMN.revoked, Expr::value(true))
        .filter(oidc_access_token::COLUMN.user_id.eq(account.id))
        .filter(oidc_access_token::COLUMN.client_id.eq(app.id))
        .exec(&tx)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    tx.commit().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}
