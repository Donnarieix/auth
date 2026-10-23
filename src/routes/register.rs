use argon2::{Argon2, PasswordHasher};
use axum::{Json, extract::State, http::StatusCode};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, TransactionTrait};
use serde::Deserialize;
use uuid::Uuid;

use crate::{entities, state::AppState};

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub username: String,
    pub password: String,
}

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<StatusCode, StatusCode> {
    // Temporary minimal validation. Full input policy and abuse controls belong to #9.
    let email = payload.email.trim().to_ascii_lowercase();
    let username = payload.username.trim();
    if !email.is_ascii()
        || !email.contains('@')
        || email.len() > 254
        || username.is_empty()
        || username.len() > 64
        || payload.password.len() < 12
        || payload.password.len() > 1024
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    let password_hash = Argon2::default()
        .hash_password(payload.password.as_bytes())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .to_string();

    let now = chrono::Utc::now();
    let user_id = Uuid::new_v4();
    let tx = state.db.begin().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    entities::user::ActiveModel {
        id: Set(user_id),
        email: Set(email),
        email_verified: Set(false),
        username: Set(username.to_owned()),
        display_name: Set(None),
        avatar_url: Set(None),
        active: Set(true),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&tx)
    .await
    .map_err(|_| StatusCode::CONFLICT)?;

    entities::password_credential::ActiveModel {
        user_id: Set(user_id),
        password_hash: Set(password_hash),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&tx)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tx.commit()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::CREATED)
}
