use argon2::{Argon2, PasswordHasher};
use axum::{Json, extract::State, http::StatusCode};
use sea_orm::{ActiveModelTrait, ActiveValue::Set};
use serde::Deserialize;
use uuid::Uuid;

use crate::{entities, services::user::get_user_by_username, state::AppState};

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
}

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<StatusCode, StatusCode> {
    let user = get_user_by_username(&state, payload.username.clone()).await?;

    if user.is_some() {
        return Err(StatusCode::CONFLICT);
    }

    let hash = Argon2::default()
        .hash_password(payload.password.clone().as_bytes())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let user = entities::user::ActiveModel {
        id: Set(Uuid::new_v4()),
        username: Set(payload.username.clone()),
        password: Set(hash.to_string()),
    };
    user.insert(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::CREATED)
}