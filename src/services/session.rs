use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngExt;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait, QueryFilter};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{entities, state::AppState};

pub async fn get_session(
    state: &AppState,
    hash: Vec<u8>,
) -> Result<Option<entities::session::Model>, StatusCode> {
    let session = entities::session::Entity::find()
        .filter(entities::session::COLUMN.token_hash.eq(hash))
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(session)
}

pub async fn get_active_session(
    state: &AppState,
    user: entities::user::Model,
) -> Result<Option<entities::session::Model>, StatusCode> {
    let sessions = entities::session::Entity::find()
        .filter(entities::session::COLUMN.user_id.eq(user.id))
        .filter(entities::session::COLUMN.active.eq(true))
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(sessions)
}

pub async fn create_session(
    state: &AppState,
    user: entities::user::Model,
) -> Result<String, StatusCode> {
    let (token, hash) = generate_token();

    let session = entities::session::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        user_id: Set(user.id),
        token_hash: Set(hash),
        created_at: Set(chrono::Utc::now().into()),
        expires_at: Set((chrono::Utc::now() + chrono::Duration::hours(1)).into()),
        last_use: Set(chrono::Utc::now().into()),
        active: Set(true),
    };

    session.insert(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(token)
}

pub fn generate_token() -> (String, Vec<u8>) {
    let bytes: [u8; 32] = rand::rng().random();
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let hash = Sha256::digest(token.as_bytes());
    (token, hash.to_vec())
}

pub async fn get_session_by_user(
    state: &AppState,
    user: &entities::user::Model,
) -> Result<Option<entities::session::Model>, StatusCode> {
    let session = entities::session::Entity::find()
        .filter(entities::session::COLUMN.user_id.eq(user.id))
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(session)
}