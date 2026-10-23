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
        id: Set(Uuid::new_v4()),
        user_id: Set(user.id),
        token_hash: Set(hash),
        created_at: Set(chrono::Utc::now()),
        expires_at: Set(chrono::Utc::now() + chrono::Duration::hours(1)),
        last_use: Set(chrono::Utc::now()),
        active: Set(true),
    };

    session
        .insert(&state.db)
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};

    use super::generate_token;

    #[test]
    fn session_token_is_32_random_bytes_encoded_and_hashed() {
        let (token, hash) = generate_token();
        let raw = URL_SAFE_NO_PAD.decode(&token).expect("valid base64url token");

        assert_eq!(raw.len(), 32);
        assert_eq!(hash, Sha256::digest(token.as_bytes()).to_vec());
        assert_ne!(hash, token.as_bytes());
    }

    #[test]
    fn independently_generated_session_tokens_are_distinct() {
        let tokens: HashSet<String> = (0..128).map(|_| generate_token().0).collect();
        assert_eq!(tokens.len(), 128);
    }
}
