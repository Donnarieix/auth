use axum::http::StatusCode;
use sea_orm::{EntityTrait, QueryFilter};
use uuid::Uuid;

use crate::{entities, state::AppState};

pub async fn get_user_by_email(
    state: &AppState,
    email: &str,
) -> Result<Option<entities::user::Model>, StatusCode> {
    entities::user::Entity::find()
        .filter(entities::user::COLUMN.email.eq(email))
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub async fn get_password_credential(
    state: &AppState,
    user_id: Uuid,
) -> Result<Option<entities::password_credential::Model>, StatusCode> {
    entities::password_credential::Entity::find_by_id(user_id)
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
