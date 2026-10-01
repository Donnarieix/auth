use axum::http::StatusCode;
use sea_orm::{EntityTrait, QueryFilter};

use crate::{entities, state::AppState};

pub async fn get_user_by_username(
    state: &AppState,
    username: String,
) -> Result<Option<entities::user::Model>, StatusCode> {
    let user = entities::user::Entity::find()
        .filter(entities::user::COLUMN.username.eq(username))
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(user)
}
