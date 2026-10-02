use axum::http::StatusCode;
use sea_orm::{EntityTrait, ModelTrait, QueryFilter};

use crate::{entities, state::AppState};

pub async fn get_client(
    state: &AppState,
    client_id: String,
) -> Result<Option<entities::client::Model>, StatusCode> {
    let client = entities::client::Entity::find()
        .filter(entities::client::COLUMN.client_id.eq(client_id))
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(client)
}

pub async fn get_redirect_uris(
    state: &AppState,
    client: entities::client::Model,
) -> Result<Vec<entities::client_redirect_uri::Model>, StatusCode> {
    let redirect_uris = client
        .find_related(entities::client_redirect_uri::Entity)
        .all(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(redirect_uris)
}

pub async fn is_redirect_uri_allowed(
    state: &AppState,
    client: entities::client::Model,
    redirect_uri: String,
) -> Result<bool, StatusCode> {
    let redirect_uris = get_redirect_uris(state, client).await?;

    let is_allowed = redirect_uris
        .iter()
        .any(|uri| uri.redirect_uri == redirect_uri);

    Ok(is_allowed)
}
