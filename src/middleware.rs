use axum::{extract::{Request, State}, http::StatusCode, middleware::Next, response::Response};
use axum_extra::extract::CookieJar;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ModelTrait};
use sha2::{Digest, Sha256};

use crate::{entities, services::session::get_session, state::AppState};

pub async fn auth(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let jar = CookieJar::from_headers(request.headers());

    let cookie = jar
        .get("session")
        .map(|cookie| cookie.value());

    if cookie.is_none() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let cookie = cookie.unwrap();

    let hash = Sha256::digest(cookie.to_string().as_bytes());
    let session = get_session(&state, hash.to_vec()).await?;

    if session.is_none() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let mut session = session.unwrap();
    
    let mut session_mutable: entities::session::ActiveModel = session.clone().into();
    session_mutable.last_use = Set(chrono::Utc::now());
    if session.expires_at <= chrono::Utc::now() {
        session_mutable.active = Set(false);
    }
    session = session_mutable
        .update(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !session.active {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let user = session
        .find_related(entities::user::Entity)
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if user.is_none() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let user = user.unwrap();

    request.extensions_mut().insert(user);

    Ok(next.run(request).await)
}