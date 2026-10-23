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
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let hash = Sha256::digest(cookie.value().as_bytes());
    let mut session = get_session(&state, hash.to_vec())
        .await?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !session.active {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let now = chrono::Utc::now();
    if session.expires_at <= now {
        let mut expired: entities::session::ActiveModel = session.into();
        expired.active = Set(false);
        expired
            .update(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        return Err(StatusCode::UNAUTHORIZED);
    }

    let mut active: entities::session::ActiveModel = session.clone().into();
    active.last_use = Set(now);
    session = active
        .update(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let user = session
        .find_related(entities::user::Entity)
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    request.extensions_mut().insert(user);
    request.extensions_mut().insert(session);

    Ok(next.run(request).await)
}
