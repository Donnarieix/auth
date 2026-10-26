use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use axum_extra::extract::CookieJar;
use chrono::Utc;
use sea_orm::{EntityTrait, ModelTrait, QueryFilter, sea_query::Expr};
use sha2::{Digest, Sha256};

use crate::{entities, services::session::get_session, state::AppState};

pub async fn auth(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let jar = CookieJar::from_headers(request.headers());
    let cookie = jar
        .get(state.security.cookie_name())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let hash = Sha256::digest(cookie.value().as_bytes());
    let session = get_session(&state, hash.to_vec())
        .await?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !session.active {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let now = Utc::now();
    if session.expires_at <= now {
        // Expire the record without ever reactivating it.
        entities::session::Entity::update_many()
            .col_expr(entities::session::COLUMN.active, Expr::value(false))
            .filter(entities::session::COLUMN.id.eq(session.id))
            .filter(entities::session::COLUMN.active.eq(true))
            .exec(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        return Err(StatusCode::UNAUTHORIZED);
    }

    let user = session
        .find_related(entities::user::Entity)
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if !user.active {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Recheck the session at write time; never let a concurrently revoked or
    // expired session pass through on the basis of an earlier read.
    let updated = entities::session::Entity::update_many()
        .col_expr(entities::session::COLUMN.last_use, Expr::value(now))
        .filter(entities::session::COLUMN.id.eq(session.id))
        .filter(entities::session::COLUMN.active.eq(true))
        .filter(entities::session::COLUMN.expires_at.gt(now))
        .exec(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if updated.rows_affected != 1 {
        return Err(StatusCode::UNAUTHORIZED);
    }

    request.extensions_mut().insert(user);
    request.extensions_mut().insert(session);
    Ok(next.run(request).await)
}
