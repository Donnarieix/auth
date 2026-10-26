use axum::{Extension, extract::State, http::StatusCode};
use axum_extra::extract::CookieJar;
use sea_orm::{EntityTrait, QueryFilter, sea_query::Expr};

use crate::{entities, state::AppState};

pub async fn logout(
    State(state): State<AppState>,
    Extension(session): Extension<entities::session::Model>,
    jar: CookieJar,
) -> Result<(StatusCode, CookieJar), StatusCode> {
    // Revoke only the session represented by the incoming cookie.
    let updated = entities::session::Entity::update_many()
        .col_expr(entities::session::COLUMN.active, Expr::value(false))
        .filter(entities::session::COLUMN.id.eq(session.id))
        .filter(entities::session::COLUMN.active.eq(true))
        .exec(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if updated.rows_affected != 1 {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok((StatusCode::NO_CONTENT, jar.remove(state.security.clear_cookie())))
}
