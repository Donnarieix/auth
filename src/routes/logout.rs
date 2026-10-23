use axum::{Extension, extract::State, http::StatusCode};
use axum_extra::extract::{CookieJar, cookie::Cookie};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, IntoActiveModel};

use crate::{entities, state::AppState};

pub async fn logout(
    State(state): State<AppState>,
    Extension(session): Extension<entities::session::Model>,
    jar: CookieJar,
) -> Result<(StatusCode, CookieJar), StatusCode> {
    let mut session = session.into_active_model();
    session.active = Set(false);
    session
        .update(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((StatusCode::OK, jar.remove(Cookie::from("session"))))
}
