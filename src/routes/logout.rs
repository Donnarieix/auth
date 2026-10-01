use axum::{Extension, extract::State, http::StatusCode};
use axum_extra::extract::{CookieJar, cookie::Cookie};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, IntoActiveModel};

use crate::{entities, services::session::get_session_by_user, state::AppState};

pub async fn logout(
    State(state): State<AppState>,
    Extension(user): Extension<entities::user::Model>,
    jar: CookieJar,
) -> Result<(StatusCode, CookieJar), StatusCode> {
    let session = get_session_by_user(&state, &user).await?;

    if let Some(session) = session {
        let mut session = session.into_active_model();
        session.active = Set(false);
        session
            .update(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    Ok((StatusCode::OK, jar.remove(Cookie::from("session"))))
}