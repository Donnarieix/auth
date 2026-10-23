use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{Json, extract::State, http::StatusCode};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use sea_orm::{ActiveModelTrait, ActiveValue::Set};
use serde::Deserialize;

use crate::{
    entities,
    services::{
        session::{create_session, get_active_session},
        user::{get_password_credential, get_user_by_email},
    },
    state::AppState,
};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<LoginRequest>,
) -> Result<CookieJar, StatusCode> {
    let email = payload.email.trim().to_ascii_lowercase();
    let user = get_user_by_email(&state, &email)
        .await?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !user.active {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let credential = get_password_credential(&state, user.id)
        .await?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let hash = PasswordHash::new(&credential.password_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if Argon2::default()
        .verify_password(payload.password.as_bytes(), &hash)
        .is_err()
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if let Some(existing_session) = get_active_session(&state, user.clone()).await? {
        let mut session: entities::session::ActiveModel = existing_session.into();
        session.active = Set(false);
        session
            .update(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    let token = create_session(&state, user).await?;

    let cookie = Cookie::build(("session", token))
        .http_only(true)
        .same_site(SameSite::Lax)
        // Local development only. #11 must require Secure cookies under HTTPS.
        .path("/")
        .build();

    Ok(jar.add(cookie))
}
