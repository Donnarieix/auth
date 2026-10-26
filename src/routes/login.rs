use axum::{Json, extract::State, http::StatusCode};
use axum_extra::extract::CookieJar;
use serde::Deserialize;

use crate::{
    services::{
        identity::normalize_email,
        password::{self, DUMMY_HASH},
        session::create_session,
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
    let email = normalize_email(&payload.email).ok_or(StatusCode::UNAUTHORIZED)?;
    if payload.password.len() > 512 || payload.password.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if !state.abuse.allow("login", &email, 80, 12).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let user = get_user_by_email(&state, &email).await?;
    let credential = match &user {
        Some(user) => get_password_credential(&state, user.id).await?,
        None => None,
    };
    let stored_hash = credential
        .map(|credential| credential.password_hash)
        .unwrap_or_else(|| DUMMY_HASH.to_owned());
    // One expensive verification even when the email does not exist.
    let valid = password::verify(&state, payload.password, stored_hash).await?;

    let user = user
        .filter(|user| user.active && valid)
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Independent devices keep their own sessions. Only logout of the exact
    // cookie or a password reset revokes an existing session.
    let token = create_session(&state, user).await?;

    let cookie = state.security.issue_cookie(token);
    Ok(jar.add(cookie))
}
