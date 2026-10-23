use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{Json, extract::State, http::StatusCode};
use axum_extra::extract::{CookieJar, cookie::{Cookie, SameSite}};
use sea_orm::{ActiveModelTrait, ActiveValue::Set};
use serde::Deserialize;

use crate::{entities, services::{session::{create_session, get_active_session}, user::get_user_by_username}, state::AppState};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<LoginRequest>,
) -> Result<CookieJar, StatusCode> {
    let user = get_user_by_username(
        &state,
        payload.username.clone()
    ).await?;

    if user.is_none() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let user = user.unwrap();

    let hash = PasswordHash::new(&user.password)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if !Argon2::default()
        .verify_password(payload.password.as_bytes(), &hash)
        .is_ok()
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let session = get_active_session(
        &state,
        user.clone()
    ).await?;

    if session.is_some() {
        let mut session: entities::session::ActiveModel = session
            .unwrap()
            .into();
        session.active = Set(false);
        session
            .update(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    
    let token = create_session(
        &state,
        user.clone()
    ).await?;

    let cookie = Cookie::build(("session", token.clone()))
        .http_only(true)
        .same_site(SameSite::Lax)
        // .secure(true)
        .path("/")
        .build();
    

    Ok(jar.add(cookie))
}