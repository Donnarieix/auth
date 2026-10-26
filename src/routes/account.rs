use axum::{Json, extract::State, http::StatusCode};
use serde::Deserialize;

use crate::{
    services::{
        account::{self, Purpose},
        identity::normalize_email,
    },
    state::AppState,
};

#[derive(Deserialize)]
pub struct EmailRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub struct CodeRequest {
    pub token: String,
}

#[derive(Deserialize)]
pub struct PasswordResetRequest {
    pub token: String,
    pub new_password: String,
}

async fn request_code(
    state: AppState,
    raw_email: String,
    purpose: Purpose,
    scope: &'static str,
) -> StatusCode {
    let Some(email) = normalize_email(&raw_email) else {
        return StatusCode::BAD_REQUEST;
    };
    if !state.abuse.allow(scope, &email, 40, 3).await {
        return StatusCode::TOO_MANY_REQUESTS;
    }
    // Detached from the response, so account existence and SMTP failure never
    // change its HTTP status. Credentials/codes are never returned in the API.
    tokio::spawn(async move {
        let _ = account::issue(&state, &email, purpose).await;
    });
    StatusCode::ACCEPTED
}

pub async fn request_verification(
    State(state): State<AppState>,
    Json(payload): Json<EmailRequest>,
) -> StatusCode {
    request_code(state, payload.email, Purpose::VerifyEmail, "verify_email").await
}

pub async fn request_reset(
    State(state): State<AppState>,
    Json(payload): Json<EmailRequest>,
) -> StatusCode {
    request_code(
        state,
        payload.email,
        Purpose::ResetPassword,
        "reset_password",
    )
    .await
}

pub async fn confirm_verification(
    State(state): State<AppState>,
    Json(payload): Json<CodeRequest>,
) -> Result<StatusCode, StatusCode> {
    account::consume(&state, &payload.token, Purpose::VerifyEmail, None).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn confirm_reset(
    State(state): State<AppState>,
    Json(payload): Json<PasswordResetRequest>,
) -> Result<StatusCode, StatusCode> {
    account::consume(
        &state,
        &payload.token,
        Purpose::ResetPassword,
        Some(payload.new_password),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
