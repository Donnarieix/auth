use axum::{Json, extract::State, http::StatusCode};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, SqlErr, TransactionTrait};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    entities,
    services::{account::{self, Purpose}, identity::validate_registration, password},
    state::AppState,
};

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub username: String,
    pub password: String,
}

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<StatusCode, StatusCode> {
    let input = validate_registration(&payload.email, &payload.username, &payload.password)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Global budget blocks attackers from evading throttling by varying email.
    // An email-specific budget bounds repeated attempts at a single account.
    if !state.abuse.allow("register", &input.email, 40, 12).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // Hash even for duplicates to avoid a cheap existence check.
    let password_hash = password::hash(&state, payload.password).await?;
    let email_for_verification = input.email.clone();
    let now = chrono::Utc::now();
    let user_id = Uuid::new_v4();
    let tx = state
        .db
        .begin()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let result = entities::user::ActiveModel {
        id: Set(user_id),
        email: Set(input.email),
        email_verified: Set(false),
        username: Set(input.username),
        display_name: Set(None),
        avatar_url: Set(None),
        active: Set(true),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&tx)
    .await;

    match result {
        Ok(_) => {}
        // Neither email nor username existence is disclosed publicly.
        Err(err) if matches!(err.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) => {
            return Ok(StatusCode::ACCEPTED);
        }
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    }

    entities::password_credential::ActiveModel {
        user_id: Set(user_id),
        password_hash: Set(password_hash),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&tx)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tx.commit()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Email delivery is detached; the API never reveals whether SMTP succeeded.
    // If SMTP is unconfigured, verification can be requested after setup.
    if state.mailer.enabled() {
        tokio::spawn(async move {
            let _ = account::issue(&state, &email_for_verification, Purpose::VerifyEmail).await;
        });
    }
    Ok(StatusCode::ACCEPTED)
}
