//! One-time email and recovery codes. Only SHA-256 hashes are stored in SQLite.
use axum::http::StatusCode;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, TransactionTrait,
    sea_query::Expr,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    entities::{account_token, password_credential, session, user},
    services::{
        email::Mail, identity::valid_password, password, session::generate_token,
        user::get_user_by_email,
    },
    state::AppState,
};

#[derive(Clone, Copy)]
pub enum Purpose {
    VerifyEmail,
    ResetPassword,
}

impl Purpose {
    fn key(self) -> &'static str {
        match self {
            Self::VerifyEmail => "verify_email",
            Self::ResetPassword => "reset_password",
        }
    }

    fn validity(self) -> Duration {
        match self {
            Self::VerifyEmail => Duration::hours(24),
            Self::ResetPassword => Duration::minutes(30),
        }
    }
}

pub async fn issue(state: &AppState, email: &str, purpose: Purpose) -> Result<(), ()> {
    if !state.mailer.enabled() {
        return Ok(());
    }

    let existing = get_user_by_email(state, email).await.map_err(|_| ())?;
    let Some(account) = existing.filter(|user| user.active) else {
        return Ok(());
    };
    if matches!(purpose, Purpose::VerifyEmail) && account.email_verified {
        return Ok(());
    }

    let (token, hash) = generate_token();
    let now = Utc::now();
    let id = Uuid::new_v4();
    let tx = state.db.begin().await.map_err(|_| ())?;
    // Reissued codes invalidate earlier codes for this purpose.
    account_token::Entity::delete_many()
        .filter(account_token::COLUMN.user_id.eq(account.id))
        .filter(account_token::COLUMN.purpose.eq(purpose.key()))
        .exec(&tx)
        .await
        .map_err(|_| ())?;

    account_token::ActiveModel {
        id: Set(id),
        user_id: Set(account.id),
        purpose: Set(purpose.key().into()),
        email: Set(account.email.clone()),
        token_hash: Set(hash),
        created_at: Set(now),
        expires_at: Set(now + purpose.validity()),
        consumed_at: Set(None),
    }
    .insert(&tx)
    .await
    .map_err(|_| ())?;
    tx.commit().await.map_err(|_| ())?;

    let (subject, explanation) = match purpose {
        Purpose::VerifyEmail => (
            "Donnarieix Auth: verify your email",
            "Enter this verification code using POST /email/verification/confirm",
        ),
        Purpose::ResetPassword => (
            "Donnarieix Auth: reset your password",
            "Enter this recovery code with a new password using POST /password/reset/confirm",
        ),
    };
    let mail = Mail {
        recipient: account.email,
        subject: subject.into(),
        body: format!(
            "{explanation}\n\nCode: {token}\n\nExpires in {} minutes. If you did not request this, ignore it.",
            purpose.validity().num_minutes()
        ),
    };
    if state.mailer.send(mail).await.is_err() {
        // Never expose delivery failures based on whether an account exists.
        let _ = account_token::Entity::delete_by_id(id)
            .exec(&state.db)
            .await;
        return Err(());
    }
    Ok(())
}

pub async fn consume(
    state: &AppState,
    raw_token: &str,
    purpose: Purpose,
    new_password: Option<String>,
) -> Result<(), StatusCode> {
    let decoded = URL_SAFE_NO_PAD
        .decode(raw_token)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if decoded.len() != 32 || raw_token.len() != 43 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let new_hash = if matches!(purpose, Purpose::ResetPassword) {
        let password = new_password.ok_or(StatusCode::BAD_REQUEST)?;
        if !valid_password(&password) {
            return Err(StatusCode::BAD_REQUEST);
        }
        Some(password::hash(state, password).await?)
    } else {
        None
    };

    let digest = Sha256::digest(raw_token.as_bytes()).to_vec();
    let now = Utc::now();
    let tx = state
        .db
        .begin()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let record = account_token::Entity::find()
        .filter(account_token::COLUMN.token_hash.eq(digest))
        .filter(account_token::COLUMN.purpose.eq(purpose.key()))
        .one(&tx)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::BAD_REQUEST)?;

    if record.consumed_at.is_some() || record.expires_at <= now {
        return Err(StatusCode::BAD_REQUEST);
    }

    let account = user::Entity::find_by_id(record.user_id)
        .one(&tx)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Codes issued for a previous email are never valid for a new address.
    if !account.active || !account.email.eq_ignore_ascii_case(&record.email) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let consumed = account_token::Entity::update_many()
        .col_expr(account_token::COLUMN.consumed_at, Expr::value(now))
        .filter(account_token::COLUMN.id.eq(record.id))
        .filter(account_token::COLUMN.consumed_at.is_null())
        .filter(account_token::COLUMN.expires_at.gt(now))
        .exec(&tx)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if consumed.rows_affected != 1 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let event = match (purpose, new_hash) {
        (Purpose::VerifyEmail, None) => {
            user::Entity::update_many()
                .col_expr(user::COLUMN.email_verified, Expr::value(true))
                .col_expr(user::COLUMN.updated_at, Expr::value(now))
                .filter(user::COLUMN.id.eq(account.id))
                .exec(&tx)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            "email_verified"
        }
        (Purpose::ResetPassword, Some(hash)) => {
            let result = password_credential::Entity::update_many()
                .col_expr(password_credential::COLUMN.password_hash, Expr::value(hash))
                .col_expr(password_credential::COLUMN.updated_at, Expr::value(now))
                .filter(password_credential::COLUMN.user_id.eq(account.id))
                .exec(&tx)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            if result.rows_affected != 1 {
                return Err(StatusCode::BAD_REQUEST);
            }
            session::Entity::update_many()
                .col_expr(session::COLUMN.active, Expr::value(false))
                .filter(session::COLUMN.user_id.eq(account.id))
                .exec(&tx)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            "password_reset"
        }
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    // After successful confirmation revoke any remaining codes of this type.
    account_token::Entity::update_many()
        .col_expr(account_token::COLUMN.consumed_at, Expr::value(now))
        .filter(account_token::COLUMN.user_id.eq(account.id))
        .filter(account_token::COLUMN.purpose.eq(purpose.key()))
        .filter(account_token::COLUMN.consumed_at.is_null())
        .exec(&tx)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    use sea_orm::{ConnectionTrait, DbBackend, Statement};
    tx.execute_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "INSERT INTO account_security_events (id,user_id,event_kind,created_at) VALUES (?,?,?,?)",
        [
            Uuid::new_v4().into(),
            account.id.into(),
            event.into(),
            now.into(),
        ],
    ))
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tx.commit()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(())
}
