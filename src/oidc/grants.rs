//! Authorization codes are opaque, short-lived, and bound to a single session,
//! client, redirect URI and S256 challenge. Never log the plaintext code.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, DatabaseConnection, DbErr, EntityTrait, QueryFilter,
    TransactionTrait, sea_query::Expr,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    entities::{authorization_code, client, client_redirect_uri, session, user},
    oidc::{AuthorizationRequest, matches_s256, validate_authorization_request},
    services::session::generate_token,
};

#[derive(Debug, PartialEq, Eq)]
pub enum GrantError {
    InvalidRequest,
    InvalidGrant,
    Database,
}

impl From<DbErr> for GrantError {
    fn from(_: DbErr) -> Self {
        Self::Database
    }
}

pub struct RedeemedGrant {
    pub user_id: Uuid,
    pub client_id: String,
    pub scope: String,
    pub nonce: String,
}

pub async fn issue(
    db: &DatabaseConnection,
    request: &AuthorizationRequest,
    user_id: Uuid,
    session_id: Uuid,
) -> Result<String, GrantError> {
    // Fail closed before generating a code.
    validate_authorization_request(db, request)
        .await
        .map_err(|_| GrantError::InvalidRequest)?;
    let tx = db.begin().await?;
    let now = Utc::now();

    let app = client::Entity::find()
        .filter(client::COLUMN.client_id.eq(&request.client_id))
        .filter(client::COLUMN.active.eq(true))
        .one(&tx)
        .await?
        .ok_or(GrantError::InvalidRequest)?;
    // Recheck registered callback in the transaction to avoid changes or
    // deactivation of the client between validation and issuance.
    if client_redirect_uri::Entity::find()
        .filter(client_redirect_uri::COLUMN.client_id.eq(app.id))
        .filter(client_redirect_uri::COLUMN.redirect_uri.eq(&request.redirect_uri))
        .one(&tx)
        .await?
        .is_none()
    {
        return Err(GrantError::InvalidRequest);
    }
    let account = user::Entity::find_by_id(user_id)
        .one(&tx)
        .await?
        .ok_or(GrantError::InvalidRequest)?;
    let browser = session::Entity::find_by_id(session_id)
        .one(&tx)
        .await?
        .ok_or(GrantError::InvalidRequest)?;
    if !account.active
        || !account.email_verified
        || !browser.active
        || browser.user_id != user_id
        || browser.expires_at <= now
    {
        return Err(GrantError::InvalidRequest);
    }

    let (code, hash) = generate_token();
    authorization_code::ActiveModel {
        id: Set(Uuid::new_v4()),
        code_hash: Set(hash),
        client_id: Set(app.id),
        user_id: Set(user_id),
        session_id: Set(session_id),
        redirect_uri: Set(request.redirect_uri.clone()),
        scope: Set(request.scope.clone()),
        nonce: Set(request.nonce.clone()),
        code_challenge: Set(request.code_challenge.clone()),
        created_at: Set(now),
        expires_at: Set(now + Duration::minutes(5)),
        consumed_at: Set(None),
    }
    .insert(&tx)
    .await?;
    tx.commit().await?;
    Ok(code)
}

pub async fn redeem(
    db: &DatabaseConnection,
    raw_code: &str,
    client_id: &str,
    redirect_uri: &str,
    verifier: &str,
) -> Result<RedeemedGrant, GrantError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(raw_code)
        .map_err(|_| GrantError::InvalidGrant)?;
    if raw_code.len() != 43 || decoded.len() != 32 || URL_SAFE_NO_PAD.encode(decoded) != raw_code {
        return Err(GrantError::InvalidGrant);
    }
    let digest = Sha256::digest(raw_code.as_bytes()).to_vec();
    let now = Utc::now();
    let tx = db.begin().await?;

    let record = authorization_code::Entity::find()
        .filter(authorization_code::COLUMN.code_hash.eq(digest))
        .one(&tx)
        .await?
        .ok_or(GrantError::InvalidGrant)?;
    if record.consumed_at.is_some()
        || record.expires_at <= now
        || record.redirect_uri != redirect_uri
        || !matches_s256(&record.code_challenge, verifier)
    {
        return Err(GrantError::InvalidGrant);
    }

    let app = client::Entity::find_by_id(record.client_id)
        .one(&tx)
        .await?
        .ok_or(GrantError::InvalidGrant)?;
    if !app.active || app.client_id != client_id {
        return Err(GrantError::InvalidGrant);
    }
    let account = user::Entity::find_by_id(record.user_id)
        .one(&tx)
        .await?
        .ok_or(GrantError::InvalidGrant)?;
    let browser = session::Entity::find_by_id(record.session_id)
        .one(&tx)
        .await?
        .ok_or(GrantError::InvalidGrant)?;
    if !account.active
        || !account.email_verified
        || !browser.active
        || browser.user_id != record.user_id
        || browser.expires_at <= now
    {
        return Err(GrantError::InvalidGrant);
    }

    let result = authorization_code::Entity::update_many()
        .col_expr(authorization_code::COLUMN.consumed_at, Expr::value(now))
        .filter(authorization_code::COLUMN.id.eq(record.id))
        .filter(authorization_code::COLUMN.consumed_at.is_null())
        .filter(authorization_code::COLUMN.expires_at.gt(now))
        .exec(&tx)
        .await?;
    if result.rows_affected != 1 {
        return Err(GrantError::InvalidGrant);
    }
    tx.commit().await?;
    Ok(RedeemedGrant {
        user_id: account.id,
        client_id: app.client_id,
        scope: record.scope,
        nonce: record.nonce,
    })
}
