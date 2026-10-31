//! Authorization codes are opaque, short-lived, and bound to a single session,
//! client, redirect URI and S256 challenge. Never log the plaintext code.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, DatabaseConnection, DbErr, EntityTrait, QueryFilter,
    TransactionTrait, ConnectionTrait, DbBackend, Statement, sea_query::Expr,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    entities::{authorization_code, client, client_redirect_uri, session, user},
    oidc::{AuthorizationRequest, consent, matches_s256, validate_authorization_request},
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
    pub resource: Option<String>,
    pub nonce: String,
    pub auth_time: chrono::DateTime<Utc>,
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
        .filter(
            client_redirect_uri::COLUMN
                .redirect_uri
                .eq(&request.redirect_uri),
        )
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

    if !consent::approved(&tx, account.id, app.id, &request.scope).await? {
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
        audience: Set(request.resource.clone()),
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
    // Revoking an approved callback also invalidates codes issued for it.
    if client_redirect_uri::Entity::find()
        .filter(client_redirect_uri::COLUMN.client_id.eq(app.id))
        .filter(client_redirect_uri::COLUMN.redirect_uri.eq(redirect_uri))
        .one(&tx)
        .await?
        .is_none()
    {
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

    // Resource grants can be withdrawn while a code is outstanding.
    if let Some(audience) = &record.audience {
        let allowed = tx.query_one_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT 1 FROM oauth_client_resources cr JOIN oauth_resources r ON cr.resource_id = r.id WHERE cr.client_id = (SELECT id FROM clients WHERE client_id = ?) AND r.audience = ? AND r.active = 1",
            [app.client_id.clone().into(), audience.clone().into()],
        )).await?;
        if allowed.is_none() { return Err(GrantError::InvalidGrant); }
    }

    // Consent may be revoked between authorization and code redemption.
    if !consent::approved(&tx, account.id, app.id, &record.scope).await? {
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
        resource: record.audience,
        nonce: record.nonce,
        auth_time: browser.created_at,
    })
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use sea_orm::{
        ActiveModelTrait, ActiveValue::Set, Database, EntityTrait, QueryFilter, sea_query::Expr,
    };
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use super::{GrantError, issue, redeem};
    use crate::{
        entities::{authorization_code, session, user},
        oidc::{AuthorizationRequest, consent},
        schema,
        services::client::{ClientType, disable_client, get_client, register_client},
    };

    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    async fn fixture() -> (
        sea_orm::DatabaseConnection,
        AuthorizationRequest,
        Uuid,
        Uuid,
    ) {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        schema::apply(&db).await.unwrap();
        let redirect = "https://app.example.com/callback".to_string();
        let client_id = register_client(
            &db,
            "Test",
            ClientType::Web,
            std::slice::from_ref(&redirect),
        )
        .await
        .unwrap();
        let uid = Uuid::new_v4();
        let sid = Uuid::new_v4();
        let now = Utc::now();
        user::ActiveModel {
            id: Set(uid),
            email: Set("test@example.com".into()),
            email_verified: Set(true),
            username: Set("tester".into()),
            display_name: Set(None),
            avatar_url: Set(None),
            active: Set(true),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(&db)
        .await
        .unwrap();
        session::ActiveModel {
            id: Set(sid),
            user_id: Set(uid),
            token_hash: Set(Sha256::digest("test-session").to_vec()),
            created_at: Set(now),
            expires_at: Set(now + chrono::Duration::minutes(30)),
            last_use: Set(now),
            active: Set(true),
        }
        .insert(&db)
        .await
        .unwrap();
        let app = get_client(&db, &client_id).await.unwrap().unwrap();
        consent::approve(&db, uid, app.id, "openid profile")
            .await
            .unwrap();

        let request = AuthorizationRequest {
            response_type: "code".into(),
            client_id,
            redirect_uri: redirect,
            scope: "openid profile".into(),
            resource: None,
            state: "unique-state-value-1234".into(),
            nonce: "unique-nonce-value-1234".into(),
            code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into(),
            code_challenge_method: "S256".into(),
        };
        (db, request, uid, sid)
    }

    #[tokio::test]
    async fn a_code_is_stored_only_as_hash_and_redeemed_once() {
        let (db, req, uid, sid) = fixture().await;
        let code = issue(&db, &req, uid, sid).await.unwrap();
        assert_eq!(code.len(), 43);
        let stored = authorization_code::Entity::find()
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.code_hash, Sha256::digest(code.as_bytes()).to_vec());
        assert_ne!(stored.code_hash, code.as_bytes());
        assert!(stored.expires_at <= Utc::now() + chrono::Duration::minutes(5));

        let result = redeem(&db, &code, &req.client_id, &req.redirect_uri, VERIFIER)
            .await
            .unwrap();
        assert_eq!(result.user_id, uid);
        assert_eq!(result.client_id, req.client_id);
        assert_eq!(result.scope, "openid profile");
        assert_eq!(result.nonce, req.nonce);
        assert!(matches!(
            redeem(&db, &code, &req.client_id, &req.redirect_uri, VERIFIER).await,
            Err(GrantError::InvalidGrant)
        ));
    }

    #[tokio::test]
    async fn invalid_pkce_client_and_redirect_fail_without_consuming_code() {
        let (db, req, uid, sid) = fixture().await;
        let code = issue(&db, &req, uid, sid).await.unwrap();
        assert!(matches!(
            redeem(
                &db,
                &code,
                &req.client_id,
                &req.redirect_uri,
                "x".repeat(43).as_str()
            )
            .await,
            Err(GrantError::InvalidGrant)
        ));
        assert!(matches!(
            redeem(
                &db,
                &code,
                &Uuid::new_v4().to_string(),
                &req.redirect_uri,
                VERIFIER
            )
            .await,
            Err(GrantError::InvalidGrant)
        ));
        assert!(matches!(
            redeem(
                &db,
                &code,
                &req.client_id,
                "https://evil.example/callback",
                VERIFIER
            )
            .await,
            Err(GrantError::InvalidGrant)
        ));
        assert!(
            redeem(&db, &code, &req.client_id, &req.redirect_uri, VERIFIER)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn expired_or_disabled_grants_cannot_be_redeemed() {
        let (db, req, uid, sid) = fixture().await;
        let code = issue(&db, &req, uid, sid).await.unwrap();
        authorization_code::Entity::update_many()
            .col_expr(
                authorization_code::COLUMN.expires_at,
                Expr::value(Utc::now() - chrono::Duration::seconds(1)),
            )
            .exec(&db)
            .await
            .unwrap();
        assert!(matches!(
            redeem(&db, &code, &req.client_id, &req.redirect_uri, VERIFIER).await,
            Err(GrantError::InvalidGrant)
        ));

        let code2 = issue(&db, &req, uid, sid).await.unwrap();
        disable_client(&db, &req.client_id).await.unwrap();
        assert!(matches!(
            redeem(&db, &code2, &req.client_id, &req.redirect_uri, VERIFIER).await,
            Err(GrantError::InvalidGrant)
        ));
    }

    #[tokio::test]
    async fn removing_a_callback_revokes_outstanding_codes_for_it() {
        use crate::entities::client_redirect_uri;
        let (db, req, uid, sid) = fixture().await;
        let code = issue(&db, &req, uid, sid).await.unwrap();
        client_redirect_uri::Entity::delete_many()
            .filter(
                client_redirect_uri::COLUMN
                    .redirect_uri
                    .eq(&req.redirect_uri),
            )
            .exec(&db)
            .await
            .unwrap();
        assert!(matches!(
            redeem(&db, &code, &req.client_id, &req.redirect_uri, VERIFIER).await,
            Err(GrantError::InvalidGrant)
        ));
    }

    #[tokio::test]
    async fn unverified_users_and_revoked_sessions_cannot_authorize() {
        let (db, req, uid, sid) = fixture().await;
        user::Entity::update_many()
            .col_expr(user::COLUMN.email_verified, Expr::value(false))
            .filter(user::COLUMN.id.eq(uid))
            .exec(&db)
            .await
            .unwrap();
        assert!(matches!(
            issue(&db, &req, uid, sid).await,
            Err(GrantError::InvalidRequest)
        ));
        user::Entity::update_many()
            .col_expr(user::COLUMN.email_verified, Expr::value(true))
            .filter(user::COLUMN.id.eq(uid))
            .exec(&db)
            .await
            .unwrap();
        let code = issue(&db, &req, uid, sid).await.unwrap();
        session::Entity::update_many()
            .col_expr(session::COLUMN.active, Expr::value(false))
            .filter(session::COLUMN.id.eq(sid))
            .exec(&db)
            .await
            .unwrap();
        assert!(matches!(
            redeem(&db, &code, &req.client_id, &req.redirect_uri, VERIFIER).await,
            Err(GrantError::InvalidGrant)
        ));
        assert!(matches!(
            issue(&db, &req, uid, sid).await,
            Err(GrantError::InvalidRequest)
        ));
    }
    #[tokio::test]
    async fn concurrent_redemption_has_at_most_one_success() {
        let (db, req, uid, sid) = fixture().await;
        let code = issue(&db, &req, uid, sid).await.unwrap();
        let first = redeem(&db, &code, &req.client_id, &req.redirect_uri, VERIFIER);
        let second = redeem(&db, &code, &req.client_id, &req.redirect_uri, VERIFIER);
        let (a, b) = tokio::join!(first, second);
        let successes = usize::from(a.is_ok()) + usize::from(b.is_ok());
        assert_eq!(
            successes, 1,
            "the authorization code must be consumed exactly once"
        );
    }

    #[tokio::test]
    async fn unapproved_or_revoked_scopes_never_yield_grants() {
        let (db, mut request, uid, sid) = fixture().await;
        request.scope = "openid email".into();
        assert!(matches!(
            issue(&db, &request, uid, sid).await,
            Err(GrantError::InvalidRequest)
        ));
        request.scope = "openid profile".into();
        let issued = issue(&db, &request, uid, sid).await.unwrap();
        let client = get_client(&db, &request.client_id).await.unwrap().unwrap();
        assert!(consent::revoke(&db, uid, client.id).await.unwrap());
        assert!(matches!(
            redeem(
                &db,
                &issued,
                &request.client_id,
                &request.redirect_uri,
                VERIFIER
            )
            .await,
            Err(GrantError::InvalidGrant)
        ));
    }
}
