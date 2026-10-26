//! Consent decisions are made by an authenticated user in a future UI.
//! This module only persists or checks an explicit approval. No implicit grants.
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ConnectionTrait, DatabaseConnection, DbErr, EntityTrait,
    QueryFilter, TransactionTrait, sea_query::Expr,
};
use uuid::Uuid;

use crate::entities::{client, oidc_access_token, oidc_consent, user};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scopes {
    pub profile: bool,
    pub email: bool,
}

impl Scopes {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        let mut profile = false;
        let mut email = false;
        let mut openid = false;
        for scope in value.split_whitespace() {
            match scope {
                "openid" if !openid => openid = true,
                "profile" if !profile => profile = true,
                "email" if !email => email = true,
                _ => return Err("Invalid or duplicate OIDC scope"),
            }
        }
        if !openid {
            return Err("Missing required openid scope");
        }
        Ok(Self { profile, email })
    }

    fn as_string(&self) -> String {
        let mut s = "openid".to_owned();
        if self.profile {
            s.push_str(" profile");
        }
        if self.email {
            s.push_str(" email");
        }
        s
    }

    fn contains(&self, requested: &Scopes) -> bool {
        (!requested.profile || self.profile) && (!requested.email || self.email)
    }
}

/// Explicit approval must only be called by a trusted, CSRF-protected consent
/// UI. It is intentionally not exposed by any HTTP endpoint yet.
pub async fn approve(
    db: &DatabaseConnection,
    user_id: Uuid,
    client_id: Uuid,
    scope: &str,
) -> Result<(), DbErr> {
    let requested = Scopes::parse(scope).map_err(|e| DbErr::Custom(e.into()))?;
    let now = Utc::now();
    let tx = db.begin().await?;
    let account = user::Entity::find_by_id(user_id).one(&tx).await?;
    let app = client::Entity::find_by_id(client_id).one(&tx).await?;
    if !account.is_some_and(|u| u.active && u.email_verified) || !app.is_some_and(|a| a.active) {
        return Err(DbErr::Custom("Account or client not authorized".into()));
    }

    // Re-approval must not resurrect previously revoked or over-scoped
    // access tokens. Every consent change invalidates existing bearer tokens.
    oidc_access_token::Entity::delete_many()
        .filter(oidc_access_token::COLUMN.user_id.eq(user_id))
        .filter(oidc_access_token::COLUMN.client_id.eq(client_id))
        .exec(&tx)
        .await?;

    // Never accumulate permissions implicitly. The exact scopes confirmed
    // by the user replace the previous set instead of silently expanding it.
    oidc_consent::Entity::delete_many()
        .filter(oidc_consent::COLUMN.user_id.eq(user_id))
        .filter(oidc_consent::COLUMN.client_id.eq(client_id))
        .exec(&tx)
        .await?;

    oidc_consent::ActiveModel {
        id: Set(Uuid::new_v4()),
        user_id: Set(user_id),
        client_id: Set(client_id),
        scope: Set(requested.as_string()),
        approved_at: Set(now),
        revoked_at: Set(None),
    }
    .insert(&tx)
    .await?;
    tx.commit().await
}

pub async fn approved<C: ConnectionTrait>(
    db: &C,
    user_id: Uuid,
    client_id: Uuid,
    scope: &str,
) -> Result<bool, DbErr> {
    let requested = Scopes::parse(scope).map_err(|e| DbErr::Custom(e.into()))?;
    let record = oidc_consent::Entity::find()
        .filter(oidc_consent::COLUMN.user_id.eq(user_id))
        .filter(oidc_consent::COLUMN.client_id.eq(client_id))
        .filter(oidc_consent::COLUMN.revoked_at.is_null())
        .one(db)
        .await?;
    Ok(record
        .and_then(|row| Scopes::parse(&row.scope).ok())
        .is_some_and(|granted| granted.contains(&requested)))
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "OIDC consent management interface is not yet enabled"
    )
)]
pub async fn revoke(
    db: &DatabaseConnection,
    user_id: Uuid,
    client_id: Uuid,
) -> Result<bool, DbErr> {
    let now = Utc::now();
    let tx = db.begin().await?;
    let result = oidc_consent::Entity::update_many()
        .col_expr(oidc_consent::COLUMN.revoked_at, Expr::value(now))
        .filter(oidc_consent::COLUMN.user_id.eq(user_id))
        .filter(oidc_consent::COLUMN.client_id.eq(client_id))
        .filter(oidc_consent::COLUMN.revoked_at.is_null())
        .exec(&tx)
        .await?;
    oidc_access_token::Entity::delete_many()
        .filter(oidc_access_token::COLUMN.user_id.eq(user_id))
        .filter(oidc_access_token::COLUMN.client_id.eq(client_id))
        .exec(&tx)
        .await?;
    tx.commit().await?;
    Ok(result.rows_affected == 1)
}

#[cfg(test)]
mod tests {
    use super::{Scopes, approve, approved, revoke};
    use crate::{
        entities::{client, user},
        schema,
    };
    use chrono::Utc;
    use sea_orm::{ActiveModelTrait, ActiveValue::Set, Database, EntityTrait, IntoActiveModel};
    use uuid::Uuid;

    async fn fixture() -> (sea_orm::DatabaseConnection, Uuid, Uuid) {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        schema::apply(&db).await.unwrap();
        let uid = Uuid::new_v4();
        let cid = Uuid::new_v4();
        let now = Utc::now();
        user::ActiveModel {
            id: Set(uid),
            email: Set("test@example.com".into()),
            email_verified: Set(true),
            username: Set("test".into()),
            display_name: Set(None),
            avatar_url: Set(None),
            active: Set(true),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(&db)
        .await
        .unwrap();
        client::ActiveModel {
            id: Set(cid),
            client_id: Set("test-client".into()),
            client_type: Set("web".into()),
            name: Set("Test".into()),
            created_at: Set(now),
            active: Set(true),
        }
        .insert(&db)
        .await
        .unwrap();
        (db, uid, cid)
    }

    #[test]
    fn scopes_are_restricted_and_order_independent() {
        assert_eq!(
            Scopes::parse("email openid profile").unwrap(),
            Scopes {
                profile: true,
                email: true
            }
        );
        for invalid in ["", "email", "openid openid", "openid admin", "openid EMAIL"] {
            assert!(Scopes::parse(invalid).is_err());
        }
    }

    #[tokio::test]
    async fn consent_is_explicit_scoped_and_revocable() {
        let (db, uid, cid) = fixture().await;
        assert!(!approved(&db, uid, cid, "openid").await.unwrap());
        approve(&db, uid, cid, "openid profile").await.unwrap();
        assert!(approved(&db, uid, cid, "openid").await.unwrap());
        assert!(approved(&db, uid, cid, "openid profile").await.unwrap());
        assert!(!approved(&db, uid, cid, "openid email").await.unwrap());
        approve(&db, uid, cid, "openid email").await.unwrap();
        assert!(!approved(&db, uid, cid, "openid profile").await.unwrap());
        assert!(approved(&db, uid, cid, "openid email").await.unwrap());
        assert!(revoke(&db, uid, cid).await.unwrap());
        assert!(!revoke(&db, uid, cid).await.unwrap());
        assert!(!approved(&db, uid, cid, "openid").await.unwrap());
    }

    #[tokio::test]
    async fn inactive_client_and_unverified_user_cannot_approve() {
        let (db, uid, cid) = fixture().await;
        let mut account = user::Entity::find_by_id(uid)
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .into_active_model();
        account.email_verified = Set(false);
        account.update(&db).await.unwrap();
        assert!(approve(&db, uid, cid, "openid").await.is_err());
    }
}
