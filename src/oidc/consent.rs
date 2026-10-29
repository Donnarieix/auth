//! Consent decisions are made by an authenticated user in a future UI.
//! This module only persists or checks an explicit approval. No implicit grants.
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ConnectionTrait, DatabaseConnection, DbBackend, DbErr,
    EntityTrait, QueryFilter, Statement, TransactionTrait, sea_query::Expr,
};
use uuid::Uuid;

use crate::entities::{client, oidc_consent, user};

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
    approve_request(db, user_id, client_id, scope, None, None).await
}

/// Both the identity grant and any API resource consent are saved atomically.
pub async fn approve_request(
    db: &DatabaseConnection,
    user_id: Uuid,
    client_id: Uuid,
    scope: &str,
    resource: Option<&str>,
    resource_scope: Option<&str>,
) -> Result<(), DbErr> {
    let requested = Scopes::parse(scope).map_err(|e| DbErr::Custom(e.into()))?;
    if resource.is_some() != resource_scope.is_some() {
        return Err(DbErr::Custom(
            "Resource and permissions must occur together".into(),
        ));
    }
    let now = Utc::now();
    let tx = db.begin().await?;
    let account = user::Entity::find_by_id(user_id).one(&tx).await?;
    let app = client::Entity::find_by_id(client_id).one(&tx).await?;
    if !account.is_some_and(|u| u.active && u.email_verified) || !app.is_some_and(|a| a.active) {
        return Err(DbErr::Custom("Account or client not authorized".into()));
    }

    if let (Some(audience), Some(permissions)) = (resource, resource_scope) {
        let requested_permissions: Vec<_> = permissions.split_whitespace().collect();
        if requested_permissions.is_empty()
            || requested_permissions.len() > 16
            || requested_permissions
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                != requested_permissions.len()
        {
            return Err(DbErr::Custom("Invalid resource permissions".into()));
        }
        for permission in &requested_permissions {
            let allowed = tx.query_one_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT 1 FROM oauth_client_resource_scopes crs JOIN oauth_resources r ON r.id=crs.resource_id WHERE crs.client_id=? AND r.audience=? AND r.active=1 AND crs.scope=?",
                [client_id.to_string().into(), audience.to_owned().into(), (*permission).to_owned().into()],
            )).await?;
            if allowed.is_none() {
                return Err(DbErr::Custom("Resource permission not allowed".into()));
            }
        }
        // Re-approval replaces (rather than accumulates) resource permissions.
        tx.execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "DELETE FROM oauth_resource_consents WHERE user_id=? AND client_id=? AND resource_id=(SELECT id FROM oauth_resources WHERE audience=?)",
            [user_id.to_string().into(),client_id.to_string().into(),audience.to_owned().into()],
        )).await?;
        tx.execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "UPDATE oidc_access_tokens SET revoked=1 WHERE user_id=? AND client_id=? AND audience=?",
            [user_id.to_string().into(),client_id.to_string().into(),audience.to_owned().into()],
        )).await?;
        let inserted = tx.execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO oauth_resource_consents(user_id,client_id,resource_id,scope,approved_at,revoked_at) SELECT ?,?,id,?,?,NULL FROM oauth_resources WHERE audience=? AND active=1",
            [user_id.to_string().into(),client_id.to_string().into(),permissions.to_owned().into(),now.to_rfc3339().into(),audience.to_owned().into()],
        )).await?;
        if inserted.rows_affected() != 1 {
            return Err(DbErr::Custom("Unknown resource".into()));
        }
    }

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

/// Check the resource's recorded end-user approval, independently of the
/// operator's assignment of application permissions.
pub async fn approved_resource<C: ConnectionTrait>(
    db: &C,
    user_id: Uuid,
    client_id: Uuid,
    resource: Option<&str>,
    resource_scope: Option<&str>,
) -> Result<bool, DbErr> {
    let (Some(audience), Some(scope)) = (resource, resource_scope) else {
        return Ok(resource.is_none() && resource_scope.is_none());
    };
    let record = db.query_one_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "SELECT rc.scope FROM oauth_resource_consents rc JOIN oauth_resources r ON r.id=rc.resource_id WHERE rc.user_id=? AND rc.client_id=? AND r.audience=? AND r.active=1 AND rc.revoked_at IS NULL",
        [user_id.to_string().into(),client_id.to_string().into(),audience.to_owned().into()],
    )).await?;
    let Some(record) = record else {
        return Ok(false);
    };
    let saved: String = record.try_get("", "scope")?;
    let granted: std::collections::HashSet<_> = saved.split_whitespace().collect();
    Ok(!scope.split_whitespace().collect::<Vec<_>>().is_empty()
        && scope
            .split_whitespace()
            .all(|value| granted.contains(value)))
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
    let result = oidc_consent::Entity::update_many()
        .col_expr(oidc_consent::COLUMN.revoked_at, Expr::value(now))
        .filter(oidc_consent::COLUMN.user_id.eq(user_id))
        .filter(oidc_consent::COLUMN.client_id.eq(client_id))
        .filter(oidc_consent::COLUMN.revoked_at.is_null())
        .exec(db)
        .await?;
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
            client_secret_hash: Set(None),
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
    #[tokio::test]
    async fn explicit_api_consent_requires_an_operator_grant_and_is_resource_specific() {
        use sea_orm::{ConnectionTrait, DbBackend, Statement};
        let (db, user_id, client_id) = fixture().await;
        let resource_id = Uuid::new_v4().to_string();
        let api = "https://api.example.test";
        db.execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO oauth_resources(id,audience,name,secret_hash,active) VALUES(?,?,?,?,1)",
            [resource_id.clone().into(), api.into(), "Test API".into(), vec![0u8;32].into()],
        )).await.unwrap();
        db.execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO oauth_client_resources(client_id,resource_id) VALUES(?,?)",
            [client_id.to_string().into(), resource_id.clone().into()],
        )).await.unwrap();
        assert!(super::approve_request(&db,user_id,client_id,"openid",
            Some(api),Some("documents:read")).await.is_err());

        db.execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO oauth_resource_scopes(resource_id,scope) VALUES(?,?)",
            [resource_id.clone().into(),"documents:read".into()],
        )).await.unwrap();
        db.execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO oauth_client_resource_scopes(client_id,resource_id,scope) VALUES(?,?,?)",
            [client_id.to_string().into(),resource_id.into(),"documents:read".into()],
        )).await.unwrap();
        assert!(super::approve_request(&db,user_id,client_id,"openid",
            Some(api),Some("documents:read")).await.is_ok());
        assert!(super::approved_resource(&db,user_id,client_id,Some(api),
            Some("documents:read")).await.unwrap());
        assert!(!super::approved_resource(&db,user_id,client_id,Some(api),
            Some("documents:write")).await.unwrap());
        assert!(!super::approved_resource(&db,user_id,client_id,
            Some("https://other.example.test"),Some("documents:read")).await.unwrap());
        assert!(!super::approved_resource(&db,Uuid::new_v4(),client_id,
            Some(api),Some("documents:read")).await.unwrap());
    }

}
