//! Only an administrator with local database access may register a client.
//! Never accept client registrations over an unauthenticated public endpoint.
use crate::services::session::generate_token;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ConnectionTrait, DatabaseConnection, DbBackend, DbErr,
    EntityTrait, ModelTrait, QueryFilter, Statement, TransactionTrait,
};
use sha2::{Digest, Sha256};
use url::{Host, Url};
use uuid::Uuid;

use crate::entities::{client, client_redirect_uri};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientType {
    Web,
    Desktop,
}

impl ClientType {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "web" => Some(Self::Web),
            "desktop" => Some(Self::Desktop),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Desktop => "desktop",
        }
    }
}

pub fn validate_redirect_uri(kind: ClientType, raw: &str) -> Result<(), &'static str> {
    if raw.is_empty()
        || raw.len() > 2048
        || raw.trim() != raw
        || raw.bytes().any(|b| b.is_ascii_control())
    {
        return Err("Invalid redirect URI length or whitespace");
    }
    let url = Url::parse(raw).map_err(|_| "Malformed redirect URI")?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err("Redirect URI cannot contain credentials or a fragment");
    }

    // Accept only absolute HTTPS URLs for web applications. Desktop native
    // applications may use HTTP loopback callbacks with a declared port.
    if url.scheme() == "https" {
        if url.host().is_none() {
            return Err("HTTPS redirect requires a hostname");
        }
        return Ok(());
    }
    if kind == ClientType::Desktop
        && url.scheme() == "http"
        && url.port().is_some()
        && matches!(
            url.host(),
            Some(Host::Ipv4(ip)) if ip.is_loopback()
        )
    {
        return Ok(());
    }
    if kind == ClientType::Desktop
        && url.scheme() == "http"
        && url.port().is_some()
        && matches!(
            url.host(),
            Some(Host::Ipv6(ip)) if ip.is_loopback()
        )
    {
        return Ok(());
    }
    Err("Only HTTPS or desktop loopback callbacks are allowed")
}

pub async fn register_client(
    db: &DatabaseConnection,
    name: &str,
    kind: ClientType,
    uris: &[String],
) -> Result<String, DbErr> {
    register_client_with_actor(db, name, kind, uris, None).await
}

/// The developer API passes a verified administrator ID to make registration
/// and its privileged audit entry part of the same SQLite transaction.
pub async fn register_client_with_actor(
    db: &DatabaseConnection,
    name: &str,
    kind: ClientType,
    uris: &[String],
    actor: Option<Uuid>,
) -> Result<String, DbErr> {
    if name.trim() != name || name.is_empty() || name.len() > 100 {
        return Err(DbErr::Custom("Invalid client display name".into()));
    }
    if uris.is_empty() || uris.len() > 12 {
        return Err(DbErr::Custom(
            "A client requires 1 to 12 redirect URIs".into(),
        ));
    }
    let unique: std::collections::HashSet<_> = uris.iter().collect();
    if unique.len() != uris.len() {
        return Err(DbErr::Custom("Duplicate redirect URI".into()));
    }
    for uri in uris {
        validate_redirect_uri(kind, uri).map_err(|err| DbErr::Custom(err.into()))?;
    }

    let id = Uuid::new_v4();
    let public_id = Uuid::new_v4().to_string();
    let tx = db.begin().await?;

    client::ActiveModel {
        id: Set(id),
        client_id: Set(public_id.clone()),
        client_type: Set(kind.as_str().into()),
        name: Set(name.into()),
        created_at: Set(Utc::now()),
        active: Set(true),
        client_secret_hash: Set(None),
    }
    .insert(&tx)
    .await?;
    for uri in uris {
        client_redirect_uri::ActiveModel {
            id: Set(Uuid::new_v4()),
            client_id: Set(id),
            redirect_uri: Set(uri.to_owned()),
        }
        .insert(&tx)
        .await?;
    }
    if let Some(actor) = actor {
        tx.execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO developer_admin_events (id, administrator_id, event_type, created_at) VALUES (?, ?, ?, ?)",
            [
                Uuid::new_v4().to_string().into(),
                actor.to_string().into(),
                format!("client_created:{public_id}").into(),
                Utc::now().to_rfc3339().into(),
            ],
        )).await?;
    }
    tx.commit().await?;
    Ok(public_id)
}

pub async fn get_client(
    db: &DatabaseConnection,
    public_id: &str,
) -> Result<Option<client::Model>, DbErr> {
    client::Entity::find()
        .filter(client::COLUMN.client_id.eq(public_id))
        .filter(client::COLUMN.active.eq(true))
        .one(db)
        .await
}

pub async fn is_redirect_uri_allowed(
    db: &DatabaseConnection,
    app: &client::Model,
    redirect_uri: &str,
) -> Result<bool, DbErr> {
    // Look up the current database state, not a potentially stale model.
    if get_client(db, &app.client_id).await?.is_none() {
        return Ok(false);
    }
    let Some(kind) = ClientType::parse(&app.client_type) else {
        return Ok(false);
    };
    if validate_redirect_uri(kind, redirect_uri).is_err() {
        return Ok(false);
    }
    let allowed = app
        .find_related(client_redirect_uri::Entity)
        .all(db)
        .await?
        .into_iter()
        .any(|uri| uri.redirect_uri == redirect_uri);
    Ok(allowed)
}

/// Rotates a confidential web-client secret; plaintext is returned once to
/// the local operator and only the SHA-256 digest is stored in SQLite.
pub async fn rotate_web_client_secret(
    db: &DatabaseConnection,
    public_id: &str,
) -> Result<String, DbErr> {
    let app = get_client(db, public_id)
        .await?
        .filter(|app| app.client_type == "web")
        .ok_or_else(|| DbErr::Custom("Unknown or non-web client".into()))?;
    let (secret, _) = generate_token();
    let digest = Sha256::digest(secret.as_bytes()).to_vec();
    use sea_orm::IntoActiveModel;
    let mut model = app.into_active_model();
    model.client_secret_hash = Set(Some(digest));
    model.update(db).await?;
    Ok(secret)
}

pub async fn disable_client(db: &DatabaseConnection, public_id: &str) -> Result<bool, DbErr> {
    use sea_orm::sea_query::Expr;
    let affected = client::Entity::update_many()
        .col_expr(client::COLUMN.active, Expr::value(false))
        .filter(client::COLUMN.client_id.eq(public_id))
        .filter(client::COLUMN.active.eq(true))
        .exec(db)
        .await?;
    Ok(affected.rows_affected == 1)
}

#[cfg(test)]
mod tests {
    use sea_orm::{Database, EntityTrait};

    use super::{
        ClientType, disable_client, get_client, is_redirect_uri_allowed, register_client,
        validate_redirect_uri,
    };
    use crate::{entities::client_redirect_uri, schema};

    #[test]
    fn redirects_are_strictly_scoped_to_client_types() {
        assert!(validate_redirect_uri(ClientType::Web, "https://app.example.com/callback").is_ok());
        assert!(
            validate_redirect_uri(ClientType::Desktop, "http://127.0.0.1:43516/callback").is_ok()
        );
        assert!(validate_redirect_uri(ClientType::Desktop, "http://[::1]:43516/callback").is_ok());
        for uri in [
            "http://app.example.com/callback",
            "https://user:pass@app.example.com/callback",
            "https://app.example.com/callback#fragment",
            "https://app.example.com/callback ",
            "javascript:alert(1)",
            "https://app.example.com/callback\r\nheader:bad",
        ] {
            assert!(
                validate_redirect_uri(ClientType::Web, uri).is_err(),
                "{uri}"
            );
        }
        for uri in [
            "http://localhost:3000/callback",
            "http://127.0.0.1/callback",
            "http://192.168.1.5:3000/callback",
            "http://example.com:3000/callback",
        ] {
            assert!(
                validate_redirect_uri(ClientType::Desktop, uri).is_err(),
                "{uri}"
            );
        }
    }

    #[tokio::test]
    async fn registry_is_transactional_exact_and_rejects_disabled_clients() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        schema::apply(&db).await.unwrap();

        let callback = "https://app.example.com/oauth/callback".to_owned();
        let id = register_client(
            &db,
            "Test Web",
            ClientType::Web,
            std::slice::from_ref(&callback),
        )
        .await
        .unwrap();
        let app = get_client(&db, &id).await.unwrap().unwrap();
        assert_eq!(app.client_type, "web");
        assert!(is_redirect_uri_allowed(&db, &app, &callback).await.unwrap());
        assert!(
            !is_redirect_uri_allowed(&db, &app, "https://app.example.com/oauth/callback/")
                .await
                .unwrap()
        );
        assert!(
            !is_redirect_uri_allowed(&db, &app, "https://evil.example/oauth/callback")
                .await
                .unwrap()
        );
        assert!(
            !is_redirect_uri_allowed(
                &db,
                &app,
                "https://app.example.com/oauth/callback?next=evil"
            )
            .await
            .unwrap()
        );

        assert!(
            register_client(
                &db,
                "Bad",
                ClientType::Web,
                &["http://evil.example/callback".into()]
            )
            .await
            .is_err()
        );
        assert_eq!(
            client_redirect_uri::Entity::find()
                .all(&db)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(disable_client(&db, &id).await.unwrap());
        assert!(get_client(&db, &id).await.unwrap().is_none());
        assert!(!is_redirect_uri_allowed(&db, &app, &callback).await.unwrap());
    }
}
