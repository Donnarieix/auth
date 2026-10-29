//! Administrative CLI only. No remote client registration or developer API.
use sea_orm::{
    ConnectionTrait, Database, DatabaseConnection, DbBackend, DbErr, EntityTrait, ModelTrait,
    Statement, TransactionTrait,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    admin_totp,
    entities::{client, client_redirect_uri},
    schema,
    services::{
        client::{ClientType, disable_client, register_client, rotate_web_client_secret},
        session::generate_token,
    },
};

async fn audit_resource<C: ConnectionTrait>(
    connection: &C,
    kind: &str,
    audience: &str,
    client: Option<&str>,
) -> Result<(), DbErr> {
    connection.execute_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "INSERT INTO oauth_resource_events(id,event_kind,resource_audience,client_public_id,created_at) VALUES(?,?,?,?,?)",
        [Uuid::new_v4().to_string().into(),kind.into(),audience.into(),client.map(str::to_owned).into(),chrono::Utc::now().to_rfc3339().into()],
    )).await?;
    Ok(())
}

async fn db() -> Result<DatabaseConnection, Box<dyn std::error::Error>> {
    std::fs::create_dir_all("data")?;
    let db = Database::connect("sqlite://data/auth.db?mode=rwc").await?;
    schema::apply(&db).await?;
    Ok(db)
}

/// Bootstraps the initial administrator without creating a user account or a
/// shared/default password. The generated high-entropy token is printed once
/// on the operator's trusted terminal and only its digest is stored.
async fn bootstrap_administrator(
    db: &DatabaseConnection,
    username: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if username.len() < 3
        || username.len() > 32
        || !username
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("Invalid administrator username".into());
    }
    let count = db
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT COUNT(*) AS total FROM developer_administrators",
        ))
        .await?
        .ok_or("Unable to inspect administrator accounts")?;
    let total: i64 = count.try_get("", "total")?;
    if total != 0 {
        return Err("An administrator already exists; bootstrap is single-use".into());
    }
    let (token, _) = generate_token();
    let digest = Sha256::digest(token.as_bytes()).to_vec();
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "INSERT INTO developer_administrators (id, username, token_hash, created_at, active) VALUES (?, ?, ?, ?, 1)",
        [
            Uuid::new_v4().to_string().into(),
            username.to_owned().into(),
            digest.into(),
            chrono::Utc::now().to_rfc3339().into(),
        ],
    ))
    .await?;
    println!("Administrator recovery token (displayed once, store in a password manager): {token}");
    Ok(())
}

/// Credential recovery/rotation requires trusted local database access.
async fn rotate_administrator_token(
    db: &DatabaseConnection,
    username: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (token, _) = generate_token();
    let digest = Sha256::digest(token.as_bytes()).to_vec();
    let tx = db.begin().await?;
    let updated = tx
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "UPDATE developer_administrators SET token_hash = ? WHERE username = ? AND active = 1",
            [digest.into(), username.to_owned().into()],
        ))
        .await?;
    if updated.rows_affected() != 1 {
        return Err("Unknown or disabled administrator".into());
    }
    tx.execute_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "INSERT INTO developer_admin_events(id, administrator_id, event_type, created_at) SELECT ?, id, 'credential_rotated', ? FROM developer_administrators WHERE username = ?",
        [
            Uuid::new_v4().to_string().into(),
            chrono::Utc::now().to_rfc3339().into(),
            username.to_owned().into(),
        ],
    )).await?;
    tx.commit().await?;
    println!("New administrator token (previous token revoked; store this once): {token}");
    Ok(())
}

/// Explicit local enrollment: secret is shown once in a trusted terminal.
/// TOTP provisioning never happens through an end-user SSO session.
async fn enroll_totp(
    db: &DatabaseConnection,
    username: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use rand::RngExt;
    let mut secret = [0u8; 32];
    rand::rng().fill(&mut secret);
    let result = db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "UPDATE developer_administrators SET totp_secret = ?, totp_last_step = -1, totp_required = 1 WHERE username = ? AND active = 1 AND totp_secret IS NULL",
        [secret.to_vec().into(), username.to_owned().into()],
    )).await?;
    if result.rows_affected() != 1 {
        return Err("Unknown, disabled, or already enrolled administrator".into());
    }
    let encoded = admin_totp::encode_base32(&secret);
    println!("TOTP seed (shown once; store offline): {encoded}");
    println!(
        "Authenticator setup: otpauth://totp/DonnarieixAuth:{username}?secret={encoded}&issuer=DonnarieixAuth&algorithm=SHA256&digits=6&period=30"
    );
    Ok(())
}

/// Local-only emergency MFA recovery. Requiring possession of the SQLite
/// storage host avoids any browser or SSO-based second-factor bypass.
async fn reset_totp(
    db: &DatabaseConnection,
    username: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let tx = db.begin().await?;
    let updated = tx
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "UPDATE developer_administrators SET totp_secret = NULL, totp_last_step = -1 WHERE username = ? AND active = 1 AND totp_secret IS NOT NULL",
            [username.to_owned().into()],
        ))
        .await?;
    if updated.rows_affected() != 1 {
        return Err("Unknown, disabled, or unenrolled administrator".into());
    }
    tx.execute_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "UPDATE developer_sessions SET revoked = 1 WHERE administrator_id IN (SELECT id FROM developer_administrators WHERE username = ?)",
        [username.to_owned().into()],
    ))
    .await?;
    tx.execute_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "INSERT INTO developer_admin_events(id, administrator_id, event_type, created_at) SELECT ?, id, 'totp_reset', ? FROM developer_administrators WHERE username = ?",
        [
            Uuid::new_v4().to_string().into(),
            chrono::Utc::now().to_rfc3339().into(),
            username.to_owned().into(),
        ],
    ))
    .await?;
    tx.commit().await?;
    println!(
        "Second factor reset locally. All developer sessions revoked. Re-enroll TOTP before using privileged operations."
    );
    Ok(())
}

pub async fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let db = db().await?;
    match args {
        [command, action, operation, username]
            if command == "admin" && action == "totp" && operation == "reset" =>
        {
            reset_totp(&db, username).await?;
        }
        [command, action, operation, username]
            if command == "admin" && action == "totp" && operation == "enroll" =>
        {
            enroll_totp(&db, username).await?;
        }
        [command, action, username] if command == "admin" && action == "bootstrap" => {
            bootstrap_administrator(&db, username).await?;
        }
        [command, action, operation, username]
            if command == "admin" && action == "token" && operation == "rotate" =>
        {
            rotate_administrator_token(&db, username).await?;
        }
        [command, action, audience, scope] if command == "resource" && action == "scope" => {
            if scope.is_empty() || scope.len() > 64 || !scope.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b,b':'|b'.'|b'_'|b'-')) {
                return Err("Invalid resource permission".into());
            }
            let tx = db.begin().await?;
            let inserted = tx.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite,
                "INSERT INTO oauth_resource_scopes(resource_id,scope) SELECT id,? FROM oauth_resources WHERE audience=? AND active=1",
                [scope.to_owned().into(), audience.to_owned().into()]
            )).await?;
            if inserted.rows_affected()!=1 { return Err("Resource unavailable or scope exists".into()); }
            tx.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite,
                "INSERT INTO oauth_resource_events(id,event_kind,resource_audience,created_at) VALUES(?,'scope_added',?,?)",
                [Uuid::new_v4().to_string().into(),audience.to_owned().into(),chrono::Utc::now().to_rfc3339().into()]
            )).await?;
            tx.commit().await?;
        }
        [command, action, operation, client_id, audience, scope] if command == "resource" && action == "permission" && operation == "allow" => {
            let tx = db.begin().await?;
            let result = tx.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite,
                "INSERT INTO oauth_client_resource_scopes(client_id,resource_id,scope) SELECT c.id,r.id,? FROM clients c JOIN oauth_client_resources cr ON cr.client_id=c.id JOIN oauth_resources r ON r.id=cr.resource_id JOIN oauth_resource_scopes rs ON rs.resource_id=r.id AND rs.scope=? WHERE c.client_id=? AND r.audience=? AND c.active=1 AND r.active=1",
                [scope.to_owned().into(),scope.to_owned().into(),client_id.to_owned().into(),audience.to_owned().into()]
            )).await?;
            if result.rows_affected()!=1 { return Err("No active permission grant or duplicate".into()); }
            tx.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite,
                "INSERT INTO oauth_resource_events(id,event_kind,resource_audience,client_public_id,created_at) VALUES(?,'permission_allowed',?,?,?)",
                [Uuid::new_v4().to_string().into(),audience.to_owned().into(),client_id.to_owned().into(),chrono::Utc::now().to_rfc3339().into()]
            )).await?;
            tx.commit().await?;
        }
        [command, action, operation, client_id, audience, scope] if command == "resource" && action == "permission" && operation == "deny" => {
            let tx = db.begin().await?;
            tx.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite,
                "DELETE FROM oauth_client_resource_scopes WHERE client_id=(SELECT id FROM clients WHERE client_id=?) AND resource_id=(SELECT id FROM oauth_resources WHERE audience=?) AND scope=?",
                [client_id.to_owned().into(),audience.to_owned().into(),scope.to_owned().into()]
            )).await?;
            tx.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite,
                "UPDATE oidc_access_tokens SET revoked=1 WHERE client_id=(SELECT id FROM clients WHERE client_id=?) AND audience=? AND (' ' || COALESCE(resource_scope,'') || ' ') LIKE ?",
                [client_id.to_owned().into(),audience.to_owned().into(),format!("% {scope} %").into()]
            )).await?;
            tx.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite,
                "INSERT INTO oauth_resource_events(id,event_kind,resource_audience,client_public_id,created_at) VALUES(?,'permission_denied',?,?,?)",
                [Uuid::new_v4().to_string().into(),audience.to_owned().into(),client_id.to_owned().into(),chrono::Utc::now().to_rfc3339().into()]
            )).await?;
            tx.commit().await?;
        }
        [command, action, audience, name] if command == "resource" && action == "add" => {
            if audience.len() > 256 || audience.len() < 8 || name.is_empty() || name.len() > 100 {
                return Err("Invalid resource identifier or name".into());
            }
            let parsed = url::Url::parse(audience)?;
            if parsed.scheme() != "https" || parsed.fragment().is_some()
                || !parsed.username().is_empty() || parsed.password().is_some()
                || parsed.query().is_some() || parsed.as_str() != audience
            {
                return Err("Resource audience must be a canonical HTTPS URL without query, fragment or credentials".into());
            }
            let (secret, _) = generate_token();
            let resource_id = Uuid::new_v4().to_string();
            let tx = db.begin().await?;
            tx.execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "INSERT INTO oauth_resources(id,audience,name,secret_hash,active) VALUES(?,?,?,?,1)",
                [
                    resource_id.clone().into(),
                    audience.to_owned().into(),
                    name.to_owned().into(),
                    Sha256::digest(secret.as_bytes()).to_vec().into(),
                ],
            )).await?;
            println!("Resource audience: {audience}");
            println!("Resource credential ID: {resource_id}");
            println!("Resource introspection secret (displayed once): {secret}");
            audit_resource(&tx, "resource_created", audience, None).await?;
            tx.commit().await?;
        }
        [command, action, operation, audience] if command == "resource" && action == "secret" && operation == "rotate" => {
            let (secret, _) = generate_token();
            let result = db.execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE oauth_resources SET secret_hash = ? WHERE audience = ? AND active = 1",
                [Sha256::digest(secret.as_bytes()).to_vec().into(), audience.to_owned().into()],
            )).await?;
            if result.rows_affected() != 1 { return Err("Unknown resource".into()); }
            println!("Rotated resource secret (displayed once): {secret}");
            audit_resource(&tx, "resource_secret_rotated", audience, None).await?;
            tx.commit().await?;
        }
        [command, action, client_id, audience] if command == "resource" && action == "allow" => {
            let result = db.execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "INSERT INTO oauth_client_resources(client_id,resource_id) SELECT c.id,r.id FROM clients c CROSS JOIN oauth_resources r WHERE c.client_id = ? AND c.active = 1 AND r.audience = ? AND r.active = 1",
                [client_id.to_owned().into(), audience.to_owned().into()],
            )).await?;
            if result.rows_affected() != 1 { return Err("Unknown client/resource or already allowed".into()); }
            println!("Client permitted to request resource");
            audit_resource(&tx, "client_link_allowed", audience, Some(client_id)).await?;
            tx.commit().await?;
        }
        [command, action, client_id, audience] if command == "resource" && action == "deny" => {
            let tx = db.begin().await?;
            tx.execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "DELETE FROM oauth_client_resources WHERE client_id = (SELECT id FROM clients WHERE client_id = ?) AND resource_id = (SELECT id FROM oauth_resources WHERE audience = ?)",
                [client_id.to_owned().into(), audience.to_owned().into()],
            )).await?;
            tx.execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE oidc_access_tokens SET revoked = 1 WHERE client_id = (SELECT id FROM clients WHERE client_id = ?) AND audience = ?",
                [client_id.to_owned().into(), audience.to_owned().into()],
            )).await?;
            println!("Client resource access denied; existing tokens revoked");
            audit_resource(&tx, "client_link_denied", audience, Some(client_id)).await?;
            tx.commit().await?;
        }
        [command, action, audience] if command == "resource" && action == "disable" => {
            let tx = db.begin().await?;
            tx.execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE oauth_resources SET active = 0 WHERE audience = ?",
                [audience.to_owned().into()],
            )).await?;
            tx.execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE oidc_access_tokens SET revoked = 1 WHERE audience = ?",
                [audience.to_owned().into()],
            )).await?;
            audit_resource(&tx, "resource_disabled", audience, None).await?;
            tx.commit().await?;
        }
        [command, action, kind, name, redirects @ ..] if command == "client" && action == "add" => {
            let kind = ClientType::parse(kind).ok_or("Type must be web or desktop")?;
            let id = register_client(&db, name, kind, redirects).await?;
            println!("Registered client ID: {id}");
        }
        [command, action, id] if command == "client" && action == "disable" => {
            if disable_client(&db, id).await? {
                println!("Client disabled");
            } else {
                return Err("No active client with that ID".into());
            }
        }
        [command, action, operation, id]
            if command == "client" && action == "secret" && operation == "rotate" =>
        {
            let secret = rotate_web_client_secret(&db, id).await?;
            println!("New client secret (save now; it cannot be retrieved again): {secret}");
        }
        [command, action] if command == "client" && action == "list" => {
            for app in client::Entity::find().all(&db).await? {
                println!("{} | {} | {} | active={}", app.client_id, app.name, app.client_type, app.active);
                for redirect in app.find_related(client_redirect_uri::Entity).all(&db).await? {
                    println!("  redirect: {}", redirect.redirect_uri);
                }
            }
        }
        _ => return Err("Usage: cargo run -- client add <web|desktop> <name> <redirect-uri>... | client list | client disable <id> | client secret rotate <web-client-id> | admin bootstrap <username> | admin token rotate <username> | admin totp enroll <username> | admin totp reset <username>".into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{ConnectionTrait, Database, DbBackend, Statement};
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use super::{reset_totp, rotate_administrator_token};
    use crate::schema;

    #[tokio::test]
    async fn local_mfa_reset_audits_and_revokes_all_sessions() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        schema::apply(&db).await.unwrap();
        let id = Uuid::new_v4().to_string();
        db.execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO developer_administrators(id,username,token_hash,created_at,active,totp_secret) VALUES(?,?,?,?,1,?)",
            [
                id.clone().into(),
                "operator".to_owned().into(),
                Sha256::digest(b"admin-credential").to_vec().into(),
                chrono::Utc::now().to_rfc3339().into(),
                b"12345678901234567890123456789012".to_vec().into(),
            ],
        ))
        .await
        .unwrap();
        db.execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO developer_sessions(id,administrator_id,token_hash,expires_at,revoked) VALUES(?,?,?,?,0)",
            [
                Uuid::new_v4().to_string().into(),
                id.into(),
                Sha256::digest(b"active-session").to_vec().into(),
                (chrono::Utc::now() + chrono::Duration::minutes(30))
                    .to_rfc3339()
                    .into(),
            ],
        ))
        .await
        .unwrap();
        reset_totp(&db, "operator").await.unwrap();
        let result = db.query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT a.totp_secret, a.totp_last_step, s.revoked FROM developer_administrators a JOIN developer_sessions s ON s.administrator_id = a.id WHERE a.username = 'operator'",
        )).await.unwrap().unwrap();
        let secret: Option<Vec<u8>> = result.try_get("", "totp_secret").unwrap();
        let step: i64 = result.try_get("", "totp_last_step").unwrap();
        let revoked: bool = result.try_get("", "revoked").unwrap();
        assert!(secret.is_none());
        assert_eq!(step, -1);
        assert!(revoked);
        let event = db
            .query_one_raw(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT id FROM developer_admin_events WHERE event_type = 'totp_reset'",
            ))
            .await
            .unwrap();
        assert!(event.is_some());
        assert!(reset_totp(&db, "operator").await.is_err());
    }

    #[tokio::test]
    async fn rotation_changes_credential_and_writes_audit_event() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        schema::apply(&db).await.unwrap();
        let previous = Sha256::digest(b"previous-secret").to_vec();
        db.execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO developer_administrators(id, username, token_hash, created_at, active) VALUES (?, ?, ?, ?, 1)",
            [
                Uuid::new_v4().to_string().into(),
                "operator".to_owned().into(),
                previous.clone().into(),
                chrono::Utc::now().to_rfc3339().into(),
            ],
        )).await.unwrap();
        rotate_administrator_token(&db, "operator").await.unwrap();
        let row = db
            .query_one_raw(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT token_hash FROM developer_administrators WHERE username = 'operator'",
            ))
            .await
            .unwrap()
            .unwrap();
        let new_hash: Vec<u8> = row.try_get("", "token_hash").unwrap();
        assert_ne!(previous, new_hash);
        let event = db
            .query_one_raw(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT id FROM developer_admin_events WHERE event_type = 'credential_rotated'",
            ))
            .await
            .unwrap();
        assert!(event.is_some());
        assert!(rotate_administrator_token(&db, "unknown").await.is_err());
    }
}
