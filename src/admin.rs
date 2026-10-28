//! Administrative CLI only. No remote client registration or developer API.
use sea_orm::{
    ConnectionTrait, Database, DatabaseConnection, DbBackend, EntityTrait, ModelTrait, Statement,
    TransactionTrait,
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
        "UPDATE developer_administrators SET totp_secret = ?, totp_last_step = -1 WHERE username = ? AND active = 1 AND totp_secret IS NULL",
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

pub async fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let db = db().await?;
    match args {
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
        _ => return Err("Usage: cargo run -- client add <web|desktop> <name> <redirect-uri>... | client list | client disable <id> | client secret rotate <web-client-id> | admin bootstrap <username> | admin token rotate <username> | admin totp enroll <username>".into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{ConnectionTrait, Database, DbBackend, Statement};
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use super::rotate_administrator_token;
    use crate::schema;

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
