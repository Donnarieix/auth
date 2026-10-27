//! Administrative CLI only. No remote client registration or developer API.
use sea_orm::{
    ConnectionTrait, Database, DatabaseConnection, DbBackend, EntityTrait, ModelTrait, Statement,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
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

pub async fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let db = db().await?;
    match args {
        [command, action, username] if command == "admin" && action == "bootstrap" => {
            bootstrap_administrator(&db, username).await?;
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
        _ => return Err("Usage: cargo run -- client add <web|desktop> <name> <redirect-uri>... | client list | client disable <id> | client secret rotate <web-client-id> | admin bootstrap <username>".into()),
    }
    Ok(())
}
