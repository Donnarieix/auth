//! Administrative CLI only. No remote client registration or developer API.
use sea_orm::{Database, DatabaseConnection, EntityTrait, ModelTrait};

use crate::{
    entities::{client, client_redirect_uri},
    schema,
    services::client::{ClientType, disable_client, register_client},
};

async fn db() -> Result<DatabaseConnection, Box<dyn std::error::Error>> {
    std::fs::create_dir_all("data")?;
    let db = Database::connect("sqlite://data/auth.db?mode=rwc").await?;
    schema::apply(&db).await?;
    Ok(db)
}

pub async fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let db = db().await?;
    match args {
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
        [command, action] if command == "client" && action == "list" => {
            for app in client::Entity::find().all(&db).await? {
                println!("{} | {} | {} | active={}", app.client_id, app.name, app.client_type, app.active);
                for redirect in app.find_related(client_redirect_uri::Entity).all(&db).await? {
                    println!("  redirect: {}", redirect.redirect_uri);
                }
            }
        }
        _ => return Err("Usage: cargo run -- client add <web|desktop> <name> <redirect-uri>... | client list | client disable <id>".into()),
    }
    Ok(())
}
