use sea_orm::{ActiveModelTrait, ActiveValue::Set, Database, DatabaseConnection, EntityTrait, QueryFilter};
use uuid::Uuid;

use crate::entities;

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
}

impl AppState {
    pub async fn new() -> Self {
        std::fs::create_dir_all("data").unwrap();

        let db = Database::connect("sqlite://data/auth.db?mode=rwc")
            .await
            .expect("Failed to create / connect database");

        db.get_schema_registry("auth::entities::*")
            .sync(&db)
            .await
            .unwrap();

        if dotenvy::var("env").unwrap_or_default() == "dev" {
            let debug_client = entities::client::Entity::find()
                .filter(entities::client::COLUMN.client_id.eq("debug"))
                .one(&db)
                .await
                .unwrap();
            if debug_client.is_some() {
                return Self { db };
            }

            let client = entities::client::ActiveModel {
                id: Set(Uuid::new_v4().into()),
                client_id: Set("debug".into()),
                name: Set("Debug Client".into()),
                created_at: Set(chrono::Utc::now().into()),
                active: Set(true),
            };
            client.insert(&db).await.unwrap();
        }

        Self { db }
    }
}