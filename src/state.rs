use sea_orm::{Database, DatabaseConnection};

use crate::schema;

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
}

impl AppState {
    pub async fn new() -> Self {
        std::fs::create_dir_all("data").expect("Failed to create local data directory");

        let db = Database::connect("sqlite://data/auth.db?mode=rwc")
            .await
            .expect("Failed to connect to SQLite database");

        schema::apply(&db)
            .await
            .expect("Schema migration refused or failed; do not reuse an old prototype database");

        Self { db }
    }
}
