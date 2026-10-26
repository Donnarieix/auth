use std::sync::Arc;

use sea_orm::{Database, DatabaseConnection};
use tokio::sync::Semaphore;

use crate::{schema, services::abuse::AbuseGuard};

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub abuse: Arc<AbuseGuard>,
    pub hash_slots: Arc<Semaphore>,
}

impl AppState {
    pub fn with_db(db: DatabaseConnection) -> Self {
        Self {
            db,
            abuse: Arc::new(AbuseGuard::default()),
            hash_slots: Arc::new(Semaphore::new(4)),
        }
    }

    pub async fn new() -> Self {
        std::fs::create_dir_all("data").expect("Failed to create local data directory");

        let db = Database::connect("sqlite://data/auth.db?mode=rwc")
            .await
            .expect("Failed to connect to SQLite database");

        schema::apply(&db)
            .await
            .expect("Schema migration refused or failed; do not reuse an old prototype database");

        Self::with_db(db)
    }
}
