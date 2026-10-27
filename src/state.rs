use rsa::{
    RsaPrivateKey,
    pkcs8::{EncodePrivateKey, LineEnding},
};
use std::{io::Write, path::Path, sync::Arc};

use sea_orm::{Database, DatabaseConnection};
use tokio::sync::Semaphore;

use crate::{
    oidc::signing::SigningKeys,
    schema,
    security::SecurityConfig,
    services::{abuse::AbuseGuard, email::Mailer},
};

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub abuse: Arc<AbuseGuard>,
    pub hash_slots: Arc<Semaphore>,
    pub mailer: Mailer,
    pub security: SecurityConfig,
    pub oidc_keys: Option<Arc<SigningKeys>>,
}

impl AppState {
    fn development_keys() -> Result<SigningKeys, String> {
        let directory = Path::new("data").join("keys");
        std::fs::create_dir_all(&directory)
            .map_err(|_| "Cannot create development key directory")?;
        let file_path = directory.join("dev.private.pem");
        if !file_path.exists() {
            let key = RsaPrivateKey::new(&mut rand_core::OsRng, 2048)
                .map_err(|_| "Cannot create local RSA key")?;
            let pem = key
                .to_pkcs8_pem(LineEnding::LF)
                .map_err(|_| "Cannot encode local RSA key")?;
            let mut file_options = std::fs::OpenOptions::new();
            file_options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                file_options.mode(0o600);
            }
            let mut file = file_options
                .open(&file_path)
                .map_err(|_| "Cannot save local key")?;
            file.write_all(pem.as_bytes())
                .map_err(|_| "Cannot write local key")?;
        }
        let pem = std::fs::read_to_string(&file_path).map_err(|_| "Cannot read local key")?;
        SigningKeys::from_pem("http://127.0.0.1:3000", "development-local", &pem, &[])
    }

    #[cfg(test)]
    pub fn with_db(db: DatabaseConnection) -> Self {
        Self::with_mailer(db, Mailer::Disabled)
    }

    pub fn with_mailer(db: DatabaseConnection, mailer: Mailer) -> Self {
        Self {
            db,
            abuse: Arc::new(AbuseGuard::default()),
            hash_slots: Arc::new(Semaphore::new(4)),
            mailer,
            security: SecurityConfig::development(),
            oidc_keys: None,
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

        let security = SecurityConfig::from_env().expect("Invalid AUTH_PUBLIC_ORIGIN");
        let mut state = Self::with_mailer(db, Mailer::from_env(security.secure));
        let configured = SigningKeys::from_env(&security.origin)
            .expect("Invalid OIDC signing key configuration");
        state.oidc_keys = configured
            .or_else(|| {
                (!security.secure).then(|| {
                    Self::development_keys().expect("Cannot initialize loopback signing key")
                })
            })
            .map(Arc::new);
        state.security = security;
        state
    }
}
