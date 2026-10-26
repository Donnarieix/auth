//! Explicit, versioned SQLite schema. Never silently migrate a legacy prototype database.
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, DbErr, Statement, TransactionTrait};

const INITIAL_SCHEMA: &[&str] = &[
    r#"CREATE TABLE users (
        id TEXT PRIMARY KEY NOT NULL,
        email TEXT NOT NULL COLLATE NOCASE UNIQUE CHECK (length(trim(email)) BETWEEN 3 AND 254),
        email_verified INTEGER NOT NULL DEFAULT 0 CHECK (email_verified IN (0, 1)),
        username TEXT NOT NULL COLLATE NOCASE UNIQUE CHECK (length(trim(username)) BETWEEN 1 AND 64),
        display_name TEXT,
        avatar_url TEXT,
        active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )"#,
    r#"CREATE TRIGGER users_id_immutable
        BEFORE UPDATE OF id ON users
        FOR EACH ROW WHEN NEW.id <> OLD.id
        BEGIN SELECT RAISE(ABORT, 'User UUID cannot be changed'); END"#,
    r#"CREATE TRIGGER users_email_change_resets_verification
        AFTER UPDATE OF email ON users
        FOR EACH ROW WHEN NEW.email <> OLD.email COLLATE NOCASE
        BEGIN UPDATE users SET email_verified = 0 WHERE id = NEW.id; END"#,
    r#"CREATE TABLE password_credentials (
        user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )"#,
    r#"CREATE TABLE sessions (
        id TEXT PRIMARY KEY NOT NULL,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash BLOB NOT NULL UNIQUE,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        last_use TEXT NOT NULL,
        active INTEGER NOT NULL CHECK (active IN (0, 1))
    )"#,
    "CREATE INDEX sessions_user_id_idx ON sessions(user_id)",
    r#"CREATE TABLE clients (
        id TEXT PRIMARY KEY NOT NULL,
        client_id TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL,
        active INTEGER NOT NULL CHECK (active IN (0, 1))
    )"#,
    r#"CREATE TABLE client_redirect_uris (
        id TEXT PRIMARY KEY NOT NULL,
        client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        redirect_uri TEXT NOT NULL,
        UNIQUE (client_id, redirect_uri)
    )"#,
];

const RECOVERY_SCHEMA: &[&str] = &[
    r#"CREATE TABLE account_tokens (
        id TEXT PRIMARY KEY NOT NULL,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        purpose TEXT NOT NULL CHECK (purpose IN ('verify_email', 'reset_password')),
        email TEXT NOT NULL COLLATE NOCASE,
        token_hash BLOB NOT NULL UNIQUE,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        consumed_at TEXT
    )"#,
    "CREATE INDEX account_tokens_user_purpose_idx ON account_tokens(user_id, purpose)",
    r#"CREATE TABLE account_security_events (
        id TEXT PRIMARY KEY NOT NULL,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        event_kind TEXT NOT NULL CHECK (event_kind IN ('email_verified', 'password_reset')),
        created_at TEXT NOT NULL
    )"#,
];

const SESSION_SECURITY_SCHEMA: &[&str] = &[
    r#"CREATE TRIGGER users_disable_revokes_sessions
        AFTER UPDATE OF active ON users
        FOR EACH ROW WHEN NEW.active = 0 AND OLD.active <> NEW.active
        BEGIN UPDATE sessions SET active = 0 WHERE user_id = NEW.id; END"#,
    "UPDATE sessions SET active = 0 WHERE user_id IN (SELECT id FROM users WHERE active = 0)",
];

const CLIENT_REGISTRY_SCHEMA: &[&str] = &[
    r#"ALTER TABLE clients ADD COLUMN client_type TEXT NOT NULL DEFAULT 'web'
       CHECK (client_type IN ('web', 'desktop'))"#,
];

const AUTHORIZATION_CODE_SCHEMA: &[&str] = &[
    r#"CREATE TABLE authorization_codes (
        id TEXT PRIMARY KEY NOT NULL,
        code_hash BLOB NOT NULL UNIQUE,
        client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        redirect_uri TEXT NOT NULL,
        scope TEXT NOT NULL,
        nonce TEXT NOT NULL,
        code_challenge TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        consumed_at TEXT
    )"#,
    "CREATE INDEX authorization_codes_user_idx ON authorization_codes(user_id)",
    "CREATE INDEX authorization_codes_expiry_idx ON authorization_codes(expires_at)",
];

const OIDC_CONSENT_SCHEMA: &[&str] = &[
    r#"CREATE TABLE oidc_consents (
        id TEXT PRIMARY KEY NOT NULL,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        scope TEXT NOT NULL,
        approved_at TEXT NOT NULL,
        revoked_at TEXT,
        UNIQUE (user_id, client_id)
    )"#,
    "CREATE INDEX oidc_consents_client_idx ON oidc_consents(client_id)",
];

const ACCESS_TOKEN_SCHEMA: &[&str] = &[
    r#"CREATE TABLE oidc_access_tokens (
        id TEXT PRIMARY KEY NOT NULL,
        token_hash BLOB NOT NULL UNIQUE,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        scope TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1))
    )"#,
    "CREATE INDEX oidc_access_tokens_user_idx ON oidc_access_tokens(user_id)",
    "CREATE INDEX oidc_access_tokens_expiry_idx ON oidc_access_tokens(expires_at)",
];

fn statement(sql: &str) -> Statement {
    Statement::from_string(DbBackend::Sqlite, sql.to_owned())
}

pub async fn apply(db: &DatabaseConnection) -> Result<(), DbErr> {
    // Both schema revisions and migration markers are committed atomically.
    let tx = db.begin().await?;
    tx.execute_raw(statement(
        "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY NOT NULL)",
    ))
    .await?;

    if tx
        .query_one_raw(statement(
            "SELECT version FROM schema_migrations WHERE version > 7 LIMIT 1",
        ))
        .await?
        .is_some()
    {
        return Err(DbErr::Custom(
            "Database schema is newer than this server".into(),
        ));
    }

    let has_v1 = tx
        .query_one_raw(statement(
            "SELECT version FROM schema_migrations WHERE version = 1",
        ))
        .await?
        .is_some();

    if !has_v1 {
        if tx
            .query_one_raw(statement(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('users', 'sessions', 'clients', 'client_redirect_uris', 'password_credentials') LIMIT 1",
            ))
            .await?
            .is_some()
        {
            return Err(DbErr::Custom(
                "Unversioned Auth tables found. Back up and migrate explicitly; a fresh database is required for schema v1.".into(),
            ));
        }
        for sql in INITIAL_SCHEMA {
            tx.execute_raw(statement(sql)).await?;
        }
        tx.execute_raw(statement(
            "INSERT INTO schema_migrations (version) VALUES (1)",
        ))
        .await?;
    }

    let has_v2 = tx
        .query_one_raw(statement(
            "SELECT version FROM schema_migrations WHERE version = 2",
        ))
        .await?
        .is_some();
    if !has_v2 {
        for sql in RECOVERY_SCHEMA {
            tx.execute_raw(statement(sql)).await?;
        }
        tx.execute_raw(statement(
            "INSERT INTO schema_migrations (version) VALUES (2)",
        ))
        .await?;
    }

    let has_v3 = tx
        .query_one_raw(statement(
            "SELECT version FROM schema_migrations WHERE version = 3",
        ))
        .await?
        .is_some();
    if !has_v3 {
        for sql in SESSION_SECURITY_SCHEMA {
            tx.execute_raw(statement(sql)).await?;
        }
        tx.execute_raw(statement(
            "INSERT INTO schema_migrations (version) VALUES (3)",
        ))
        .await?;
    }

    let has_v4 = tx
        .query_one_raw(statement(
            "SELECT version FROM schema_migrations WHERE version = 4",
        ))
        .await?
        .is_some();
    if !has_v4 {
        for sql in CLIENT_REGISTRY_SCHEMA {
            tx.execute_raw(statement(sql)).await?;
        }
        tx.execute_raw(statement(
            "INSERT INTO schema_migrations (version) VALUES (4)",
        ))
        .await?;
    }

    let has_v5 = tx
        .query_one_raw(statement(
            "SELECT version FROM schema_migrations WHERE version = 5",
        ))
        .await?
        .is_some();
    if !has_v5 {
        for sql in AUTHORIZATION_CODE_SCHEMA {
            tx.execute_raw(statement(sql)).await?;
        }
        tx.execute_raw(statement(
            "INSERT INTO schema_migrations (version) VALUES (5)",
        ))
        .await?;
    }

    let has_v6 = tx
        .query_one_raw(statement(
            "SELECT version FROM schema_migrations WHERE version = 6",
        ))
        .await?
        .is_some();
    if !has_v6 {
        for sql in OIDC_CONSENT_SCHEMA {
            tx.execute_raw(statement(sql)).await?;
        }
        tx.execute_raw(statement(
            "INSERT INTO schema_migrations (version) VALUES (6)",
        ))
        .await?;
    }

    let has_v7 = tx
        .query_one_raw(statement(
            "SELECT version FROM schema_migrations WHERE version = 7",
        ))
        .await?
        .is_some();
    if !has_v7 {
        for sql in ACCESS_TOKEN_SCHEMA {
            tx.execute_raw(statement(sql)).await?;
        }
        tx.execute_raw(statement(
            "INSERT INTO schema_migrations (version) VALUES (7)",
        ))
        .await?;
    }

    tx.commit().await
}

#[cfg(test)]
mod tests {
    use sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ConnectionTrait, Database, DatabaseConnection,
        DbBackend, EntityTrait, IntoActiveModel, Statement,
    };
    use uuid::Uuid;

    use super::apply;
    use crate::entities::{password_credential, user};

    async fn empty_db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("in-memory SQLite");
        apply(&db).await.expect("initial migration");
        db
    }

    fn account(email: &str, username: &str) -> user::ActiveModel {
        let now = chrono::Utc::now();
        user::ActiveModel {
            id: Set(Uuid::new_v4()),
            email: Set(email.to_owned()),
            email_verified: Set(false),
            username: Set(username.to_owned()),
            display_name: Set(None),
            avatar_url: Set(None),
            active: Set(true),
            created_at: Set(now),
            updated_at: Set(now),
        }
    }

    #[tokio::test]
    async fn migrator_is_idempotent_and_rejects_unversioned_databases() {
        let db = empty_db().await;
        apply(&db).await.expect("idempotent migration");

        let old = Database::connect("sqlite::memory:").await.unwrap();
        old.execute_raw(Statement::from_string(
            DbBackend::Sqlite,
            "CREATE TABLE users (id TEXT PRIMARY KEY, password TEXT NOT NULL)".to_owned(),
        ))
        .await
        .unwrap();
        assert!(apply(&old).await.is_err());
    }

    #[tokio::test]
    async fn upgrades_version_one_without_losing_accounts() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_raw(Statement::from_string(
            DbBackend::Sqlite,
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY NOT NULL)".to_owned(),
        ))
        .await
        .unwrap();
        for sql in super::INITIAL_SCHEMA {
            db.execute_raw(super::statement(sql)).await.unwrap();
        }
        db.execute_raw(super::statement(
            "INSERT INTO schema_migrations (version) VALUES (1)",
        ))
        .await
        .unwrap();
        let existing = account("upgrade@example.com", "upgrade")
            .insert(&db)
            .await
            .unwrap();

        apply(&db).await.expect("upgrade v1 to v2");
        apply(&db).await.expect("migration stays idempotent");
        assert!(
            user::Entity::find_by_id(existing.id)
                .one(&db)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            db.query_one_raw(super::statement(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'account_tokens'",
            ))
            .await
            .unwrap()
            .is_some()
        );
        assert!(
            db.query_one_raw(super::statement(
                "SELECT version FROM schema_migrations WHERE version = 2",
            ))
            .await
            .unwrap()
            .is_some()
        );
    }

    #[tokio::test]
    async fn existing_client_registry_upgrades_to_version_four() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_raw(super::statement(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY NOT NULL)",
        ))
        .await
        .unwrap();

        for sql in super::INITIAL_SCHEMA
            .iter()
            .chain(super::RECOVERY_SCHEMA)
            .chain(super::SESSION_SECURITY_SCHEMA)
        {
            db.execute_raw(super::statement(sql)).await.unwrap();
        }
        db.execute_raw(super::statement(
            "INSERT INTO schema_migrations (version) VALUES (1), (2), (3)",
        ))
        .await
        .unwrap();
        db.execute_raw(super::statement(
            "INSERT INTO clients(id,client_id,name,created_at,active) VALUES ('00000000-0000-4000-8000-000000000001', 'legacy-client', 'Legacy', '2026-01-01T00:00:00Z', 1)",
        ))
        .await
        .unwrap();

        apply(&db).await.unwrap();
        apply(&db).await.unwrap();
        let found = db
            .query_one_raw(super::statement(
                "SELECT client_type FROM clients WHERE client_id = 'legacy-client'",
            ))
            .await
            .unwrap()
            .unwrap();
        let kind: String = found.try_get("", "client_type").unwrap();
        assert_eq!(kind, "web");
        assert!(
            db.query_one_raw(super::statement(
                "SELECT version FROM schema_migrations WHERE version = 4",
            ))
            .await
            .unwrap()
            .is_some()
        );
    }

    #[tokio::test]
    async fn client_registry_upgrades_to_grants_without_losing_clients() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_raw(super::statement(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY NOT NULL)",
        ))
        .await
        .unwrap();
        for sql in super::INITIAL_SCHEMA
            .iter()
            .chain(super::RECOVERY_SCHEMA)
            .chain(super::SESSION_SECURITY_SCHEMA)
            .chain(super::CLIENT_REGISTRY_SCHEMA)
        {
            db.execute_raw(super::statement(sql)).await.unwrap();
        }
        db.execute_raw(super::statement(
            "INSERT INTO schema_migrations (version) VALUES (1), (2), (3), (4)",
        ))
        .await
        .unwrap();
        db.execute_raw(super::statement(
            "INSERT INTO clients(id,client_id,client_type,name,created_at,active) VALUES ('00000000-0000-4000-8000-000000000001', 'known-client', 'desktop', 'Existing', '2026-01-01T00:00:00Z', 1)",
        )).await.unwrap();

        apply(&db).await.expect("upgrade from v4");
        apply(&db).await.expect("idempotent after v5");
        let row = db
            .query_one_raw(super::statement(
                "SELECT client_type FROM clients WHERE client_id='known-client'",
            ))
            .await
            .unwrap()
            .unwrap();
        let kind: String = row.try_get("", "client_type").unwrap();
        assert_eq!(kind, "desktop");
        assert!(
            db.query_one_raw(super::statement(
                "SELECT version FROM schema_migrations WHERE version=5",
            ))
            .await
            .unwrap()
            .is_some()
        );
        assert!(
            db.query_one_raw(super::statement(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='authorization_codes'",
            ))
            .await
            .unwrap()
            .is_some()
        );
    }

    #[tokio::test]
    async fn unique_email_username_and_mutable_profile() {
        let db = empty_db().await;
        let first = account("hello@example.com", "TestUser")
            .insert(&db)
            .await
            .unwrap();
        assert!(
            account("HELLO@EXAMPLE.COM", "different")
                .insert(&db)
                .await
                .is_err()
        );
        assert!(
            account("other@example.com", "testuser")
                .insert(&db)
                .await
                .is_err()
        );

        let mut edit = first.clone().into_active_model();
        edit.username = Set("newname".to_owned());
        edit.display_name = Set(Some("My Name".to_owned()));
        edit.avatar_url = Set(Some("https://example.com/avatar.png".to_owned()));
        edit.updated_at = Set(chrono::Utc::now());
        edit.update(&db).await.unwrap();

        let updated = user::Entity::find_by_id(first.id)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.username, "newname");
        assert_eq!(updated.display_name.as_deref(), Some("My Name"));
        assert_eq!(updated.email, first.email);
    }

    #[tokio::test]
    async fn email_change_resets_verification_and_uuid_is_immutable() {
        let db = empty_db().await;
        let original = account("first@example.com", "first")
            .insert(&db)
            .await
            .unwrap();
        let mut verified = original.clone().into_active_model();
        verified.email_verified = Set(true);
        verified.update(&db).await.unwrap();

        let mut changed = user::Entity::find_by_id(original.id)
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .into_active_model();
        changed.email = Set("second@example.com".to_owned());
        changed.update(&db).await.unwrap();
        let current = user::Entity::find_by_id(original.id)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert!(!current.email_verified);

        let change_id = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "UPDATE users SET id = ? WHERE id = ?",
            [Uuid::new_v4().into(), original.id.into()],
        );
        assert!(db.execute_raw(change_id).await.is_err());
        assert!(
            user::Entity::find_by_id(original.id)
                .one(&db)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn credentials_are_separate_and_reference_an_account() {
        let db = empty_db().await;
        let user = account("test@example.com", "test")
            .insert(&db)
            .await
            .unwrap();
        let now = chrono::Utc::now();
        let credential = password_credential::ActiveModel {
            user_id: Set(user.id),
            password_hash: Set("$argon2id$example".into()),
            created_at: Set(now),
            updated_at: Set(now),
        };
        credential.insert(&db).await.unwrap();
        assert!(
            password_credential::Entity::find_by_id(user.id)
                .one(&db)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            password_credential::ActiveModel {
                user_id: Set(Uuid::new_v4()),
                password_hash: Set("never persist".to_owned()),
                created_at: Set(now),
                updated_at: Set(now),
            }
            .insert(&db)
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn updates_enforce_uniqueness_and_preserve_user_status() {
        let db = empty_db().await;
        let primary = account("primary@example.com", "Primary")
            .insert(&db)
            .await
            .unwrap();
        let secondary = account("secondary@example.com", "Secondary")
            .insert(&db)
            .await
            .unwrap();

        let mut duplicate_email = secondary.clone().into_active_model();
        duplicate_email.email = Set("PRIMARY@EXAMPLE.COM".to_owned());
        assert!(duplicate_email.update(&db).await.is_err());

        let mut duplicate_username = secondary.clone().into_active_model();
        duplicate_username.username = Set("primary".to_owned());
        assert!(duplicate_username.update(&db).await.is_err());

        let mut disabled = primary.clone().into_active_model();
        let modified_at = chrono::Utc::now() + chrono::Duration::seconds(5);
        disabled.active = Set(false);
        disabled.updated_at = Set(modified_at);
        disabled.update(&db).await.unwrap();

        let current = user::Entity::find_by_id(primary.id)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert!(!current.active);
        assert_eq!(current.updated_at, modified_at);
    }
}
