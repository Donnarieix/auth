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

fn statement(sql: &str) -> Statement {
    Statement::from_string(DbBackend::Sqlite, sql.to_owned())
}

pub async fn apply(db: &DatabaseConnection) -> Result<(), DbErr> {
    // DDL and migration marker are committed together.
    let tx = db.begin().await?;
    tx.execute_raw(statement(
        "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY NOT NULL)",
    ))
    .await?;

    if tx
        .query_one_raw(statement(
            "SELECT version FROM schema_migrations WHERE version = 1",
        ))
        .await?
        .is_some()
    {
        return tx.commit().await;
    }

    // An older database may store passwords inside users. Never overwrite it.
    if tx
        .query_one_raw(statement(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('users', 'sessions', 'clients', 'client_redirect_uris', 'password_credentials') LIMIT 1",
        ))
        .await?
        .is_some()
    {
        return Err(DbErr::Custom(
            "Unversioned Auth tables found. Back up and migrate them explicitly; a fresh database is required for schema v1.".into(),
        ));
    }

    for sql in INITIAL_SCHEMA {
        tx.execute_raw(statement(sql)).await?;
    }
    tx.execute_raw(statement(
        "INSERT INTO schema_migrations (version) VALUES (1)",
    ))
    .await?;
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
}
