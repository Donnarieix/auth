//! Keep memory-hard password hashing off the async executor.
//! Never log submitted passwords or the password hash.
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::http::StatusCode;
use tokio::task;

use crate::state::AppState;

// Fixed, public Argon2id hash of a dummy password, used solely to reduce the
// timing difference between unknown email addresses and invalid passwords.
pub const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$l4hDjNPFrZwfy9K1ltsGBA$MscCpHVegeqPNFGryq0yESBWiP1yfWDBgyKV968TANg";

pub async fn hash(state: &AppState, password: String) -> Result<String, StatusCode> {
    let permit = state
        .hash_slots
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    task::spawn_blocking(move || {
        let _permit = permit;
        Argon2::default()
            .hash_password(password.as_bytes())
            .map(|hash| hash.to_string())
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub async fn verify(
    state: &AppState,
    password: String,
    stored_hash: String,
) -> Result<bool, StatusCode> {
    let permit = state
        .hash_slots
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    task::spawn_blocking(move || {
        let _permit = permit;
        PasswordHash::new(&stored_hash)
            .ok()
            .is_some_and(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[cfg(test)]
mod tests {
    use sea_orm::Database;

    use super::{DUMMY_HASH, hash, verify};
    use crate::state::AppState;

    #[tokio::test]
    async fn random_salts_and_roundtrip() {
        let state = AppState::with_db(Database::connect("sqlite::memory:").await.unwrap());
        let a = hash(&state, "same secure password".into()).await.unwrap();
        let b = hash(&state, "same secure password".into()).await.unwrap();
        assert_ne!(a, b);
        assert!(a.starts_with("$argon2id$"));
        assert!(!a.contains("same secure password"));
        assert!(verify(&state, "same secure password".into(), a.clone()).await.unwrap());
        assert!(!verify(&state, "different password".into(), a).await.unwrap());
        assert!(!verify(&state, "random password".into(), DUMMY_HASH.into()).await.unwrap());
    }
}
