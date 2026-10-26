use std::time::Duration;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use chrono::Utc;
use sea_orm::{Database, EntityTrait, QueryFilter, sea_query::Expr};
use tokio::{sync::mpsc, time::timeout};
use tower::ServiceExt;

use crate::{
    entities::{account_token, password_credential, session, user},
    router, schema,
    services::email::{Mail, Mailer},
    state::AppState,
};

async fn test_app() -> (Router, AppState, mpsc::UnboundedReceiver<Mail>) {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    schema::apply(&db).await.unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    let state = AppState::with_mailer(db, Mailer::Test(tx));
    (router(state.clone()), state, rx)
}

async fn post(app: &Router, path: &str, payload: &str) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(payload.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn register(app: &Router, email: &str) {
    let body = format!(
        r#"{{"email":"{email}","username":"testuser","password":"Initial password 123!"}}"#
    );
    assert_eq!(
        post(app, "/register", &body).await.status(),
        StatusCode::ACCEPTED
    );
}

async fn received(rx: &mut mpsc::UnboundedReceiver<Mail>) -> String {
    let mail = timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("mail delivery timeout")
        .expect("mail channel closed");
    let token = mail
        .body
        .lines()
        .find_map(|line| line.strip_prefix("Code: "))
        .expect("mail contains code");
    assert_eq!(mail.recipient, "known@example.com");
    token.to_owned()
}

#[tokio::test]
async fn verification_codes_are_hashed_single_use_and_email_bound() {
    let (app, state, mut rx) = test_app().await;
    register(&app, "known@example.com").await;
    // Registration sends the initial confirmation code automatically.
    let first = received(&mut rx).await;
    let hashes = account_token::Entity::find().all(&state.db).await.unwrap();
    assert_eq!(hashes.len(), 1);
    assert_ne!(hashes[0].token_hash, first.as_bytes());

    let confirm = format!(r#"{{"token":"{first}"}}"#);
    assert_eq!(
        post(&app, "/email/verification/confirm", &confirm)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        post(&app, "/email/verification/confirm", &confirm)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let account = user::Entity::find().one(&state.db).await.unwrap().unwrap();
    assert!(account.email_verified);

    // Change the address: the old address is no longer verified.
    user::Entity::update_many()
        .col_expr(user::COLUMN.email, Expr::value("other@example.com"))
        .filter(user::COLUMN.id.eq(account.id))
        .exec(&state.db)
        .await
        .unwrap();
    assert!(
        !user::Entity::find_by_id(account.id)
            .one(&state.db)
            .await
            .unwrap()
            .unwrap()
            .email_verified
    );
    // Obtain an unconsumed code for the current address, then change it.
    user::Entity::update_many()
        .col_expr(user::COLUMN.email, Expr::value("known@example.com"))
        .filter(user::COLUMN.id.eq(account.id))
        .exec(&state.db)
        .await
        .unwrap();
    assert_eq!(
        post(
            &app,
            "/email/verification/request",
            r#"{"email":"known@example.com"}"#,
        )
        .await
        .status(),
        StatusCode::ACCEPTED
    );
    let pending = received(&mut rx).await;
    user::Entity::update_many()
        .col_expr(user::COLUMN.email, Expr::value("new@example.com"))
        .filter(user::COLUMN.id.eq(account.id))
        .exec(&state.db)
        .await
        .unwrap();
    let stale = format!(r#"{{"token":"{pending}"}}"#);
    assert_eq!(
        post(&app, "/email/verification/confirm", &stale)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn expired_code_is_rejected_and_unknown_email_is_not_disclosed() {
    let (app, state, mut rx) = test_app().await;
    register(&app, "known@example.com").await;
    let token = received(&mut rx).await;
    account_token::Entity::update_many()
        .col_expr(
            account_token::COLUMN.expires_at,
            Expr::value(Utc::now() - chrono::Duration::minutes(1)),
        )
        .exec(&state.db)
        .await
        .unwrap();
    let confirm = format!(r#"{{"token":"{token}"}}"#);
    assert_eq!(
        post(&app, "/email/verification/confirm", &confirm)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let unknown = r#"{"email":"absent@example.com"}"#;
    let existing = r#"{"email":"known@example.com"}"#;
    assert_eq!(
        post(&app, "/password/reset/request", unknown)
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(
        post(&app, "/password/reset/request", existing)
            .await
            .status(),
        StatusCode::ACCEPTED
    );
}

#[tokio::test]
async fn password_recovery_revokes_sessions_and_old_password() {
    let (app, state, mut rx) = test_app().await;
    register(&app, "known@example.com").await;
    let _ = received(&mut rx).await;
    let initial_login = r#"{"email":"known@example.com","password":"Initial password 123!"}"#;
    assert_eq!(
        post(&app, "/login", initial_login).await.status(),
        StatusCode::OK
    );

    assert_eq!(
        post(
            &app,
            "/password/reset/request",
            r#"{"email":"known@example.com"}"#
        )
        .await
        .status(),
        StatusCode::ACCEPTED
    );
    let token = received(&mut rx).await;
    let request = format!(r#"{{"token":"{token}","new_password":"Updated password 123!"}}"#);
    assert_eq!(
        post(&app, "/password/reset/confirm", &request)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        post(&app, "/password/reset/confirm", &request)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post(&app, "/login", initial_login).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post(
            &app,
            "/login",
            r#"{"email":"known@example.com","password":"Updated password 123!"}"#
        )
        .await
        .status(),
        StatusCode::OK
    );
    // Previous session revoked; a successful new login creates a new session.
    let sessions = session::Entity::find().all(&state.db).await.unwrap();
    assert_eq!(sessions.len(), 2);
    assert!(!sessions[0].active);

    let credential = password_credential::Entity::find()
        .one(&state.db)
        .await
        .unwrap()
        .unwrap();
    assert!(!credential.password_hash.contains("Updated password 123!"));
}

#[tokio::test]
async fn recovery_code_is_invalidated_after_email_change() {
    let (app, state, mut rx) = test_app().await;
    register(&app, "known@example.com").await;
    let _ = received(&mut rx).await;
    post(
        &app,
        "/password/reset/request",
        r#"{"email":"known@example.com"}"#,
    )
    .await;
    let token = received(&mut rx).await;
    user::Entity::update_many()
        .col_expr(user::COLUMN.email, Expr::value("changed@example.com"))
        .exec(&state.db)
        .await
        .unwrap();
    let request = format!(r#"{{"token":"{token}","new_password":"Updated password 123!"}}"#);
    assert_eq!(
        post(&app, "/password/reset/confirm", &request)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
}


#[tokio::test]
async fn resending_verification_invalidates_the_previous_code() {
    let (app, state, mut rx) = test_app().await;
    register(&app, "known@example.com").await;
    let initial = received(&mut rx).await;
    assert_eq!(
        post(&app, "/email/verification/request", r#"{"email":"known@example.com"}"#)
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    let next = received(&mut rx).await;
    assert_ne!(initial, next);
    let old_body = format!(r#"{{"token":"{initial}"}}"#);
    let new_body = format!(r#"{{"token":"{next}"}}"#);
    assert_eq!(
        post(&app, "/email/verification/confirm", &old_body).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post(&app, "/email/verification/confirm", &new_body).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        account_token::Entity::find().all(&state.db).await.unwrap().len(),
        1
    );
}
