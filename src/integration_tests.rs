use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use sea_orm::{Database, EntityTrait, PaginatorTrait};
use tower::ServiceExt;

use crate::{
    entities::{password_credential, user},
    router, schema,
    state::AppState,
};

async fn app() -> (Router, AppState) {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    schema::apply(&db).await.unwrap();
    let state = AppState::with_db(db);
    (router(state.clone()), state)
}

async fn post(app: Router, path: &str, payload: &str) -> Response {
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("origin", "http://127.0.0.1:3000")
        .body(Body::from(payload.to_owned()))
        .unwrap();
    app.oneshot(request).await.unwrap()
}

fn registration(email: &str, username: &str, password: &str) -> String {
    format!(r#"{{"email":"{email}","username":"{username}","password":"{password}"}}"#)
}

#[tokio::test]
async fn registration_is_atomic_and_does_not_reveal_existing_account() {
    let (app, state) = app().await;
    let body = registration("A@Example.com", "first", "Secure password 123!");
    let response = post(app.clone(), "/register", &body).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let by_email = registration("a@example.com", "another", "Secure password 123!");
    let by_username = registration("other@example.com", "FIRST", "Secure password 123!");
    assert_eq!(
        post(app.clone(), "/register", &by_email).await.status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(
        post(app.clone(), "/register", &by_username).await.status(),
        StatusCode::ACCEPTED
    );

    assert_eq!(user::Entity::find().count(&state.db).await.unwrap(), 1);
    assert_eq!(
        password_credential::Entity::find()
            .count(&state.db)
            .await
            .unwrap(),
        1
    );
    let credential = password_credential::Entity::find()
        .one(&state.db)
        .await
        .unwrap()
        .unwrap();
    assert!(credential.password_hash.starts_with("$argon2id$"));
    assert!(!credential.password_hash.contains("Secure password 123!"));
}

#[tokio::test]
async fn concurrent_duplicate_registrations_create_one_account() {
    let (app, state) = app().await;
    let mut requests = Vec::new();
    for _ in 0..8 {
        let app = app.clone();
        requests.push(tokio::spawn(async move {
            post(
                app,
                "/register",
                &registration("concurrent@example.com", "someone", "Valid password 123!"),
            )
            .await
            .status()
        }));
    }
    for result in requests {
        assert_eq!(result.await.unwrap(), StatusCode::ACCEPTED);
    }
    assert_eq!(user::Entity::find().count(&state.db).await.unwrap(), 1);
    assert_eq!(
        password_credential::Entity::find()
            .count(&state.db)
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn invalid_requests_do_not_create_a_credential() {
    let (app, state) = app().await;
    let invalid = registration("bad@email", "../bad", "short");
    assert_eq!(
        post(app.clone(), "/register", &invalid).await.status(),
        StatusCode::BAD_REQUEST
    );
    let too_big = "X".repeat(20_000);
    assert_eq!(
        post(app.clone(), "/register", &too_big).await.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(user::Entity::find().count(&state.db).await.unwrap(), 0);
}

#[tokio::test]
async fn login_is_generic_for_missing_users_and_bad_passwords() {
    let (app, _) = app().await;
    post(
        app.clone(),
        "/register",
        &registration("known@example.com", "known", "Strong password 123!"),
    )
    .await;
    let unknown = r#"{"email":"missing@example.com","password":"Wrong password 123!"}"#;
    let bad = r#"{"email":"known@example.com","password":"Wrong password 123!"}"#;
    assert_eq!(
        post(app.clone(), "/login", unknown).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post(app.clone(), "/login", bad).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let ok = r#"{"email":"KNOWN@example.com","password":"Strong password 123!"}"#;
    let result = post(app, "/login", ok).await;
    assert_eq!(result.status(), StatusCode::OK);
    assert!(result.headers().get("set-cookie").is_some());
}

#[tokio::test]
async fn repeated_login_attempts_are_throttled() {
    let (app, _) = app().await;
    let payload = r#"{"email":"absent@example.com","password":"Wrong password 123!"}"#;
    for _ in 0..12 {
        assert_eq!(
            post(app.clone(), "/login", payload).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        post(app, "/login", payload).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}
