use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use sea_orm::{ConnectionTrait, Database, DbBackend, Statement};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

use crate::{router, schema, state::AppState};

#[tokio::test]
async fn developer_browser_session_is_isolated_and_revocable() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    schema::apply(&db).await.unwrap();
    let token = "Q".repeat(43);
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "INSERT INTO developer_administrators(id, username, token_hash, created_at, active) VALUES (?, ?, ?, ?, 1)",
        [
            Uuid::new_v4().to_string().into(),
            "operator".to_owned().into(),
            Sha256::digest(token.as_bytes()).to_vec().into(),
            chrono::Utc::now().to_rfc3339().into(),
        ],
    ))
    .await
    .unwrap();
    let app = router(AppState::with_db(db));
    let invalid = app.clone().oneshot(
        Request::builder()
            .method(Method::POST)
            .uri("/developer/login")
            .header(header::ORIGIN, "http://127.0.0.1:3000")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"username":"operator","token":"wrong"}"#))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
    let response = app.clone().oneshot(
        Request::builder()
            .method(Method::POST)
            .uri("/developer/login")
            .header(header::ORIGIN, "http://127.0.0.1:3000")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(r#"{{"username":"operator","token":"{token}"}}"#)))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Strict"));
    let session = cookie.split(';').next().unwrap();
    let profile = app.clone().oneshot(
        Request::builder()
            .uri("/developer/clients")
            .header(header::COOKIE, session)
            .body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(profile.status(), StatusCode::OK);
    let logout = app.clone().oneshot(
        Request::builder()
            .method(Method::POST)
            .uri("/developer/logout")
            .header(header::ORIGIN, "http://127.0.0.1:3000")
            .header(header::COOKIE, session)
            .body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(logout.status(), StatusCode::OK);
    let rejected = app.oneshot(
        Request::builder()
            .uri("/developer/clients")
            .header(header::COOKIE, session)
            .body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
}
