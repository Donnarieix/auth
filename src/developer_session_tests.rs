use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use sea_orm::{ConnectionTrait, Database, DbBackend, Statement};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

use crate::{router, schema, state::AppState};

async fn call(
    app: &Router,
    method: Method,
    path: &str,
    body: String,
    headers: &[(&str, &str)],
) -> Response {
    let mut request = Request::builder().method(method).uri(path);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    app.clone()
        .oneshot(request.body(Body::from(body)).unwrap())
        .await
        .unwrap()
}

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
    let headers = [
        ("origin", "http://127.0.0.1:3000"),
        ("content-type", "application/json"),
    ];
    let invalid = call(
        &app,
        Method::POST,
        "/developer/login",
        r#"{"username":"operator","token":"wrong"}"#.into(),
        &headers,
    )
    .await;
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
    let login = call(
        &app,
        Method::POST,
        "/developer/login",
        format!(r#"{{"username":"operator","token":"{token}"}}"#),
        &headers,
    )
    .await;
    assert_eq!(login.status(), StatusCode::OK);
    let cookie = login.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Strict"));
    let session = cookie.split(';').next().unwrap();
    let profile = call(
        &app,
        Method::GET,
        "/developer/clients",
        String::new(),
        &[("cookie", session)],
    )
    .await;
    assert_eq!(profile.status(), StatusCode::OK);
    let logout = call(
        &app,
        Method::POST,
        "/developer/logout",
        String::new(),
        &[("origin", "http://127.0.0.1:3000"), ("cookie", session)],
    )
    .await;
    assert_eq!(logout.status(), StatusCode::OK);
    let rejected = call(
        &app,
        Method::GET,
        "/developer/clients",
        String::new(),
        &[("cookie", session)],
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
}
