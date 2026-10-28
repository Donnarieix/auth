use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use sea_orm::{ConnectionTrait, Database, DbBackend, Statement};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

use crate::{
    router, schema,
    services::client::{ClientType, register_client},
    state::AppState,
};

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
    let inspect_db = db.clone();
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
    let create_payload = r#"{"name":"Desktop Test","client_type":"desktop","redirect_uris":["http://127.0.0.1:44888/callback"]}"#;
    let blocked = call(
        &app,
        Method::POST,
        "/developer/clients",
        create_payload.into(),
        &[
            ("origin", "http://127.0.0.1:3000"),
            ("content-type", "application/json"),
        ],
    )
    .await;
    assert_eq!(blocked.status(), StatusCode::UNAUTHORIZED);
    let created = call(
        &app,
        Method::POST,
        "/developer/clients",
        create_payload.into(),
        &[
            ("origin", "http://127.0.0.1:3000"),
            ("content-type", "application/json"),
            ("cookie", session),
        ],
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let audit = inspect_db
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT id FROM developer_admin_events WHERE event_type LIKE 'client_created:%'",
        ))
        .await
        .unwrap();
    assert!(audit.is_some());
    let client_row = inspect_db
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT client_id FROM clients WHERE name = 'Desktop Test'",
        ))
        .await
        .unwrap()
        .unwrap();
    let client_id: String = client_row.try_get("", "client_id").unwrap();
    let updated_redirect = call(
        &app,
        Method::POST,
        &format!("/developer/clients/{client_id}/redirects"),
        r#"{"redirect_uris":["http://127.0.0.1:44999/return"]}"#.into(),
        &[
            ("origin", "http://127.0.0.1:3000"),
            ("content-type", "application/json"),
            ("cookie", session),
        ],
    )
    .await;
    assert_eq!(updated_redirect.status(), StatusCode::NO_CONTENT);
    let desktop_rotation = call(
        &app,
        Method::POST,
        &format!("/developer/clients/{client_id}/secret"),
        format!(r#"{{"administrator_token":"{token}"}}"#),
        &[
            ("origin", "http://127.0.0.1:3000"),
            ("content-type", "application/json"),
            ("cookie", session),
        ],
    )
    .await;
    assert_eq!(desktop_rotation.status(), StatusCode::NOT_FOUND);
    let web_id = register_client(
        &inspect_db,
        "Confidential Web",
        ClientType::Web,
        &["https://web.example.test/callback".to_owned()],
    )
    .await
    .unwrap();
    let incorrect_rotation = call(
        &app,
        Method::POST,
        &format!("/developer/clients/{web_id}/secret"),
        r#"{"administrator_token":"invalid"}"#.into(),
        &[
            ("origin", "http://127.0.0.1:3000"),
            ("content-type", "application/json"),
            ("cookie", session),
        ],
    )
    .await;
    assert_eq!(incorrect_rotation.status(), StatusCode::UNAUTHORIZED);
    let rotated = call(
        &app,
        Method::POST,
        &format!("/developer/clients/{web_id}/secret"),
        format!(r#"{{"administrator_token":"{token}"}}"#),
        &[
            ("origin", "http://127.0.0.1:3000"),
            ("content-type", "application/json"),
            ("cookie", session),
        ],
    )
    .await;
    assert_eq!(rotated.status(), StatusCode::OK);
    let rotation_data = to_bytes(rotated.into_body(), 2048).await.unwrap();
    let secret: serde_json::Value = serde_json::from_slice(&rotation_data).unwrap();
    assert_eq!(secret["client_secret"].as_str().unwrap().len(), 43);
    let unauthorized_disable = call(
        &app,
        Method::POST,
        &format!("/developer/clients/{client_id}/disable"),
        String::new(),
        &[("origin", "http://127.0.0.1:3000")],
    )
    .await;
    assert_eq!(unauthorized_disable.status(), StatusCode::UNAUTHORIZED);
    let disabled = call(
        &app,
        Method::POST,
        &format!("/developer/clients/{client_id}/disable"),
        String::new(),
        &[("origin", "http://127.0.0.1:3000"), ("cookie", session)],
    )
    .await;
    assert_eq!(disabled.status(), StatusCode::OK);
    let disabled_again = call(
        &app,
        Method::POST,
        &format!("/developer/clients/{client_id}/disable"),
        String::new(),
        &[("origin", "http://127.0.0.1:3000"), ("cookie", session)],
    )
    .await;
    assert_eq!(disabled_again.status(), StatusCode::NOT_FOUND);
    let disable_audit = inspect_db
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT id FROM developer_admin_events WHERE event_type LIKE 'client_disabled:%'",
        ))
        .await
        .unwrap();
    assert!(disable_audit.is_some());
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

#[tokio::test]
async fn rotated_or_expired_admin_sessions_cannot_access_clients() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    schema::apply(&db).await.unwrap();
    let admin = Uuid::new_v4();
    let token = "R".repeat(43);
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "INSERT INTO developer_administrators(id, username, token_hash, created_at, active) VALUES (?, ?, ?, ?, 1)",
        [
            admin.to_string().into(),
            "operator".to_owned().into(),
            Sha256::digest(token.as_bytes()).to_vec().into(),
            chrono::Utc::now().to_rfc3339().into(),
        ],
    ))
    .await
    .unwrap();
    let app = router(AppState::with_db(db.clone()));
    let login = call(
        &app,
        Method::POST,
        "/developer/login",
        format!(r#"{{"username":"operator","token":"{token}"}}"#),
        &[
            ("origin", "http://127.0.0.1:3000"),
            ("content-type", "application/json"),
        ],
    )
    .await;
    assert_eq!(login.status(), StatusCode::OK);
    let cookie = login.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let profile = call(
        &app,
        Method::GET,
        "/developer/clients",
        String::new(),
        &[("cookie", &cookie)],
    )
    .await;
    assert_eq!(profile.status(), StatusCode::OK);

    // A trusted operator rotates the root credential. SQLite's migration
    // trigger must revoke all previously issued developer sessions.
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "UPDATE developer_administrators SET token_hash = ? WHERE id = ?",
        [
            Sha256::digest(b"new-operator-credential").to_vec().into(),
            admin.to_string().into(),
        ],
    ))
    .await
    .unwrap();
    let revoked = call(
        &app,
        Method::GET,
        "/developer/clients",
        String::new(),
        &[("cookie", &cookie)],
    )
    .await;
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
    let count = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT COUNT(*) AS count FROM developer_sessions WHERE administrator_id = ? AND revoked = 1",
            [admin.to_string().into()],
        ))
        .await
        .unwrap()
        .unwrap();
    let revoked_count: i64 = count.try_get("", "count").unwrap();
    assert_eq!(revoked_count, 1);

    // Even if the revoked bit is cleared, an expired session stays denied.
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "UPDATE developer_sessions SET revoked = 0, expires_at = ? WHERE administrator_id = ?",
        [
            (chrono::Utc::now() - chrono::Duration::hours(1))
                .to_rfc3339()
                .into(),
            admin.to_string().into(),
        ],
    ))
    .await
    .unwrap();
    let expired = call(
        &app,
        Method::GET,
        "/developer/clients",
        String::new(),
        &[("cookie", &cookie)],
    )
    .await;
    assert_eq!(expired.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn developer_login_throttling_cannot_be_bypassed_by_username_case() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    schema::apply(&db).await.unwrap();
    let app = router(AppState::with_db(db));
    let headers = [
        ("origin", "http://127.0.0.1:3000"),
        ("content-type", "application/json"),
    ];
    for attempt in 0..6 {
        let username = if attempt % 2 == 0 {
            "Operator"
        } else {
            "operator"
        };
        let response = call(
            &app,
            Method::POST,
            "/developer/login",
            format!(
                r#"{{"username":"{username}","token":"{}"}}"#,
                "X".repeat(43)
            ),
            &headers,
        )
        .await;
        assert_eq!(
            response.status(),
            if attempt == 5 {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::UNAUTHORIZED
            },
        );
    }
}
