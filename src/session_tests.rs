use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use chrono::Utc;
use sea_orm::{Database, EntityTrait, QueryFilter, sea_query::Expr};
use tower::ServiceExt;

use crate::{
    entities::{session, user},
    router, schema,
    state::AppState,
};

async fn test_app() -> (Router, AppState) {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    schema::apply(&db).await.unwrap();
    let state = AppState::with_db(db);
    (router(state.clone()), state)
}

async fn request(
    app: &Router,
    method: Method,
    path: &str,
    body: &str,
    cookie: Option<&str>,
    origin: Option<&str>,
    fetch_site: Option<&str>,
) -> Response {
    let mut builder = Request::builder().method(method).uri(path);
    builder = builder.header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some(origin) = origin {
        builder = builder.header(header::ORIGIN, origin);
    }
    if let Some(fetch_site) = fetch_site {
        builder = builder.header("sec-fetch-site", fetch_site);
    }
    app.clone()
        .oneshot(builder.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap()
}

async fn post(app: &Router, path: &str, body: &str, cookie: Option<&str>) -> Response {
    request(
        app,
        Method::POST,
        path,
        body,
        cookie,
        Some("http://127.0.0.1:3000"),
        Some("same-origin"),
    )
    .await
}

async fn register(app: &Router) {
    assert_eq!(
        post(
            app,
            "/register",
            r#"{"email":"known@example.com","username":"known","password":"Secure password 123!"}"#,
            None,
        )
        .await
        .status(),
        StatusCode::ACCEPTED
    );
}

async fn login(app: &Router) -> String {
    let response = post(
        app,
        "/login",
        r#"{"email":"known@example.com","password":"Secure password 123!"}"#,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(cookie.starts_with("auth_session="));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Lax"));
    assert!(cookie.contains("Path=/"));
    assert!(cookie.contains("Max-Age=3600"));
    assert!(!cookie.contains("Domain="));
    assert!(!cookie.contains("Secure")); // HTTP loopback only
    cookie.split(';').next().unwrap().to_owned()
}

#[tokio::test]
async fn origins_are_required_for_all_mutations_and_safe_reads_still_work() {
    let (app, state) = test_app().await;
    assert_eq!(
        request(
            &app,
            Method::POST,
            "/register",
            r#"{"email":"known@example.com","username":"known","password":"Secure password 123!"}"#,
            None,
            None,
            None,
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            &app,
            Method::POST,
            "/register",
            "{}",
            None,
            Some("http://evil.example"),
            Some("cross-site"),
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            &app,
            Method::POST,
            "/login",
            "{}",
            None,
            Some("http://127.0.0.1:3000"),
            Some("cross-site"),
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            &app,
            Method::POST,
            "/password/reset/request",
            "{}",
            None,
            None,
            None
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&app, Method::GET, "/health", "", None, None, None)
            .await
            .status(),
        StatusCode::OK
    );
    assert!(user::Entity::find().one(&state.db).await.unwrap().is_none());
}

#[tokio::test]
async fn logging_out_revokes_only_the_current_browser_session() {
    let (app, state) = test_app().await;
    register(&app).await;
    let first = login(&app).await;
    let second = login(&app).await;
    assert_ne!(first, second);
    assert_eq!(
        request(&app, Method::GET, "/me", "", Some(&first), None, None)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        request(&app, Method::GET, "/me", "", Some(&second), None, None)
            .await
            .status(),
        StatusCode::OK
    );

    // A cross-site logout cannot revoke a valid session.
    assert_eq!(
        request(
            &app,
            Method::POST,
            "/logout",
            "",
            Some(&first),
            Some("https://evil.example"),
            Some("cross-site"),
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&app, Method::GET, "/me", "", Some(&first), None, None)
            .await
            .status(),
        StatusCode::OK
    );

    let response = post(&app, "/logout", "", Some(&first)).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let cleared = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(cleared.contains("auth_session="));
    assert!(cleared.contains("Max-Age=0"));
    assert_eq!(
        request(&app, Method::GET, "/me", "", Some(&first), None, None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(&app, Method::GET, "/me", "", Some(&second), None, None)
            .await
            .status(),
        StatusCode::OK
    );

    let all = session::Entity::find().all(&state.db).await.unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all.iter().filter(|record| record.active).count(), 1);
}

#[tokio::test]
async fn expired_sessions_are_rejected_and_revoked() {
    let (app, state) = test_app().await;
    register(&app).await;
    let cookie = login(&app).await;

    session::Entity::update_many()
        .col_expr(
            session::COLUMN.expires_at,
            Expr::value(Utc::now() - chrono::Duration::seconds(1)),
        )
        .exec(&state.db)
        .await
        .unwrap();
    assert_eq!(
        request(&app, Method::GET, "/me", "", Some(&cookie), None, None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let after = session::Entity::find()
        .one(&state.db)
        .await
        .unwrap()
        .unwrap();
    assert!(!after.active);
}

#[tokio::test]
async fn disabling_a_user_revokes_existing_sessions_even_after_reactivation() {
    let (app, state) = test_app().await;
    register(&app).await;
    let first = login(&app).await;
    let second = login(&app).await;
    let account = user::Entity::find().one(&state.db).await.unwrap().unwrap();

    user::Entity::update_many()
        .col_expr(user::COLUMN.active, Expr::value(false))
        .filter(user::COLUMN.id.eq(account.id))
        .exec(&state.db)
        .await
        .unwrap();
    assert_eq!(
        request(&app, Method::GET, "/me", "", Some(&first), None, None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(&app, Method::GET, "/me", "", Some(&second), None, None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post(
            &app,
            "/login",
            r#"{"email":"known@example.com","password":"Secure password 123!"}"#,
            None
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );

    user::Entity::update_many()
        .col_expr(user::COLUMN.active, Expr::value(true))
        .filter(user::COLUMN.id.eq(account.id))
        .exec(&state.db)
        .await
        .unwrap();
    // Re-enabling does not resurrect sessions revoked at deactivation.
    assert_eq!(
        request(&app, Method::GET, "/me", "", Some(&first), None, None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let all = session::Entity::find().all(&state.db).await.unwrap();
    assert!(all.iter().all(|record| !record.active));
    let _new_session = login(&app).await;
}
