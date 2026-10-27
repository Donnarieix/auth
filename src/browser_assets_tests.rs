use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use sea_orm::Database;
use tower::ServiceExt;

use crate::{router, schema, state::AppState};

#[tokio::test]
async fn browser_assets_have_javascript_mime_and_no_inline_script_policy() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    schema::apply(&db).await.unwrap();
    let app = router(AppState::with_db(db));
    let account = app.clone().oneshot(
        Request::builder().uri("/account").body(Body::empty()).unwrap()
    ).await.unwrap();
    assert_eq!(account.status(), StatusCode::OK);
    assert!(account.headers()["content-security-policy"].to_str().unwrap().contains("script-src 'self'"));
    let page = to_bytes(account.into_body(), 100_000).await.unwrap();
    let html = std::str::from_utf8(&page).unwrap();
    assert!(html.contains("src='/assets/account.js'"));
    assert!(!html.contains("<script>"));

    let js = app.oneshot(
        Request::builder().uri("/assets/account.js").body(Body::empty()).unwrap()
    ).await.unwrap();
    assert_eq!(js.status(), StatusCode::OK);
    assert_eq!(
        js.headers()[header::CONTENT_TYPE],
        "application/javascript; charset=utf-8"
    );
    let content = to_bytes(js.into_body(), 100_000).await.unwrap();
    assert!(std::str::from_utf8(&content).unwrap().contains("fetch(form.dataset.path"));
}
