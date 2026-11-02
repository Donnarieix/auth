//! Regression checks for the primary browser journeys and shared layout.
use axum::{body::{Body, to_bytes}, http::{Request, StatusCode}, Router};
use sea_orm::Database;
use tower::ServiceExt;
use crate::{router, schema, state::AppState};

async fn html_at(app: &Router, uri: &str) -> String {
    let response=app.clone().oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{uri}");
    let content_type=response.headers().get("content-type").unwrap().to_str().unwrap();
    assert!(content_type.starts_with("text/html"), "unexpected content-type for {uri}: {content_type}");
    String::from_utf8(to_bytes(response.into_body(),200_000).await.unwrap().to_vec()).unwrap()
}

#[tokio::test]
async fn every_browser_screen_has_the_brand_and_coherent_navigation() {
    let db=Database::connect("sqlite::memory:").await.unwrap();
    schema::apply(&db).await.unwrap();
    let app=router(AppState::with_db(db));
    for (url, expected) in [
        ("/account", "Se connecter à votre compte"),
        ("/account/profile", "Mon profil"),
        ("/account/permissions", "Applications connectées"),
        ("/developer", "Mes applications"),
        ("/developer/new-client", "Nouvelle application"),
        ("/developer/manage-client?client_id=missing", "Configuration de l'application"),
    ] {
        let html=html_at(&app,url).await;
        assert!(html.contains("/assets/donnarieix-logo.svg"), "missing logo on {url}");
        assert!(html.contains(expected), "missing page title/content on {url}");
    }
    let profile=html_at(&app,"/account/profile").await;
    assert!(profile.contains("href=\"/account/profile\" aria-current=\"page\""));
    let dashboard=html_at(&app,"/developer").await;
    assert!(!dashboard.contains("Taux d’erreur"));
    assert!(!dashboard.contains("Tableau de bord"));
    assert!(dashboard.contains("href=\"/developer/new-client\""));
}

#[tokio::test]
async fn application_setup_has_no_redundant_manual_client_lookup() {
    let db=Database::connect("sqlite::memory:").await.unwrap();
    schema::apply(&db).await.unwrap();
    let app=router(AppState::with_db(db));
    let create=html_at(&app,"/developer/new-client").await;
    assert!(create.contains("id=\"client-kind\""));
    assert!(create.contains("id=\"manage-created\""));
    let manage=html_at(&app,"/developer/manage-client?client_id=example").await;
    assert!(manage.contains("id=\"client_id\" type=\"hidden\""));
    assert!(!manage.contains("Charger la configuration"));
    assert!(manage.contains("id=\"web-secret\" hidden"));
    assert!(manage.contains("id=\"disable-section\""));
    let account=html_at(&app,"/account").await;
    assert!(!account.contains("data/outbox"));
    assert!(account.contains("Mot de passe oublié"));
}
