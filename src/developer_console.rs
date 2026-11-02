//! Authenticated graphite developer dashboard with original Donnarieix brand.
use axum::{extract::State, http::{header, StatusCode}, response::{Html, IntoResponse}};
use axum_extra::extract::CookieJar;
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use serde::Serialize;
use crate::{developer_session::authenticated_cookie, state::AppState};

const LOGO: &str = include_str!("assets/donnarieix-logo.svg");
const CSS: &str = include_str!("assets/developer-console.css");
const JS: &str = include_str!("assets/developer-console.js");

// The dashboard loads external first-party assets, unlike the older inline UI.
// Scope the policy to this HTML response; do not relax CSP for OIDC or account
// pages. Inline attributes currently used for presentation still need styles.
const DEVELOPER_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

pub async fn logo() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "image/svg+xml; charset=utf-8"), (header::CACHE_CONTROL, "public, max-age=3600")], LOGO)
}
pub async fn styles() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], CSS)
}
pub async fn script() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], JS)
}
pub async fn page() -> impl IntoResponse {
    (
        [(header::CONTENT_SECURITY_POLICY, DEVELOPER_CSP)],
        Html(r####"<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><meta name="theme-color" content="#090d13"><title>Applications · Donnarieix Auth</title><link rel="icon" href="/assets/donnarieix-logo.svg" type="image/svg+xml"><link rel="stylesheet" href="/assets/developer-console.css"></head><body>
<div class="layout">
<aside class="sidebar">
<a href="/developer" class="brand"><img class="brand-logo" src="/assets/donnarieix-logo.svg" width="51" height="51" alt=""><span class="brand-text"><span class="brand-name">Donnarieix Auth</span><span class="brand-sub" style="display:block">Console développeur</span></span></a>
<nav class="side-nav" aria-label="Navigation développeur">
<a href="/developer" class="side-link selected" aria-current="page"><svg viewBox="0 0 24 24"><path d="m12 2 9 5-9 5-9-5 9-5zm-9 5v10l9 5 9-5V7M12 12v10"/></svg>Applications</a>
<div class="side-divider"></div>
<a href="/account/profile" class="side-link"><svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-8 16-8 16 0"/></svg>Mon profil SSO</a>
<a href="/account/permissions" class="side-link"><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11z"/></svg>Mes autorisations</a>
</nav>
<div class="sidebar-bottom"><div class="environment"><span>◈</span> Espace distinct du compte SSO</div></div>
</aside>
<div class="main">
<header class="topbar"><div><h1 class="page-title">Applications</h1><p class="subtitle">Vos intégrations OpenID Connect au même endroit.</p></div><div class="top-actions"><div class="account" id="account-info" hidden><span id="account-avatar" class="avatar">D</span><span><span id="account-name" class="account-name">Développeur</span><span class="account-role" style="display:block">Administrateur</span></span></div><button type="button" class="action" id="logout-button" hidden>Déconnexion</button></div></header>
<main class="content">
<p id="notice" class="message" role="status" aria-live="polite"></p>
<div id="loading-view" class="loading">Chargement sécurisé…</div>
<section id="signin-view" class="login-box" hidden aria-label="Connexion administrateur">
<h2>Connexion développeur</h2><p>Cet accès est indépendant de votre session SSO habituelle.</p>
<form id="signin-form" class="login-form"><label>Identifiant<input type="text" name="username" autocomplete="username" required minlength="3" maxlength="32"></label><label>Clé administrateur<input type="password" name="token" autocomplete="current-password" required></label><label>Code de vérification TOTP (si activé)<input type="text" name="totp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6"></label><button type="submit" id="signin-submit" class="submit">Se connecter</button></form></section>
<div id="dashboard-view" hidden>
<div class="content-header"><div><h2>Mes applications</h2><p class="muted" id="app-summary">Chargement…</p></div><a href="/developer/new-client" class="action primary">＋ Nouvelle application</a></div>
<section class="panel" id="applications" aria-label="Applications enregistrées">
<div class="app-tools"><input id="app-search" class="search" type="search" placeholder="Rechercher par nom ou identifiant…" aria-label="Rechercher une application"><label class="filter"><input id="active-only" type="checkbox"> Actives uniquement</label></div>
<div class="table-wrap"><table class="data-table"><thead><tr><th>Application</th><th>Type</th><th>Identifiant client</th><th>Statut</th><th>Actions</th></tr></thead><tbody id="app-rows"></tbody></table></div>
<p class="metric-hint" style="margin:17px 2px 0">Les URI de retour et les secrets web se configurent dans chaque application.</p>
</section>
</div>
</main>
</div></div>
<script src="/assets/developer-console.js" defer></script></body></html>"####)
    )
}

#[derive(Serialize)]
pub struct Overview {
    administrator: String,
    applications: i64,
    active_applications: i64,
    users: i64,
    tokens_7d: i64,
    active_sessions: i64,
    recent_events: Vec<AdminEvent>,
}
#[derive(Serialize)]
pub struct AdminEvent {
    event_type: String,
    created_at: String,
}
async fn count(state: &AppState, sql: &str) -> Result<i64, StatusCode> {
    let row = state.db.query_one_raw(Statement::from_string(DbBackend::Sqlite, sql.to_owned()))
        .await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    row.try_get("", "n").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
pub async fn overview(State(state): State<AppState>, jar: CookieJar)
    -> Result<axum::Json<Overview>, StatusCode> {
    let actor = authenticated_cookie(&state, &jar).await.ok_or(StatusCode::UNAUTHORIZED)?;
    let row = state.db.query_one_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "SELECT username FROM developer_administrators WHERE id = ? AND active = 1",
        [actor.to_string().into()],
    )).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let administrator: String = row.try_get("", "username")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let applications = count(&state, "SELECT COUNT(*) AS n FROM clients").await?;
    let active_applications = count(&state, "SELECT COUNT(*) AS n FROM clients WHERE active = 1").await?;
    let users = count(&state, "SELECT COUNT(*) AS n FROM users WHERE active = 1").await?;
    let tokens_7d = count(&state, "SELECT COUNT(*) AS n FROM oidc_access_tokens WHERE created_at >= datetime('now', '-7 days')").await?;
    let active_sessions = count(&state, "SELECT COUNT(*) AS n FROM sessions WHERE active = 1 AND expires_at > strftime('%Y-%m-%dT%H:%M:%SZ','now')").await?;
    let rows = state.db.query_all_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "SELECT event_type, created_at FROM developer_admin_events WHERE administrator_id = ? ORDER BY created_at DESC LIMIT 5",
        [actor.to_string().into()],
    )).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let recent_events = rows.into_iter().map(|r| Ok(AdminEvent {
        event_type: r.try_get("", "event_type").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        created_at: r.try_get("", "created_at").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    })).collect::<Result<Vec<_>, StatusCode>>()?;
    Ok(axum::Json(Overview { administrator, applications, active_applications, users, tokens_7d, active_sessions, recent_events }))
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    #[tokio::test]
    async fn console_csp_permits_first_party_files_and_blocks_inline_scripts() {
        use axum::{body::to_bytes, http::header};
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        crate::schema::apply(&db).await.unwrap();
        let app = crate::router(AppState::with_db(db));
        let page = app.clone().oneshot(Request::builder()
            .uri("/developer").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(page.status(), StatusCode::OK);
        let csp = page.headers()[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
        assert_eq!(csp, DEVELOPER_CSP);
        assert!(csp.contains("default-src 'none'"));
        assert!(csp.contains("script-src 'self'"));
        assert!(csp.contains("style-src 'self'"));
        assert!(!csp.contains("script-src 'unsafe-inline'"));
        let html = to_bytes(page.into_body(), 200_000).await.unwrap();
        let html = String::from_utf8(html.to_vec()).unwrap();
        assert!(html.contains("href=\"/assets/developer-console.css\""));
        assert!(html.contains("src=\"/assets/developer-console.js\""));

        for (path, media_type) in [
            ("/assets/developer-console.js", "text/javascript; charset=utf-8"),
            ("/assets/developer-console.css", "text/css; charset=utf-8"),
            ("/assets/donnarieix-logo.svg", "image/svg+xml; charset=utf-8"),
        ] {
            let response = app.clone().oneshot(Request::builder()
                .uri(path).body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(response.headers()[header::CONTENT_TYPE], media_type, "{path}");
            assert!(!to_bytes(response.into_body(), 100_000).await.unwrap().is_empty(), "{path}");
        }
        // The legacy inline UIs keep their existing CSP, not the new policy.
        let legacy = app.oneshot(Request::builder()
            .uri("/account").body(Body::empty()).unwrap()).await.unwrap();
        assert!(legacy.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str().unwrap().contains("script-src 'self' 'unsafe-inline'"));
    }

    #[tokio::test]
    async fn overview_requires_developer_session() {
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        crate::schema::apply(&db).await.unwrap();
        let app = crate::router(AppState::with_db(db));
        let response = app.oneshot(Request::builder().uri("/developer/overview").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
