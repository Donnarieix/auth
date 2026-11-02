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
    ([(header::CONTENT_SECURITY_POLICY, DEVELOPER_CSP)], Html(r####"<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><meta name="theme-color" content="#090d13"><title>Console développeur · Donnarieix Auth</title><link rel="icon" href="/assets/donnarieix-logo.svg" type="image/svg+xml"><link rel="stylesheet" href="/assets/developer-console.css"></head><body>
<div class="layout">
<aside class="sidebar">
<a href="/developer" class="brand"><img class="brand-logo" src="/assets/donnarieix-logo.svg" width="51" height="51" alt=""><span class="brand-text"><span class="brand-name">Donnarieix Auth</span><span class="brand-sub" style="display:block">Console développeur</span></span></a>
<nav class="side-nav" aria-label="Navigation développeur">
<a href="/developer" class="side-link selected" aria-current="page"><svg viewBox="0 0 24 24"><path d="m3 10 9-7 9 7v10h-7v-7h-4v7H3z"/></svg>Tableau de bord</a>
<a href="#applications" class="side-link"><svg viewBox="0 0 24 24"><path d="m12 2 9 5-9 5-9-5 9-5zm-9 5v10l9 5 9-5V7M12 12v10"/></svg>Applications</a>
<a href="#statistiques" class="side-link"><svg viewBox="0 0 24 24"><path d="M4 20V10m6 10V4m6 16v-8m4 8H2"/></svg>Statistiques</a>
<div class="side-divider"></div>
<a href="/account" class="side-link"><svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-8 16-8 16 0"/></svg>Mon compte SSO</a>
<a href="/.well-known/openid-configuration" class="side-link"><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11z"/></svg>Configuration OIDC</a>
</nav>
<img class="sidebar-mark" src="/assets/donnarieix-logo.svg" alt="" aria-hidden="true">
<div class="sidebar-bottom"><div class="environment"><span>◈</span> Environnement <strong>Test</strong></div></div>
</aside>
<div class="main">
<header class="topbar"><div><h1 class="page-title">Tableau de bord</h1><p class="subtitle">Gérez vos applications et les accès à Donnarieix Auth.</p></div><div class="top-actions"><a class="help" href="/.well-known/openid-configuration">ⓘ Aide</a><div class="account"><span id="account-avatar" class="avatar">D</span><span><span id="account-name" class="account-name">Développeur</span><span class="account-role" style="display:block">Administrateur</span></span></div><button type="button" class="action" id="logout-button" hidden>Déconnexion</button></div></header>
<main class="content">
<p id="notice" class="message" role="status" aria-live="polite"></p>
<div id="loading-view" class="loading">Chargement sécurisé de la console…</div>
<section id="signin-view" class="login-box" hidden aria-label="Connexion administrateur"><h2>Accès développeur</h2><p>Connectez-vous avec vos identifiants administrateur et votre second facteur, si activé.</p><form id="signin-form" class="login-form"><label>Identifiant<input type="text" name="username" autocomplete="username" required minlength="3" maxlength="32"></label><label>Clé administrateur<input type="password" name="token" autocomplete="current-password" required></label><label>Code TOTP (si activé)<input type="text" name="totp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6"></label><button type="submit" id="signin-submit" class="submit">Me connecter</button></form></section>
<div id="dashboard-view" hidden>
<section id="statistiques" class="metric-grid" aria-label="Statistiques">
<article class="metric"><div class="metric-icon"><svg viewBox="0 0 24 24"><path d="m12 2 9 5-9 5-9-5 9-5zm-9 5v10l9 5 9-5V7M12 12v10"/></svg></div><div><div class="metric-label">Applications</div><div id="metric-apps" class="metric-number">—</div><div id="metric-apps-note" class="metric-hint">Enregistrées</div></div></article>
<article class="metric"><div class="metric-icon blue"><svg viewBox="0 0 24 24"><circle cx="9" cy="8" r="3"/><path d="M2 20v-2c0-6 14-6 14 0v2M17 5a3 3 0 0 1 0 6m2 2c2 1 3 2 3 5v2"/></svg></div><div><div class="metric-label">Utilisateurs</div><div id="metric-users" class="metric-number">—</div><div class="metric-hint">Comptes actifs</div></div></article>
<article class="metric"><div class="metric-icon green"><svg viewBox="0 0 24 24"><circle cx="8" cy="15" r="4"/><path d="m11 12 9-9 2 2-3 3 1 2-3 3-2-1-3 3"/></svg></div><div><div class="metric-label">Jetons émis</div><div id="metric-tokens" class="metric-number">—</div><div class="metric-hint">Sept derniers jours</div></div></article>
<article class="metric"><div class="metric-icon"><svg viewBox="0 0 24 24"><rect x="4" y="3" width="16" height="18" rx="3"/><path d="M8 9h8m-8 5h8"/></svg></div><div><div class="metric-label">Sessions actives</div><div id="metric-sessions" class="metric-number">—</div><div class="metric-hint">Sessions utilisateur valides</div></div></article>
</section>
<div class="content-grid"><section class="panel" id="applications"><div class="panel-heading"><div class="panel-title"><svg viewBox="0 0 24 24"><path d="m12 2 9 5-9 5-9-5 9-5zm-9 5v10l9 5 9-5V7M12 12v10"/></svg><h2>Mes applications</h2></div><a href="/developer/new-client" class="inline-link">Créer</a></div>
<div class="app-tools"><input id="app-search" class="search" type="search" placeholder="Rechercher une application…" aria-label="Rechercher une application"><label class="filter"><input id="active-only" type="checkbox"> Actives uniquement</label></div>
<div class="table-wrap"><table class="data-table"><thead><tr><th>Nom</th><th>Type</th><th>Client ID</th><th>Statut</th><th>Action</th></tr></thead><tbody id="app-rows"></tbody></table></div></section>
<aside class="panel"><div class="panel-heading"><div class="panel-title"><svg viewBox="0 0 24 24"><path d="m13 2-9 12h7l-1 8 10-13h-7z"/></svg><h2>Actions rapides</h2></div></div><div class="action-list"><a class="action primary" href="/developer/new-client">＋ Créer une application</a><a class="action" href="/account">♙ Ouvrir mon compte</a><a class="action" href="/.well-known/openid-configuration">▤ Consulter la découverte OIDC</a><a class="action" href="/.well-known/jwks.json">⌘ Consulter les clés JWKS</a></div></aside></div>
<div class="content-grid"><section class="panel"><div class="panel-heading"><div class="panel-title"><svg viewBox="0 0 24 24"><path d="M8 6h13M8 12h13M8 18h13M2 6h2M2 12h2M2 18h2"/></svg><h2>Activités administratives récentes</h2></div></div><div id="audit-rows" class="audit-list"></div></section>
<aside class="panel"><div class="panel-heading"><div class="panel-title"><svg viewBox="0 0 24 24"><path d="M12 6C8 3 5 4 2 5v15c4-2 7-2 10 1 3-3 6-3 10-1V5c-3-1-6-2-10 1zm0 0v15"/></svg><h2>Ressources</h2></div></div><div><a class="resource-link" href="/.well-known/openid-configuration"><span><strong>Découverte OpenID Connect</strong><span>Configuration publique de l’émetteur</span></span><span class="arrow">↗</span></a><a class="resource-link" href="/.well-known/jwks.json"><span><strong>Clés de signature</strong><span>Clés publiques de vérification</span></span><span class="arrow">↗</span></a><a class="resource-link" href="/account/permissions"><span><strong>Autorisations utilisateur</strong><span>Consentements et révocations</span></span><span class="arrow">↗</span></a></div></aside></div>
</div>
</main></div></div><script src="/assets/developer-console.js" defer></script></body></html>"####))
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
    async fn overview_requires_developer_session() {
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        crate::schema::apply(&db).await.unwrap();
        let app = crate::router(AppState::with_db(db));
        let response = app.oneshot(Request::builder().uri("/developer/overview").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
