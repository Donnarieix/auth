//! Separate visual shells: personal identity, developer administration, and
//! isolated third-party consent. Never interpolate unescaped user data here.
use axum::response::Html;

const LOGO: &str = "/assets/donnarieix-logo.svg";

fn head(title: &str, description: &str, robots: &str, referrer: &str) -> String {
    format!(
        r##"<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#101722"><meta name="referrer" content="{referrer}"><meta name="robots" content="{robots}"><meta name="description" content="{description}"><title>{title} · Donnarieix Auth</title><link rel="icon" href="{LOGO}" type="image/svg+xml"><link rel="stylesheet" href="/assets/workspace.css">"##
    )
}

/// Account and developer portals are intentionally independent applications.
/// In particular the end-user navigation never exposes developer sign-in.
pub fn render(title: &str, area: &str, body: &str) -> Html<String> {
    let developer = area.starts_with("/developer");
    let legal = matches!(area, "/mentions-legales" | "/cgu" | "/confidentialite");
    let robots = if legal { "index,follow" } else { "noindex,nofollow" };
    let description = if legal {
        "Mentions légales, conditions d'utilisation et confidentialité du service Donnarieix Auth."
    } else {
        "Un seul compte pour les services Donnarieix : profil, connexion et autorisations."
    };
    let header = head(title, description, robots, "no-referrer");
    let menu = if developer {
        r#"<a href="/developer" class="nav-item" data-route="/developer">Applications</a><a href="/developer/new-client" class="nav-item" data-route="/developer/new-client">Nouvelle application</a>"#
    } else {
        r#"<a href="/account/profile" class="nav-item" data-auth-only hidden data-route="/account/profile">Mon profil</a><a href="/account/permissions" class="nav-item" data-auth-only hidden data-route="/account/permissions">Applications liées</a><a href="/account" class="nav-item" data-guest-only data-route="/account">Connexion</a>"#
    };
    let title_area = if developer { "Espace développeur" } else { "Espace personnel" };
    let header_actions = if developer {
        r#"<span class="portal-badge">Console technique</span>"#
    } else {
        r#"<button type="button" class="nav-signout" data-auth-logout hidden>Se déconnecter</button>"#
    };
    let foot = r#"<footer class="site-footer"><span>© Donnarieix Auth</span><nav aria-label="Informations légales"><a href="/mentions-legales">Mentions légales</a><a href="/confidentialite">Confidentialité</a><a href="/cgu">CGU</a><a href="mailto:auth@donnarieix.fr">Contact</a></nav></footer>"#;
    let html = if developer {
        format!(
            r#"<!doctype html><html lang="fr"><head>{header}</head><body class="workspace developer-workspace">
<div class="portal-layout">
<aside class="portal-sidebar"><a href="/developer" class="portal-brand"><img src="{LOGO}" alt="" width="44" height="44"><span>Donnarieix <b>Auth</b><small>Développeurs</small></span></a><div class="portal-section">INTÉGRATIONS</div><nav class="portal-links" aria-label="Navigation développeur">{menu}</nav><div class="portal-sidebar-note">Administration des applications et des accès techniques.</div></aside>
<div class="portal-main"><header class="portal-topbar"><div><span class="portal-kicker">{title_area}</span><h2>{title}</h2></div>{header_actions}</header><main class="page">{body}</main>{foot}</div></div>
<script src="/assets/workspace.js" defer></script></body></html>"#
        )
    } else {
        format!(
            r#"<!doctype html><html lang="fr"><head>{header}</head><body class="workspace identity-workspace">
<div class="identity-shell"><header class="identity-header"><a href="/account" class="identity-brand"><img src="{LOGO}" alt="" width="42" height="42"><span>Donnarieix <b>Auth</b><small>Votre identité, simplement.</small></span></a><nav class="identity-nav" aria-label="Navigation du compte">{menu}</nav><div class="identity-actions">{header_actions}<select aria-label="Apparence" data-theme-picker><option value="system">Système</option><option value="light">Clair</option><option value="dark">Sombre</option></select></div></header>
<main class="page" id="main-content">{body}</main>{foot}</div>
<script src="/assets/workspace.js" defer></script></body></html>"#
        )
    };
    Html(html)
}

/// Third-party authorization never renders portal navigation, developer links,
/// account settings, or a generic logged-in dashboard.
pub fn render_authorization(title: &str, body: &str) -> Html<String> {
    let header = head(
        title,
        "Connexion sécurisée et gestion des autorisations Donnarieix Auth.",
        "noindex,nofollow",
        "origin",
    );
    Html(format!(
        r#"<!doctype html><html lang="fr"><head>{header}</head><body class="workspace oauth-workspace"><div class="oauth-shell">
<header class="oauth-brand" aria-label="Donnarieix Auth"><img src="{LOGO}" alt="" width="43" height="43"><div><strong>Donnarieix Auth</strong><span>Service d'identité</span></div></header>
<main id="main-content" class="oauth-main">{body}</main>
<footer class="oauth-footer"><span>Une connexion protégée par Donnarieix Auth</span><nav aria-label="Informations légales"><a href="/confidentialite" target="_blank" rel="noopener noreferrer">Confidentialité</a><a href="/cgu" target="_blank" rel="noopener noreferrer">Conditions d'utilisation</a></nav></footer>
</div><script src="/assets/authorization.js" defer></script></body></html>"#
    ))
}

pub async fn stylesheet() -> impl axum::response::IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("assets/workspace.css"),
    )
}

pub async fn script() -> impl axum::response::IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("assets/workspace.js"),
    )
}

pub async fn authorization_script() -> impl axum::response::IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("assets/authorization.js"),
    )
}
