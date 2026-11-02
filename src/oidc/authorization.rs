//! User-facing OIDC authorization. Browser sessions and explicit consent are
//! required; unregistered callbacks never receive redirects.
use axum::{
    Form,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use sea_orm::ModelTrait;
use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    entities::{session, user},
    oidc::{AuthorizationRequest, grants, validate_authorization_request},
    services::{client::get_client, session::get_session},
    state::AppState,
};

fn escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn error_page(status: StatusCode, message: &str) -> Response {
    let body = format!(
        r#"<section class="oauth-card oauth-error"><div class="oauth-step">Connexion interrompue</div><h1>Impossible de poursuivre</h1><p>{}</p><a class="button secondary" href="/account">Accéder à mon compte</a></section>"#,
        escape(message)
    );
    (status, crate::ui::render_authorization("Demande non valide", &body)).into_response()
}

fn permission_items(scope: &str) -> String {
    scope
        .split_whitespace()
        .map(|value| {
            let (title, description) = match value {
                "openid" => (
                    "Confirmer votre identité",
                    "Permettre à l'application de vous identifier.",
                ),
                "profile" => (
                    "Consulter votre profil",
                    "Accéder à votre nom affiché et votre photo de profil.",
                ),
                "email" => (
                    "Connaître votre adresse email",
                    "Accéder à votre adresse email et son état de vérification.",
                ),
                _ => (
                    "Permission supplémentaire",
                    "Accès spécifique demandé par cette application.",
                ),
            };
            format!(
                r#"<li class="oauth-scope"><span class="oauth-scope-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="m7 12 3 3 7-7"/><circle cx="12" cy="12" r="9"/></svg></span><div><strong>{title}</strong><span>{description}</span>{}</div></li>"#,
                if matches!(value, "openid" | "profile" | "email") {
                    String::new()
                } else {
                    format!("<code class=\"mono\">{}</code>", escape(value))
                }
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

async fn browser_session(
    state: &AppState,
    jar: &CookieJar,
) -> Option<(user::Model, session::Model)> {
    let cookie = jar.get(state.security.cookie_name())?;
    let digest = Sha256::digest(cookie.value().as_bytes());
    let session = get_session(state, digest.to_vec()).await.ok()??;
    if !session.active || session.expires_at <= chrono::Utc::now() {
        return None;
    }
    let account = session
        .find_related(user::Entity)
        .one(&state.db)
        .await
        .ok()??;
    if !account.active || !account.email_verified {
        return None;
    }
    Some((account, session))
}

fn redirect_with(
    redirect_uri: &str,
    key: &str,
    value: &str,
    state: &str,
) -> Result<Redirect, StatusCode> {
    let mut url = Url::parse(redirect_uri).map_err(|_| StatusCode::BAD_REQUEST)?;
    url.query_pairs_mut()
        .append_pair(key, value)
        .append_pair("state", state);
    Ok(Redirect::to(url.as_str()))
}

fn hidden(key: &str, value: &str) -> String {
    format!(
        "<input type='hidden' name='{}' value='{}'>",
        key,
        escape(value)
    )
}

fn hidden_request(req: &AuthorizationRequest) -> String {
    [
        hidden("response_type", &req.response_type),
        hidden("client_id", &req.client_id),
        hidden("redirect_uri", &req.redirect_uri),
        hidden("scope", &req.scope),
        req.resource.as_ref().map(|r| hidden("resource", r)).unwrap_or_default(),
        hidden("state", &req.state),
        hidden("nonce", &req.nonce),
        hidden("code_challenge", &req.code_challenge),
        hidden("code_challenge_method", &req.code_challenge_method),
    ]
    .join("\n")
}

/// GET is display-only. It never grants consent or issues codes.
pub async fn authorization_page(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(request): Query<AuthorizationRequest>,
) -> Response {
    if state.oidc_keys.is_none()
        || validate_authorization_request(&state.db, &request)
            .await
            .is_err()
    {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Demande de connexion non valide ou application inconnue.",
        );
    }
    let Some(app) = get_client(&state.db, &request.client_id)
        .await
        .ok()
        .flatten()
    else {
        return error_page(StatusCode::BAD_REQUEST, "Cette application n'est pas enregistrée.");
    };
    if app.client_type != "desktop"
        && (app.client_type != "web" || app.client_secret_hash.is_none())
    {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Cette application n'est pas correctement configurée.",
        );
    }
    let Ok(callback) = Url::parse(&request.redirect_uri) else {
        return error_page(StatusCode::BAD_REQUEST, "Adresse de retour non valide.");
    };
    let callback_origin = callback.origin().ascii_serialization();
    let callback_host = callback.host_str().unwrap_or("Application locale");
    let monogram = app
        .name
        .chars()
        .find(|character| character.is_alphanumeric())
        .unwrap_or('A')
        .to_uppercase()
        .collect::<String>();
    let app_name = escape(&app.name);
    let fields = hidden_request(&request);
    let permissions = permission_items(&request.scope);
    let resource_details = request
        .resource
        .as_ref()
        .map(|resource| format!(
            "<details class=\"oauth-resource\"><summary>Informations techniques</summary><p class=\"muted\">Service demandé : <code class=\"mono\">{}</code></p></details>",
            escape(resource)
        ))
        .unwrap_or_default();
    let identity = if let Some((account, _)) = browser_session(&state, &jar).await {
        let initial = account
            .display_name
            .as_deref()
            .unwrap_or(&account.username)
            .chars()
            .find(|character| character.is_alphanumeric())
            .unwrap_or('U')
            .to_uppercase()
            .collect::<String>();
        let label = escape(account.display_name.as_deref().unwrap_or(&account.username));
        format!(
            r#"<div class="oauth-identity"><span class="oauth-identity-avatar" aria-hidden="true">{initial}</span><div><strong>{label}</strong><small>Compte Donnarieix connecté</small></div></div>
<h2 class="oauth-permission-title">Cette application souhaite :</h2><ul class="oauth-scopes">{permissions}</ul>{resource_details}
<div class="oauth-destination">Après confirmation, vous retournerez vers <strong>{}</strong>.</div>
<div class="oauth-buttons"><form method="post" action="/authorize/approve">{fields}<button type="submit">Autoriser et continuer</button></form><form method="post" action="/authorize/deny">{fields}<button type="submit" class="secondary">Refuser l'accès</button></form></div>
<p class="oauth-disclaimer">Vous restez maître des accès : vous pourrez retirer cette autorisation depuis votre compte.</p>"#,
            escape(callback_host)
        )
    } else {
        format!(
            r#"<div class="oauth-login"><h2 class="oauth-login-heading">Connectez-vous pour continuer</h2><form id="oauth-login" novalidate><label>Adresse email<input name="email" type="email" inputmode="email" autocomplete="username" required placeholder="vous@exemple.fr"></label><label>Mot de passe<input name="password" type="password" autocomplete="current-password" required></label><button type="submit" class="oauth-login-submit">Se connecter</button></form><p class="oauth-status" id="oauth-status" role="status" aria-live="polite"></p><p class="oauth-login-options"><a href="/account" target="_blank" rel="noopener noreferrer">Créer un compte ou retrouver l'accès</a> · <span>La demande reste ouverte dans cet onglet.</span></p>
<details class="oauth-resource"><summary>Voir les autorisations demandées</summary><ul class="oauth-scopes">{permissions}</ul>{resource_details}</details></div>"#
        )
    };
    let body = format!(
        r#"<section class="oauth-card" aria-labelledby="oauth-title"><div class="oauth-intro"><div class="oauth-step">Connexion à une application</div><div class="oauth-app-mark" aria-hidden="true">{}</div><h1 id="oauth-title"><span class="oauth-app-name">{app_name}</span> souhaite accéder à votre compte</h1><p>Identifiez-vous et choisissez les informations que vous souhaitez partager.</p></div><div class="oauth-body">{identity}</div></section>"#,
        escape(&monogram)
    );
    let page = crate::ui::render_authorization("Connexion à une application", &body);
    // Native consent form submissions preserve the Origin for our strict CSRF
    // check, but never disclose query strings or PKCE parameters via Referrer.
    // Redirects after the form POST are allowed only to this validated client.
    let policy = format!(
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self' {callback_origin}; base-uri 'none'; frame-ancestors 'none'"
    );
    let Ok(policy) = axum::http::HeaderValue::from_str(&policy) else {
        return error_page(StatusCode::BAD_REQUEST, "Origine de retour non valide.");
    };
    (
        [
            (
                axum::http::header::CACHE_CONTROL,
                axum::http::HeaderValue::from_static("no-store"),
            ),
            (
                axum::http::header::REFERRER_POLICY,
                axum::http::HeaderValue::from_static("origin"),
            ),
            (axum::http::header::CONTENT_SECURITY_POLICY, policy),
        ],
        page,
    )

}

/// An approval is never inferred from an existing session or a GET request.
pub async fn approve(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(request): Form<AuthorizationRequest>,
) -> Response {
    if state.oidc_keys.is_none()
        || validate_authorization_request(&state.db, &request)
            .await
            .is_err()
    {
        return error_page(StatusCode::BAD_REQUEST, "Invalid authorization request.");
    }
    let Some((account, browser)) = browser_session(&state, &jar).await else {
        return error_page(StatusCode::UNAUTHORIZED, "Une session vérifiée est nécessaire.");
    };
    let Some(app) = get_client(&state.db, &request.client_id)
        .await
        .ok()
        .flatten()
    else {
        return error_page(StatusCode::BAD_REQUEST, "Cette application n'est pas enregistrée.");
    };
    if app.client_type != "desktop"
        && (app.client_type != "web" || app.client_secret_hash.is_none())
    {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Cette application n'est pas correctement configurée.",
        );
    }
    if crate::oidc::consent::approve(&state.db, account.id, app.id, &request.scope)
        .await
        .is_err()
    {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Impossible d'enregistrer votre autorisation.",
        );
    }
    match grants::issue(&state.db, &request, account.id, browser.id).await {
        Ok(code) => match redirect_with(&request.redirect_uri, "code", &code, &request.state) {
            Ok(response) => response.into_response(),
            Err(error) => error_page(error, "Adresse de retour non valide."),
        },
        Err(_) => error_page(
            StatusCode::BAD_REQUEST,
            "La demande de connexion a expiré ou n'est plus valide.",
        ),
    }
}

pub async fn deny(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(request): Form<AuthorizationRequest>,
) -> Response {
    if state.oidc_keys.is_none()
        || validate_authorization_request(&state.db, &request)
            .await
            .is_err()
        || browser_session(&state, &jar).await.is_none()
    {
        return error_page(StatusCode::BAD_REQUEST, "Invalid authorization request.");
    }
    match redirect_with(
        &request.redirect_uri,
        "error",
        "access_denied",
        &request.state,
    ) {
        Ok(response) => response.into_response(),
        Err(error) => error_page(error, "Adresse de retour non valide."),
    }
}
