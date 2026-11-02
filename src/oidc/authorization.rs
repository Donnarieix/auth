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
    (status, crate::ui::render(
        "Demande non valide",
        "/account",
        &format!("<div class=\"page-heading\"><div class=\"eyebrow\">Authentification</div><h1>Cette demande ne peut pas aboutir.</h1></div><section class=\"panel\" style=\"max-width:600px\"><p>{}</p><a href=\"/account\">Retour au compte</a></section>", escape(message))
    )).into_response()
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
    let fields = hidden_request(&request);
    let resource_display = request.resource.as_deref().map(|resource| {
        format!("<p class=\"muted\">API concernée : <code>{}</code></p>", escape(resource))
    }).unwrap_or_default();
    let details = format!(
        "<h2>Autoriser {}</h2><p>Cette application demande les accès suivants : <code>{}</code>.</p>{resource_display}",
        escape(&app.name),
        escape(&request.scope),
    );
    let body = if let Some((account, _)) = browser_session(&state, &jar).await {
        format!(
            "{details}<p class='muted'>Compte utilisé : <strong>{}</strong>.</p><p class='muted'>Vous pouvez retirer cette autorisation depuis votre espace personnel.</p><div class='consent-actions'><form method='post' action='/authorize/approve'>{fields}<button type='submit'>Autoriser et continuer</button></form><form method='post' action='/authorize/deny'>{fields}<button class='secondary' type='submit'>Refuser</button></form></div>",
            escape(&account.username)
        )
    } else {
        // API login is a same-origin JSON endpoint. The browser sends the
        // Origin header and saves its host-only HttpOnly session cookie.
        format!(
            "{details}<p class='muted'>Connectez-vous pour choisir d'autoriser ou de refuser cette application. <a href=\'/account\'>Créer un compte ou retrouver l'accès</a>.</p><form id='login'><label>Adresse email <input name='email' type='email' autocomplete='username' required></label><label>Mot de passe <input name='password' type='password' autocomplete='current-password' required></label><button>Se connecter</button></form><p id='status' role='alert'></p><script>
document.getElementById('login').addEventListener('submit', async (event) => {{
 event.preventDefault();
 const form = new FormData(event.target);
 const response = await fetch('/login', {{method:'POST', headers:{{'Content-Type':'application/json'}}, credentials:'same-origin', body: JSON.stringify({{email: form.get('email'), password: form.get('password')}})}});
 if (response.ok) location.reload();
 else document.getElementById('status').textContent = 'Connexion refusée. Vérifiez vos identifiants et la confirmation de votre adresse email.';
}});
</script>"
        )
    };
    let page = crate::ui::render(
        "Autoriser l’accès",
        "/account",
        &format!(
            "<div class=\"page-heading\"><div class=\"eyebrow\">Autorisation de connexion</div><h1>Confirmation d'accès</h1><p class=\"lead\">Vérifiez le nom de l'application et les données demandées avant de continuer.</p></div><section class=\"panel\" style=\"max-width:680px\">{body}</section>"
        ),
    );
    // On a native HTML form POST, no-referrer can cause Origin: null.
    // Only disclose the origin (never the sensitive authorization URL).
    // The origin check remains strict on /authorize/approve and /deny.
    let mut page = page;
    page.0 = page.0.replace(
        "name=\"referrer\" content=\"no-referrer\"",
        "name=\"referrer\" content=\"origin\"",
    );
    // A form POST to /authorize/approve responds with a 303 to the registered
    // callback. Browsers may apply form-action to the entire redirect chain.
    // Permit only this validated client's origin, not arbitrary destinations.
    let Ok(callback) = Url::parse(&request.redirect_uri) else {
        return error_page(StatusCode::BAD_REQUEST, "Adresse de retour non valide.");
    };
    let origin = callback.origin().ascii_serialization();
    let policy = format!(
        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src https: 'self'; connect-src 'self'; form-action 'self' {origin}; base-uri 'none'; frame-ancestors 'none'"
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
        .into_response()
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
