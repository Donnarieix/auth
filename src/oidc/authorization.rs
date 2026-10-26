//! User-facing OIDC authorization. Browser sessions and explicit consent are
//! required; unregistered callbacks never receive redirects.
use axum::{
    Form,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
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
    (status, Html(format!(
        "<!doctype html><html><head><meta charset='utf-8'><meta name='referrer' content='no-referrer'><title>Auth</title></head><body><h1>Donnarieix Auth</h1><p>{}</p></body></html>",
        escape(message)
    ))).into_response()
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
            "Invalid or unregistered authorization request.",
        );
    }
    let Some(app) = get_client(&state.db, &request.client_id)
        .await
        .ok()
        .flatten()
    else {
        return error_page(StatusCode::BAD_REQUEST, "Unregistered client.");
    };
    if app.client_type != "desktop" {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Only public native clients are supported.",
        );
    }
    let fields = hidden_request(&request);
    let details = format!(
        "<p>Application: <strong>{}</strong></p><p>Requested permissions: <code>{}</code></p>",
        escape(&app.name),
        escape(&request.scope),
    );
    let body = if let Some((account, _)) = browser_session(&state, &jar).await {
        format!(
            "{details}<p>Signed in as <strong>{}</strong>.</p><form method='post' action='/authorize/approve'>{fields}<button type='submit'>Allow this application</button></form><form method='post' action='/authorize/deny'>{fields}<button type='submit'>Deny</button></form>",
            escape(&account.username)
        )
    } else {
        // API login is a same-origin JSON endpoint. The browser sends the
        // Origin header and saves its host-only HttpOnly session cookie.
        format!(
            "{details}<p>Sign in with your verified email to approve access.</p><form id='login'><label>Email <input name='email' type='email' autocomplete='username' required></label><label>Password <input name='password' type='password' autocomplete='current-password' required></label><button>Sign in</button></form><p id='status' role='alert'></p><script>
document.getElementById('login').addEventListener('submit', async (event) => {{
 event.preventDefault();
 const form = new FormData(event.target);
 const response = await fetch('/login', {{method:'POST', headers:{{'Content-Type':'application/json'}}, credentials:'same-origin', body: JSON.stringify({{email: form.get('email'), password: form.get('password')}})}});
 if (response.ok) location.reload();
 else document.getElementById('status').textContent = 'Sign-in failed. Check credentials and email verification.';
}});
</script>"
        )
    };
    let page = format!(
        "<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='referrer' content='no-referrer'><meta name='viewport' content='width=device-width, initial-scale=1'><title>Donnarieix Auth</title></head><body><main><h1>Donnarieix Auth</h1>{body}</main></body></html>",
    );
    (
        [
            (axum::http::header::CACHE_CONTROL, "no-store"),
            (axum::http::header::REFERRER_POLICY, "no-referrer"),
        ],
        Html(page),
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
        return error_page(StatusCode::UNAUTHORIZED, "A verified session is required.");
    };
    let Some(app) = get_client(&state.db, &request.client_id)
        .await
        .ok()
        .flatten()
    else {
        return error_page(StatusCode::BAD_REQUEST, "Unregistered client.");
    };
    if app.client_type != "desktop" {
        return error_page(StatusCode::BAD_REQUEST, "Unsupported client type.");
    }
    if crate::oidc::consent::approve(&state.db, account.id, app.id, &request.scope)
        .await
        .is_err()
    {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not record consent.",
        );
    }
    match grants::issue(&state.db, &request, account.id, browser.id).await {
        Ok(code) => match redirect_with(&request.redirect_uri, "code", &code, &request.state) {
            Ok(response) => response.into_response(),
            Err(error) => error_page(error, "Invalid redirect URI."),
        },
        Err(_) => error_page(
            StatusCode::BAD_REQUEST,
            "Authorization request expired or invalid.",
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
        Err(error) => error_page(error, "Invalid redirect URI."),
    }
}
