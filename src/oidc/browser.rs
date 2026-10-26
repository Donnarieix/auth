//! Browser-facing OIDC authorization and consent.
//! The browser never directly receives tokens; only a short-lived code is
//! returned to a pre-registered redirect URI.
use axum::{
    Form,
    extract::{Query, State},
    http::{StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use chrono::Utc;
use sea_orm::{EntityTrait, ModelTrait};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    entities::{session, user},
    oidc::{AuthorizationRequest, consent, grants, validate_authorization_request},
    services::{
        client::get_client,
        password::{self, DUMMY_HASH},
        session::{create_session, get_session},
        user::{get_password_credential, get_user_by_email},
    },
    state::AppState,
};

#[derive(Deserialize)]
pub struct LoginAction {
    #[serde(flatten)]
    request: AuthorizationRequest,
    email: String,
    password: String,
}

#[derive(Deserialize)]
pub struct ConsentAction {
    #[serde(flatten)]
    request: AuthorizationRequest,
    decision: String,
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn hidden(request: &AuthorizationRequest) -> String {
    let values = [
        ("response_type", request.response_type.as_str()),
        ("client_id", request.client_id.as_str()),
        ("redirect_uri", request.redirect_uri.as_str()),
        ("scope", request.scope.as_str()),
        ("state", request.state.as_str()),
        ("nonce", request.nonce.as_str()),
        ("code_challenge", request.code_challenge.as_str()),
        (
            "code_challenge_method",
            request.code_challenge_method.as_str(),
        ),
    ];
    values
        .iter()
        .map(|(name, value)| {
            format!(
                "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
                name,
                escape(value)
            )
        })
        .collect::<String>()
}

fn query(request: &AuthorizationRequest) -> String {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair("response_type", &request.response_type);
    form.append_pair("client_id", &request.client_id);
    form.append_pair("redirect_uri", &request.redirect_uri);
    form.append_pair("scope", &request.scope);
    form.append_pair("state", &request.state);
    form.append_pair("nonce", &request.nonce);
    form.append_pair("code_challenge", &request.code_challenge);
    form.append_pair("code_challenge_method", &request.code_challenge_method);
    format!("/authorize?{}", form.finish())
}

fn document(body: &str) -> Response {
    let html = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>Donnarieix Auth</title>
<style>
:root {{color-scheme:dark;font-family:system-ui,sans-serif}}
body {{margin:0;background:#101727;color:#f2f6ff;min-height:100vh;display:grid;place-items:center}}
main {{width:min(430px,90vw);padding:30px;border:1px solid #34465e;background:#1b293d;border-radius:18px}}
h1 {{font-size:24px}}p {{line-height:1.6;color:#c8d5e5}}
label {{display:block;margin-top:15px}}input:not([type=hidden]) {{display:block;box-sizing:border-box;width:100%;padding:10px;border-radius:7px;margin-top:5px}}
button {{background:#a7ceff;border:0;border-radius:9px;padding:12px 16px;color:#102037;font-weight:bold;cursor:pointer;margin-top:20px}}
.secondary {{background:#63768b;color:white;margin-left:8px}}
</style></head><body><main>{body}</main></body></html>"#
    );
    (
        [(header::CACHE_CONTROL, "no-store"),
         (header::REFERRER_POLICY, "no-referrer"),
         (header::X_FRAME_OPTIONS, "DENY"),
         (header::CONTENT_SECURITY_POLICY,
          "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")],
        Html(html),
    ).into_response()
}

fn bad_request() -> Response {
    (
        StatusCode::BAD_REQUEST,
        document(
            "<h1>Invalid authorization request</h1><p>The client parameters were rejected.</p>",
        ),
    )
        .into_response()
}

async fn browser(state: &AppState, jar: &CookieJar) -> Option<(user::Model, session::Model)> {
    let raw = jar.get(state.security.cookie_name())?.value();
    if raw.len() != 43 {
        return None;
    }
    let hashed = Sha256::digest(raw.as_bytes()).to_vec();
    let session = get_session(state, hashed).await.ok()??;
    if !session.active || session.expires_at <= Utc::now() {
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

pub async fn authorize(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(request): Query<AuthorizationRequest>,
) -> Response {
    if validate_authorization_request(&state.db, &request)
        .await
        .is_err()
    {
        return bad_request();
    }
    let Some((account, _session)) = browser(&state, &jar).await else {
        let body = format!(
            "<h1>Sign in to Donnarieix</h1><p>Sign in to review what this application is requesting. A verified email address is required.</p>
<form method=\"post\" action=\"/authorize/login\">{}
<label>Email<input type=\"email\" name=\"email\" autocomplete=\"username\" required></label>
<label>Password<input type=\"password\" name=\"password\" autocomplete=\"current-password\" required></label>
<button type=\"submit\">Sign in</button></form>",
            hidden(&request)
        );
        return document(&body);
    };
    let Some(app) = get_client(&state.db, &request.client_id)
        .await
        .ok()
        .flatten()
    else {
        return bad_request();
    };
    let body = format!(
        "<h1>Authorize {}</h1><p>Signed in as <strong>{}</strong>. This application is requesting:</p>
<p><strong>{}</strong></p><p>Only approve if you trust this application.</p>
<form method=\"post\" action=\"/authorize/consent\">{}
<button type=\"submit\" name=\"decision\" value=\"approve\">Approve</button>
<button class=\"secondary\" type=\"submit\" name=\"decision\" value=\"deny\">Deny</button></form>",
        escape(&app.name), escape(&account.username), escape(&request.scope), hidden(&request)
    );
    document(&body)
}

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(action): Form<LoginAction>,
) -> Response {
    if validate_authorization_request(&state.db, &action.request)
        .await
        .is_err()
    {
        return bad_request();
    }
    let Some(email) = crate::services::identity::normalize_email(&action.email) else {
        return (
            StatusCode::UNAUTHORIZED,
            document("<h1>Unable to sign in</h1><p>Invalid credentials or unverified account.</p>"),
        )
            .into_response();
    };
    if action.password.len() > 512
        || action.password.is_empty()
        || !state.abuse.allow("oidc_login", &email, 80, 10).await
    {
        return (
            StatusCode::UNAUTHORIZED,
            document("<h1>Unable to sign in</h1><p>Invalid credentials or unverified account.</p>"),
        )
            .into_response();
    }
    let account = match get_user_by_email(&state, &email).await {
        Ok(a) => a,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let credential = match &account {
        Some(a) => match get_password_credential(&state, a.id).await {
            Ok(c) => c,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        },
        None => None,
    };
    let hash = credential
        .map(|v| v.password_hash)
        .unwrap_or_else(|| DUMMY_HASH.into());
    let valid = match password::verify(&state, action.password, hash).await {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let Some(account) = account.filter(|a| valid && a.active && a.email_verified) else {
        return (
            StatusCode::UNAUTHORIZED,
            document("<h1>Unable to sign in</h1><p>Invalid credentials or unverified account.</p>"),
        )
            .into_response();
    };
    let token = match create_session(&state, account).await {
        Ok(token) => token,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    (
        jar.add(state.security.issue_cookie(token)),
        Redirect::to(&query(&action.request)),
    )
        .into_response()
}

fn client_redirect(
    request: &AuthorizationRequest,
    code: Option<&str>,
    error: Option<&str>,
) -> Response {
    // The redirect URI was validated against the registered client immediately
    // before this function is called. Never call it for validation failures.
    let mut target = match Url::parse(&request.redirect_uri) {
        Ok(uri) => uri,
        Err(_) => return bad_request(),
    };
    {
        let mut pairs = target.query_pairs_mut();
        if let Some(code) = code {
            pairs.append_pair("code", code);
        }
        if let Some(error) = error {
            pairs.append_pair("error", error);
        }
        pairs.append_pair("state", &request.state);
    }
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        Redirect::to(target.as_str()),
    )
        .into_response()
}

pub async fn consent(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(action): Form<ConsentAction>,
) -> Response {
    if validate_authorization_request(&state.db, &action.request)
        .await
        .is_err()
    {
        return bad_request();
    }
    let Some((account, session)) = browser(&state, &jar).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match action.decision.as_str() {
        "deny" => return client_redirect(&action.request, None, Some("access_denied")),
        "approve" => {}
        _ => return bad_request(),
    }
    let Some(client) = get_client(&state.db, &action.request.client_id)
        .await
        .ok()
        .flatten()
    else {
        return bad_request();
    };
    if consent::approve(&state.db, account.id, client.id, &action.request.scope)
        .await
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    match grants::issue(&state.db, &action.request, account.id, session.id).await {
        Ok(code) => client_redirect(&action.request, Some(&code), None),
        Err(grants::GrantError::Database) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        Err(_) => bad_request(),
    }
}
