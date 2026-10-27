//! Isolated browser login for developer administrators.
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::Html,
};
use axum_extra::extract::{CookieJar, cookie::{Cookie, SameSite}};
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{services::session::generate_token, state::AppState};

fn cookie_name(state: &AppState) -> &'static str {
    if state.security.secure {
        "__Host-developer_session"
    } else {
        "developer_session"
    }
}

fn session_cookie(state: &AppState, token: String) -> Cookie<'static> {
    Cookie::build((cookie_name(state), token))
        .http_only(true)
        .secure(state.security.secure)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(time::Duration::minutes(30))
        .build()
}

#[derive(Deserialize)]
pub struct DeveloperLogin {
    username: String,
    token: String,
}

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(credentials): Json<DeveloperLogin>,
) -> Result<CookieJar, StatusCode> {
    if credentials.username.len() > 32
        || credentials.username.len() < 3
        || credentials.token.len() != 43
        || !credentials.token.is_ascii()
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if !state
        .abuse
        .allow("developer_login", &credentials.username, 30, 5)
        .await
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let digest = Sha256::digest(credentials.token.as_bytes()).to_vec();
    let row = state
        .db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT id FROM developer_administrators WHERE username = ? AND token_hash = ? AND active = 1",
            [credentials.username.into(), digest.into()],
        ))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let admin_id: String = row
        .try_get("", "id")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let (session, hash) = generate_token();
    state
        .db
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO developer_sessions(id, administrator_id, token_hash, expires_at, revoked) VALUES(?, ?, ?, ?, 0)",
            [
                Uuid::new_v4().to_string().into(),
                admin_id.into(),
                hash.into(),
                (chrono::Utc::now() + chrono::Duration::minutes(30))
                    .to_rfc3339()
                    .into(),
            ],
        ))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(jar.add(session_cookie(&state, session)))
}

pub async fn authenticated_cookie(state: &AppState, jar: &CookieJar) -> Option<Uuid> {
    let raw = jar.get(cookie_name(state))?.value();
    if raw.len() != 43 || !raw.is_ascii() {
        return None;
    }
    let hash = Sha256::digest(raw.as_bytes()).to_vec();
    let row = state
        .db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT s.administrator_id, s.expires_at FROM developer_sessions s JOIN developer_administrators a ON a.id = s.administrator_id WHERE s.token_hash = ? AND s.revoked = 0 AND a.active = 1",
            [hash.into()],
        ))
        .await
        .ok()??;
    let expires: String = row.try_get("", "expires_at").ok()?;
    if chrono::DateTime::parse_from_rfc3339(&expires).ok()?.with_timezone(&chrono::Utc)
        <= chrono::Utc::now()
    {
        return None;
    }
    let id: String = row.try_get("", "administrator_id").ok()?;
    Uuid::parse_str(&id).ok()
}

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<CookieJar, StatusCode> {
    if let Some(raw) = jar.get(cookie_name(&state)) {
        let digest = Sha256::digest(raw.value().as_bytes()).to_vec();
        state
            .db
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE developer_sessions SET revoked = 1 WHERE token_hash = ?",
                [digest.into()],
            ))
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    let cleared = Cookie::build((cookie_name(&state), ""))
        .http_only(true)
        .secure(state.security.secure)
        .same_site(SameSite::Strict)
        .path("/")
        .build();
    Ok(jar.remove(cleared))
}

pub async fn page() -> Html<&'static str> {
    Html(r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Developer console</title></head><body><main><h1>Donnarieix Auth — Developer console</h1><form id="signin"><label>Administrator <input name="username" required autocomplete="username"></label><label>Recovery credential <input type="password" name="token" required autocomplete="current-password"></label><button>Sign in</button></form><p id="status" role="alert"></p><section><h2>Registered applications</h2><ul id="apps"></ul></section><button id="signout">Sign out</button></main><script>
const status = document.getElementById('status');
async function refresh() {
 const r = await fetch('/developer/clients', {credentials:'same-origin'});
 const list = document.getElementById('apps');
 list.replaceChildren();
 if (!r.ok) { status.textContent='Sign in with your developer credentials.'; return; }
 status.textContent='Developer session active.';
 for (const app of await r.json()) {
  const li=document.createElement('li');
  li.textContent=app.name+' — '+app.client_type+' — '+(app.active?'active':'disabled');
  list.append(li);
 }
}
document.getElementById('signin').addEventListener('submit', async e => {
 e.preventDefault();
 const data=new FormData(e.target);
 const r=await fetch('/developer/login',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:data.get('username'),token:data.get('token')})});
 e.target.reset();
 if (!r.ok) { status.textContent='Authentication failed.'; return; }
 await refresh();
});
document.getElementById('signout').addEventListener('click', async () => {
 await fetch('/developer/logout',{method:'POST',credentials:'same-origin'});
 await refresh();
});
refresh();
</script></body></html>"#)
}
