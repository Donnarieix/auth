//! Isolated browser login for developer administrators.
use axum::{Json, extract::State, http::StatusCode, response::Html};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{admin_totp, services::session::generate_token, state::AppState};

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
    totp: Option<String>,
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
        .allow(
            "developer_login",
            &credentials.username.to_ascii_lowercase(),
            30,
            5,
        )
        .await
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let digest = Sha256::digest(credentials.token.as_bytes()).to_vec();
    let row = state
        .db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT id, totp_secret, totp_last_step, totp_required FROM developer_administrators WHERE username = ? AND token_hash = ? AND active = 1",
            [credentials.username.into(), digest.into()],
        ))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let admin_id: String = row
        .try_get("", "id")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let totp_secret: Option<Vec<u8>> = row
        .try_get("", "totp_secret")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let totp_required: bool = row
        .try_get("", "totp_required")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if totp_required && totp_secret.is_none() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if let Some(secret) = totp_secret {
        let last_step: i64 = row
            .try_get("", "totp_last_step")
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let provided = credentials
            .totp
            .as_deref()
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let step = admin_totp::verify(&secret, provided, chrono::Utc::now().timestamp(), last_step)
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let updated = state.db.execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "UPDATE developer_administrators SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?",
            [step.into(), admin_id.clone().into(), step.into()],
        )).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if updated.rows_affected() != 1 {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }
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
    if chrono::DateTime::parse_from_rfc3339(&expires)
        .ok()?
        .with_timezone(&chrono::Utc)
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

pub async fn page() -> Html<String> {
    crate::ui::render(
        "Console développeur",
        "/developer",
        r####"<div class="page-heading"><div class="eyebrow">Console développeur</div><h1>Vos applications, simplement.</h1><p class="lead">Gérez les intégrations qui utilisent Donnarieix Auth, leurs accès et leurs adresses de retour.</p></div><div class="columns"><section class="panel" id="signin-panel"><h2>Accès administrateur</h2><p class="muted">Un espace réservé aux développeurs, indépendant de votre compte personnel.</p><form id="signin"><label>Identifiant<input name="username" autocomplete="username" required></label><label>Clé administrateur<input name="token" type="password" autocomplete="current-password" required></label><label>Code d'authentification (si activé)<input name="totp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}"></label><button type="submit">Me connecter</button></form></section><section class="panel" id="apps-panel" hidden><div class="toolbar"><h2>Mes applications</h2><a class="button" href="/developer/new-client">Créer une application</a></div><div id="apps"></div><button class="secondary" type="button" id="signout" style="margin-top:20px">Déconnexion</button></section><aside class="stack"><section class="panel"><h2>Comment ça fonctionne ?</h2><p class="muted">Chaque application possède un identifiant unique et une liste précise d'adresses de retour. Les secrets web restent privés.</p><a href="/.well-known/openid-configuration">Découverte OpenID Connect</a></section><section class="panel"><h2>Sécurité renforcée</h2><p class="muted">Utilisez un compte administrateur distinct et activez un authentificateur TOTP. Les changements sensibles sont journalisés.</p></section></aside></div><p class="status" id="status" role="status" aria-live="polite"></p><script>
const status=document.getElementById('status'),sign=document.getElementById('signin-panel'),panel=document.getElementById('apps-panel'),list=document.getElementById('apps');
async function refresh(){try{const response=await fetch('/developer/clients',{credentials:'same-origin'});sign.hidden=response.ok;panel.hidden=!response.ok;list.replaceChildren();if(!response.ok)return;const clients=await response.json();if(!clients.length){const empty=document.createElement('p');empty.className='empty';empty.textContent='Aucune application pour le moment.';list.append(empty);}for(const app of clients){const row=document.createElement('div');row.className='item';const info=document.createElement('div'),name=document.createElement('div'),type=document.createElement('div');name.className='item-title';name.textContent=app.name;type.className='hint';type.textContent=(app.client_type==='web'?'Web':'Bureau')+' · '+(app.active?'Active':'Désactivée');info.append(name,type);const link=document.createElement('a');link.className='button secondary';link.href='/developer/manage-client?client_id='+encodeURIComponent(app.client_id);link.textContent='Gérer';row.append(info,link);list.append(row);}}catch{status.textContent='Connexion au serveur impossible.';status.dataset.error='true';}}
document.getElementById('signin').addEventListener('submit',async e=>{e.preventDefault();const form=e.target,button=form.querySelector('button');button.disabled=true;const data=new FormData(form);try{const r=await fetch('/developer/login',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:data.get('username'),token:data.get('token'),totp:data.get('totp')||null})});form.reset();status.textContent=r.ok?'Connexion réussie.':'Identifiants ou code incorrects.';status.dataset.error=String(!r.ok);await refresh();}catch{status.textContent='Connexion impossible.';status.dataset.error='true';}finally{button.disabled=false;}});
document.getElementById('signout').addEventListener('click',async()=>{await fetch('/developer/logout',{method:'POST',credentials:'same-origin'});await refresh();status.textContent='Vous êtes déconnecté.';});refresh();
</script>"####,
    )
}
