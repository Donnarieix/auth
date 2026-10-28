//! Authenticated developer client registration, independent of end-user SSO.
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::Html,
};
use axum_extra::extract::CookieJar;
use sea_orm::{ConnectionTrait, DbBackend, Statement, TransactionTrait};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    developer_session::authenticated_cookie,
    services::{
        client::{ClientType, register_client_with_actor, validate_redirect_uri},
        session::generate_token,
    },
    state::AppState,
};

#[derive(Deserialize)]
pub struct RegisterClientRequest {
    name: String,
    client_type: String,
    redirect_uris: Vec<String>,
}

#[derive(Serialize)]
pub struct RegisteredClient {
    client_id: String,
}

pub async fn create(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<RegisterClientRequest>,
) -> Result<(StatusCode, Json<RegisteredClient>), StatusCode> {
    let actor = authenticated_cookie(&state, &jar)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if !state
        .abuse
        .allow("developer_client_create", &actor.to_string(), 30, 10)
        .await
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let kind = ClientType::parse(&payload.client_type).ok_or(StatusCode::BAD_REQUEST)?;
    let client_id = register_client_with_actor(
        &state.db,
        &payload.name,
        kind,
        &payload.redirect_uris,
        Some(actor),
    )
    .await
    .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok((StatusCode::CREATED, Json(RegisteredClient { client_id })))
}

pub async fn create_page() -> Html<String> {
    crate::ui::render("Nouvelle application", "/developer", r####"<div class="page-heading"><div class="eyebrow">Intégration OIDC</div><h1>Créer une application</h1><p class="lead">Quelques informations suffisent pour connecter votre application à Donnarieix Auth.</p></div><div class="columns"><section class="panel"><form id="client"><label>Nom de l'application<input name="name" maxlength="100" required placeholder="Ex. Mon application"></label><label>Type d'application<select name="kind"><option value="desktop">Application desktop — PKCE</option><option value="web">Application web — serveur confidentiel</option></select></label><label>Adresses de retour autorisées<textarea name="uris" required placeholder="http://127.0.0.1:4000/callback"></textarea><span class="hint">Une URI exacte par ligne. Une application web exige HTTPS.</span></label><button type="submit">Créer cette application</button></form><p class="status" id="status" role="status" aria-live="polite"></p><div id="result" class="notice" hidden><p><strong>Application enregistrée.</strong> Conservez son identifiant pour votre intégration :</p><code class="mono" id="new-id"></code><p class="hint">Pour une application web, configurez également son secret depuis sa page de gestion.</p></div></section><aside class="panel"><h2>Avant de commencer</h2><p class="muted">L'identifiant du client identifie votre application. Les URL de retour évitent qu'une autre adresse reçoive les codes de connexion.</p><p class="muted">Les clients desktop utilisent PKCE sans secret. Les clients web échangent les jetons uniquement depuis leur backend.</p><a href="/developer">Retour aux applications</a></aside></div><script>
document.getElementById('client').addEventListener('submit',async e=>{e.preventDefault();const form=e.target,button=form.querySelector('button'),status=document.getElementById('status');button.disabled=true;status.textContent='Création en cours…';status.dataset.error='false';try{const data=new FormData(form),payload={name:data.get('name'),client_type:data.get('kind'),redirect_uris:String(data.get('uris')).split(/\r?\n/).map(s=>s.trim()).filter(Boolean)};const res=await fetch('/developer/clients',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});if(!res.ok){status.textContent='Création refusée. Vérifiez votre session et les adresses de retour.';status.dataset.error='true';return;}const app=await res.json();document.getElementById('new-id').textContent=app.client_id;document.getElementById('result').hidden=false;status.textContent='Application créée avec succès.';}catch{status.textContent='Serveur injoignable.';status.dataset.error='true';}finally{button.disabled=false;}});
</script>"####)
}

#[derive(Serialize)]
pub struct DisabledClient {
    disabled: bool,
}

/// Administrative deactivation is audited in the same transaction.
/// Disabling a client prevents authorization, token redemption and userinfo
/// because those endpoints check active client status.
pub async fn disable(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    jar: CookieJar,
) -> Result<Json<DisabledClient>, StatusCode> {
    let actor = authenticated_cookie(&state, &jar)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if !state
        .abuse
        .allow("developer_client_disable", &actor.to_string(), 30, 10)
        .await
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let tx = state
        .db
        .begin()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let updated = tx
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "UPDATE clients SET active = 0 WHERE client_id = ? AND active = 1",
            [client_id.clone().into()],
        ))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if updated.rows_affected() != 1 {
        return Err(StatusCode::NOT_FOUND);
    }
    tx.execute_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "INSERT INTO developer_admin_events(id, administrator_id, event_type, created_at) VALUES (?, ?, ?, ?)",
        [
            Uuid::new_v4().to_string().into(),
            actor.to_string().into(),
            format!("client_disabled:{client_id}").into(),
            chrono::Utc::now().to_rfc3339().into(),
        ],
    ))
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    tx.commit()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(DisabledClient { disabled: true }))
}

#[derive(Deserialize)]
pub struct RedirectUpdate {
    redirect_uris: Vec<String>,
}

pub async fn replace_redirects(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    jar: CookieJar,
    Json(payload): Json<RedirectUpdate>,
) -> Result<StatusCode, StatusCode> {
    let actor = authenticated_cookie(&state, &jar)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if !state
        .abuse
        .allow("developer_redirect_update", &actor.to_string(), 30, 10)
        .await
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    if payload.redirect_uris.is_empty() || payload.redirect_uris.len() > 12 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let unique: std::collections::HashSet<_> = payload.redirect_uris.iter().collect();
    if unique.len() != payload.redirect_uris.len() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let tx = state
        .db
        .begin()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let row = tx
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT id, client_type FROM clients WHERE client_id = ? AND active = 1",
            [client_id.clone().into()],
        ))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let internal_id: Uuid = row
        .try_get("", "id")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let kind: String = row
        .try_get("", "client_type")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let kind = ClientType::parse(&kind).ok_or(StatusCode::BAD_REQUEST)?;
    for uri in &payload.redirect_uris {
        validate_redirect_uri(kind, uri).map_err(|_| StatusCode::BAD_REQUEST)?;
    }
    tx.execute_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "DELETE FROM client_redirect_uris WHERE client_id = ?",
        [internal_id.into()],
    ))
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    for uri in &payload.redirect_uris {
        tx.execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO client_redirect_uris (id,client_id,redirect_uri) VALUES (?,?,?)",
            [
                Uuid::new_v4().to_string().into(),
                internal_id.into(),
                uri.clone().into(),
            ],
        ))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    tx.execute_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "INSERT INTO developer_admin_events (id,administrator_id,event_type,created_at) VALUES (?,?,?,?)",
        [
            Uuid::new_v4().to_string().into(),
            actor.to_string().into(),
            format!("redirects_updated:{client_id}").into(),
            chrono::Utc::now().to_rfc3339().into(),
        ],
    ))
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    tx.commit()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct RotateSecretRequest {
    administrator_token: String,
}

#[derive(Serialize)]
pub struct RotatedSecret {
    client_secret: String,
}

pub async fn rotate_secret(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    jar: CookieJar,
    Json(payload): Json<RotateSecretRequest>,
) -> Result<Json<RotatedSecret>, StatusCode> {
    let actor = authenticated_cookie(&state, &jar)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if !state
        .abuse
        .allow("developer_client_secret", &actor.to_string(), 15, 3)
        .await
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    if payload.administrator_token.len() != 43 || !payload.administrator_token.is_ascii() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let admin_hash = Sha256::digest(payload.administrator_token.as_bytes()).to_vec();
    let (secret, _) = generate_token();
    let new_hash = Sha256::digest(secret.as_bytes()).to_vec();
    let tx = state
        .db
        .begin()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let authorized = tx.query_one_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "SELECT id FROM developer_administrators WHERE id = ? AND token_hash = ? AND active = 1",
        [actor.to_string().into(), admin_hash.into()],
    )).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if authorized.is_none() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let updated = tx.execute_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "UPDATE clients SET client_secret_hash = ? WHERE client_id = ? AND client_type = 'web' AND active = 1",
        [new_hash.into(), client_id.clone().into()],
    )).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if updated.rows_affected() != 1 {
        return Err(StatusCode::NOT_FOUND);
    }
    tx.execute_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "INSERT INTO developer_admin_events(id,administrator_id,event_type,created_at) VALUES (?,?,?,?)",
        [
            Uuid::new_v4().to_string().into(),
            actor.to_string().into(),
            format!("client_secret_rotated:{client_id}").into(),
            chrono::Utc::now().to_rfc3339().into(),
        ],
    )).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    tx.commit()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(RotatedSecret {
        client_secret: secret,
    }))
}
