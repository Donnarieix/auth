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
use uuid::Uuid;

use crate::{
    developer_session::authenticated_cookie,
    services::client::{ClientType, register_client_with_actor, validate_redirect_uri},
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

pub async fn create_page() -> Html<&'static str> {
    Html(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>Register client</title></head><body><main><h1>Register OIDC application</h1><p>Only authenticated developer administrators may register clients. Use HTTPS callbacks for web clients; desktop callbacks may use explicitly registered loopback ports.</p><form id="client"><label>Application name <input name="name" maxlength="100" required></label><label>Type <select name="kind"><option value="desktop">Desktop (public PKCE)</option><option value="web">Web (confidential backend)</option></select></label><label>Redirect URIs (one per line) <textarea name="uris" required></textarea></label><button>Create client</button></form><p id="status" role="alert"></p><p><a href="/developer">Developer console</a></p></main><script>
document.getElementById('client').addEventListener('submit', async e => {
 e.preventDefault();
 const data=new FormData(e.target);
 const payload={name:data.get('name'),client_type:data.get('kind'),redirect_uris:String(data.get('uris')).split('\n').map(v=>v.trim()).filter(Boolean)};
 const result=await fetch('/developer/clients',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
 const status=document.getElementById('status');
 if (!result.ok) {status.textContent='Could not register the application. Check login and callback values.';return;}
 const client=await result.json();
 status.textContent='Created client ID: '+client.client_id+'. Save this ID. Web clients also require a confidential secret from the trusted operator CLI.';
});
</script></body></html>"#,
    )
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
    )).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
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
    let internal_id: String = row
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
        [internal_id.clone().into()],
    )).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    for uri in &payload.redirect_uris {
        tx.execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO client_redirect_uris (id,client_id,redirect_uri) VALUES (?,?,?)",
            [Uuid::new_v4().to_string().into(), internal_id.clone().into(), uri.clone().into()],
        )).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
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
    )).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    tx.commit().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}
