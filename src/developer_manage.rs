//! Authenticated developer client registration, independent of end-user SSO.
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::Html,
};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};

use crate::{
    developer_session::authenticated_cookie,
    services::client::{ClientType, register_client_with_actor},
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
