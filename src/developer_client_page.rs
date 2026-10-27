use axum::response::Html;

pub async fn page() -> Html<&'static str> {
    Html(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>Manage OIDC client</title></head><body><main><h1>OIDC Client Management</h1><a href="/developer">Developer console</a><label>Client ID <input id="client_id"></label><label>Redirect URIs <textarea id="redirects"></textarea></label><button id="save">Save redirects</button><label>Developer credential <input type="password" id="admin_token" autocomplete="off"></label><button id="rotate">Rotate confidential secret</button><pre id="secret"></pre><label><input type="checkbox" id="confirm_disable"> I understand that disabling this application invalidates grants</label><button id="disable">Disable application</button><p id="status" role="status"></p></main></body></html>"#,
    )
}
