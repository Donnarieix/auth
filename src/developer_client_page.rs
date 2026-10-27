use axum::response::Html;

pub async fn page() -> Html<&'static str> {
    Html(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>Manage OIDC client</title></head><body><main><h1>OIDC Client Management</h1><a href="/developer">Developer console</a><label>Client ID <input id="client_id"></label><button id="load">Load current callbacks</button><label>Redirect URIs <textarea id="redirects"></textarea></label><button id="save">Save redirects</button><label>Developer credential <input type="password" id="admin_token" autocomplete="off"></label><button id="rotate">Rotate confidential secret</button><pre id="secret"></pre><label><input type="checkbox" id="confirm_disable"> I understand that disabling this application invalidates grants</label><button id="disable">Disable application</button><p id="status" role="status"></p></main><script>
const id=document.getElementById('client_id');
const status=document.getElementById('status');
id.value=new URLSearchParams(location.search).get('client_id')||'';
const endpoint=suffix=>'/developer/clients/'+encodeURIComponent(id.value.trim())+suffix;
document.getElementById('load').addEventListener('click',async()=>{
 const r=await fetch('/developer/clients',{credentials:'same-origin'});
 if(!r.ok){status.textContent='Developer login required.';return;}
 const client=(await r.json()).find(v=>v.client_id===id.value.trim());
 if(!client){status.textContent='Client not found.';return;}
 document.getElementById('redirects').value=client.redirect_uris.join('\\n');
 status.textContent=client.name+' — '+client.client_type+' — '+(client.active?'active':'disabled');
});
document.getElementById('save').addEventListener('click',async()=>{
 const uris=document.getElementById('redirects').value.split('\\n').map(v=>v.trim()).filter(Boolean);
 const r=await fetch(endpoint('/redirects'),{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({redirect_uris:uris})});
 status.textContent=r.ok?'Redirect URIs saved.':'Redirect update refused.';
});
document.getElementById('rotate').addEventListener('click',async()=>{
 const field=document.getElementById('admin_token');
 const administrator_token=field.value;
 field.value='';
 const display=document.getElementById('secret');
 display.textContent='';
 const r=await fetch(endpoint('/secret'),{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({administrator_token})});
 if(!r.ok){status.textContent='Credential rejected or web client unavailable.';return;}
 display.textContent=(await r.json()).client_secret;
 status.textContent='Secret rotated. Store it in your backend now; it will not be shown again.';
});
document.getElementById('disable').addEventListener('click',async()=>{
 if(!document.getElementById('confirm_disable').checked){status.textContent='Confirm deactivation first.';return;}
 const r=await fetch(endpoint('/disable'),{method:'POST',credentials:'same-origin'});
 status.textContent=r.ok?'Application disabled.':'Deactivation refused.';
});
</script></body></html>"#,
    )
}
