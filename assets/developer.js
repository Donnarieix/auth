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
  if (app.active) {
   const disable=document.createElement('button');
   disable.textContent='Disable';
   disable.addEventListener('click', async () => {
    if (!confirm('Disable '+app.name+'? Existing authorization grants will become unusable.')) return;
    const res=await fetch('/developer/clients/'+encodeURIComponent(app.client_id)+'/disable',{method:'POST',credentials:'same-origin'});
    if (!res.ok) {status.textContent='Could not disable client.';return;}
    await refresh();
   });
   li.append(' ',disable);
  }
  const manage=document.createElement('a');
  manage.href='/developer/manage-client?client_id='+encodeURIComponent(app.client_id);
  manage.textContent='Manage';
  li.append(' ',manage);
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

