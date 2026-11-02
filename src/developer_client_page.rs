use axum::response::Html;

pub async fn page() -> Html<String> {
    crate::ui::render(
        "Gérer une application",
        "/developer",
        r####"<div class="page-heading"><div class="eyebrow"><a href="/developer">Applications</a> / Configuration</div><h1 id="client-title">Configuration de l'application</h1><p class="lead">Gérez les adresses de retour, le secret web et l'activation de cette intégration.</p></div><div class="columns"><section class="panel"><input id="client_id" type="hidden"><div class="toolbar"><span class="hint">Identifiant : <code id="client-id-display" class="mono">—</code></span><button class="secondary" type="button" id="load">Actualiser</button></div><div id="client-content" hidden><h2>Adresses de retour</h2><p class="muted">Autorisez uniquement les adresses exactes utilisées par votre application.</p><label>URI autorisées<textarea id="redirects" spellcheck="false"></textarea></label><button type="button" id="save" style="margin-top:14px">Enregistrer les adresses</button><section id="web-secret" hidden><hr><h2>Secret du client web</h2><p class="muted">Un nouveau secret invalide l'ancien. Conservez-le uniquement dans le backend de votre application. Il ne sera affiché qu'une fois.</p><label>Confirmer avec votre clé administrateur<input type="password" id="admin_token" autocomplete="off"></label><button type="button" class="secondary" id="rotate" style="margin-top:14px">Générer un nouveau secret</button><div class="notice" id="secret-result" hidden><strong>Copiez et sauvegardez ce secret maintenant. Il ne sera plus affiché.</strong><p class="mono" id="secret"></p><button type="button" class="secondary" id="copy-secret">Copier</button></div></section><section id="disable-section"><hr><h2>Désactiver l'application</h2><p class="muted">Cette opération bloque les futures connexions et l'utilisation des jetons de cette application.</p><label><input type="checkbox" id="confirm_disable"> Je confirme vouloir désactiver cette application.</label><button type="button" class="danger" id="disable" style="margin-top:14px">Désactiver l'application</button></section></div><p class="status" id="status" role="status" aria-live="polite"></p><a class="button secondary" id="login-link" href="/developer" hidden>Se connecter à la console développeur</a></section><aside class="panel"><h2>Points à vérifier</h2><p class="muted">Chaque adresse de retour doit correspondre exactement à celle utilisée par votre application.</p><p class="muted">Changer le secret web invalide immédiatement le précédent.</p><p class="muted">La désactivation bloque les futurs échanges de jetons et n'est pas réversible depuis cette interface.</p><a href="/developer">Retour aux applications</a></aside></div><script>
const id=document.getElementById('client_id'),status=document.getElementById('status'),content=document.getElementById('client-content');
id.value=new URLSearchParams(location.search).get('client_id')||'';
const $=name=>document.getElementById(name);
const endpoint=s=>'/developer/clients/'+encodeURIComponent(id.value.trim())+s;
const notify=(message,error=false)=>{status.textContent=message;status.dataset.error=String(error);};
async function withButton(button,action){
  button.disabled=true;
  try{await action();}catch{notify('Impossible de joindre le serveur. Réessayez.',true);}
  finally{button.disabled=false;}
}
async function load(){
  if(!id.value.trim()){notify('Choisissez une application dans la liste pour afficher sa configuration.',true);$('load').hidden=true;return;}
  try{
    const r=await fetch('/developer/clients',{credentials:'same-origin',cache:'no-store'});
    if(r.status===401){content.hidden=true;$('login-link').hidden=false;notify('La session administrateur a expiré.',true);return;}
    if(!r.ok)throw new Error('network');
    const app=(await r.json()).find(v=>v.client_id===id.value.trim());
    if(!app){content.hidden=true;notify('Application introuvable. Revenez à la liste.',true);return;}
    $('login-link').hidden=true;
    $('client-title').textContent=app.name;
    document.title=app.name+' · Donnarieix Auth';
    $('client-id-display').textContent=app.client_id;
    $('redirects').value=(app.redirect_uris||[]).join('\n');
    $('web-secret').hidden=app.client_type!=='web'||!app.active;
    $('disable-section').hidden=!app.active;
    $('save').disabled=!app.active;
    $('confirm_disable').checked=false;
    content.hidden=false;
    notify(app.active?'Application active.':'Cette application est désactivée.');
  }catch{notify('Impossible de charger la configuration.',true);}
}
$('load').addEventListener('click',load);
$('save').addEventListener('click',async event=>withButton(event.currentTarget,async()=>{
  const uris=$('redirects').value.split(/\r?\n/).map(v=>v.trim()).filter(Boolean);
  if(!uris.length){notify('Ajoutez au moins une adresse de retour.',true);return;}
  const r=await fetch(endpoint('/redirects'),{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({redirect_uris:uris})});
  notify(r.ok?'Adresses de retour enregistrées.':r.status===401?'Session expirée. Reconnectez-vous.':'Adresses refusées. Vérifiez le format et le type du client.',!r.ok);
}));
$('rotate').addEventListener('click',async event=>withButton(event.currentTarget,async()=>{
  const token=$('admin_token').value.trim();
  if(!token){notify('Saisissez votre clé administrateur pour confirmer cette action.',true);return;}
  if(!confirm('Le secret actuel cessera immédiatement de fonctionner. Continuer ?'))return;
  $('admin_token').value='';
  $('secret').textContent='';
  $('secret-result').hidden=true;
  const r=await fetch(endpoint('/secret'),{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({administrator_token:token})});
  if(!r.ok){notify('Renouvellement refusé. Vérifiez votre clé et votre session.',true);return;}
  $('secret').textContent=(await r.json()).client_secret;
  $('secret-result').hidden=false;
  notify('Secret renouvelé. Sauvegardez-le avant de quitter cette page.');
}));
$('copy-secret').addEventListener('click',async()=>{
  try{await navigator.clipboard.writeText($('secret').textContent);notify('Secret copié.');}
  catch{notify('Copie indisponible. Sélectionnez le secret pour le copier.',true);}
});
$('disable').addEventListener('click',async event=>withButton(event.currentTarget,async()=>{
  if(!$('confirm_disable').checked){notify('Cochez la confirmation avant de désactiver.',true);return;}
  if(!confirm('Désactiver cette application ? Les jetons et futures connexions seront bloqués.'))return;
  const r=await fetch(endpoint('/disable'),{method:'POST',credentials:'same-origin'});
  if(!r.ok){notify('Désactivation refusée. Vérifiez votre session.',true);return;}
  $('secret').textContent='';$('secret-result').hidden=true;
  await load();
  notify('Application désactivée.');
}));
load();
</script>"####,
    )
}
