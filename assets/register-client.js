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

