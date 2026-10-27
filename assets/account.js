const status = document.getElementById('status');
document.querySelectorAll('form[data-path]').forEach(form => {
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const payload=Object.fromEntries(new FormData(form));
    try {
      const response=await fetch(form.dataset.path,{
        method:'POST',credentials:'same-origin',
        headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)
      });
      status.textContent=response.ok
        ? 'Request accepted. Check your mail or local development outbox if a code is needed.'
        : 'Request rejected. Verify the submitted information and try again.';
      if (response.ok) form.reset();
    } catch (_) {
      status.textContent='Unable to reach the authentication service.';
    }
  });
});

