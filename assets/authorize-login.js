document.getElementById('login').addEventListener('submit', async (event) => {
 event.preventDefault();
 const form = new FormData(event.target);
 const response = await fetch('/login', {method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin', body: JSON.stringify({email: form.get('email'), password: form.get('password')})});
 if (response.ok) location.reload();
 else document.getElementById('status').textContent = 'Sign-in failed. Check credentials and email verification.';
});

