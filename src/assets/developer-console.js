'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const signin = $('signin-view');
  const dashboard = $('dashboard-view');
  const loading = $('loading-view');
  const notice = $('notice');
  const form = $('signin-form');
  let clients = [];
  function message(text, error = false) {
    notice.textContent = text;
    notice.dataset.error = String(error);
  }
  function show(mode) {
    loading.hidden = mode !== 'loading';
    signin.hidden = mode !== 'signin';
    dashboard.hidden = mode !== 'dashboard';
    $('logout-button').hidden = mode !== 'dashboard';
    $('account-info').hidden = mode !== 'dashboard';
  }
  async function request(url, options = {}) {
    return fetch(url, {credentials: 'same-origin', cache: 'no-store', ...options});
  }
  function cell(row, content) {
    const td = document.createElement('td');
    if (content instanceof Node) td.append(content);
    else td.textContent = String(content);
    row.append(td);
    return td;
  }
  function renderClients() {
    const tbody = $('app-rows');
    tbody.replaceChildren();
    const query = $('app-search').value.toLocaleLowerCase('fr').trim();
    const activeOnly = $('active-only').checked;
    const filtered = clients.filter(app =>
      (!activeOnly || app.active) &&
      (!query || app.name.toLocaleLowerCase('fr').includes(query) ||
        app.client_id.toLocaleLowerCase('fr').includes(query))
    );
    for (const app of filtered) {
      const row = document.createElement('tr');
      const name = document.createElement('strong');
      name.textContent = app.name;
      cell(row, name);
      const type = document.createElement('span');
      type.className = 'type-pill';
      type.textContent = app.client_type === 'web' ? 'Web' : 'Bureau';
      cell(row, type);
      const id = document.createElement('code');
      id.className = 'code';
      id.textContent = app.client_id.length > 22 ? app.client_id.slice(0, 14) + '…' : app.client_id;
      id.title = app.client_id;
      const group = document.createElement('div');
      group.className = 'id-group';
      group.append(id);
      const copy = document.createElement('button');
      copy.type = 'button';
      copy.className = 'copy-id';
      copy.textContent = 'Copier';
      copy.setAttribute('aria-label', 'Copier l’identifiant de ' + app.name);
      copy.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(app.client_id);
          message('Identifiant client copié.');
        } catch {
          message('La copie est indisponible. Ouvrez la gestion pour consulter l’identifiant complet.', true);
        }
      });
      group.append(copy);
      cell(row, group);
      const badge = document.createElement('span');
      badge.className = 'status-pill ' + (app.active ? 'active' : 'disabled');
      badge.textContent = app.active ? 'Active' : 'Désactivée';
      cell(row, badge);
      const link = document.createElement('a');
      link.className = 'manage-link';
      link.href = '/developer/manage-client?client_id=' + encodeURIComponent(app.client_id);
      link.textContent = 'Configurer';
      link.setAttribute('aria-label', 'Configurer ' + app.name);
      cell(row, link);
      tbody.append(row);
    }
    if (filtered.length === 0) {
      const row = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 5;
      td.className = 'empty-row';
      if (!clients.length) {
        const text = document.createElement('p');
        text.textContent = 'Aucune application enregistrée.';
        const link = document.createElement('a');
        link.className = 'manage-link';
        link.href = '/developer/new-client';
        link.textContent = 'Créer votre première application';
        td.append(text, link);
      } else {
        td.textContent = 'Aucun résultat. Modifiez les filtres pour afficher vos applications.';
      }
      row.append(td);
      tbody.append(row);
    }
  }
  async function refresh() {
    show('loading');
    message('');
    try {
      const response = await request('/developer/clients');
      if (response.status === 401) {
        show('signin');
        return;
      }
      if (!response.ok) throw new Error('clients');
      clients = await response.json();
      clients.sort((a, b) => Number(b.active) - Number(a.active) || a.name.localeCompare(b.name, 'fr'));
      const active = clients.filter(c => c.active).length;
      $('app-summary').textContent = clients.length === 0 ?
        'Aucune application pour le moment.' :
        clients.length + ' application' + (clients.length > 1 ? 's' : '') +
        ' enregistrée' + (clients.length > 1 ? 's' : '') +
        ', dont ' + active + ' active' + (active > 1 ? 's' : '') + '.';
      renderClients();
      show('dashboard');
      // Identity metadata is optional: a reporting failure must not block
      // the primary application-management journey.
      try {
        const overviewResponse = await request('/developer/overview');
        if (overviewResponse.ok) {
          const overview = await overviewResponse.json();
          $('account-name').textContent = overview.administrator;
          $('account-avatar').textContent = overview.administrator.slice(0, 2).toUpperCase();
        }
      } catch { /* Non-critical display only. */ }
    } catch {
      show('signin');
      message('Impossible de charger les applications. Réessayez après avoir vérifié le service.', true);
    }
  }
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const button = $('signin-submit');
    button.disabled = true;
    message('');
    const data = new FormData(form);
    try {
      const response = await request('/developer/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          username: data.get('username'),
          token: data.get('token'),
          totp: data.get('totp') || null,
        }),
      });
      if (!response.ok) {
        message(response.status === 401 ? 'Identifiant, clé ou code TOTP incorrect.' :
          response.status === 403 ? 'Requête refusée : origine HTTPS non autorisée.' :
          response.status === 429 ? 'Trop de tentatives. Réessayez plus tard.' :
          'Connexion impossible (HTTP ' + response.status + ').', true);
        return;
      }
      form.reset();
      await refresh();
    } catch {
      message('Le service ne répond pas.', true);
    } finally {
      button.disabled = false;
    }
  });
  $('logout-button').addEventListener('click', async () => {
    try {
      const response = await request('/developer/logout', {method: 'POST'});
      if (!response.ok) throw new Error('logout');
      await refresh();
      message('Vous êtes déconnecté.');
    } catch {
      message('Déconnexion non confirmée. Réessayez.', true);
    }
  });
  $('app-search').addEventListener('input', renderClients);
  $('active-only').addEventListener('change', renderClients);
  refresh();
})();