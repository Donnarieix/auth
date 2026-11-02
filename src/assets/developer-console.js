
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
  }
  async function request(url, options = {}) {
    return fetch(url, { credentials: 'same-origin', cache: 'no-store', ...options });
  }
  function setValue(id, value) {
    $(id).textContent = String(value);
  }
  function badge(active) {
    const span = document.createElement('span');
    span.className = 'status-pill ' + (active ? 'active' : 'disabled');
    span.textContent = active ? 'Active' : 'Désactivée';
    return span;
  }
  function cell(row, content) {
    const td = document.createElement('td');
    if (content instanceof Node) td.append(content);
    else td.textContent = String(content);
    row.append(td);
  }
  function renderClients() {
    const tbody = $('app-rows');
    tbody.replaceChildren();
    const query = $('app-search').value.toLocaleLowerCase('fr').trim();
    const activeOnly = $('active-only').checked;
    const filtered = clients.filter(app => (!activeOnly || app.active) &&
      (!query || app.name.toLocaleLowerCase('fr').includes(query) ||
        app.client_id.toLocaleLowerCase('fr').includes(query)));
    if (!filtered.length) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 5;
      td.className = 'empty-row';
      td.textContent = clients.length ? 'Aucune application ne correspond à la recherche.' : 'Aucune application enregistrée.';
      tr.append(td);
      tbody.append(tr);
      return;
    }
    for (const app of filtered) {
      const row = document.createElement('tr');
      const group = document.createElement('span');
      group.className = 'app-name';
      const mark = document.createElement('span');
      mark.className = 'app-icon';
      mark.setAttribute('aria-hidden', 'true');
      mark.textContent = app.client_type === 'web' ? '⌘' : '▣';
      const name = document.createElement('span');
      name.textContent = app.name;
      group.append(mark, name);
      cell(row, group);
      const type = document.createElement('span');
      type.className = 'type-pill';
      type.textContent = app.client_type === 'web' ? 'Web · OIDC' : 'Desktop · OIDC';
      cell(row, type);
      const id = document.createElement('span');
      id.className = 'code';
      id.textContent = app.client_id.length > 18 ? app.client_id.slice(0, 12) + '…' : app.client_id;
      id.title = app.client_id;
      cell(row, id);
      cell(row, badge(app.active));
      const link = document.createElement('a');
      link.className = 'manage-link';
      link.href = '/developer/manage-client?client_id=' + encodeURIComponent(app.client_id);
      link.textContent = 'Gérer';
      link.setAttribute('aria-label', 'Gérer ' + app.name);
      cell(row, link);
      tbody.append(row);
    }
  }
  function renderAudit(events) {
    const list = $('audit-rows');
    list.replaceChildren();
    if (!events.length) {
      const p = document.createElement('p');
      p.className = 'metric-hint';
      p.textContent = 'Aucun événement administratif enregistré.';
      list.append(p);
      return;
    }
    for (const event of events) {
      const row = document.createElement('div');
      row.className = 'audit-item';
      const label = document.createElement('span');
      label.textContent = event.event_type.replaceAll('_', ' ');
      const when = document.createElement('time');
      when.className = 'audit-time';
      when.dateTime = event.created_at;
      const date = new Date(event.created_at);
      when.textContent = Number.isNaN(date.getTime()) ? event.created_at :
        new Intl.DateTimeFormat('fr-FR', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }).format(date);
      row.append(label, when);
      list.append(row);
    }
  }
  async function refresh() {
    show('loading');
    message('');
    try {
      const response = await request('/developer/overview');
      if (response.status === 401) { show('signin'); return; }
      if (!response.ok) throw new Error('overview');
      const overview = await response.json();
      const apps = await request('/developer/clients');
      if (!apps.ok) throw new Error('apps');
      clients = await apps.json();
      setValue('metric-apps', overview.applications);
      setValue('metric-users', overview.users);
      setValue('metric-tokens', overview.tokens_7d);
      setValue('metric-sessions', overview.active_sessions);
      setValue('account-name', overview.administrator);
      $('account-avatar').textContent = overview.administrator.slice(0, 2).toUpperCase();
      $('metric-apps-note').textContent = overview.active_applications + ' actives';
      renderClients();
      renderAudit(overview.recent_events);
      show('dashboard');
    } catch {
      show('signin');
      message('Impossible de charger la console. Vérifiez la connexion au serveur.', true);
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
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: data.get('username'),
          token: data.get('token'),
          totp: data.get('totp') || null,
        }),
      });
      if (!response.ok) {
        message(response.status === 401 ? 'Identifiant, clé ou code TOTP incorrect.' :
          response.status === 429 ? 'Trop de tentatives. Réessayez plus tard.' :
          response.status === 403 ? 'Origine HTTPS non autorisée.' :
          'Connexion impossible (HTTP ' + response.status + ').', true);
        return;
      }
      form.reset();
      await refresh();
    } catch {
      message('Le serveur ne répond pas.', true);
    } finally {
      button.disabled = false;
    }
  });
  $('logout-button').addEventListener('click', async () => {
    try { await request('/developer/logout', { method: 'POST' }); }
    catch { /* We re-check the active session instead of claiming success. */ }
    await refresh();
  });
  $('app-search').addEventListener('input', renderClients);
  $('active-only').addEventListener('change', renderClients);
  refresh();
})();
