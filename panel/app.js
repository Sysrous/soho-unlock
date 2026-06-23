const API = '';
let token = localStorage.getItem('soho_token') || '';

function headers() {
  const h = { 'Content-Type': 'application/json' };
  if (token) h['Authorization'] = 'Bearer ' + token;
  return h;
}

async function api(path, opts = {}) {
  const res = await fetch(API + path, { headers: headers(), ...opts });
  if (res.status === 401) { toast('Unauthorized — set token in Settings'); return null; }
  if (!res.ok) { toast('Error: ' + res.status); return null; }
  return res.json();
}

function toast(msg) {
  const el = $('toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('show'), 2800);
}

function $(id) { return document.getElementById(id); }

function show(id) {
  document.querySelectorAll('.page').forEach(p => p.classList.add('hidden'));
  $(id).classList.remove('hidden');
}

function navigate(page) {
  document.querySelectorAll('.sidebar a').forEach(a =>
    a.classList.toggle('active', a.dataset.page === page)
  );
  show('page-' + page);
  if (page === 'status') loadStatus();
  else if (page === 'services') loadServices();
  else if (page === 'sources') loadSources();
  else if (page === 'rules') loadRules();
  else if (page === 'settings') loadSettings();
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.sidebar a').forEach(a =>
    a.addEventListener('click', e => { e.preventDefault(); navigate(a.dataset.page); })
  );

  $('token-input').value = token;
  $('token-save').addEventListener('click', () => {
    token = $('token-input').value.trim();
    localStorage.setItem('soho_token', token);
    toast('Token saved');
    loadStatus();
  });

  $('init-services-btn').addEventListener('click', initServices);
  $('add-service-btn').addEventListener('click', () => openSvcModal(null));

  $('add-source-btn').addEventListener('click', addSource);
  $('add-source-addr').addEventListener('keydown', e => { if (e.key === 'Enter') addSource(); });
  $('bulk-source-btn').addEventListener('click', bulkImportSources);
  $('apply-fw-btn').addEventListener('click', applyFirewall);
  $('clear-sources-btn').addEventListener('click', clearSources);

  $('import-domains-btn').addEventListener('click', () => importText($('domain-input')));
  $('import-cidrs-btn').addEventListener('click', () => importText($('cidr-input')));
  $('import-mixed-btn').addEventListener('click', () => importText($('mixed-input')));

  $('clear-domains-btn').addEventListener('click', () => clearByType('domain'));
  $('clear-cidrs-btn').addEventListener('click', () => clearByType('cidr'));
  $('clear-all-btn').addEventListener('click', clearAll);

  navigate('status');
});

// ── Status ──

async function loadStatus() {
  const d = await api('/api/status');
  if (!d) return;
  $('stat-content').innerHTML = `
    <div class="stats-grid">
      <div class="stat accent"><div class="val">${fmt(d.stats.dns_queries)}</div><div class="label">DNS Queries</div></div>
      <div class="stat success"><div class="val">${fmt(d.stats.dns_matched)}</div><div class="label">Matched</div></div>
      <div class="stat"><div class="val">${fmt(d.stats.dns_forwarded)}</div><div class="label">Forwarded</div></div>
      <div class="stat danger"><div class="val">${fmt(d.stats.dns_blocked)}</div><div class="label">Blocked</div></div>
      <div class="stat accent"><div class="val">${fmt(d.stats.sni_connections)}</div><div class="label">SNI Conn</div></div>
      <div class="stat success"><div class="val">${fmt(d.stats.sni_relayed)}</div><div class="label">Relayed</div></div>
      <div class="stat danger"><div class="val">${fmt(d.stats.sni_blocked)}</div><div class="label">SNI Blocked</div></div>
      <div class="stat orange"><div class="val">${fmtUptime(d.stats.uptime_secs)}</div><div class="label">Uptime</div></div>
    </div>
    <div class="card">
      <table class="info-table">
        <tr><td>Version</td><td>${esc(d.version)}</td></tr>
        <tr><td>Unlock Target</td><td>${esc(d.unlock_target)}</td></tr>
        <tr><td>Resolved IP</td><td>${d.unlock_ip ? esc(d.unlock_ip) : '<span class="muted">N/A</span>'}</td></tr>
        <tr><td>Rules</td><td>${d.rule_count}</td></tr>
        <tr><td>Sources</td><td>${d.source_count || '<span class="muted">open</span>'}</td></tr>
        <tr><td>Firewall</td><td>${d.firewall_enabled ? 'Enabled' : '<span class="muted">Disabled</span>'}</td></tr>
      </table>
    </div>`;
}

// ── Sources ──

async function loadSources() {
  const d = await api('/api/sources');
  if (!d) return;
  $('source-count').textContent = d.length;
  if (d.length === 0) {
    $('sources-list').innerHTML = '<p class="muted" style="padding:8px 0">No sources — accepting all traffic.</p>';
    return;
  }
  let html = '<table><tr><th>Address</th><th>Type</th><th>Resolved</th><th>Note</th><th style="width:50px"></th></tr>';
  d.forEach(s => {
    const type = s.is_domain
      ? '<span class="type-tag tag-keyword">domain</span>'
      : '<span class="type-tag tag-exact">IP</span>';
    const resolved = s.is_domain
      ? (s.resolved && s.resolved.length > 0
          ? '<span class="mono resolved-ok">' + s.resolved.map(esc).join(', ') + '</span>'
          : '<span class="resolved-fail">failed</span>')
      : '<span class="muted">—</span>';
    html += `<tr>
      <td class="mono">${esc(s.addr)}</td>
      <td>${type}</td>
      <td>${resolved}</td>
      <td>${esc(s.note || '')}</td>
      <td><button class="btn btn-danger btn-sm" onclick="removeSource('${esc(s.addr)}')">Del</button></td>
    </tr>`;
  });
  html += '</table>';
  $('sources-list').innerHTML = html;
}

async function addSource() {
  const addr = $('add-source-addr').value.trim();
  const note = $('add-source-note').value.trim();
  if (!addr) return;
  const d = await api('/api/sources', { method: 'POST', body: JSON.stringify({ addr, note }) });
  if (d) {
    $('add-source-addr').value = '';
    $('add-source-note').value = '';
    toast('Source added');
    loadSources();
  }
}

async function bulkImportSources() {
  const text = $('bulk-source-input').value.trim();
  if (!text) return;
  const btn = $('bulk-source-btn');
  btn.disabled = true;
  btn.textContent = 'Importing...';
  const d = await api('/api/sources/bulk', { method: 'POST', body: JSON.stringify({ text }) });
  btn.disabled = false;
  btn.textContent = 'Import All';
  if (d) {
    let msg = `Added ${d.added} sources (total: ${d.total})`;
    if (d.failed.length > 0) {
      msg += ` — ${d.failed.length} failed`;
    }
    toast(msg);
    $('bulk-source-input').value = '';
    // Show result detail
    const el = $('bulk-result');
    if (d.failed.length > 0) {
      el.innerHTML = '<strong>Failed entries:</strong><br>' + d.failed.map(esc).join('<br>');
      el.classList.remove('hidden');
    } else {
      el.classList.add('hidden');
    }
    loadSources();
  }
}

async function removeSource(addr) {
  await api('/api/sources/' + encodeURIComponent(addr), { method: 'DELETE' });
  toast('Removed');
  loadSources();
}

async function clearSources() {
  if (!confirm('Clear ALL sources? This will open access to everyone.')) return;
  await api('/api/sources/clear', { method: 'POST' });
  toast('All sources cleared');
  loadSources();
}

async function applyFirewall() {
  const d = await api('/api/firewall/apply', { method: 'POST' });
  if (d) toast('Firewall: ' + d.backend);
}

// ── Rules ──

async function loadRules() {
  const d = await api('/api/rules');
  if (!d) return;

  const domains = [];
  const cidrs = [];
  d.entries.forEach((r, i) => {
    r._idx = i;
    if (r.rule_type === 'IP-CIDR' || r.rule_type === 'IP-CIDR6') cidrs.push(r);
    else domains.push(r);
  });

  $('domain-count').textContent = domains.length;
  $('cidr-count').textContent = cidrs.length;

  $('domain-list').innerHTML = renderRuleList(domains, 200);
  $('cidr-list').innerHTML = renderRuleList(cidrs, 200);
}

function renderRuleList(rules, limit) {
  if (rules.length === 0) return '';
  const show = rules.slice(0, limit);
  let html = '';
  show.forEach(r => {
    const tag = tagFor(r.rule_type);
    html += `<div class="rule-item">
      <span><span class="type-tag ${tag.cls}">${tag.label}</span>${esc(r.value)}</span>
      <button class="del-btn" onclick="removeRule(${r._idx})" title="Delete">&times;</button>
    </div>`;
  });
  if (rules.length > limit) {
    html += `<div class="rule-item" style="justify-content:center;color:var(--text2)">… and ${rules.length - limit} more</div>`;
  }
  return html;
}

function tagFor(type) {
  switch (type) {
    case 'DOMAIN-SUFFIX': return { cls: 'tag-suffix', label: 'suffix' };
    case 'DOMAIN': return { cls: 'tag-exact', label: 'exact' };
    case 'DOMAIN-KEYWORD': return { cls: 'tag-keyword', label: 'keyword' };
    case 'IP-CIDR': return { cls: 'tag-cidr', label: 'cidr' };
    case 'IP-CIDR6': return { cls: 'tag-cidr', label: 'cidr6' };
    default: return { cls: '', label: type };
  }
}

async function importText(textarea) {
  const text = textarea.value.trim();
  if (!text) return;
  const d = await api('/api/rules/import', { method: 'POST', body: JSON.stringify({ text }) });
  if (d) {
    toast(`Imported ${d.added} rules (total: ${d.total})`);
    textarea.value = '';
    loadRules();
  }
}

async function removeRule(idx) {
  await api('/api/rules/' + idx, { method: 'DELETE' });
  loadRules();
}

async function clearByType(kind) {
  const d = await api('/api/rules');
  if (!d) return;
  const keep = d.entries.filter(r => {
    const isCidr = r.rule_type === 'IP-CIDR' || r.rule_type === 'IP-CIDR6';
    return kind === 'cidr' ? !isCidr : isCidr;
  });
  await api('/api/rules/clear', { method: 'POST' });
  if (keep.length > 0) {
    await api('/api/rules', { method: 'POST', body: JSON.stringify({ entries: keep }) });
  }
  toast(kind === 'cidr' ? 'CIDRs cleared' : 'Domains cleared');
  loadRules();
}

async function clearAll() {
  if (!confirm('Clear ALL rules?')) return;
  await api('/api/rules/clear', { method: 'POST' });
  toast('All rules cleared');
  loadRules();
}

// ── Services ──

const SVC_COLORS = {
  netflix:'#E50914', disney:'#113CCF', hbo:'#6B3FA0', appletv:'#555',
  primevideo:'#00A8E1', youtube:'#FF0000', spotify:'#1DB954', chatgpt:'#74AA9C',
  sora:'#412991', 'meta-ai':'#0668E1', 'google-ai':'#4285F4', 'apple-ai':'#555',
  claude:'#D97706', 'google-search':'#4285F4', 'google-play':'#01875F',
  steam:'#1B2838', dazn:'#F8F80D', bahamut:'#0681C8', bilibili:'#FB7299',
  tiktok:'#010101', iqiyi:'#00BE06', nhk:'#333', unext:'#08B5FF',
  tver:'#27B5C3', danimestore:'#FF6699', fod:'#EB1C23', radiko:'#00B4E7',
  mytvsuper:'#E60000', jav:'#333',
};

function svcColor(id) { return SVC_COLORS[id] || '#6366f1'; }

function svcInitials(name) {
  if (!name) return '?';
  const words = name.replace(/[^a-zA-Z0-9一-鿿 ]/g, '').split(/\s+/).filter(Boolean);
  if (words.length >= 2) return (words[0][0] + words[1][0]).toUpperCase();
  return name.slice(0, 2).toUpperCase();
}

let _services = [];

async function loadServices() {
  const d = await api('/api/services');
  if (!d) return;
  _services = d;
  renderServiceGrid(d);
  loadExportStatus();
}

function renderServiceGrid(svcs) {
  const grid = $('service-grid');
  if (svcs.length === 0) {
    grid.innerHTML = `<div class="svc-empty">
      <p>No services yet.</p>
      <p class="hint">Click <strong>Load Builtins</strong> to add 30+ pre-configured streaming services,<br>or <strong>+ Add Service</strong> to create a custom one.</p>
    </div>`;
    return;
  }
  let html = '';
  svcs.forEach(s => {
    const color = svcColor(s.id);
    const initials = svcInitials(s.name);
    const domCount = s.domains ? s.domains.length : 0;
    const cidrCount = s.cidrs ? s.cidrs.length : 0;
    const geo = [];
    if (s.geosite) geo.push('geosite:' + s.geosite);
    if (s.geoip) geo.push('geoip:' + s.geoip);
    const meta = [];
    if (domCount) meta.push(domCount + ' domain' + (domCount > 1 ? 's' : ''));
    if (cidrCount) meta.push(cidrCount + ' CIDR' + (cidrCount > 1 ? 's' : ''));
    if (geo.length) meta.push(geo.join(', '));

    const isDark = isColorDark(color);
    html += `<div class="svc-card ${s.enabled ? 'svc-enabled' : 'svc-disabled'}" onclick="openSvcModal('${esc(s.id)}')">
      <div class="svc-card-top">
        <div class="svc-icon" style="background:${color};color:${isDark ? '#fff' : '#222'}">${esc(initials)}</div>
        <label class="toggle" onclick="event.stopPropagation()">
          <input type="checkbox" ${s.enabled ? 'checked' : ''} onchange="toggleService('${esc(s.id)}')">
          <span class="toggle-slider"></span>
        </label>
      </div>
      <div class="svc-card-name">${esc(s.name)}</div>
      <div class="svc-card-meta">${meta.length ? esc(meta.join(' · ')) : '<span class="muted">no rules</span>'}</div>
    </div>`;
  });
  grid.innerHTML = html;
}

function isColorDark(hex) {
  const c = hex.replace('#', '');
  const r = parseInt(c.substr(0, 2), 16);
  const g = parseInt(c.substr(2, 2), 16);
  const b = parseInt(c.substr(4, 2), 16);
  return (r * 0.299 + g * 0.587 + b * 0.114) < 160;
}

async function toggleService(id) {
  const d = await api('/api/services/' + encodeURIComponent(id) + '/toggle', { method: 'POST' });
  if (d) {
    const idx = _services.findIndex(s => s.id === id);
    if (idx >= 0) _services[idx] = d;
    renderServiceGrid(_services);
    loadExportStatus();
    toast(d.name + (d.enabled ? ' enabled' : ' disabled'));
  }
}

async function initServices() {
  const btn = $('init-services-btn');
  btn.disabled = true;
  btn.textContent = 'Loading...';
  const d = await api('/api/services/init', { method: 'POST' });
  btn.disabled = false;
  btn.textContent = 'Load Builtins';
  if (d) {
    toast('Added ' + d.added + ' builtin services');
    loadServices();
  }
}

async function loadExportStatus() {
  const d = await api('/api/export/status');
  if (!d) return;
  const bar = $('export-bar');
  if (d.total_services === 0) { bar.classList.add('hidden'); return; }
  bar.classList.remove('hidden');
  bar.innerHTML = `<div class="export-info">
    <span class="export-dot ${d.enabled_services > 0 ? 'dot-active' : ''}"></span>
    <strong>${d.enabled_services}</strong> / ${d.total_services} services enabled
  </div>
  <div class="export-links">
    <a href="/api/export/dns.json" target="_blank" class="btn btn-sm btn-outline">dns.json</a>
    <a href="/api/export/route.json" target="_blank" class="btn btn-sm btn-outline">route.json</a>
  </div>`;
}

// ── Service Modal ──

let _editingId = null;

function openSvcModal(id) {
  _editingId = id;
  const modal = $('svc-modal');
  const idInput = $('svc-id');

  if (id) {
    const svc = _services.find(s => s.id === id);
    if (!svc) return;
    $('svc-modal-title').textContent = 'Edit Service';
    idInput.value = svc.id;
    idInput.disabled = true;
    $('svc-name').value = svc.name;
    $('svc-domains').value = (svc.domains || []).join('\n');
    $('svc-cidrs').value = (svc.cidrs || []).join('\n');
    $('svc-geosite').value = svc.geosite || '';
    $('svc-geoip').value = svc.geoip || '';
    $('svc-delete-btn').style.display = '';
  } else {
    $('svc-modal-title').textContent = 'New Service';
    idInput.value = '';
    idInput.disabled = false;
    $('svc-name').value = '';
    $('svc-domains').value = '';
    $('svc-cidrs').value = '';
    $('svc-geosite').value = '';
    $('svc-geoip').value = '';
    $('svc-delete-btn').style.display = 'none';
  }
  modal.classList.remove('hidden');
  (id ? $('svc-name') : idInput).focus();
}

function closeSvcModal() {
  $('svc-modal').classList.add('hidden');
  _editingId = null;
}

async function saveService() {
  const id = _editingId || $('svc-id').value.trim();
  if (!id) { toast('ID is required'); return; }
  const name = $('svc-name').value.trim() || id;
  const domains = $('svc-domains').value.split('\n').map(s => s.trim()).filter(Boolean);
  const cidrs = $('svc-cidrs').value.split('\n').map(s => s.trim()).filter(Boolean);
  const geosite = $('svc-geosite').value.trim();
  const geoip = $('svc-geoip').value.trim();

  const existing = _services.find(s => s.id === id);
  const body = {
    id, name, icon: id,
    enabled: existing ? existing.enabled : false,
    domains, cidrs, geosite, geoip,
  };

  const d = await api('/api/services/' + encodeURIComponent(id), {
    method: 'POST',
    body: JSON.stringify(body),
  });
  if (d) {
    toast('Service saved');
    closeSvcModal();
    loadServices();
  }
}

async function deleteServiceFromModal() {
  if (!_editingId) return;
  if (!confirm('Delete this service?')) return;
  await api('/api/services/' + encodeURIComponent(_editingId), { method: 'DELETE' });
  toast('Service deleted');
  closeSvcModal();
  loadServices();
}

// ── Settings ──

async function loadSettings() {
  const d = await api('/api/status');
  if (!d) return;
  $('server-info').innerHTML = `<table class="info-table">
    <tr><td>Version</td><td>${esc(d.version)}</td></tr>
    <tr><td>Unlock Target</td><td>${esc(d.unlock_target)}</td></tr>
    <tr><td>Rules</td><td>${d.rule_count}</td></tr>
    <tr><td>Sources</td><td>${d.source_count}</td></tr>
  </table>`;
}

// ── Helpers ──

function fmt(n) {
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
  if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
  return n.toString();
}

function fmtUptime(s) {
  if (s < 60) return s + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm';
  if (s < 86400) return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm';
  return Math.floor(s / 86400) + 'd ' + Math.floor((s % 86400) / 3600) + 'h';
}

function esc(s) {
  if (!s) return '';
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}
