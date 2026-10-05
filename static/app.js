/* Sentinel dashboard logic. WHAT: fetches the API, renders panels, handles scan/whitelist/filter.
   WHY: vanilla JS keeps the project dependency-free and fully offline-capable. */
(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const state = { lastScan: null, chart: null, shown: { critical: 0, high: 0, medium: 0, low: 0 } };

  /** Escapes text before it goes into innerHTML — log data (usernames etc.) is attacker-controlled. */
  function esc(v) {
    return String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  /** GET JSON helper that throws on non-2xx. */
  async function getJSON(url) {
    const r = await fetch(url);
    if (!r.ok) throw new Error(url + ' -> ' + r.status);
    return r.json();
  }

  /** Animates a stat number from its current value to the new one. */
  function countUp(el, key, to) {
    const from = state.shown[key];
    if (from === to) return;
    state.shown[key] = to;
    const t0 = performance.now();
    const dur = 600;
    (function tick(now) {
      const p = Math.min(1, (now - t0) / dur);
      el.textContent = Math.round(from + (to - from) * p);
      if (p < 1) requestAnimationFrame(tick);
    })(t0);
  }

  /** Updates the sticky clock and the "Last scan: Xs ago" label every second. */
  function tickClock() {
    $('clock').textContent = new Date().toLocaleTimeString();
    if (state.lastScan) {
      const s = Math.max(0, Math.round((Date.now() - new Date(state.lastScan).getTime()) / 1000));
      $('lastScan').textContent = 'Last scan: ' + (s < 120 ? s + 's' : Math.round(s / 60) + 'm') + ' ago';
    }
  }

  /** Stat cards + mock badge. */
  async function loadSummary() {
    const s = await getJSON('/api/summary');
    ['critical', 'high', 'medium', 'low'].forEach((k) => countUp($('n-' + k), k, s[k]));
    state.lastScan = s.last_scan;
    $('mockBadge').hidden = !s.mock_mode;
  }

  /** Decides what whitelisting a given event means: {type, value} or null when not applicable. */
  function whitelistTarget(e) {
    if (e.category === 'failed_login') return { type: 'ip', value: e.source };
    if (e.category === 'suspicious_proc') return { type: 'process', value: String(e.source).toLowerCase().replace(/\.exe$/, '') };
    if (e.category === 'open_port') {
      try { return { type: 'port', value: String(JSON.parse(e.raw_data).port) }; } catch (_) { return null; }
    }
    return null;
  }

  /** Alerts table (newest first, as returned by the API). */
  async function loadEvents() {
    const events = await getJSON('/api/events');
    const body = document.querySelector('#alerts tbody');
    body.innerHTML = events.map((e) => {
      const t = whitelistTarget(e);
      const btn = t ? `<button class="wl" data-type="${esc(t.type)}" data-value="${esc(t.value)}">Add to Whitelist</button>` : '';
      const mitre = e.mitre_id
        ? `<a class="pill" target="_blank" rel="noopener" href="https://attack.mitre.org/techniques/${esc(e.mitre_id)}/">${esc(e.mitre_id)}</a>` : '';
      return `<tr data-sev="${esc(e.severity)}">
        <td class="time">${esc(new Date(e.timestamp).toLocaleString())}</td>
        <td><span class="badge ${esc(e.severity)}">${esc(e.severity)}</span></td>
        <td class="c-cat">${esc(e.category)}</td>
        <td class="desc">${esc(e.description)}</td>
        <td class="c-mitre">${mitre}</td>
        <td>${btn}</td></tr>`;
    }).join('');
    applyFilter();
  }

  /** Client-side severity filter over the loaded rows. */
  function applyFilter() {
    const want = $('sevFilter').value;
    let visible = 0;
    document.querySelectorAll('#alerts tbody tr').forEach((tr) => {
      const show = !want || tr.dataset.sev === want;
      tr.hidden = !show;
      if (show) visible++;
    });
    $('empty').hidden = visible > 0;
  }

  /** Bar chart of events per hour; created once, then updated in place. */
  async function loadChart() {
    const rows = await getJSON('/api/chart');
    const labels = rows.map((r) => new Date(r.hour).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
    const data = rows.map((r) => r.count);
    if (!window.Chart) return;
    if (state.chart) {
      state.chart.data.labels = labels;
      state.chart.data.datasets[0].data = data;
      state.chart.update();
      return;
    }
    const grid = { color: '#30363d' };
    const ticks = { color: '#8b949e' };
    state.chart = new Chart($('chart'), {
      type: 'bar',
      data: { labels, datasets: [{ label: 'Events', data, backgroundColor: '#00d4ff', borderRadius: 4 }] },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { x: { grid: grid, ticks: ticks }, y: { beginAtZero: true, grid: grid, ticks: { ...ticks, precision: 0 }, title: { display: true, text: 'Events', color: '#8b949e' } } }
      }
    });
  }

  /** Open ports table. */
  async function loadPorts() {
    const ports = await getJSON('/api/ports');
    document.querySelector('#ports tbody').innerHTML = ports.map((p) =>
      `<tr><td>${esc(p.port)}</td><td>${esc(p.process_name)}</td><td class="c-pid">${esc(p.pid ?? '—')}</td>
       <td>${p.allowed ? '✅ allowed' : '⚠️ unknown'}</td></tr>`).join('');
  }

  /** Running processes table; watchlist hits first, then by CPU. */
  async function loadProcesses() {
    const procs = (await getJSON('/api/processes')).slice()
      .sort((a, b) => (b.suspicious - a.suspicious) || (b.cpu - a.cpu)).slice(0, 150);
    document.querySelector('#procs tbody').innerHTML = procs.map((p) =>
      `<tr><td class="c-pid">${esc(p.pid)}</td><td>${esc(p.name)}</td><td>${esc(p.cpu)}</td>
       <td class="c-mem">${esc(p.memory)}</td><td>${p.suspicious ? '🔴 watchlist' : 'ok'}</td></tr>`).join('');
  }

  /** Refreshes every panel in parallel; charts only when asked (60s cadence). */
  async function refresh(includeChart) {
    const jobs = [loadSummary(), loadEvents(), loadPorts(), loadProcesses()];
    if (includeChart) jobs.push(loadChart());
    const results = await Promise.allSettled(jobs);
    results.filter((r) => r.status === 'rejected').forEach((r) => console.error('[Sentinel UI]', r.reason));
    $('refreshed').textContent = 'Last refresh: ' + new Date().toLocaleTimeString();
  }

  /** Scan Now: disable, spin, POST, then force refresh. */
  async function scanNow() {
    const btn = $('scanBtn');
    btn.disabled = true;
    btn.querySelector('.spinner').hidden = false;
    btn.querySelector('.label').textContent = 'Scanning…';
    try {
      const r = await fetch('/api/scan', { method: 'POST' });
      if (!r.ok) throw new Error('scan failed: ' + r.status);
      await refresh(true);
    } catch (err) {
      console.error('[Sentinel UI]', err);
    } finally {
      btn.disabled = false;
      btn.querySelector('.spinner').hidden = true;
      btn.querySelector('.label').textContent = 'Scan Now';
    }
  }

  /** Whitelist click (delegated): POST, fade the row out, then remove it from the DOM. */
  document.querySelector('#alerts tbody').addEventListener('click', async (ev) => {
    const b = ev.target.closest('.wl');
    if (!b) return;
    b.disabled = true;
    try {
      const r = await fetch('/api/whitelist', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: b.dataset.type, value: b.dataset.value })
      });
      if (!r.ok) throw new Error('whitelist failed: ' + r.status);
      const tr = b.closest('tr');
      tr.classList.add('fading');
      setTimeout(() => { tr.remove(); applyFilter(); }, 450);
    } catch (err) {
      console.error('[Sentinel UI]', err);
      b.disabled = false;
    }
  });

  $('scanBtn').addEventListener('click', scanNow);
  $('sevFilter').addEventListener('change', applyFilter);

  tickClock();
  setInterval(tickClock, 1000);
  refresh(true);
  setInterval(() => refresh(false), 10000);
  setInterval(() => loadChart().catch((e) => console.error('[Sentinel UI]', e)), 60000);
})();
