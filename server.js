/**
 * Sentinel server.
 * WHAT: Express app serving the dashboard + JSON API, with a node-cron job that scans every minute.
 * WHY: ties collectors, database and UI together; one `node server.js` runs everything.
 */
const path = require('path');
const express = require('express');
const cron = require('node-cron');
const db = require('./database');
const collectors = require('./collectors');

const PORT = 3000;
const VALID_TYPES = ['ip', 'process', 'port'];
const VALID_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

const app = express();
app.use(express.json());
app.use('/static', express.static(path.join(__dirname, 'static')));

/** Wraps an async route so any error becomes a clean 500 (no stack traces leak to the client). */
function route(handler) {
  return async (req, res) => {
    try {
      await handler(req, res);
    } catch (err) {
      console.error(`[Sentinel] ${req.method} ${req.path} failed: ${err.message}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  };
}

/** True while a scan is running, so overlapping scans (cron + button) are not stacked. */
let scanning = null;

/** Runs a scan, sharing the in-flight promise if one is already running. */
function scanOnce() {
  if (!scanning) scanning = collectors.runAll().finally(() => { scanning = null; });
  return scanning;
}

app.get('/', route((req, res) => {
  res.sendFile(path.join(__dirname, 'templates', 'dashboard.html'));
}));

app.get('/api/summary', route((req, res) => {
  res.json({ ...db.getSummary(), mock_mode: collectors.isMockMode() });
}));

/** True when an event matches a whitelist entry (ip / process / port), so the UI can hide it. */
function isEventWhitelisted(e) {
  if (e.category === 'failed_login') return db.isWhitelisted('ip', e.source);
  if (e.category === 'suspicious_proc') return db.isWhitelisted('process', String(e.source).toLowerCase().replace(/\.exe$/, ''));
  if (e.category === 'open_port') {
    try { return db.isWhitelisted('port', JSON.parse(e.raw_data).port); } catch (_) { return false; }
  }
  return false;
}

app.get('/api/events', route((req, res) => {
  const { severity } = req.query;
  if (severity !== undefined && !VALID_SEVERITIES.includes(String(severity).toUpperCase())) {
    return res.status(400).json({ error: `severity must be one of ${VALID_SEVERITIES.join(', ')}` });
  }
  const rows = db.getEvents(500, severity ? String(severity).toUpperCase() : null);
  res.json(rows.filter((e) => !isEventWhitelisted(e)).slice(0, 100));
}));

app.get('/api/ports', route(async (req, res) => {
  res.json(await collectors.getPorts());
}));

app.get('/api/processes', route(async (req, res) => {
  res.json(await collectors.getProcesses());
}));

app.get('/api/chart', route((req, res) => {
  res.json(db.getEventsPerHour());
}));

app.get('/api/whitelist', route((req, res) => {
  res.json(db.getWhitelist());
}));

app.post('/api/whitelist', route((req, res) => {
  const { type, value } = req.body || {};
  if (!VALID_TYPES.includes(type)) return res.status(400).json({ error: `type must be one of ${VALID_TYPES.join(', ')}` });
  if (value === undefined || value === null || String(value).trim() === '' || String(value).length > 200) {
    return res.status(400).json({ error: 'value is required (max 200 chars)' });
  }
  const id = db.addWhitelist(type, String(value).trim());
  res.status(201).json({ id: Number(id), type, value: String(value).trim() });
}));

app.delete('/api/whitelist/:id', route((req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return res.status(400).json({ error: 'invalid id' });
  if (!db.removeWhitelist(id)) return res.status(404).json({ error: 'not found' });
  res.json({ deleted: id });
}));

app.post('/api/scan', route(async (req, res) => {
  const t0 = Date.now();
  const r = await scanOnce();
  res.json({ inserted: r.inserted, took_ms: Date.now() - t0 });
}));

/** Boots DB, probes real log access (decides mock mode), starts cron and the HTTP server. */
async function main() {
  db.initDb();
  await collectors.probe();
  const task = cron.schedule('* * * * *', () => {
    scanOnce().catch((err) => console.error(`[Sentinel] scheduled scan failed: ${err.message}`));
  });
  await scanOnce();

  const server = app.listen(PORT, () => {
    console.log('═══════════════════════════════════════');
    console.log(` Sentinel running on http://localhost:${PORT}`);
    console.log(` Mode: ${collectors.isMockMode() ? 'MOCK' : 'REAL'}`);
    console.log('═══════════════════════════════════════');
  });
  server.on('error', (err) => {
    console.error(`[Sentinel] cannot listen on port ${PORT}: ${err.message}`);
    task.stop();
    process.exit(1);
  });

  process.on('SIGINT', () => {
    console.log('\n[Sentinel] shutting down');
    task.stop();
    server.close(() => process.exit(0));
  });
}

main().catch((err) => {
  console.error(`[Sentinel] fatal: ${err.message}`);
  process.exit(1);
});
