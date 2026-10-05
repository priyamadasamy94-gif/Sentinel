/**
 * Sentinel database layer (better-sqlite3, synchronous).
 * WHAT: schema creation and every query the app needs.
 * WHY: one module owns all SQL so the rest of the code never builds queries.
 */
const path = require('path');
const Database = require('better-sqlite3');

const DB_PATH = path.join(__dirname, 'sentinel.db');
let db = null;
let mockMode = false;

/** Returns the open connection, opening/initialising it on first use. */
function conn() {
  if (!db) initDb();
  return db;
}

/** Creates sentinel.db and its tables if they do not exist yet. */
function initDb() {
  if (db) return db;
  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL, -- ISO 8601 (new Date().toISOString())
      category TEXT NOT NULL,
      severity TEXT NOT NULL,
      source TEXT,
      description TEXT,
      raw_data TEXT,
      mitre_id TEXT
    );
    CREATE TABLE IF NOT EXISTS whitelist (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT NOT NULL,
      value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS scan_state (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity);
  `);
  return db;
}

/** Records whether the collectors are currently running on synthetic data (shown in summary). */
function setMockMode(value) {
  mockMode = !!value;
}

/** Inserts one event; timestamp defaults to now (ISO 8601). Returns the new row id. */
function insertEvent(event) {
  const e = event || {};
  const raw = e.raw_data && typeof e.raw_data !== 'string' ? JSON.stringify(e.raw_data) : e.raw_data || null;
  const info = conn()
    .prepare(`INSERT INTO events (timestamp, category, severity, source, description, raw_data, mitre_id)
              VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(e.timestamp || new Date().toISOString(), e.category, e.severity, e.source || null,
      e.description || null, raw, e.mitre_id || null);
  return info.lastInsertRowid;
}

/** Newest-first events, optionally filtered by severity. */
function getEvents(limit = 100, severity = null) {
  const lim = Math.max(1, Math.min(1000, Number(limit) || 100));
  if (severity) {
    return conn().prepare('SELECT * FROM events WHERE severity = ? ORDER BY timestamp DESC, id DESC LIMIT ?')
      .all(String(severity).toUpperCase(), lim);
  }
  return conn().prepare('SELECT * FROM events ORDER BY timestamp DESC, id DESC LIMIT ?').all(lim);
}

/** Severity counts, last scan time and total for the stat cards. */
function getSummary() {
  const rows = conn().prepare('SELECT severity, COUNT(*) AS c FROM events GROUP BY severity').all();
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  let total = 0;
  for (const r of rows) {
    if (r.severity in counts) counts[r.severity] = r.c;
    total += r.c;
  }
  const last = conn().prepare('SELECT MAX(timestamp) AS t FROM events').get();
  return {
    critical: counts.CRITICAL,
    high: counts.HIGH,
    medium: counts.MEDIUM,
    low: counts.LOW,
    last_scan: last.t || null,
    mock_mode: mockMode,
    total
  };
}

/** Event counts for each of the last 24 hours (oldest first, zero-filled). */
function getEventsPerHour() {
  const now = new Date();
  now.setMinutes(0, 0, 0);
  const start = new Date(now.getTime() - 23 * 3600 * 1000);
  const rows = conn().prepare(`SELECT substr(timestamp, 1, 13) AS h, COUNT(*) AS c
                               FROM events WHERE timestamp >= ? GROUP BY h`).all(start.toISOString());
  const map = new Map(rows.map((r) => [r.h, r.c]));
  const out = [];
  for (let i = 0; i < 24; i++) {
    const d = new Date(start.getTime() + i * 3600 * 1000);
    const key = d.toISOString().slice(0, 13);
    out.push({ hour: key + ':00Z', count: map.get(key) || 0 });
  }
  return out;
}

/** Number of failed-login events from an IP in the last N minutes (used for severity scoring). */
function countRecentFailedLogins(ip, minutes = 10) {
  const since = new Date(Date.now() - minutes * 60000).toISOString();
  return conn().prepare(`SELECT COUNT(*) AS c FROM events
                         WHERE category = 'failed_login' AND source = ? AND timestamp >= ?`).get(ip, since).c;
}

/** Adds a whitelist entry (type: ip | process | port). Returns its id; ignores duplicates. */
function addWhitelist(type, value) {
  const v = String(value);
  const existing = conn().prepare('SELECT id FROM whitelist WHERE type = ? AND value = ?').get(type, v);
  if (existing) return existing.id;
  return conn().prepare('INSERT INTO whitelist (type, value) VALUES (?, ?)').run(type, v).lastInsertRowid;
}

/** True when type/value is on the whitelist. */
function isWhitelisted(type, value) {
  return !!conn().prepare('SELECT 1 FROM whitelist WHERE type = ? AND value = ?').get(type, String(value));
}

/** All whitelist entries. */
function getWhitelist() {
  return conn().prepare('SELECT * FROM whitelist ORDER BY id DESC').all();
}

/** Removes a whitelist entry by id; returns true if a row was deleted. */
function removeWhitelist(id) {
  return conn().prepare('DELETE FROM whitelist WHERE id = ?').run(Number(id)).changes > 0;
}

/** Saves a JSON snapshot (e.g. the latest port scan) so the API can serve it after restarts. */
function setState(key, value) {
  conn().prepare(`INSERT INTO scan_state (key, value, updated) VALUES (?, ?, ?)
                  ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated = excluded.updated`)
    .run(key, JSON.stringify(value), new Date().toISOString());
}

/** Reads a snapshot saved by setState; returns {data, updated} or null. */
function getState(key) {
  const row = conn().prepare('SELECT value, updated FROM scan_state WHERE key = ?').get(key);
  return row ? { data: JSON.parse(row.value), updated: row.updated } : null;
}

module.exports = {
  initDb, insertEvent, getEvents, getSummary, getEventsPerHour, addWhitelist,
  isWhitelisted, getWhitelist, removeWhitelist, countRecentFailedLogins, setMockMode, setState, getState
};
