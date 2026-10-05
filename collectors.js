/**
 * Sentinel collectors.
 * WHAT: gathers failed logins, listening ports, processes and host info, scores each finding,
 *       and stores it. WHY: this is the "sensor" half of the mini-SIEM; everything else reads
 *       what these functions write.
 *
 * MOCK MODE: when real logs are unreachable (no permission / unsupported OS) the failed-login,
 * process-flag and port findings fall back to realistic synthetic data so the dashboard is
 * always demonstrable. Every synthetic event carries raw_data.mock = true.
 */
const fs = require('fs');
const os = require('os');
const { execFile } = require('child_process');
const findProcess = require('find-process');
const db = require('./database');
const { SEVERITY_RULES, PROCESS_WATCHLIST, ALLOWED_PORTS, MITRE_MAP } = require('./config');

const AUTH_LOG = '/var/log/auth.log';
const WIN_SECURITY_LOG = 'C:\\Windows\\System32\\winevt\\Logs\\Security.evtx';

let MOCK_MODE = false;
let bannerShown = false;
let cycle = 0;
let authOffset = null; // byte offset already consumed in auth.log
let lastProcesses = [];
let lastPorts = [];
const seenPorts = new Set(); // ports already alerted on (re-alert only if they disappear and return)
const seenProcs = new Set(); // "pid:name" already alerted on

/** Returns true while synthetic data is in use. */
function isMockMode() {
  return MOCK_MODE;
}

/** Switches to mock mode (once), prints the banner and tells the DB layer. */
function enableMock(reason) {
  MOCK_MODE = true;
  db.setMockMode(true);
  if (!bannerShown) {
    bannerShown = true;
    console.log('[!] MOCK MODE ACTIVE — using synthetic data (no real logs available)');
    if (reason) console.log(`    reason: ${reason}`);
  }
}

/** Runs a command and resolves with stdout (empty string on failure; never rejects). */
function run(cmd, args) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: 8000, maxBuffer: 8 * 1024 * 1024 }, (err, stdout) => resolve(err ? '' : stdout));
  });
}

/** Random integer in [min, max]. */
function rnd(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

/** Synthetic failed logins: one persistent attacker plus random others so every severity can occur. */
function mockFailedLogins() {
  const pool = ['185.220.101.', '45.142.212.', '193.32.162.', '91.240.118.'];
  const users = ['root', 'admin', 'ubuntu', 'postgres', 'test', 'oracle'];
  const out = [];
  const n = rnd(2, 8);
  for (let i = 0; i < n; i++) {
    const ip = Math.random() < 0.5 ? '185.220.101.14' : pool[rnd(0, pool.length - 1)] + rnd(1, 254);
    out.push({ ip, timestamp: new Date().toISOString(), user: users[rnd(0, users.length - 1)], mock: true });
  }
  return out;
}

/** Pulls source IP / user / event id out of a parsed EVTX record without assuming a fixed shape. */
function readEvtxRecord(rec) {
  const text = JSON.stringify(rec.event || rec);
  if (!/"EventID"[^0-9]{0,40}4625/.test(text)) return null;
  const ip = (text.match(/"IpAddress"[^0-9a-fA-F:.]{0,40}([0-9a-fA-F:.]+)/) || [])[1] || '-';
  const user = (text.match(/"TargetUserName"[^"]*"[^"]*"[^"]*"([^"]+)"/) || [])[1] || 'unknown';
  return { ip, user };
}

/**
 * Failed-login collector.
 * Windows: parses Security.evtx with winevtx for Event ID 4625 (needs admin).
 * Linux: tails /var/log/auth.log for "Failed password ... from <ip>".
 * Anything else / no access: mock mode.
 * Returns [{ ip, timestamp, user }].
 */
async function collectFailedLogins() {
  try {
    const platform = os.platform();
    if (platform === 'linux') {
      const fd = fs.openSync(AUTH_LOG, 'r');
      try {
        const size = fs.fstatSync(fd).size;
        if (authOffset === null || authOffset > size) authOffset = Math.max(0, size - 65536);
        const buf = Buffer.alloc(size - authOffset);
        fs.readSync(fd, buf, 0, buf.length, authOffset);
        authOffset = size;
        const out = [];
        for (const line of buf.toString('utf8').split('\n')) {
          const m = line.match(/Failed password.*from (\d+\.\d+\.\d+\.\d+)/);
          if (!m) continue;
          const u = line.match(/Failed password for (?:invalid user )?(\S+)/);
          out.push({ ip: m[1], timestamp: new Date().toISOString(), user: u ? u[1] : 'unknown' });
        }
        return out;
      } finally {
        fs.closeSync(fd);
      }
    }
    if (platform === 'win32') {
      const { parseEvtxFile } = require('winevtx');
      const out = [];
      for (const rec of parseEvtxFile(fs.readFileSync(WIN_SECURITY_LOG))) {
        const hit = readEvtxRecord(rec);
        if (hit) out.push({ ip: hit.ip, timestamp: new Date().toISOString(), user: hit.user });
      }
      return out.slice(-200);
    }
    enableMock(`unsupported platform: ${platform}`);
    return mockFailedLogins();
  } catch (err) {
    if (!MOCK_MODE) console.error(`[Sentinel] collectFailedLogins failed: ${err.message}`);
    enableMock(err.code === 'EACCES' || err.code === 'EPERM' ? 'permission denied reading auth log' : err.message);
    return mockFailedLogins();
  }
}

/** Lists listening TCP port numbers using the OS's own tables (find-process cannot enumerate). */
async function listListeningPorts() {
  const ports = new Set();
  const platform = os.platform();
  if (platform === 'linux') {
    for (const f of ['/proc/net/tcp', '/proc/net/tcp6']) {
      try {
        for (const line of fs.readFileSync(f, 'utf8').split('\n').slice(1)) {
          const c = line.trim().split(/\s+/);
          if (c[3] === '0A') ports.add(parseInt(c[1].split(':')[1], 16)); // 0A = LISTEN
        }
      } catch (e) { /* table not present */ }
    }
  } else if (platform === 'win32') {
    for (const line of (await run('netstat', ['-ano', '-p', 'tcp'])).split('\n')) {
      const m = line.match(/LISTENING/) && line.trim().split(/\s+/)[1];
      if (m) ports.add(parseInt(m.split(':').pop(), 10));
    }
  } else {
    for (const line of (await run('lsof', ['-iTCP', '-sTCP:LISTEN', '-nP'])).split('\n').slice(1)) {
      const m = line.match(/:(\d+) \(LISTEN\)/);
      if (m) ports.add(parseInt(m[1], 10));
    }
  }
  return [...ports].filter((p) => Number.isFinite(p)).sort((a, b) => a - b);
}

/** Open-port collector: enumerates listening ports and resolves owner via find-process. */
async function collectOpenPorts() {
  try {
    const result = [];
    for (const port of await listListeningPorts()) {
      let pid = null;
      let name = 'unknown';
      try {
        const found = await findProcess('port', port);
        if (found && found[0]) {
          pid = found[0].pid;
          name = found[0].name || 'unknown';
        }
      } catch (e) { /* owner not visible without privileges */ }
      result.push({ port, pid, process_name: name, allowed: ALLOWED_PORTS.includes(port) });
    }
    if (MOCK_MODE && cycle % 5 === 0) {
      result.push({ port: [4444, 31337, 6667, 9001][rnd(0, 3)], pid: rnd(2000, 9000), process_name: 'nc', allowed: false, mock: true });
    }
    return result;
  } catch (err) {
    console.error(`[Sentinel] collectOpenPorts failed: ${err.message}`);
    return [];
  }
}

/** Process collector via ps-list (ESM-only, loaded with dynamic import). Flags watchlist matches. */
async function collectProcesses() {
  try {
    const { default: psList } = await import('ps-list');
    const list = await psList();
    const out = list.map((p) => {
      const base = String(p.name || '').toLowerCase().replace(/\.exe$/, '');
      return {
        pid: p.pid,
        name: p.name,
        cpu: typeof p.cpu === 'number' ? Math.round(p.cpu * 10) / 10 : 0,
        memory: typeof p.memory === 'number' ? Math.round(p.memory * 10) / 10 : 0,
        suspicious: PROCESS_WATCHLIST.includes(base)
      };
    });
    if (MOCK_MODE && out.length && Math.random() < 0.5) {
      const pick = out[rnd(0, out.length - 1)];
      pick.suspicious = true;
      pick.mock = true;
    }
    return out;
  } catch (err) {
    console.error(`[Sentinel] collectProcesses failed: ${err.message}`);
    return [];
  }
}

/** Host info collector: hostname, platform, uptime. */
function collectHostStatus() {
  try {
    return { hostname: os.hostname(), platform: os.platform(), uptime_seconds: Math.floor(os.uptime()) };
  } catch (err) {
    console.error(`[Sentinel] collectHostStatus failed: ${err.message}`);
    return { hostname: 'unknown', platform: 'unknown', uptime_seconds: 0 };
  }
}

/** Maps failed-login count within the window to a severity using SEVERITY_RULES. */
function scoreLogin(count) {
  if (count > SEVERITY_RULES.failed_login_threshold_crit) return 'CRITICAL';
  if (count > SEVERITY_RULES.failed_login_threshold_high) return 'HIGH';
  return SEVERITY_RULES.default;
}

/** Inserts an event and bumps the counter, swallowing DB errors so scans never crash. */
function store(event, counter) {
  try {
    db.insertEvent(event);
    counter.n++;
  } catch (err) {
    console.error(`[Sentinel] insertEvent failed: ${err.message}`);
  }
}

/**
 * Runs every collector once, scores results and stores events.
 * Never throws. Returns { inserted, mock_mode }.
 */
async function runAll() {
  const counter = { n: 0 };
  cycle++;
  try {
    db.initDb();

    // Failed logins: score by how many from the same IP in the last 10 minutes (incl. this batch).
    const logins = await collectFailedLogins();
    for (const l of logins) {
      if (db.isWhitelisted('ip', l.ip)) continue;
      const count = db.countRecentFailedLogins(l.ip, 10) + 1;
      store({
        timestamp: l.timestamp, category: 'failed_login', severity: scoreLogin(count), source: l.ip,
        description: `Failed login for "${l.user}" from ${l.ip} (${count} in last 10 min)${l.mock ? ' [mock]' : ''}`,
        raw_data: l, mitre_id: MITRE_MAP.failed_login
      }, counter);
    }

    // Ports: alert on first sight of each listening port; unknown = MEDIUM, known = LOW.
    const ports = await collectOpenPorts();
    lastPorts = ports;
    const nowPorts = new Set(ports.map((p) => p.port));
    for (const p of seenPorts) if (!nowPorts.has(p)) seenPorts.delete(p);
    for (const p of ports) {
      if (seenPorts.has(p.port) || db.isWhitelisted('port', p.port)) continue;
      seenPorts.add(p.port);
      store({
        category: 'open_port', severity: p.allowed ? SEVERITY_RULES.default : SEVERITY_RULES.unknown_port,
        source: `port ${p.port}`, mitre_id: MITRE_MAP.open_port, raw_data: p,
        description: `${p.allowed ? 'Listening' : 'Unexpected listening'} port ${p.port} (${p.process_name}, pid ${p.pid ?? '?'})${p.mock ? ' [mock]' : ''}`
      }, counter);
    }

    // Processes: only watchlist hits become events (the full list is served live to the UI).
    const procs = await collectProcesses();
    lastProcesses = procs;
    for (const p of procs.filter((x) => x.suspicious)) {
      const key = `${p.pid}:${p.name}`;
      const base = String(p.name).toLowerCase().replace(/\.exe$/, '');
      if (seenProcs.has(key) || db.isWhitelisted('process', base)) continue;
      seenProcs.add(key);
      store({
        category: 'suspicious_proc', severity: SEVERITY_RULES.watchlist_hit, source: p.name,
        mitre_id: MITRE_MAP.suspicious_proc, raw_data: p,
        description: `Watchlisted process "${p.name}" running (pid ${p.pid})${p.mock ? ' [mock]' : ''}`
      }, counter);
    }

    // Host heartbeat: one LOW event per scan so the "last scan" time and chart always move.
    const host = collectHostStatus();
    store({
      category: 'host_status', severity: SEVERITY_RULES.default, source: host.hostname, raw_data: host,
      description: `Host ${host.hostname} (${host.platform}) up ${Math.floor(host.uptime_seconds / 60)} min`
    }, counter);
  } catch (err) {
    console.error(`[Sentinel] runAll failed: ${err.message}`);
  }
  return { inserted: counter.n, mock_mode: MOCK_MODE };
}

/**
 * Startup probe: tries the real log source once so mock mode (and its banner) is decided before
 * the first scan or the first API call. Does not store anything.
 */
async function probe() {
  await collectFailedLogins();
  authOffset = null; // let the first real scan read the recent tail of the log
  return MOCK_MODE;
}

/** Returns the most recent port scan (live collect if none yet). */
async function getPorts() {
  if (!lastPorts.length) lastPorts = await collectOpenPorts();
  return lastPorts;
}

/** Returns the most recent process list (live collect if none yet). */
async function getProcesses() {
  if (!lastProcesses.length) lastProcesses = await collectProcesses();
  return lastProcesses;
}

module.exports = {
  runAll, probe, isMockMode, collectFailedLogins, collectOpenPorts, collectProcesses,
  collectHostStatus, getPorts, getProcesses
};
