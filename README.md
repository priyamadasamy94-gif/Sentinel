# Sentinel — Local Threat Monitor

Sentinel is a small self-hosted dashboard that watches your own computer for suspicious activity, saves what it finds in a local database and shows it on a live web page. Think of it as a "mini SIEM for one computer".

## Why it matters
If someone is trying to hack your machine — guessing passwords over SSH, opening a strange port, or running a tool like `nmap` or `mimikatz` — the evidence is scattered across logs and process lists nobody reads. Sentinel collects it, scores how serious it is, tags it with a MITRE ATT&CK technique and puts it in one place. It is 100% local and works offline.

## Features
- Failed-login detection (Linux `/var/log/auth.log`, Windows Event ID 4625)
- Listening-port audit against an allow-list
- Running-process scan against a hacking-tool watchlist
- Severity scoring: LOW / MEDIUM / HIGH / CRITICAL
- MITRE ATT&CK tagging of every finding
- SQLite storage, scan every 60 seconds (or on demand)
- Live dark-theme dashboard: stat cards, 24h chart, alerts table with severity filter, ports and processes panels
- One-click whitelist for IPs, processes and ports
- Automatic **Mock Mode** when real logs are unavailable

## MITRE ATT&CK mapping
| Category | Technique | Name |
|---|---|---|
| failed_login | T1110 | Brute Force |
| open_port | T1046 | Network Service Discovery |
| suspicious_proc | T1059 | Command and Scripting Interpreter |
| firewall_off | T1562 | Impair Defenses |

## Install & run
1. Install Node.js 20 or newer.
2. `cd sentinel`
3. `npm install`
4. `node server.js`
5. Open http://localhost:3000

On Linux, run with `sudo` (or make `/var/log/auth.log` readable) for real login data; on Windows, run from an Administrator terminal.

## Screenshots
- `docs/dashboard.png` — _placeholder: full dashboard_
- `docs/mobile.png` — _placeholder: mobile layout_

## Architecture
```
 +-------------+     +-----------+     +--------------+     +-----------+
 | collectors  | --> |  SQLite   | --> | Express API  | --> | Dashboard |
 | logins      |     | sentinel  |     | /api/*       |     | HTML/JS   |
 | ports       |     |   .db     |     | + node-cron  |     | Chart.js  |
 | processes   |     +-----------+     +--------------+     +-----------+
 +-------------+          ^                   |
        ^                 +----- scoring -----+ (severity + MITRE tag applied before insert)
   OS logs / ports / process list
```

## Mock Mode explained
If Sentinel cannot read real security logs (no permission, file missing, or macOS), it switches to Mock Mode automatically and prints:
`[!] MOCK MODE ACTIVE — using synthetic data (no real logs available)`
It then generates realistic fake failed logins (including a persistent attacker IP so HIGH/CRITICAL alerts appear), occasionally flags a real process as suspicious and occasionally reports an unexpected port. Port and process lists still come from your real machine. Mock events are labelled `[mock]` and have `"mock": true` in `raw_data`. The dashboard shows a pulsing orange MOCK MODE badge.

## Configuration
Edit `config.js` for thresholds, `PROCESS_WATCHLIST`, `ALLOWED_PORTS` and MITRE IDs.

## Notes
- Whitelisting hides matching alerts and suppresses future ones; historical counts on the stat cards are unchanged.
- Listening ports are listed via `/proc/net/tcp` (Linux), `netstat` (Windows) or `lsof` (macOS); `find-process` then resolves the owning process. Owner names may show as `unknown` without elevated privileges.
- `winevtx` parses `.evtx` files, so on Windows Sentinel reads `Security.evtx` directly. It is an optional dependency.
- Chart.js loads from the CDN, with a bundled copy in `static/chart.umd.js` used when offline.

## Roadmap — what to add next
- ML-based anomaly detection on login patterns
- Email / webhook alerts for CRITICAL events
- Cloud deployment and multi-host collection
