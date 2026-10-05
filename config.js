/**
 * Sentinel configuration.
 * WHAT: central place for severity rules, watchlists, allowed ports and MITRE mappings.
 * WHY: keeping rules out of the logic lets you tune detection without touching code.
 */

/** Thresholds and fixed severities used by the scoring engine. */
const SEVERITY_RULES = {
  failed_login_threshold_high: 5, // same IP within 10 minutes -> HIGH
  failed_login_threshold_crit: 20, // same IP within 10 minutes -> CRITICAL
  watchlist_hit: 'HIGH',
  unknown_port: 'MEDIUM',
  default: 'LOW'
};

/** Process names that are commonly used for attacks or recon. */
const PROCESS_WATCHLIST = [
  'nmap', 'netcat', 'nc', 'hydra', 'john', 'hashcat', 'mimikatz',
  'tcpdump', 'wireshark', 'ettercap', 'aircrack', 'msfconsole',
  'sqlmap', 'burpsuite'
];

/** Listening ports considered normal; anything else is a MEDIUM finding. */
const ALLOWED_PORTS = [22, 80, 443, 3000, 5000, 5432, 8080];

/** Event category -> MITRE ATT&CK technique id. */
const MITRE_MAP = {
  failed_login: 'T1110', // Brute Force
  open_port: 'T1046', // Network Service Discovery
  suspicious_proc: 'T1059', // Command & Scripting Interpreter
  firewall_off: 'T1562' // Impair Defenses
};

module.exports = { SEVERITY_RULES, PROCESS_WATCHLIST, ALLOWED_PORTS, MITRE_MAP };
