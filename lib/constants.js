const path = require('path');

/** Config PM2 in produzione: centralizzato + SmartShell separato. */
const ECOSYSTEM_CENTRAL = '/home/ubuntu/ecosystem.config.js';
const ECOSYSTEM_SMARTSHELL = '/home/ubuntu/SmartShellTerminal/ecosystem.config.cjs';
const ECOSYSTEM_TIBERI = '/home/ubuntu/TiberiStudio/ecosystem.config.js';
const ECOSYSTEM_DRUMTEACHER = '/home/ubuntu/DrumTeacher/server/ecosystem.config.cjs';

const ECOSYSTEMS = [
  { path: ECOSYSTEM_CENTRAL, name: 'padel-tour' },
  { path: ECOSYSTEM_CENTRAL, name: 'roma-buche' },
  { path: ECOSYSTEM_CENTRAL, name: 'gestione-veicoli' },
  { path: ECOSYSTEM_CENTRAL, name: 'mattgame' },
  { path: ECOSYSTEM_CENTRAL, name: 'mattgame-ogar' },
  { path: ECOSYSTEM_CENTRAL, name: 'control-room' },
  { path: ECOSYSTEM_CENTRAL, name: 'jethealth' },
  { path: ECOSYSTEM_SMARTSHELL, name: 'smartshell-api' },
  { path: ECOSYSTEM_TIBERI, name: 'tiberi-next' },
  { path: ECOSYSTEM_TIBERI, name: 'tiberi-v2' },
  { path: ECOSYSTEM_DRUMTEACHER, name: 'drumteacher-api' },
];

const WEB_SITES = [
  { name: 'Banana Padel Tour', url: 'https://bananapadeltour.duckdns.org', port: 3000, pm2: 'padel-tour', kind: 'app' },
  {
    name: 'Roma-Buche',
    url: 'https://ibuche.duckdns.org',
    port: 3001,
    pm2: 'roma-buche',
    kind: 'app',
    // PM2 gira da .next/standalone; git/.env stanno nella root del repo
    repoRoot: '/home/ubuntu/Roma-Buche',
  },
  { name: 'Gestione Veicoli', url: 'https://gestione-veicoli.duckdns.org', port: 3002, pm2: 'gestione-veicoli', kind: 'app' },
  { name: 'MattGame', url: 'https://mattgame.duckdns.org', port: 3003, pm2: 'mattgame', kind: 'app', healthPath: '/login' },
  {
    name: 'MattGame OgarII',
    url: 'https://mattgame.duckdns.org',
    port: 3010,
    pm2: 'mattgame-ogar',
    kind: 'app',
    // Solo WebSocket: HTTP su / risponde 426 Upgrade Required (sano).
    healthMode: 'websocket',
    // Il dominio pubblico è condiviso con mattgame (HTTP), non espone Ogar.
    skipPublicCheck: true,
  },
  {
    name: 'SmartShell Terminal',
    url: 'https://smartshellterminal.duckdns.org',
    port: 4000,
    pm2: 'smartshell-api',
    kind: 'app',
    healthPath: '/api/health',
  },
  { name: 'Control Room', url: 'https://matteroma.duckdns.org', port: 3005, pm2: 'control-room', kind: 'app' },
  {
    name: 'JetHealth',
    url: 'https://jethealth.duckdns.org',
    port: 3006,
    pm2: 'jethealth',
    kind: 'app',
    healthPath: '/api/health',
    // PM2 gira da .next/standalone; git/.env stanno nella root del repo
    repoRoot: '/home/ubuntu/JetHealth',
  },
  {
    name: 'Studio Tiberi demo A',
    url: 'https://next.studiodemo.duckdns.org',
    port: 3008,
    pm2: 'tiberi-next',
    kind: 'app',
    repoRoot: '/home/ubuntu/TiberiStudio/next',
  },
  {
    name: 'Studio Tiberi Payload v2',
    url: 'https://v2.studiodemo.duckdns.org',
    port: 3009,
    pm2: 'tiberi-v2',
    kind: 'app',
    // PM2 gira da site/; .env in site/
    repoRoot: '/home/ubuntu/TiberiStudio/site',
  },
  {
    name: 'DrumTeacher API',
    url: 'https://drumteacher.duckdns.org',
    port: 4010,
    pm2: 'drumteacher-api',
    kind: 'app',
    healthPath: '/api/health',
    // API solo su 127.0.0.1:4010; pubblico è nginx static + proxy API
    healthUrl: 'http://127.0.0.1:4010/api/health',
    skipPublicCheck: true,
    repoRoot: '/home/ubuntu/DrumTeacher/server',
  },
  {
    name: 'D&D Oneshot sync',
    url: 'https://dndoneshot.duckdns.org',
    port: 3099,
    pm2: null, // systemd ampb-sync (non PM2)
    kind: 'app',
    healthPath: '/api/health',
    healthUrl: 'http://127.0.0.1:3099/api/health',
  },
  { name: 'Nginx HTTP', url: '', port: 80, pm2: null, kind: 'proxy' },
  { name: 'Nginx HTTPS', url: '', port: 443, pm2: null, kind: 'proxy' },
];

/** App Node (PM2) con URL pubblico per daily check. */
const DAILY_CHECK_SITES = WEB_SITES.filter((s) => s.url && s.kind === 'app' && s.pm2);

/** Nomi processo PM2 gestiti (runbook, restart batch, ecc.). */
const MANAGED_PM2_APPS = [...new Set(WEB_SITES.filter((s) => s.kind === 'app' && s.pm2).map((s) => s.pm2))];

const DAILY_CHECK_STATE_PATH = path.join(__dirname, '..', 'data', 'daily-check-state.json');
const DAILY_CHECK_HISTORY_PATH = path.join(__dirname, '..', 'logs', 'daily-check-history.log');
const INCIDENTS_PATH = path.join(__dirname, '..', 'data', 'incidents.json');
const RUNBOOK_HISTORY_PATH = path.join(__dirname, '..', 'logs', 'runbook-history.log');
const NOTIFY_DEAD_LETTER_PATH = path.join(__dirname, '..', 'logs', 'notify-dead-letter.log');

module.exports = {
  ECOSYSTEM_CENTRAL,
  ECOSYSTEM_SMARTSHELL,
  ECOSYSTEM_TIBERI,
  ECOSYSTEM_DRUMTEACHER,
  ECOSYSTEMS,
  WEB_SITES,
  DAILY_CHECK_SITES,
  MANAGED_PM2_APPS,
  DAILY_CHECK_STATE_PATH,
  DAILY_CHECK_HISTORY_PATH,
  INCIDENTS_PATH,
  RUNBOOK_HISTORY_PATH,
  NOTIFY_DEAD_LETTER_PATH,
};
