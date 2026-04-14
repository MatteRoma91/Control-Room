const path = require('path');

const ECOSYSTEMS = [
  { path: '/home/ubuntu/Sito-Padel/ecosystem.config.js', name: 'padel-tour' },
  { path: '/home/ubuntu/Roma-Buche/ecosystem.config.js', name: 'roma-buche' },
  { path: '/home/ubuntu/Gestione-Veicoli/ecosystem.config.js', name: 'gestione-veicoli' },
  { path: '/home/ubuntu/control-room/ecosystem.config.js', name: 'control-room' },
];

/** Servizio systemd per PHP-FPM (GENERATOR / dndpgbuilder). Override: `CR_PHP_FPM_SERVICE`. */
const PHP_FPM_SERVICE = process.env.CR_PHP_FPM_SERVICE || 'php8.3-fpm';

const WEB_SITES = [
  { name: 'Banana Padel Tour', url: 'https://bananapadeltour.duckdns.org', port: 3000, pm2: 'padel-tour', kind: 'app' },
  { name: 'Roma-Buche', url: 'https://ibuche.duckdns.org', port: 3001, pm2: 'roma-buche', kind: 'app' },
  { name: 'Gestione Veicoli', url: 'https://gestione-veicoli.duckdns.org', port: 3002, pm2: 'gestione-veicoli', kind: 'app' },
  { name: 'Control Room', url: 'https://matteroma.duckdns.org', port: 3005, pm2: 'control-room', kind: 'app' },
  {
    name: 'GENERATOR (D&D)',
    url: 'https://dndpgbuilder.duckdns.org',
    port: null,
    pm2: null,
    kind: 'php',
  },
  { name: 'Nginx HTTP', url: '', port: 80, pm2: null, kind: 'proxy' },
  { name: 'Nginx HTTPS', url: '', port: 443, pm2: null, kind: 'proxy' },
];

/** App Node (PM2) + sito PHP pubblico (solo HTTP, nessun PM2). */
const DAILY_CHECK_SITES = WEB_SITES.filter((s) => s.url && ((s.kind === 'app' && s.pm2) || s.kind === 'php'));
const DAILY_CHECK_STATE_PATH = path.join(__dirname, '..', 'data', 'daily-check-state.json');
const DAILY_CHECK_HISTORY_PATH = path.join(__dirname, '..', 'logs', 'daily-check-history.log');
const INCIDENTS_PATH = path.join(__dirname, '..', 'data', 'incidents.json');
const RUNBOOK_HISTORY_PATH = path.join(__dirname, '..', 'logs', 'runbook-history.log');
const NOTIFY_DEAD_LETTER_PATH = path.join(__dirname, '..', 'logs', 'notify-dead-letter.log');

module.exports = {
  ECOSYSTEMS,
  WEB_SITES,
  DAILY_CHECK_SITES,
  PHP_FPM_SERVICE,
  DAILY_CHECK_STATE_PATH,
  DAILY_CHECK_HISTORY_PATH,
  INCIDENTS_PATH,
  RUNBOOK_HISTORY_PATH,
  NOTIFY_DEAD_LETTER_PATH,
};
