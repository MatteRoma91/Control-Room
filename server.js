/**
 * Control Room - PM2 Dashboard Avanzato
 * Node.js/Express dashboard per gestire processi PM2, Nginx e manutenzione server
 */
require('dotenv').config();

// Structured logging per osservabilità e audit (JSON one-liner, parseable)
function logEvent(event, payload) {
  const entry = { ts: new Date().toISOString(), event, ...payload };
  console.log('[CR] ' + JSON.stringify(entry));
}
const http = require('http');
const path = require('path');
const fs = require('fs').promises;
const os = require('os');
const { execSync, spawn } = require('child_process');

const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Server } = require('socket.io');
const pm2 = require('pm2');
const si = require('systeminformation');
const { Client } = require('ssh2');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const schedule = require('node-schedule');

const ECOSYSTEMS = [
  { path: '/home/ubuntu/Sito-Padel/ecosystem.config.js', name: 'padel-tour' },
  { path: '/home/ubuntu/Roma-Buche/ecosystem.config.js', name: 'roma-buche' },
  { path: '/home/ubuntu/control-room/ecosystem.config.js', name: 'control-room' },
];

const app = express();
const PORT = process.env.PORT || 3005;
const AUTH_USER = process.env.AUTH_USER || 'Matt91';
const AUTH_PASSWORD = process.env.AUTH_PASSWORD || 'MattCONTROL1!';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-me-in-production';

// DB credentials per backup (opzionale)
const DB_HOST = process.env.DB_HOST || process.env.MYSQL_HOST;
const DB_USER = process.env.DB_USER || process.env.MYSQL_USER;
const DB_PASSWORD = process.env.DB_PASSWORD || process.env.MYSQL_PASSWORD;
const DB_NAME = process.env.DB_NAME || process.env.MYSQL_DATABASE;
const DB_CONFIGURED = !!(DB_HOST && DB_USER && DB_NAME);

// Trust first proxy (Nginx) for X-Forwarded-Proto
app.set('trust proxy', 1);

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Static files (favicon, icons, etc.)
app.use(express.static(path.join(__dirname, 'public')));

// Helmet - sicurezza headers
app.use(helmet({ contentSecurityPolicy: false })); // CSP disabilitato per CDN Tailwind/Alpine

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const SESSION_MAX_AGE_DAYS = parseInt(process.env.SESSION_MAX_AGE_DAYS || '7', 10);
const SESSION_MAX_AGE_MS = SESSION_MAX_AGE_DAYS * 24 * 60 * 60 * 1000;

const sessionMiddleware = session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: SESSION_MAX_AGE_MS,
  },
});
app.use(sessionMiddleware);

// Rate limit sul login (brute force protection)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minuti
  max: 5,
  handler: (req, res) => res.redirect('/login?rateLimited=1'),
  standardHeaders: true,
  legacyHeaders: false,
});

const login2FALimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  handler: (req, res) => res.redirect('/login/2fa?rateLimited=1'),
  standardHeaders: true,
  legacyHeaders: false,
});

// Auth middleware - redirect to login if not authenticated
function requireAuth(req, res, next) {
  if (req.session?.user) {
    req.session._lastAccess = Date.now();
    return next();
  }
  res.redirect('/login');
}

// ============ IP WHITELIST MIDDLEWARE (runs before auth) ============

async function ipWhitelistMiddleware(req, res, next) {
  try {
    const settings = await loadSettings();
    const clientIp = (req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || req.connection?.remoteAddress || '').replace(/^::ffff:/, '');

    // Panic Mode: only panicModeIp can access
    if (settings.panicMode && settings.panicModeIp) {
      if (clientIp === settings.panicModeIp) return next();
      res.status(403).send('Accesso negato. Panic Mode attivo.');
      return;
    }

    // If whitelist not enabled, allow all
    if (!settings.ipWhitelistEnabled || !Array.isArray(settings.ipWhitelist) || settings.ipWhitelist.length === 0) {
      return next();
    }

    // Check if IP is in whitelist (exact match for MVP)
    const allowed = settings.ipWhitelist.some((entry) => {
      const ip = String(entry).trim();
      if (!ip) return false;
      return clientIp === ip;
    });

    if (allowed) return next();
    res.status(403).send('Accesso negato. IP non autorizzato.');
  } catch (err) {
    console.error('IP whitelist error:', err);
    next();
  }
}

app.use(ipWhitelistMiddleware);

// ============ ROUTES ============

// Login page (GET)
app.get('/login', (req, res) => {
  if (req.session?.user) return res.redirect('/');
  res.render('login', {
    error: req.query.error === '1',
    rateLimited: req.query.rateLimited === '1',
  });
});

// Login (POST) - con rate limiting
app.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (username === AUTH_USER && password === AUTH_PASSWORD) {
    const settings = await loadSettings();
    if (settings.totpEnabled && settings.totpSecret) {
      req.session.pending2FA = username;
      req.session.pending2FATime = Date.now();
      return res.redirect('/login/2fa');
    }
    req.session.user = username;
    logEvent('login', { user: username });
    return res.redirect('/');
  }
  logEvent('login_fail', { reason: 'invalid_credentials' });
  res.redirect('/login?error=1');
});

// Login 2FA (GET) - form codice a 6 cifre
app.get('/login/2fa', (req, res) => {
  if (req.session?.user) return res.redirect('/');
  if (!req.session?.pending2FA) return res.redirect('/login');
  res.render('login-2fa', {
    error: req.query.error === '1',
    rateLimited: req.query.rateLimited === '1',
  });
});

// Login 2FA (POST) - verifica codice
app.post('/login/2fa', login2FALimiter, async (req, res) => {
  const username = req.session?.pending2FA;
  if (!username) return res.redirect('/login');
  const { code } = req.body || {};
  const settings = await loadSettings();
  if (!settings.totpSecret || !code || code.length !== 6) {
    return res.redirect('/login/2fa?error=1');
  }
  const valid = speakeasy.totp.verify({
    secret: settings.totpSecret,
    encoding: 'base32',
    token: code.trim(),
    window: 1,
  });
  if (valid) {
    req.session.user = username;
    delete req.session.pending2FA;
    delete req.session.pending2FATime;
    logEvent('login', { user: username, mfa: true });
    return res.redirect('/');
  }
  logEvent('login_fail', { reason: 'invalid_2fa' });
  res.redirect('/login/2fa?error=1');
});

// Logout
app.post('/logout', (req, res) => {
  const user = req.session?.user;
  req.session.destroy(() => {
    if (user) logEvent('logout', { user });
    res.redirect('/login');
  });
});

// Dashboard principale
app.get('/', requireAuth, async (req, res) => {
  try {
    const list = await pm2List();
    res.render('layout', { contentPartial: 'dashboard', processes: list, dbConfigured: DB_CONFIGURED });
  } catch (err) {
    console.error('PM2 list error:', err);
    res.render('layout', { contentPartial: 'dashboard', processes: [], error: err.message, dbConfigured: DB_CONFIGURED });
  }
});

// Redirect index per retrocompatibilità
app.get('/index', requireAuth, (req, res) => res.redirect('/'));

// Vista dettaglio processo
app.get('/process/:name', requireAuth, async (req, res) => {
  const { name } = req.params;
  try {
    const list = await pm2List();
    const proc = list.find((p) => p.name === name);
    if (!proc) return res.status(404).render('layout', { contentPartial: 'dashboard', processes: list, error: 'Processo non trovato', dbConfigured: DB_CONFIGURED });
    const headExtra = '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css" />';
    res.render('layout', { contentPartial: 'process-detail', process: proc, headExtra });
  } catch (err) {
    console.error('Process detail error:', err);
    res.redirect('/');
  }
});

// ============ API ROUTES ============

// API: process action (restart, stop, start)
app.post('/api/process/:action/:name', requireAuth, async (req, res) => {
  const { action, name } = req.params;
  if (!['restart', 'stop', 'start'].includes(action)) {
    return res.status(400).json({ ok: false, error: 'Invalid action' });
  }
  try {
    await pm2Action(action, name);
    logEvent('process_action', { action, process: name, user: req.session?.user });
    res.json({ ok: true });
  } catch (err) {
    logEvent('process_action_error', { action, process: name, user: req.session?.user, error: err.message });
    console.error(`PM2 ${action} error:`, err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// API: flush logs
app.post('/api/process/flush/:name', requireAuth, (req, res) => {
  const { name } = req.params;
  pm2.flush(name, (err) => {
    if (err) {
      logEvent('process_flush_error', { process: name, user: req.session?.user, error: err.message });
      console.error('PM2 flush error:', err);
      return res.status(500).json({ ok: false, error: err.message });
    }
    logEvent('process_flush', { process: name, user: req.session?.user });
    res.json({ ok: true });
  });
});

// API: git pull & restart
app.post('/api/process/git-pull/:name', requireAuth, async (req, res) => {
  const { name } = req.params;
  try {
    const cwd = await pm2GetCwd(name);
    if (!cwd) return res.status(400).json({ ok: false, error: 'Processo non trovato o cwd non disponibile' });
    const output = execSync('git pull 2>&1', { encoding: 'utf8', cwd });
    await pm2Action('restart', name);
    logEvent('git_pull', { process: name, user: req.session?.user });
    res.json({ ok: true, output });
  } catch (err) {
    logEvent('git_pull_error', { process: name, user: req.session?.user, error: err.message });
    console.error('Git pull error:', err);
    let output = '';
    if (err.stdout) output += Buffer.isBuffer(err.stdout) ? err.stdout.toString() : err.stdout;
    if (err.stderr) output += (Buffer.isBuffer(err.stderr) ? err.stderr.toString() : err.stderr) || '';
    if (!output) output = err.message || String(err);
    res.status(500).json({ ok: false, error: err.message, output });
  }
});

// API: get last 50 lines of logs
app.get('/api/logs/:name', requireAuth, async (req, res) => {
  try {
    const logs = await pm2GetLogs(req.params.name);
    res.json(logs);
  } catch (err) {
    console.error('PM2 logs error:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// API: lista processi PM2 (per polling live)
app.get('/api/processes', requireAuth, async (req, res) => {
  try {
    const list = await pm2List();
    res.json({ processes: list });
  } catch (err) {
    console.error('PM2 processes error:', err);
    res.status(500).json({ ok: false, error: err.message, processes: [] });
  }
});

// API: processi di sistema (top 25 per CPU, per monitoraggio generale)
app.get('/api/system/processes', requireAuth, async (req, res) => {
  try {
    const data = await si.processes();
    const list = (data.list || [])
      .filter((p) => p.pid && (p.cpu > 0 || (p.memRss || 0) > 0))
      .sort((a, b) => (b.cpu || 0) - (a.cpu || 0))
      .slice(0, 25)
      .map((p) => ({
        pid: p.pid,
        name: p.name || '(unknown)',
        cpu: (p.cpu || 0).toFixed(1),
        memRss: Math.round((p.memRss || 0) / 1024), // memRss in KB → MB
        user: p.user || '-',
      }));
    res.json({ processes: list });
  } catch (err) {
    console.error('System processes error:', err);
    res.status(500).json({ ok: false, error: err.message, processes: [] });
  }
});

// API: system info (completo, per overview)
app.get('/api/system', requireAuth, async (req, res) => {
  try {
    const [load, mem, disk] = await Promise.all([
      si.currentLoad(),
      si.mem(),
      si.fsSize('/').catch(() => ({ used: 0, size: 0 })),
    ]);
    const diskInfo = Array.isArray(disk) ? disk[0] : disk;
    const uptimeSec = os.uptime();
    res.json({
      uptime: formatUptime(uptimeSec * 1000),
      uptimeSec,
      loadAvg1: load.currentLoad != null ? load.currentLoad.toFixed(2) : '-',
      memoryUsedMB: Math.round((mem.total - mem.free) / 1024 / 1024),
      memoryTotalMB: Math.round(mem.total / 1024 / 1024),
      memoryPercent: mem.total ? Math.round(100 * (mem.total - mem.free) / mem.total) : 0,
      diskUsedGB: diskInfo?.used ? (diskInfo.used / 1024 / 1024 / 1024).toFixed(2) : '0',
      diskTotalGB: diskInfo?.size ? (diskInfo.size / 1024 / 1024 / 1024).toFixed(2) : '0',
      diskPercent: diskInfo?.use || 0,
      cpuPercent: load.currentLoad ?? 0,
      memUsedMB: Math.round((mem.total - mem.free) / 1024 / 1024),
    });
  } catch (err) {
    console.error('System info error:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Buffer stats CPU/RAM dall'ultimo avvio (per grafici persistenti)
const statsHistory = [];
const STATS_HISTORY_MAX = 100;
const STATS_INTERVAL_MS = 3000;

async function collectStatsPoint() {
  try {
    const [load, mem] = await Promise.all([si.currentLoad(), si.mem()]);
    const ramPercent = mem.total ? 100 * (mem.total - mem.free) / mem.total : 0;
    const now = new Date();
    statsHistory.push({
      label: now.toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      cpu: load.currentLoad ?? 0,
      ram: ramPercent,
    });
    if (statsHistory.length > STATS_HISTORY_MAX) statsHistory.shift();
  } catch (_) {}
}
setInterval(collectStatsPoint, STATS_INTERVAL_MS);
collectStatsPoint();

// API: system stats per Chart.js (CPU %, RAM %) + history dall'avvio
app.get('/api/system/stats', requireAuth, async (req, res) => {
  try {
    const [load, mem] = await Promise.all([si.currentLoad(), si.mem()]);
    const usedMemMB = Math.round((mem.total - mem.free) / 1024 / 1024);
    const memoryPercent = mem.total ? 100 * (mem.total - mem.free) / mem.total : 0;
    const history = {
      labels: statsHistory.map((p) => p.label),
      cpu: statsHistory.map((p) => p.cpu),
      ram: statsHistory.map((p) => p.ram),
    };
    res.json({
      cpuPercent: load.currentLoad ?? 0,
      memoryPercent,
      memoryUsedMB: usedMemMB,
      memoryTotalMB: Math.round(mem.total / 1024 / 1024),
      timestamp: new Date().toISOString(),
      history,
    });
  } catch (err) {
    console.error('System stats error:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// API: restart all webapps
app.post('/api/process/restart-all', requireAuth, async (req, res) => {
  const apps = ['padel-tour', 'roma-buche'];
  try {
    await Promise.all(apps.map((name) => pm2Action('restart', name)));
    logEvent('restart_all', { processes: apps, user: req.session?.user });
    res.json({ ok: true });
  } catch (err) {
    logEvent('restart_all_error', { user: req.session?.user, error: err.message });
    console.error('Restart-all error:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// API: restore all processes
app.post('/api/process/restore-all', requireAuth, async (req, res) => {
  try {
    const list = await pm2ListRaw();
    for (const { path: cfgPath, name } of ECOSYSTEMS) {
      const proc = list.find((p) => (p.pm2_env || p).name === name);
      const status = proc?.pm2_env?.status;
      if (!proc) {
        await pm2StartEcosystem(cfgPath);
      } else if (status && status !== 'online') {
        await pm2Action('restart', name);
      }
    }
    logEvent('restore_all', { user: req.session?.user });
    res.json({ ok: true });
  } catch (err) {
    logEvent('restore_all_error', { user: req.session?.user, error: err.message });
    console.error('Restore-all error:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// API: health check
app.get('/api/health', requireAuth, async (req, res) => {
  const urls = [
    { url: 'https://bananapadeltour.duckdns.org', name: 'Banana Padel Tour' },
    { url: 'https://ibuche.duckdns.org', name: 'Roma-Buche' },
  ];
  const results = [];
  for (const { url, name } of urls) {
    const start = Date.now();
    try {
      const resp = await fetch(url, { method: 'GET', signal: AbortSignal.timeout(10000) });
      const elapsed = Date.now() - start;
      results.push({ url, name, status: resp.status, elapsed, ok: resp.ok });
    } catch (err) {
      results.push({ url, name, status: 0, elapsed: Date.now() - start, ok: false, error: err.message });
    }
  }
  res.json({ results });
});

// API: nginx status
app.get('/api/nginx-status', requireAuth, (req, res) => {
  try {
    const out = execSync('systemctl is-active nginx 2>/dev/null', { encoding: 'utf8' }).trim();
    res.json({ active: out === 'active' });
  } catch {
    res.json({ active: false });
  }
});

// API: nginx reload
app.post('/api/nginx-reload', requireAuth, (req, res) => {
  try {
    execSync('sudo /bin/systemctl reload nginx 2>/dev/null', { encoding: 'utf8' });
    logEvent('nginx_reload', { user: req.session?.user });
    res.json({ ok: true });
  } catch (err) {
    logEvent('nginx_reload_error', { user: req.session?.user, error: err.message });
    console.error('Nginx reload error:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Nginx Config Generator page
app.get('/nginx', requireAuth, (req, res) => {
  res.render('layout', { contentPartial: 'nginx' });
});

// API: nginx config generator
app.post('/api/nginx-generate', requireAuth, async (req, res) => {
  let output = [];
  try {
    const { domain, port, ssl } = req.body || {};
    if (!domain || typeof domain !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$/.test(domain.trim())) {
      return res.status(400).json({ ok: false, error: 'Dominio non valido' });
    }
    const safeDomain = domain.trim().replace(/\./g, '_');
    const portNum = parseInt(port || 3000, 10);
    if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
      return res.status(400).json({ ok: false, error: 'Porta non valida' });
    }

    const httpBlock = `# Generato da Control Room - ${domain}
server {
    listen 80;
    listen [::]:80;
    server_name ${domain};
    location / {
        proxy_pass http://127.0.0.1:${portNum};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
`;
    const tmpPath = `/tmp/controlroom-nginx-${safeDomain}.conf`;
    const destPath = `/etc/nginx/sites-available/${domain}.conf`;

    await fs.writeFile(tmpPath, httpBlock, 'utf8');
    output.push('File generato: ' + tmpPath);

    execSync(`sudo cp ${tmpPath} ${destPath}`, { encoding: 'utf8' });
    output.push('Copiato in: ' + destPath);

    execSync(`sudo ln -sf ${destPath} /etc/nginx/sites-enabled/${domain}.conf`, { encoding: 'utf8' });
    output.push('Symlink creato in sites-enabled');

    if (ssl) {
      try {
        const certbotEmail = process.env.CR_CONTACT_EMAIL || `admin@${domain}`;
        execSync(`sudo certbot certonly --nginx -d ${domain} --non-interactive --agree-tos --email ${certbotEmail} 2>&1`, { encoding: 'utf8' });
        output.push('Certificato SSL ottenuto con Certbot');
        const httpsBlock = `
# HTTPS - abilitato da Certbot
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${domain};
    ssl_certificate /etc/letsencrypt/live/${domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;

    location / {
        proxy_pass http://127.0.0.1:${portNum};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
`;
        await fs.writeFile(tmpPath, httpBlock + httpsBlock, 'utf8');
        execSync(`sudo cp ${tmpPath} ${destPath}`, { encoding: 'utf8' });
      } catch (certErr) {
        output.push('Certbot fallito (certificati potrebbero esistere già): ' + (certErr.message || certErr));
      }
    }

    execSync('sudo nginx -t 2>&1', { encoding: 'utf8' });
    output.push('nginx -t OK');

    execSync('sudo /bin/systemctl reload nginx 2>&1', { encoding: 'utf8' });
    output.push('Nginx ricaricato');

    res.json({ ok: true, output: output.join('\n') });
  } catch (err) {
    console.error('Nginx generate error:', err);
    res.status(500).json({ ok: false, error: err.message, output: output.join('\n') });
  }
});

// API: db backup (mysqldump | gzip, stream download)
app.get('/api/db-backup', requireAuth, (req, res) => {
  if (!DB_CONFIGURED) return res.status(503).json({ ok: false, error: 'Database non configurato' });
  const filename = `backup-${new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '')}.sql.gz`;
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Content-Type', 'application/gzip');

  const args = ['-h', DB_HOST, '-u', DB_USER];
  if (DB_PASSWORD) args.push(`-p${DB_PASSWORD}`);
  args.push(DB_NAME);

  const mysqldump = spawn('mysqldump', args, {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const gzip = spawn('gzip', ['-c'], { stdio: ['pipe', 'pipe', 'pipe'] });

  mysqldump.stdout.pipe(gzip.stdin);
  gzip.stdout.pipe(res);

  mysqldump.stderr.on('data', (d) => console.error('mysqldump:', d.toString()));
  gzip.stderr.on('data', (d) => console.error('gzip:', d.toString()));

  mysqldump.on('error', (err) => {
    console.error('mysqldump error:', err);
    if (!res.headersSent) res.status(500).json({ ok: false, error: err.message });
  });
  mysqldump.on('close', (code) => {
    if (code !== 0) {
      gzip.stdin.end();
      if (!res.headersSent) res.status(500).end('Backup failed');
    }
  });
  gzip.on('error', (err) => {
    console.error('gzip error:', err);
    if (!res.headersSent) res.status(500).json({ ok: false, error: err.message });
  });
});

// API: check if DB is configured (per frontend)
app.get('/api/db-configured', requireAuth, (req, res) => {
  res.json({ configured: DB_CONFIGURED });
});

// ============ SETTINGS (settings.json) ============

const SETTINGS_PATH = path.join(__dirname, 'settings.json');

async function loadSettings() {
  try {
    const data = await fs.readFile(SETTINGS_PATH, 'utf8');
    const s = JSON.parse(data);
    if (s.sshHost && (!s.sshProfiles || s.sshProfiles.length === 0)) {
      s.sshProfiles = [{
        id: 'migrated',
        name: 'Server',
        host: s.sshHost,
        port: parseInt(s.sshPort || '22', 10),
        username: s.sshUser || '',
        authType: s.sshAuth || 'key',
        keyPath: s.sshKeyPath || '',
      }];
    }
    return s;
  } catch {
    return {};
  }
}

async function saveSettings(obj) {
  await fs.writeFile(SETTINGS_PATH, JSON.stringify(obj, null, 2), 'utf8');
  try {
    await fs.chmod(SETTINGS_PATH, 0o600);
  } catch (_) {}
}

// Pagina Settings
app.get('/settings', requireAuth, async (req, res) => {
  const settings = await loadSettings();
  res.render('layout', { contentPartial: 'settings', settings });
});

// API: GET settings
app.get('/api/settings', requireAuth, async (req, res) => {
  const settings = await loadSettings();
  res.json(settings);
});

// API: POST settings (salva)
app.post('/api/settings', requireAuth, async (req, res) => {
  try {
    const body = { ...(req.body || {}) };
    const current = await loadSettings();
    body.totpSecret = current.totpSecret;
    body.totpEnabled = current.totpEnabled;
    body.panicMode = current.panicMode;
    body.panicModeIp = current.panicModeIp;
    if (!Array.isArray(body.sshProfiles)) body.sshProfiles = current.sshProfiles || [];
    if (!Array.isArray(body.cronJobs)) body.cronJobs = current.cronJobs || [];
    if (!Array.isArray(body.ipWhitelist)) body.ipWhitelist = current.ipWhitelist || [];
    await saveSettings(body);
    res.json({ ok: true });
  } catch (err) {
    console.error('Settings save error:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// API: Attiva Panic Mode (solo IP corrente)
app.post('/api/settings/panic-activate', requireAuth, async (req, res) => {
  try {
    const clientIp = (req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '').replace(/^::ffff:/, '');
    const current = await loadSettings();
    current.panicMode = true;
    current.panicModeIp = clientIp;
    await saveSettings(current);
    logEvent('panic_activate', { user: req.session?.user, ip: clientIp });
    res.json({ ok: true, panicModeIp: clientIp });
  } catch (err) {
    console.error('Panic activate error:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// API: Disattiva Panic Mode
app.post('/api/settings/panic-disable', requireAuth, async (req, res) => {
  try {
    const current = await loadSettings();
    current.panicMode = false;
    current.panicModeIp = '';
    await saveSettings(current);
    logEvent('panic_disable', { user: req.session?.user });
    res.json({ ok: true });
  } catch (err) {
    console.error('Panic disable error:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ============ 2FA (Google Authenticator) ============

// Pagina setup 2FA
app.get('/settings/2fa-setup', requireAuth, async (req, res) => {
  const settings = await loadSettings();
  res.render('layout', { contentPartial: 'settings-2fa-setup', settings });
});

// API: genera secret per setup 2FA
app.post('/api/2fa/setup', requireAuth, async (req, res) => {
  try {
    const secret = speakeasy.generateSecret({
      name: `Control Room (${AUTH_USER})`,
      length: 20,
      issuer: 'Control Room',
    });
    const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url);
    req.session.temp2FASecret = secret.base32;
    res.json({ secret: secret.base32, otpauth_url: secret.otpauth_url, qrDataUrl });
  } catch (err) {
    console.error('2FA setup error:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// API: verifica codice e attiva 2FA
app.post('/api/2fa/verify-setup', requireAuth, async (req, res) => {
  try {
    const tempSecret = req.session?.temp2FASecret;
    const { code } = req.body || {};
    if (!tempSecret || !code || code.length !== 6) {
      return res.status(400).json({ ok: false, error: 'Codice non valido' });
    }
    const valid = speakeasy.totp.verify({
      secret: tempSecret,
      encoding: 'base32',
      token: code.trim(),
      window: 1,
    });
    if (!valid) {
      return res.status(400).json({ ok: false, error: 'Codice non corretto' });
    }
    const current = await loadSettings();
    current.totpSecret = tempSecret;
    current.totpEnabled = true;
    await saveSettings(current);
    delete req.session.temp2FASecret;
    res.json({ ok: true });
  } catch (err) {
    console.error('2FA verify-setup error:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// API: disattiva 2FA
app.post('/api/2fa/disable', requireAuth, async (req, res) => {
  try {
    const { password } = req.body || {};
    if (password !== AUTH_PASSWORD) {
      return res.status(401).json({ ok: false, error: 'Password non valida' });
    }
    const current = await loadSettings();
    current.totpEnabled = false;
    current.totpSecret = '';
    await saveSettings(current);
    res.json({ ok: true });
  } catch (err) {
    console.error('2FA disable error:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ============ CRON JOBS ============

const cronJobHandles = new Map(); // id -> schedule.Job

async function executeCronJob(job) {
  try {
    if (job.action === 'pm2-restart' && job.target) {
      await pm2Action('restart', job.target);
      console.log(`[Cron] Riavviato ${job.target}`);
    } else if (job.action === 'pm2-start' && job.target) {
      await pm2Action('start', job.target);
      console.log(`[Cron] Avviato ${job.target}`);
    } else if (job.action === 'command' && job.command) {
      execSync(job.command, { encoding: 'utf8', stdio: 'pipe' });
      console.log(`[Cron] Eseguito comando: ${job.command}`);
    } else if (job.action === 'db-backup' && DB_CONFIGURED) {
      const fname = `backup-${new Date().toISOString().slice(0, 10)}.sql.gz`;
      const outPath = path.join(__dirname, 'backups', fname);
      await fs.mkdir(path.join(__dirname, 'backups'), { recursive: true });
      const args = ['-h', DB_HOST, '-u', DB_USER];
      if (DB_PASSWORD) args.push(`-p${DB_PASSWORD}`);
      args.push(DB_NAME);
      const mysqldump = spawn('mysqldump', args, { stdio: ['ignore', 'pipe', 'pipe'] });
      const gzip = spawn('gzip', ['-c'], { stdio: ['pipe', 'pipe', 'pipe'] });
      const wstream = require('fs').createWriteStream(outPath);
      mysqldump.stdout.pipe(gzip.stdin);
      gzip.stdout.pipe(wstream);
      await new Promise((resolve, reject) => {
        let dumpOk = true;
        mysqldump.on('close', (code) => { if (code !== 0) dumpOk = false; });
        wstream.on('finish', () => { if (dumpOk) resolve(); else reject(new Error('mysqldump failed')); });
        wstream.on('error', reject);
        mysqldump.on('error', reject);
        gzip.on('error', reject);
      });
      console.log(`[Cron] Backup DB salvato in ${outPath}`);
    }
  } catch (err) {
    console.error(`[Cron] Errore job ${job.name}:`, err.message);
  }
}

function registerCronJobs() {
  cronJobHandles.forEach((j) => j.cancel());
  cronJobHandles.clear();
  loadSettings().then((settings) => {
    const jobs = settings.cronJobs || [];
    jobs.filter((j) => j.enabled !== false && j.schedule).forEach((job) => {
      try {
        const j = schedule.scheduleJob(job.schedule, () => executeCronJob(job));
        if (j) cronJobHandles.set(job.id, j);
      } catch (e) {
        console.error(`[Cron] Job ${job.name} schedule invalido:`, e.message);
      }
    });
  });
}

// Pagina Cron Jobs
app.get('/cron', requireAuth, async (req, res) => {
  const settings = await loadSettings();
  const list = await pm2List();
  res.render('layout', { contentPartial: 'cron', cronJobs: settings.cronJobs || [], processes: list });
});

// API: GET cron jobs
app.get('/api/cron-jobs', requireAuth, async (req, res) => {
  const settings = await loadSettings();
  res.json(settings.cronJobs || []);
});

// API: POST cron jobs (salva tutti)
app.post('/api/cron-jobs', requireAuth, async (req, res) => {
  try {
    const jobs = req.body?.jobs || req.body || [];
    const current = await loadSettings();
    current.cronJobs = Array.isArray(jobs) ? jobs : [];
    await saveSettings(current);
    registerCronJobs();
    res.json({ ok: true });
  } catch (err) {
    console.error('Cron jobs save error:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Vista Terminale SSH
app.get('/terminal', requireAuth, (req, res) => {
  const headExtra = '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css" />';
  res.render('layout', { contentPartial: 'terminal', headExtra });
});

// ============ EDITOR .ENV ============

const ALLOWED_CWD_PREFIX = '/home/ubuntu/';

function isPathAllowed(filePath) {
  const resolved = path.resolve(filePath);
  return resolved.startsWith(ALLOWED_CWD_PREFIX);
}

// API: GET .env di un processo
app.get('/api/env/:name', requireAuth, async (req, res) => {
  const { name } = req.params;
  try {
    const cwd = await pm2GetCwd(name);
    if (!cwd || !isPathAllowed(cwd)) return res.status(403).json({ ok: false, error: 'Accesso non consentito' });
    const envPath = path.join(cwd, '.env');
    try {
      const content = await fs.readFile(envPath, 'utf8');
      res.json({ content, exists: true, cwd });
    } catch {
      res.json({ content: '', exists: false, cwd });
    }
  } catch (err) {
    console.error('Env read error:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// API: POST .env (salva con backup)
app.post('/api/env/:name', requireAuth, async (req, res) => {
  const { name } = req.params;
  const { content } = req.body || {};
  if (typeof content !== 'string' || content.trim() === '') {
    return res.status(400).json({ ok: false, error: 'Contenuto non valido' });
  }
  try {
    const cwd = await pm2GetCwd(name);
    if (!cwd || !isPathAllowed(cwd)) return res.status(403).json({ ok: false, error: 'Accesso non consentito' });
    const envPath = path.join(cwd, '.env');
    const bakPath = path.join(cwd, '.env.bak');
    try {
      await fs.copyFile(envPath, bakPath);
    } catch (_) {}
    await fs.writeFile(envPath, content, 'utf8');
    logEvent('env_save', { process: name, user: req.session?.user });
    res.json({ ok: true });
  } catch (err) {
    logEvent('env_save_error', { process: name, user: req.session?.user, error: err.message });
    console.error('Env save error:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ============ PM2 HELPERS ============

function pm2List() {
  return new Promise((resolve, reject) => {
    pm2.list((err, list) => {
      if (err) return reject(err);
      const processes = list.map((p) => {
        const env = p.pm2_env || {};
        const monit = p.monit || {};
        return {
          name: env.name || p.name,
          status: env.status,
          cpu: monit.cpu ?? 0,
          memory: Math.round((monit.memory || 0) / 1024 / 1024),
          uptime: env.pm_uptime ? formatUptime(Date.now() - env.pm_uptime) : '-',
          restart_time: env.restart_time ?? 0,
        };
      });
      resolve(processes);
    });
  });
}

function pm2Action(action, name) {
  return new Promise((resolve, reject) => {
    const fn = pm2[action];
    if (!fn) return reject(new Error(`Unknown action: ${action}`));
    // PM2 API methods require 'this' bound to pm2 instance; fn(name,cb) loses context
    fn.call(pm2, name, (err) => (err ? reject(err) : resolve()));
  });
}

function pm2ListRaw() {
  return new Promise((resolve, reject) => {
    pm2.list((err, list) => (err ? reject(err) : resolve(list || [])));
  });
}

function pm2StartEcosystem(ecosystemPath) {
  return new Promise((resolve, reject) => {
    pm2.start(ecosystemPath, (err) => (err ? reject(err) : resolve()));
  });
}

function pm2GetCwd(name) {
  return new Promise((resolve, reject) => {
    pm2.describe(name, (err, list) => {
      if (err) return reject(err);
      const proc = Array.isArray(list) ? list[0] : list;
      resolve(proc?.pm2_env?.pm_cwd || null);
    });
  });
}

function pm2GetLogPaths(name) {
  return new Promise((resolve, reject) => {
    pm2.describe(name, (err, list) => {
      if (err) return reject(err);
      const proc = Array.isArray(list) ? list[0] : list;
      if (!proc?.pm2_env) return reject(new Error('Process not found'));
      const env = proc.pm2_env;
      resolve({
        out: env.pm_out_log_path,
        err: env.pm_err_log_path,
      });
    });
  });
}

async function pm2GetLogs(name) {
  return new Promise((resolve, reject) => {
    pm2.describe(name, async (err, list) => {
      if (err) return reject(err);
      const proc = Array.isArray(list) ? list[0] : list;
      if (!proc?.pm2_env) return reject(new Error('Process not found'));
      const env = proc.pm2_env;
      const outPath = env.pm_out_log_path;
      const errPath = env.pm_err_log_path;
      const lines = 50;

      const readLastLines = async (filePath) => {
        try {
          const content = await fs.readFile(filePath, 'utf8');
          return content.split('\n').slice(-lines).join('\n');
        } catch {
          return '(file not found or empty)';
        }
      };

      try {
        const [stdout, stderr] = await Promise.all([
          readLastLines(outPath),
          readLastLines(errPath),
        ]);
        resolve({ stdout, stderr });
      } catch (e) {
        reject(e);
      }
    });
  });
}

function formatUptime(ms) {
  if (ms < 0) return '-';
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  const h = Math.floor(m / 60);
  const d = Math.floor(h / 24);
  if (d) return `${d}d ${h % 24}h`;
  if (h) return `${h}h ${m % 60}m`;
  if (m) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

// ============ HTTP SERVER + SOCKET.IO ============

const httpServer = http.createServer(app);

const io = new Server(httpServer, {
  path: '/socket.io',
  cors: { origin: '*' },
});

// Socket.io session middleware - verifica autenticazione
io.use((socket, next) => {
  const res = {};
  res.setHeader = () => {};
  res.end = () => {};
  sessionMiddleware(socket.request, res, () => {
    if (socket.request.session?.user) return next();
    next(new Error('Unauthorized'));
  });
});

// Mappa socket.id -> tail processes (per kill on disconnect)
const tailProcesses = new Map();
const sshConnections = new Map();

io.on('connection', (socket) => {
  socket.on('term-input', (data) => {
    const entry = sshConnections.get(socket.id);
    if (entry?.stream) entry.stream.write(data);
  });

  socket.on('term-disconnect', () => {
    const ssh = sshConnections.get(socket.id);
    if (ssh) {
      ssh.conn.end();
      sshConnections.delete(socket.id);
      socket.emit('term-data', '\r\n\x1b[33mConnessione chiusa.\x1b[0m\r\n');
      socket.emit('term-disconnected');
    }
  });

  socket.on('join-logs', async (payload) => {
    const processName = typeof payload === 'string' ? payload : payload?.processName;
    if (!processName || typeof processName !== 'string') return;

    // Kill eventuali tail precedenti per questo socket
    const existing = tailProcesses.get(socket.id);
    if (existing) {
      existing.out?.kill();
      existing.err?.kill();
      tailProcesses.delete(socket.id);
    }

    try {
      const paths = await pm2GetLogPaths(processName);
      const tailProcs = { out: null, err: null };

      if (paths.out) {
        const tailOut = spawn('tail', ['-f', '-n', '0', paths.out]);
        tailOut.stdout.on('data', (chunk) => socket.emit('log-out', chunk.toString()));
        tailOut.on('error', (err) => socket.emit('log-err', `[tail error] ${err.message}\n`));
        tailProcs.out = tailOut;
      }
      if (paths.err) {
        const tailErr = spawn('tail', ['-f', '-n', '0', paths.err]);
        tailErr.stdout.on('data', (chunk) => socket.emit('log-err', chunk.toString()));
        tailErr.on('error', (err) => socket.emit('log-err', `[tail error] ${err.message}\n`));
        tailProcs.err = tailErr;
      }

      tailProcesses.set(socket.id, tailProcs);
    } catch (err) {
      socket.emit('log-err', `[Error] ${err.message}\n`);
    }
  });

  socket.on('join-ssh', async (payload) => {
    const existing = sshConnections.get(socket.id);
    if (existing) {
      existing.conn.end();
      sshConnections.delete(socket.id);
    }
    const profileId = typeof payload === 'object' && payload ? payload.profileId : null;
    const password = typeof payload === 'object' && payload ? payload.password : undefined;
    const settings = await loadSettings();
    const profiles = settings.sshProfiles || [];
    const profile = profileId ? profiles.find((p) => p.id === profileId) : profiles[0];
    if (!profile || !profile.host || !profile.username) {
      socket.emit('term-data', '\r\n\x1b[31mNessuna configurazione SSH. Vai in Impostazioni.\x1b[0m\r\n');
      return;
    }
    const host = profile.host;
    const port = parseInt(profile.port || '22', 10);
    const username = profile.username;
    const conn = new Client();
    const config = { host, port, username };
    if (profile.authType === 'password') {
      if (!password || typeof password !== 'string') {
        socket.emit('term-data', '\r\n\x1b[31mInserisci la password nella finestra di connessione.\x1b[0m\r\n');
        return;
      }
      config.password = password;
    } else {
      try {
        const keyPath = profile.keyPath || path.join(os.homedir(), '.ssh', 'id_rsa');
        config.privateKey = await fs.readFile(keyPath, 'utf8');
      } catch (e) {
        socket.emit('term-data', `\r\n\x1b[31mErrore chiave SSH: ${e.message}\x1b[0m\r\n`);
        return;
      }
    }
    conn.on('ready', () => {
      conn.shell((err, stream) => {
        if (err) {
          socket.emit('term-data', `\r\n\x1b[31mShell error: ${err.message}\x1b[0m\r\n`);
          return;
        }
        stream.on('data', (chunk) => socket.emit('term-data', chunk.toString()));
        conn.on('close', () => {
          if (sshConnections.get(socket.id)?.conn === conn) {
            sshConnections.delete(socket.id);
            socket.emit('term-data', '\r\n\x1b[33mConnessione chiusa dal server remoto.\x1b[0m\r\n');
            socket.emit('term-disconnected');
          }
        });
        sshConnections.set(socket.id, { conn, stream });
      });
    }).on('error', (err) => {
      socket.emit('term-data', `\r\n\x1b[31mSSH error: ${err.message}\x1b[0m\r\n`);
    }).connect(config);
  });

  socket.on('disconnect', () => {
    const procs = tailProcesses.get(socket.id);
    if (procs) {
      procs.out?.kill();
      procs.err?.kill();
      tailProcesses.delete(socket.id);
    }
    const ssh = sshConnections.get(socket.id);
    if (ssh) {
      ssh.conn.end();
      sshConnections.delete(socket.id);
    }
  });
});

// ============ NOTIFICHE (pm2.launchBus) ============

const notifyDebounce = new Map();
const NOTIFY_DEBOUNCE_MS = 30000;
const NOTIFY_DEBOUNCE_LOGERR_MS = 60000; // stderr più rumoroso: debounce 60s

async function sendNotification(message) {
  const settings = await loadSettings();
  const type = settings.webhookType || 'discord';
  const text = message.slice(0, 1950);

  if ((type === 'discord' || type === 'slack') && settings.webhookUrl) {
    try {
      const body = type === 'slack'
        ? { text }
        : { content: text };
      await fetch(settings.webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      logEvent('notification_sent', { channel: type, preview: text.slice(0, 80) });
    } catch (err) {
      logEvent('notification_error', { channel: type, error: err.message });
      console.error(`${type} webhook error:`, err);
    }
    return;
  }

  if (type === 'telegram' && settings.telegramBotToken && settings.telegramChatId) {
    try {
      const url = `https://api.telegram.org/bot${settings.telegramBotToken}/sendMessage`;
      await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: settings.telegramChatId, text }),
      });
      logEvent('notification_sent', { channel: 'telegram', preview: text.slice(0, 80) });
    } catch (err) {
      logEvent('notification_error', { channel: 'telegram', error: err.message });
      console.error('Telegram send error:', err);
    }
  }
}

function shouldNotifyProcess(processName, eventType, debounceMs = NOTIFY_DEBOUNCE_MS) {
  const key = `${processName}:${eventType}`;
  const now = Date.now();
  const last = notifyDebounce.get(key) || 0;
  if (now - last < debounceMs) return false;
  notifyDebounce.set(key, now);
  return true;
}

// ============ STARTUP ============

pm2.connect((err) => {
  if (err) {
    console.error('PM2 connect failed:', err);
    process.exit(1);
  }
  registerCronJobs();
  pm2.launchBus((errBus, bus) => {
    if (errBus) return;
    bus.on('process:event', async (data) => {
      const ev = data?.event;
      const name = data?.process?.name || data?.name || 'unknown';
      const restartTime = data?.process?.restart_time ?? 0;
      logEvent('pm2_event', { event: ev, process: name, restartTime });
      const settings = await loadSettings();
      if (ev === 'exit' && settings.notifyOnCrash !== false && shouldNotifyProcess(name, 'exit')) {
        await sendNotification(`⚠️ Alert: Il processo '${name}' è crashato! (Riavvio automatico in corso...)`);
      }
      if (ev === 'restart' && settings.notifyOnRestart !== false && restartTime >= 3 && shouldNotifyProcess(name, 'restart')) {
        await sendNotification(`🔄 Crash loop: Il processo '${name}' è stato riavviato ${restartTime} volte. Verifica i log.`);
      }
    });
    bus.on('process:exception', async (data) => {
      const name = data?.process?.name || data?.name || 'unknown';
      const msg = (data?.msg || data?.error?.message || 'Errore non gestito').toString().slice(0, 300);
      logEvent('pm2_exception', { process: name, message: msg.slice(0, 100) });
      const settings = await loadSettings();
      const sendException = settings.notifyOnException === true || (settings.notifyOnException !== false && settings.notifyOnCrash !== false);
      if (!sendException || !shouldNotifyProcess(name, 'exception')) return;
      await sendNotification(`⚠️ Alert: Il processo '${name}' ha emesso un'eccezione: ${msg}`);
    });
    bus.on('log:err', async (data) => {
      const name = data?.process?.name || 'unknown';
      const msg = (data?.data || '').toString().slice(0, 500);
      if (msg) logEvent('pm2_log_err', { process: name, preview: msg.slice(0, 80) });
      const settings = await loadSettings();
      const sendStderr = settings.notifyOnLogErr === true;
      if (!sendStderr || !msg || !shouldNotifyProcess(name, 'logerr', NOTIFY_DEBOUNCE_LOGERR_MS)) return;
      await sendNotification(`⚠️ PM2 stderr [${name}]: ${msg}`);
    });
  });
  httpServer.listen(PORT, () => {
    logEvent('startup', { port: PORT });
    console.log(`Control Room running on http://localhost:${PORT}`);
  });
});

// Graceful shutdown
process.on('SIGINT', () => {
  tailProcesses.forEach((p) => {
    p.out?.kill();
    p.err?.kill();
  });
  pm2.disconnect();
  process.exit(0);
});
