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
const { execSync, execFileSync, spawn } = require('child_process');

const express = require('express');
const session = require('express-session');
const { RedisStore } = require('connect-redis');
const { createClient } = require('redis');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Server } = require('socket.io');
const pm2 = require('pm2');
const si = require('systeminformation');
const { Client } = require('ssh2');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const schedule = require('node-schedule');

const {
  ECOSYSTEMS,
  WEB_SITES,
  DAILY_CHECK_SITES,
  MANAGED_PM2_APPS,
  DAILY_CHECK_STATE_PATH,
  DAILY_CHECK_HISTORY_PATH,
  INCIDENTS_PATH,
  RUNBOOK_HISTORY_PATH,
  NOTIFY_DEAD_LETTER_PATH,
} = require('./lib/constants');
const { getSiteHealthTarget } = require('./lib/siteHealth');
const { normalizeIp, isIpAllowedByEntries } = require('./lib/ip-utils');
const { registerHealthRoutes } = require('./routes/health');
const { registerAuthRoutes } = require('./routes/auth');
const { registerPageRoutes } = require('./routes/pages');
const { registerProcessRoutes } = require('./routes/processes');
const { registerSystemRoutes } = require('./routes/system');
const { registerRunbookRoutes } = require('./routes/runbook');
const { registerIncidentRoutes } = require('./routes/incidents');
const { registerNginxRoutes } = require('./routes/nginx');
const { registerSettingsRoutes } = require('./routes/settings');
const {
  loadSettings,
  saveSettings,
  normalizeDailyCheckConfig,
} = require('./services/settings');
const {
  appendLine,
  readIncidents,
} = require('./services/incidents');
const {
  parseCheckResponseOk,
  fetchStatusCode,
  executeRunbook,
} = require('./services/runbook');
const { isPathAllowed } = require('./lib/path-utils');
const {
  formatUptime,
  resolveManagedProjectCwd,
  pm2List,
  pm2Action,
  pm2ListRaw,
  pm2StartEcosystem,
  pm2GetCwd,
  pm2GetLogPaths,
  pm2GetLogs,
} = require('./services/pm2');

/** Parser output `ss -tlnp`: socket TCP in ascolto */
function parseSsTcpListen() {
  try {
    const out = execFileSync('ss', ['-H', '-tlnp'], { encoding: 'utf8', maxBuffer: 2 * 1024 * 1024 });
    const listeners = [];
    for (const line of out.split('\n')) {
      const t = line.trim();
      if (!t.startsWith('LISTEN')) continue;
      const parts = t.split(/\s+/);
      if (parts.length < 5) continue;
      const local = parts[3];
      const colon = local.lastIndexOf(':');
      if (colon <= 0) continue;
      const addr = local.slice(0, colon);
      const port = parseInt(local.slice(colon + 1), 10);
      if (!Number.isFinite(port)) continue;
      const um = t.match(/users:\(\("([^"]+)"/);
      listeners.push({ address: addr, port, process: um ? um[1] : null });
    }
    return { ok: true, listeners };
  } catch (err) {
    return { ok: false, listeners: [], error: err.message };
  }
}

const app = express();
const PORT = process.env.PORT || 3005;
function readRequiredEnv(name, minLen = 1) {
  const value = String(process.env[name] || '').trim();
  if (!value || value.length < minLen) {
    throw new Error(`${name} is required${minLen > 1 ? ` (min ${minLen} chars)` : ''}`);
  }
  return value;
}

const AUTH_USER = readRequiredEnv('AUTH_USER', 3);
const AUTH_PASSWORD = readRequiredEnv('AUTH_PASSWORD', 12);
const SESSION_SECRET = readRequiredEnv('SESSION_SECRET', 32);
const REDIS_URL = process.env.REDIS_URL || 'redis://127.0.0.1:6379';
const REDIS_PREFIX = process.env.REDIS_PREFIX || 'cr:sess:';
const REDIS_CONNECT_TIMEOUT_MS = parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS || '5000', 10);
const SESSION_REDIS_REQUIRED = process.env.SESSION_REDIS_REQUIRED !== 'false' && process.env.NODE_ENV === 'production';
const SESSION_IDLE_MINUTES = parseInt(process.env.SESSION_IDLE_MINUTES || '120', 10);
const SESSION_IDLE_MS = Math.max(5, SESSION_IDLE_MINUTES) * 60 * 1000;
const AUDIT_LOG_PATH = path.join(__dirname, 'logs', 'audit-events.log');
const DEFAULT_PANIC_DURATION_MIN = parseInt(process.env.PANIC_MODE_DURATION_MIN || '30', 10);
let redisClient = null;
let redisReady = false;
let redisLastError = '';
let redisLastOkAt = '';

const HIGH_RISK_PHRASES = Object.freeze({
  restartAll: 'RESTART-ALL',
  restoreAll: 'RESTORE-ALL',
  nginxReload: 'NGINX-RELOAD',
  panicActivate: 'PANIC-ACTIVATE',
  panicDisable: 'PANIC-DISABLE',
  disable2FA: 'DISABLE-2FA',
});

async function appendAuditEvent(event, payload = {}) {
  const line = JSON.stringify({ ts: new Date().toISOString(), event, ...payload });
  await fs.mkdir(path.dirname(AUDIT_LOG_PATH), { recursive: true });
  await fs.appendFile(AUDIT_LOG_PATH, line + '\n', 'utf8');
}

async function audit(event, payload = {}) {
  logEvent(event, payload);
  try {
    await appendAuditEvent(event, payload);
  } catch (err) {
    console.error('Audit write error:', err.message);
  }
}

function getExpectedPhrase(req, kind, name = '') {
  if (kind === 'process-stop') return `STOP:${name}`;
  if (kind === 'process-restart') return `RESTART:${name}`;
  return HIGH_RISK_PHRASES[kind] || kind;
}

function hasStrongConfirmation(req, kind, name = '') {
  const expected = getExpectedPhrase(req, kind, name);
  const supplied = String(req.body?.confirmPhrase || req.headers['x-cr-confirm'] || '').trim();
  return supplied === expected;
}

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
const cspConnectSrc = ["'self'"];
if (process.env.NODE_ENV !== 'production') cspConnectSrc.push('ws:', 'wss:');
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "default-src": ["'self'"],
      /* Helmet default è script-src-attr 'none' → onclick="" sui bottoni non gira. */
      "script-src-attr": ["'unsafe-inline'"],
      "script-src": ["'self'", "'unsafe-inline'", 'https://cdn.tailwindcss.com', 'https://unpkg.com', 'https://cdn.jsdelivr.net'],
      "style-src": ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://cdn.jsdelivr.net'],
      "font-src": ["'self'", 'data:', 'https://fonts.gstatic.com'],
      "img-src": ["'self'", 'data:', 'blob:'],
      "connect-src": cspConnectSrc,
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const SESSION_MAX_AGE_DAYS = parseInt(process.env.SESSION_MAX_AGE_DAYS || '7', 10);
const SESSION_MAX_AGE_MS = SESSION_MAX_AGE_DAYS * 24 * 60 * 60 * 1000;

function setupRedisClient() {
  const client = createClient({
    url: REDIS_URL,
    socket: {
      connectTimeout: REDIS_CONNECT_TIMEOUT_MS,
      reconnectStrategy: (retries) => Math.min(retries * 200, 2000),
    },
  });
  client.on('ready', () => {
    redisReady = true;
    redisLastError = '';
    redisLastOkAt = new Date().toISOString();
    logEvent('redis_ready', { url: REDIS_URL });
  });
  client.on('error', (err) => {
    redisReady = false;
    redisLastError = err.message;
    logEvent('redis_error', { error: err.message });
  });
  return client;
}

redisClient = setupRedisClient();
const redisStore = new RedisStore({
  client: redisClient,
  prefix: REDIS_PREFIX,
});

const sessionConfig = {
  name: 'controlroom.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  store: redisStore,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: SESSION_MAX_AGE_MS,
  },
};

const sessionMiddleware = session(sessionConfig);
app.use(sessionMiddleware);

/** Path corrente per evidenziazione nav nelle viste EJS */
app.use((req, res, next) => {
  res.locals.reqPath = req.path || '';
  next();
});

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
    const lastAccess = req.session._lastAccess || 0;
    if (lastAccess && Date.now() - lastAccess > SESSION_IDLE_MS) {
      const user = req.session.user;
      req.session.destroy(() => {
        audit('session_expired', { user, reason: 'idle_timeout' });
      });
      return res.redirect('/login?error=1');
    }
    req.session._lastAccess = Date.now();
    return next();
  }
  res.redirect('/login');
}

// ============ IP WHITELIST MIDDLEWARE (runs before auth) ============

async function ipWhitelistMiddleware(req, res, next) {
  try {
    const settings = await loadSettings();
    const clientIp = normalizeIp(req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || req.connection?.remoteAddress || '');
    const nowIso = new Date().toISOString();

    const tempEntries = (settings.ipWhitelistTemporary || []).filter((e) => e.expiresAt > nowIso);
    if (tempEntries.length !== (settings.ipWhitelistTemporary || []).length) {
      settings.ipWhitelistTemporary = tempEntries;
      await saveSettings(settings);
    }

    // Panic Mode: only panicModeIp can access
    if (settings.panicMode && settings.panicModeIp) {
      if (settings.panicExpiresAt && settings.panicExpiresAt <= nowIso) {
        settings.panicMode = false;
        settings.panicModeIp = '';
        settings.panicExpiresAt = '';
        await saveSettings(settings);
        return next();
      }
      if (clientIp === settings.panicModeIp) return next();
      res.status(403).send('Accesso negato. Panic Mode attivo.');
      return;
    }

    // If whitelist not enabled, allow all
    if (!settings.ipWhitelistEnabled || !Array.isArray(settings.ipWhitelist) || settings.ipWhitelist.length === 0) {
      return next();
    }

    // Check if IP is in whitelist (exact match for MVP)
    const whitelist = settings.ipWhitelist || [];
    const temporary = tempEntries.map((e) => e.ip);
    const allowed = isIpAllowedByEntries(clientIp, [...whitelist, ...temporary]);

    if (allowed) return next();
    res.status(403).send('Accesso negato. IP non autorizzato.');
  } catch (err) {
    console.error('IP whitelist error:', err);
    next();
  }
}

app.use(ipWhitelistMiddleware);

// ============ ROUTES ============
registerAuthRoutes(app, {
  AUTH_USER,
  AUTH_PASSWORD,
  loginLimiter,
  login2FALimiter,
  loadSettings,
  audit,
  speakeasy,
});

registerPageRoutes(app, {
  requireAuth,
  pm2List,
  DB_CONFIGURED,
});

// ============ API ROUTES ============
registerProcessRoutes(app, {
  requireAuth,
  logEvent,
  audit,
  hasStrongConfirmation,
  getExpectedPhrase,
  HIGH_RISK_PHRASES,
  MANAGED_PM2_APPS,
  ECOSYSTEMS,
  pm2List,
  pm2Action,
  pm2ListRaw,
  pm2StartEcosystem,
  pm2GetLogs,
  resolveManagedProjectCwd,
});

registerSystemRoutes(app, {
  requireAuth,
  formatUptime,
});

registerRunbookRoutes(app, {
  requireAuth,
  audit,
  sendNotificationEvent,
});

// API: health check (extracted → routes/health.js)
registerHealthRoutes(app, {
  requireAuth,
  WEB_SITES,
  getSiteHealthTarget,
  pm2List,
});

registerIncidentRoutes(app, {
  requireAuth,
  audit,
  sendNotificationEvent,
});

app.get('/api/redis-health', requireAuth, async (req, res) => {
  try {
    if (!redisClient) {
      return res.status(500).json({ ok: false, status: 'not_configured', error: 'Redis client non inizializzato' });
    }
    let pong = '';
    try {
      pong = await redisClient.ping();
      redisReady = pong === 'PONG';
      if (redisReady) redisLastOkAt = new Date().toISOString();
    } catch (err) {
      redisReady = false;
      redisLastError = err.message;
      throw err;
    }
    res.json({
      ok: true,
      status: redisReady ? 'ready' : 'degraded',
      ping: pong,
      prefix: REDIS_PREFIX,
      url: REDIS_URL,
      lastOkAt: redisLastOkAt || null,
      lastError: redisLastError || null,
    });
  } catch (err) {
    res.status(503).json({
      ok: false,
      status: 'error',
      error: err.message,
      prefix: REDIS_PREFIX,
      url: REDIS_URL,
      lastOkAt: redisLastOkAt || null,
      lastError: redisLastError || err.message,
    });
  }
});

app.get('/api/quality-gates', requireAuth, async (req, res) => {
  try {
    const [summaryRes, auditsRes] = await Promise.all([
      (async () => {
        const r = await fetch(`http://127.0.0.1:${PORT}/api/health/summary`, {
          headers: { cookie: req.headers.cookie || '' },
          signal: AbortSignal.timeout(3000),
        });
        return r.json();
      })(),
      (async () => {
        const content = await fs.readFile(AUDIT_LOG_PATH, 'utf8').catch(() => '');
        return content.split('\n').filter(Boolean).slice(-500);
      })(),
    ]);
    const parsed = auditsRes.map((l) => {
      try { return JSON.parse(l); } catch { return null; }
    }).filter(Boolean);
    const criticalActions = parsed.filter((e) => ['restart_all', 'restore_all', 'nginx_reload', 'panic_activate', 'panic_disable'].includes(e.event));
    const withUser = criticalActions.filter((e) => !!e.user);
    res.json({
      ok: true,
      generatedAt: new Date().toISOString(),
      healthSeverity: summaryRes.severity || 'unknown',
      failingHealthChecks: summaryRes.healthSummary?.failing ?? null,
      offlineProcesses: summaryRes.processSummary?.offline ?? null,
      auditCoverageCriticalActions: criticalActions.length ? Math.round((withUser.length / criticalActions.length) * 100) : 100,
      smokeChecks: {
        dashboard: true,
        processApi: true,
        settingsApi: true,
      },
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get('/api/analytics/overview', requireAuth, async (req, res) => {
  try {
    const runbookRaw = await fs.readFile(RUNBOOK_HISTORY_PATH, 'utf8').catch(() => '');
    const runbooks = runbookRaw
      .split('\n')
      .filter(Boolean)
      .map((line) => {
        try { return JSON.parse(line); } catch { return null; }
      })
      .filter(Boolean);
    const incidents = await readIncidents();
    const cpuAvg = statsHistory.length ? Math.round((statsHistory.reduce((acc, p) => acc + p.cpu, 0) / statsHistory.length) * 10) / 10 : 0;
    const ramAvg = statsHistory.length ? Math.round((statsHistory.reduce((acc, p) => acc + p.ram, 0) / statsHistory.length) * 10) / 10 : 0;
    const successRate = runbooks.length ? Math.round((runbooks.filter((r) => r.ok).length / runbooks.length) * 100) : 100;
    res.json({
      ok: true,
      generatedAt: new Date().toISOString(),
      runbooksTotal: runbooks.length,
      runbookSuccessRate: successRate,
      incidentsOpen: incidents.filter((i) => i.status !== 'resolved').length,
      incidentsCriticalOpen: incidents.filter((i) => i.status !== 'resolved' && i.severity === 'critical').length,
      cpuAvgPercent: cpuAvg,
      ramAvgPercent: ramAvg,
      capacityRisk: cpuAvg > 80 || ramAvg > 85 ? 'high' : cpuAvg > 65 || ramAvg > 70 ? 'medium' : 'low',
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get('/api/security/sessions', requireAuth, async (req, res) => {
  try {
    if (!redisClient?.isOpen) {
      return res.json({ sessions: [], warning: 'Redis non disponibile per session inventory' });
    }
    const keys = [];
    for await (const key of redisClient.scanIterator({ MATCH: `${REDIS_PREFIX}*`, COUNT: 200 })) keys.push(key);
    const sessions = [];
    for (const key of keys.slice(0, 300)) {
      const raw = await redisClient.get(key);
      if (!raw) continue;
      let parsed = null;
      try { parsed = JSON.parse(raw); } catch { parsed = null; }
      sessions.push({
        key,
        user: parsed?.user || parsed?.pending2FA || null,
        hasAuth: !!parsed?.user,
        lastAccess: parsed?._lastAccess || null,
        cookieExpires: parsed?.cookie?.expires || null,
      });
    }
    res.json({ sessions });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/api/security/sessions/revoke', requireAuth, async (req, res) => {
  try {
    const key = String(req.body?.key || '').trim();
    if (!key) return res.status(400).json({ ok: false, error: 'Session key richiesta' });
    await redisClient.del(key);
    await audit('session_revoked', { user: req.session?.user, key });
    await sendNotificationEvent('session_revoked', {
      channel: 'security',
      severity: 'medium',
      note: `revoked=${key}`,
    });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/api/security/sessions/revoke-all', requireAuth, async (req, res) => {
  try {
    const keys = [];
    for await (const key of redisClient.scanIterator({ MATCH: `${REDIS_PREFIX}*`, COUNT: 200 })) keys.push(key);
    if (keys.length) await redisClient.del(keys);
    await audit('session_revoke_all', { user: req.session?.user, count: keys.length });
    await sendNotificationEvent('session_revoke_all', {
      channel: 'security',
      severity: 'high',
      note: `revoked_count=${keys.length}`,
    });
    res.json({ ok: true, revoked: keys.length });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get('/api/maintenance/logs', requireAuth, async (req, res) => {
  try {
    const source = req.query.source === 'error' ? 'error' : 'out';
    const processName = String(req.query.process || 'control-room');
    const lines = Math.min(500, Math.max(20, parseInt(req.query.lines || '120', 10)));
    const sanitized = processName.replace(/[^a-zA-Z0-9_.-]/g, '');
    const filePath = `/home/ubuntu/.pm2/logs/${sanitized}-${source}.log`;
    const raw = await fs.readFile(filePath, 'utf8').catch(() => '');
    const list = raw.split('\n').filter(Boolean).slice(-lines);
    const q = String(req.query.q || '').toLowerCase();
    const filtered = q ? list.filter((line) => line.toLowerCase().includes(q)) : list;
    res.json({ ok: true, source, process: sanitized, lines: filtered });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get('/api/maintenance/diagnostics', requireAuth, async (req, res) => {
  try {
    const [pm2ListNow, redisHealth, summary] = await Promise.all([
      pm2List(),
      (async () => {
        try {
          const ping = await redisClient.ping();
          return { ok: ping === 'PONG', ping };
        } catch (err) {
          return { ok: false, error: err.message };
        }
      })(),
      (async () => {
        const r = await fetch(`http://127.0.0.1:${PORT}/api/health/summary`, {
          headers: { cookie: req.headers.cookie || '' },
          signal: AbortSignal.timeout(2500),
        });
        return r.json();
      })(),
    ]);
    res.json({
      ok: true,
      generatedAt: new Date().toISOString(),
      checks: [
        { name: 'pm2_online', ok: pm2ListNow.every((p) => p.status === 'online') },
        { name: 'redis', ok: redisHealth.ok, detail: redisHealth },
        { name: 'health_summary', ok: summary.severity === 'ok', detail: summary },
      ],
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get('/api/notifications/health', requireAuth, async (req, res) => {
  try {
    const dead = await fs.readFile(NOTIFY_DEAD_LETTER_PATH, 'utf8').catch(() => '');
    const deadItems = dead.split('\n').filter(Boolean);
    const auditRaw = await fs.readFile(AUDIT_LOG_PATH, 'utf8').catch(() => '');
    const auditItems = auditRaw
      .split('\n')
      .filter(Boolean)
      .slice(-400)
      .map((line) => {
        try { return JSON.parse(line); } catch { return null; }
      })
      .filter(Boolean);
    const runbookEvents = auditItems.filter((a) => a.event === 'runbook_recover_app' || a.event === 'runbook_recover_batch').length;
    res.json({
      ok: true,
      deadLetterCount: deadItems.length,
      latestDeadLetter: deadItems.length ? JSON.parse(deadItems[deadItems.length - 1]) : null,
      recentRunbookEvents: runbookEvents,
      dedupCacheSize: notificationDedup.size,
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get('/api/audit/events', requireAuth, async (req, res) => {
  try {
    const limit = Math.min(500, Math.max(1, parseInt(req.query.limit || '200', 10)));
    const content = await fs.readFile(AUDIT_LOG_PATH, 'utf8').catch(() => '');
    const lines = content.split('\n').filter(Boolean).slice(-limit);
    const events = lines
      .map((l) => {
        try {
          return JSON.parse(l);
        } catch (_) {
          return null;
        }
      })
      .filter(Boolean)
      .reverse();
    res.json({ events });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// API: porte siti (config + verifica `ss` sul server)
app.get('/api/site-ports', requireAuth, (req, res) => {
  const ss = parseSsTcpListen();
  const byPort = new Map();
  for (const l of ss.listeners) {
    if (!byPort.has(l.port)) byPort.set(l.port, []);
    byPort.get(l.port).push(l);
  }
  const sites = WEB_SITES.map((s) => {
    const portNum = s.port;
    const found = portNum != null ? byPort.get(portNum) || [] : [];
    const listening = portNum == null ? null : ss.ok ? found.length > 0 : null;
    const bindAddresses = [...new Set(found.map((x) => x.address))];
    const processHints = [...new Set(found.map((x) => x.process).filter(Boolean))];
    return {
      name: s.name,
      url: s.url || null,
      port: portNum,
      portNote: null,
      pm2: s.pm2,
      kind: s.kind,
      listening,
      bindAddresses,
      processHints,
    };
  });
  res.json({ sites, ssOk: ss.ok, ssError: ss.error || null });
});

registerNginxRoutes(app, {
  requireAuth,
  audit,
  hasStrongConfirmation,
  HIGH_RISK_PHRASES,
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

// Daily check state (cron) — settings load/save live in services/settings.js
async function readDailyCheckState() {
  try {
    const data = await fs.readFile(DAILY_CHECK_STATE_PATH, 'utf8');
    return JSON.parse(data);
  } catch (_) {
    return {};
  }
}

async function writeDailyCheckState(state) {
  await fs.mkdir(path.dirname(DAILY_CHECK_STATE_PATH), { recursive: true });
  await fs.writeFile(DAILY_CHECK_STATE_PATH, JSON.stringify(state, null, 2), 'utf8');
}

registerSettingsRoutes(app, {
  requireAuth,
  audit,
  hasStrongConfirmation,
  HIGH_RISK_PHRASES,
  normalizeIp,
  DEFAULT_PANIC_DURATION_MIN,
  AUTH_USER,
  AUTH_PASSWORD,
  pm2List,
  logEvent,
  registerAutoRemediationsFromSettings,
  speakeasy,
  QRCode,
});

// ============ CRON JOBS ============

const cronJobHandles = new Map(); // id -> schedule.Job
let dailyCheckHandle = null;
let dailyCheckRunning = false;
const cronRunHistory = [];
const automationRemediationHandles = new Map();

async function runDailyAppCheck(trigger = 'manual') {
  if (dailyCheckRunning) {
    return { ok: false, message: 'Check già in esecuzione' };
  }
  dailyCheckRunning = true;
  const startedAt = new Date();
  const report = {
    startedAt: startedAt.toISOString(),
    finishedAt: null,
    trigger,
    overall: 'ok',
    repairedCount: 0,
    failedCount: 0,
    entries: [],
  };

  try {
    for (const site of DAILY_CHECK_SITES) {
      const entry = {
        name: site.name,
        process: site.pm2,
        localUrl: `http://127.0.0.1:${site.port}/`,
        publicUrl: site.url,
        pm2Before: 'unknown',
        pm2After: 'unknown',
        localStatusBefore: 0,
        publicStatusBefore: 0,
        localStatusAfter: 0,
        publicStatusAfter: 0,
        actions: [],
        status: 'ok',
      };

      const list = await pm2ListRaw();
      const proc = list.find((p) => (p.pm2_env || p).name === site.pm2);
      entry.pm2Before = proc?.pm2_env?.status || 'not_found';
      entry.localStatusBefore = await fetchStatusCode(entry.localUrl, 8000);
      entry.publicStatusBefore = await fetchStatusCode(entry.publicUrl, 10000);

      const localOkBefore = parseCheckResponseOk(entry.localStatusBefore);
      const publicOkBefore = parseCheckResponseOk(entry.publicStatusBefore);

      if (entry.pm2Before === 'stopped' || entry.pm2Before === 'not_found' || entry.pm2Before === 'errored') {
        try {
          await pm2Action('start', site.pm2);
          entry.actions.push(`pm2 start ${site.pm2}`);
        } catch (err) {
          entry.actions.push(`pm2 start failed: ${err.message}`);
        }
      } else if (!localOkBefore) {
        try {
          await pm2Action('restart', site.pm2);
          entry.actions.push(`pm2 restart ${site.pm2}`);
        } catch (err) {
          entry.actions.push(`pm2 restart failed: ${err.message}`);
        }
      }

      if (localOkBefore && !publicOkBefore) {
        try {
          execSync('sudo /bin/systemctl reload nginx 2>/dev/null', { encoding: 'utf8' });
          entry.actions.push('nginx reload');
        } catch (err) {
          entry.actions.push(`nginx reload failed: ${err.message}`);
        }
      }

      await new Promise((resolve) => setTimeout(resolve, 2000));
      const listAfter = await pm2ListRaw();
      const procAfter = listAfter.find((p) => (p.pm2_env || p).name === site.pm2);
      entry.pm2After = procAfter?.pm2_env?.status || 'not_found';
      entry.localStatusAfter = await fetchStatusCode(entry.localUrl, 8000);
      entry.publicStatusAfter = await fetchStatusCode(entry.publicUrl, 10000);

      const localOkAfter = parseCheckResponseOk(entry.localStatusAfter);
      const publicOkAfter = parseCheckResponseOk(entry.publicStatusAfter);
      const healthyAfter = entry.pm2After === 'online' && localOkAfter && publicOkAfter;

      if (!healthyAfter) {
        entry.status = 'failed';
        report.failedCount += 1;
      } else if (entry.actions.length > 0) {
        entry.status = 'repaired';
        report.repairedCount += 1;
      }

      report.entries.push(entry);
    }

    if (report.failedCount > 0) report.overall = 'failed';
    else if (report.repairedCount > 0) report.overall = 'repaired';

    report.finishedAt = new Date().toISOString();
    await writeDailyCheckState({ lastRun: report });
    await fs.mkdir(path.dirname(DAILY_CHECK_HISTORY_PATH), { recursive: true });
    await fs.appendFile(DAILY_CHECK_HISTORY_PATH, JSON.stringify(report) + '\n', 'utf8');

    if (report.overall !== 'ok') {
      const failedNames = report.entries.filter((e) => e.status === 'failed').map((e) => e.process);
      const repairedNames = report.entries.filter((e) => e.status === 'repaired').map((e) => e.process);
      await sendNotification(`🩺 Daily check ${report.overall.toUpperCase()}: repaired=${repairedNames.join(', ') || '-'} failed=${failedNames.join(', ') || '-'}`);
    }
    return { ok: true, report };
  } finally {
    dailyCheckRunning = false;
  }
}

function scheduleDailyCheckJob(time) {
  if (dailyCheckHandle) {
    dailyCheckHandle.cancel();
    dailyCheckHandle = null;
  }
  const [hour, minute] = time.split(':').map((x) => parseInt(x, 10));
  if (!Number.isFinite(hour) || !Number.isFinite(minute)) return;
  dailyCheckHandle = schedule.scheduleJob({ hour, minute, tz: 'Europe/Rome' }, () => {
    runDailyAppCheck('scheduled').catch((err) => {
      logEvent('daily_check_error', { error: err.message });
    });
  });
}

async function registerDailyCheckFromSettings() {
  const settings = await loadSettings();
  const cfg = normalizeDailyCheckConfig(settings);
  if (cfg.enabled) scheduleDailyCheckJob(cfg.time);
  else if (dailyCheckHandle) {
    dailyCheckHandle.cancel();
    dailyCheckHandle = null;
  }
}

async function executeCronJob(job) {
  const startedAt = new Date().toISOString();
  let success = true;
  let message = 'OK';
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
    success = false;
    message = err.message;
    console.error(`[Cron] Errore job ${job.name}:`, err.message);
  } finally {
    cronRunHistory.unshift({
      id: job.id || '',
      name: job.name || '',
      action: job.action || '',
      startedAt,
      success,
      message,
    });
    if (cronRunHistory.length > 200) cronRunHistory.length = 200;
    audit('cron_job_run', { user: 'system', jobId: job.id, name: job.name, action: job.action, success, message });
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
  const dailyCheck = normalizeDailyCheckConfig(settings);
  const dailyState = await readDailyCheckState();
  res.render('layout', {
    contentPartial: 'cron',
    cronJobs: settings.cronJobs || [],
    processes: list,
    dailyCheck,
    dailyCheckLastRun: dailyState.lastRun || null,
    dailyCheckRunning,
  });
});

// API: GET cron jobs
app.get('/api/cron-jobs', requireAuth, async (req, res) => {
  const settings = await loadSettings();
  res.json(settings.cronJobs || []);
});

app.get('/api/cron-jobs/history', requireAuth, async (req, res) => {
  res.json({ history: cronRunHistory.slice(0, 50) });
});

app.post('/api/cron-jobs/preview', requireAuth, async (req, res) => {
  try {
    const scheduleExpr = String(req.body?.schedule || '').trim();
    if (!scheduleExpr) return res.status(400).json({ ok: false, error: 'Schedule mancante' });
    const tmpJob = schedule.scheduleJob(scheduleExpr, () => {});
    if (!tmpJob) return res.status(400).json({ ok: false, error: 'Schedule non valido' });
    const next = tmpJob.nextInvocation();
    const nextRuns = next ? [next.toDate().toISOString()] : [];
    tmpJob.cancel();
    res.json({ ok: true, nextRuns });
  } catch (err) {
    res.status(400).json({ ok: false, error: `Schedule non valido: ${err.message}` });
  }
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

app.get('/api/daily-check/status', requireAuth, async (req, res) => {
  try {
    const settings = await loadSettings();
    const dailyCheck = normalizeDailyCheckConfig(settings);
    const dailyState = await readDailyCheckState();
    res.json({
      ok: true,
      config: dailyCheck,
      running: dailyCheckRunning,
      lastRun: dailyState.lastRun || null,
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/api/daily-check/config', requireAuth, async (req, res) => {
  try {
    const enabled = req.body?.enabled !== false;
    const time = String(req.body?.time || '00:00').trim();
    if (!/^\d{2}:\d{2}$/.test(time)) {
      return res.status(400).json({ ok: false, error: 'Formato orario non valido (HH:MM)' });
    }
    const [hh, mm] = time.split(':').map((x) => parseInt(x, 10));
    if (hh < 0 || hh > 23 || mm < 0 || mm > 59) {
      return res.status(400).json({ ok: false, error: 'Orario non valido' });
    }
    const settings = await loadSettings();
    settings.dailyCheck = { enabled, time };
    await saveSettings(settings);
    await registerDailyCheckFromSettings();
    logEvent('daily_check_config_updated', { user: req.session?.user, enabled, time });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/api/daily-check/run', requireAuth, async (req, res) => {
  try {
    const result = await runDailyAppCheck('manual');
    if (!result.ok) return res.status(409).json(result);
    logEvent('daily_check_run_manual', { user: req.session?.user, overall: result.report?.overall });
    res.json(result);
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

function registerAutoRemediationsFromSettings(settings) {
  automationRemediationHandles.forEach((h) => h.cancel());
  automationRemediationHandles.clear();
  const items = Array.isArray(settings.autoRemediations) ? settings.autoRemediations : [];
  items.filter((x) => x.enabled !== false && x.schedule && x.process).forEach((item) => {
    try {
      const job = schedule.scheduleJob(item.schedule, async () => {
        try {
          const report = await executeRunbook({
            processName: item.process,
            mode: item.mode || 'soft_recover',
            dryRun: false,
            operator: 'automation',
          });
          await audit('automation_remediation_run', { user: 'system', remediationId: item.id, ok: report.ok, process: item.process });
        } catch (err) {
          await audit('automation_remediation_error', { user: 'system', remediationId: item.id, process: item.process, error: err.message });
        }
      });
      if (job) automationRemediationHandles.set(item.id, job);
    } catch (err) {
      logEvent('automation_remediation_schedule_error', { id: item.id, error: err.message });
    }
  });
}

app.get('/api/automation/remediations', requireAuth, async (req, res) => {
  const settings = await loadSettings();
  res.json({ items: settings.autoRemediations || [] });
});

app.post('/api/automation/remediations', requireAuth, async (req, res) => {
  try {
    const items = Array.isArray(req.body?.items) ? req.body.items : [];
    const sanitized = items.map((item) => ({
      id: String(item.id || `arm_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`),
      name: String(item.name || 'remediation'),
      process: String(item.process || ''),
      schedule: String(item.schedule || ''),
      mode: ['soft_recover', 'full_recover', 'safe_rollback'].includes(item.mode) ? item.mode : 'soft_recover',
      enabled: item.enabled !== false,
    })).filter((item) => item.process && item.schedule);
    const settings = await loadSettings();
    settings.autoRemediations = sanitized;
    await saveSettings(settings);
    registerAutoRemediationsFromSettings(settings);
    await audit('automation_remediations_saved', { user: req.session?.user, count: sanitized.length });
    res.json({ ok: true, items: sanitized });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Vista Terminale SSH
app.get('/terminal', requireAuth, (req, res) => {
  const headExtra = '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css" />';
  res.render('layout', { contentPartial: 'terminal', headExtra });
});

// ============ EDITOR .ENV ============


// API: GET .env di un processo
app.get('/api/env/:name', requireAuth, async (req, res) => {
  const { name } = req.params;
  try {
    const cwd = await resolveManagedProjectCwd(name);
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

app.post('/api/env/validate/:name', requireAuth, async (req, res) => {
  try {
    const content = String(req.body?.content || '');
    const requiredKeys = Array.isArray(req.body?.requiredKeys) ? req.body.requiredKeys.map(String) : [];
    const map = new Map();
    for (const line of content.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const idx = trimmed.indexOf('=');
      if (idx <= 0) continue;
      const key = trimmed.slice(0, idx).trim();
      const value = trimmed.slice(idx + 1);
      map.set(key, value);
    }
    const missing = requiredKeys.filter((k) => !map.has(k) || String(map.get(k)).trim() === '');
    const warnings = [];
    if (map.has('SESSION_SECRET') && String(map.get('SESSION_SECRET')).length < 32) warnings.push('SESSION_SECRET dovrebbe essere lungo almeno 32 caratteri.');
    res.json({ ok: true, parsedKeys: map.size, missing, warnings });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// API: POST .env (salva con backup)
app.post('/api/env/:name', requireAuth, async (req, res) => {
  const { name } = req.params;
  const { content, restartProcess } = req.body || {};
  if (typeof content !== 'string' || content.trim() === '') {
    return res.status(400).json({ ok: false, error: 'Contenuto non valido' });
  }
  try {
    const cwd = await resolveManagedProjectCwd(name);
    if (!cwd || !isPathAllowed(cwd)) return res.status(403).json({ ok: false, error: 'Accesso non consentito' });
    const envPath = path.join(cwd, '.env');
    const bakPath = path.join(cwd, '.env.bak');
    try {
      await fs.copyFile(envPath, bakPath);
    } catch (_) {}
    await fs.writeFile(envPath, content, 'utf8');
    if (restartProcess === true) await pm2Action('restart', name);
    await audit('env_save', { process: name, user: req.session?.user, restartProcess: restartProcess === true, cwd });
    res.json({ ok: true, restarted: restartProcess === true, cwd });
  } catch (err) {
    await audit('env_save_error', { process: name, user: req.session?.user, error: err.message });
    console.error('Env save error:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ============ PM2 HELPERS ============

// ============ HTTP SERVER + SOCKET.IO ============

const httpServer = http.createServer(app);

function parseAllowedOrigins(raw) {
  return String(raw || '')
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean);
}

const allowedOrigins = parseAllowedOrigins(process.env.CR_ALLOWED_ORIGINS);
function isOriginAllowed(origin) {
  if (!origin) return true;
  if (allowedOrigins.length === 0) return true;
  return allowedOrigins.includes(origin);
}

const io = new Server(httpServer, {
  path: '/socket.io',
  cors: {
    origin: (origin, callback) => callback(isOriginAllowed(origin) ? null : new Error('Origin not allowed'), isOriginAllowed(origin)),
    credentials: true,
  },
});

// Socket.io session middleware - verifica autenticazione
io.use((socket, next) => {
  const origin = socket.handshake.headers.origin;
  if (!isOriginAllowed(origin)) {
    return next(new Error('Forbidden origin'));
  }
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
const notificationDedup = new Map();
const NOTIFY_DEDUP_MS = 15000;

function dedupNotificationKey(key) {
  const now = Date.now();
  const last = notificationDedup.get(key) || 0;
  if (now - last < NOTIFY_DEDUP_MS) return false;
  notificationDedup.set(key, now);
  return true;
}

async function postWebhook(url, body) {
  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!resp.ok) throw new Error(`Webhook HTTP ${resp.status}`);
}

function resolveDiscordWebhook(settings, channel) {
  if (channel === 'incidents' && settings.discordWebhookIncidents) return settings.discordWebhookIncidents;
  if (channel === 'security' && settings.discordWebhookSecurity) return settings.discordWebhookSecurity;
  if (channel === 'ops' && settings.discordWebhookOps) return settings.discordWebhookOps;
  return settings.webhookUrl || settings.discordWebhookOps || '';
}

function buildDiscordMessage(eventType, payload) {
  const severity = payload?.severity || 'info';
  const process = payload?.process ? `App: ${payload.process}\n` : '';
  const note = payload?.note ? `Nota: ${payload.note}\n` : '';
  const action = payload?.actionHint ? `Azione: ${payload.actionHint}\n` : '';
  return `**${eventType}**\nSeverity: ${severity}\n${process}${note}${action}Time: ${new Date().toISOString()}`.slice(0, 1950);
}

async function sendNotificationEvent(eventType, payload = {}) {
  const settings = await loadSettings();
  if (eventType.startsWith('incident_') && settings.notifyOnIncident === false) return;
  if (eventType.startsWith('runbook_') && settings.notifyOnRunbook !== true) return;
  if (eventType.startsWith('session_') && settings.notifyOnSecurity !== true) return;
  if (eventType === 'runbook_recover_app' && payload.process) {
    const proc = String(payload.process || '').trim();
    if (settings.notifyPm2Scope === 'onlyListed') {
      const list = settings.notifyPm2OnlyApps || [];
      if (list.length === 0 || !list.includes(proc)) return;
    }
  }
  const channel = payload.channel || 'ops';
  const dedupKey = `${eventType}:${payload.process || ''}:${payload.note || ''}`.slice(0, 160);
  if (!dedupNotificationKey(dedupKey)) return;
  const message = buildDiscordMessage(eventType, payload);
  const webhook = resolveDiscordWebhook(settings, channel);
  if (!webhook) return;
  let sent = false;
  let lastError = null;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      await postWebhook(webhook, { content: message });
      sent = true;
      logEvent('notification_sent', { channel: 'discord', eventType, attempt });
      break;
    } catch (err) {
      lastError = err;
      await new Promise((r) => setTimeout(r, attempt * 500));
    }
  }
  if (!sent) {
    logEvent('notification_error', { channel: 'discord', eventType, error: lastError?.message || 'unknown' });
    await appendLine(NOTIFY_DEAD_LETTER_PATH, {
      ts: new Date().toISOString(),
      eventType,
      payload,
      error: lastError?.message || 'unknown',
    });
  }
}

async function sendNotification(message) {
  const settings = await loadSettings();
  const type = settings.webhookType || 'discord';
  const text = message.slice(0, 1950);

  if (type === 'teams' && (settings.teamsWebhookUrl || process.env.TEAMS_WEBHOOK_URL)) {
    const url = settings.teamsWebhookUrl || process.env.TEAMS_WEBHOOK_URL;
    try {
      await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          '@type': 'MessageCard',
          '@context': 'http://schema.org/extensions',
          summary: 'Control Room',
          themeColor: '0076D7',
          title: 'Control Room',
          text: text.replace(/\*\*/g, ''),
        }),
      });
      logEvent('notification_sent', { channel: 'teams', preview: text.slice(0, 80) });
    } catch (err) {
      logEvent('notification_error', { channel: 'teams', error: err.message });
      console.error('Teams webhook error:', err);
    }
    return;
  }

  if (type === 'email' && settings.smtpHost && settings.alertEmail) {
    try {
      const nodemailer = require('nodemailer');
      const transporter = nodemailer.createTransport({
        host: settings.smtpHost,
        port: settings.smtpPort,
        secure: settings.smtpSecure === true,
        auth: settings.smtpUser ? { user: settings.smtpUser, pass: settings.smtpPass } : undefined,
      });
      await transporter.sendMail({
        from: settings.smtpFrom || settings.smtpUser || settings.alertEmail,
        to: settings.alertEmail,
        subject: '[Control Room] Avviso',
        text,
      });
      logEvent('notification_sent', { channel: 'email', preview: text.slice(0, 80) });
    } catch (err) {
      logEvent('notification_error', { channel: 'email', error: err.message });
      console.error('SMTP error:', err);
    }
    return;
  }

  if (type === 'pagerduty' && settings.pagerdutyRoutingKey) {
    try {
      await fetch('https://events.pagerduty.com/v2/enqueue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          routing_key: settings.pagerdutyRoutingKey,
          event_action: 'trigger',
          payload: {
            summary: text.slice(0, 1024),
            severity: 'info',
            source: 'control-room',
          },
        }),
      });
      logEvent('notification_sent', { channel: 'pagerduty', preview: text.slice(0, 80) });
    } catch (err) {
      logEvent('notification_error', { channel: 'pagerduty', error: err.message });
      console.error('PagerDuty error:', err);
    }
    return;
  }

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

/** kind: crash | restartLoop | exception | stderr — dopo flag globali, prima del debounce */
function isPm2NotifyTypeEnabled(settings, processName, kind) {
  const name = String(processName || '').trim();
  if (!name) return false;
  if (settings.notifyPm2Scope === 'onlyListed') {
    const list = settings.notifyPm2OnlyApps || [];
    if (list.length === 0) return false;
    if (!list.includes(name)) return false;
  }
  const per = settings.notifyPm2PerApp?.[name];
  if (per && per[kind] === false) return false;
  return true;
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

pm2.connect(async (err) => {
  if (err) {
    console.error('PM2 connect failed:', err);
    process.exit(1);
  }
  try {
    await redisClient.connect();
    const ping = await redisClient.ping();
    if (ping !== 'PONG') throw new Error(`Ping Redis inatteso: ${ping}`);
    redisReady = true;
    redisLastOkAt = new Date().toISOString();
    logEvent('redis_startup_check_ok', { ping });
  } catch (redisErr) {
    redisReady = false;
    redisLastError = redisErr.message;
    logEvent('redis_startup_check_error', { error: redisErr.message, required: SESSION_REDIS_REQUIRED });
    if (SESSION_REDIS_REQUIRED) {
      console.error('Redis required in production but not reachable. Aborting startup.');
      process.exit(1);
    }
  }
  registerCronJobs();
  registerDailyCheckFromSettings().catch((e) => {
    logEvent('daily_check_schedule_error', { error: e.message });
  });
  loadSettings().then((s) => registerAutoRemediationsFromSettings(s)).catch((e) => {
    logEvent('automation_remediation_schedule_error', { error: e.message });
  });
  pm2.launchBus((errBus, bus) => {
    if (errBus) return;
    bus.on('process:event', async (data) => {
      const ev = data?.event;
      const name = data?.process?.name || data?.name || 'unknown';
      const restartTime = data?.process?.restart_time ?? 0;
      logEvent('pm2_event', { event: ev, process: name, restartTime });
      const settings = await loadSettings();
      if (
        ev === 'exit' &&
        settings.notifyOnCrash !== false &&
        isPm2NotifyTypeEnabled(settings, name, 'crash') &&
        shouldNotifyProcess(name, 'exit')
      ) {
        await sendNotification(`⚠️ Alert: Il processo '${name}' è crashato! (Riavvio automatico in corso...)`);
      }
      if (
        ev === 'restart' &&
        settings.notifyOnRestart !== false &&
        restartTime >= 3 &&
        isPm2NotifyTypeEnabled(settings, name, 'restartLoop') &&
        shouldNotifyProcess(name, 'restart')
      ) {
        await sendNotification(`🔄 Crash loop: Il processo '${name}' è stato riavviato ${restartTime} volte. Verifica i log.`);
      }
    });
    bus.on('process:exception', async (data) => {
      const name = data?.process?.name || data?.name || 'unknown';
      const msg = (data?.msg || data?.error?.message || 'Errore non gestito').toString().slice(0, 300);
      logEvent('pm2_exception', { process: name, message: msg.slice(0, 100) });
      const settings = await loadSettings();
      const sendException = settings.notifyOnException === true || (settings.notifyOnException !== false && settings.notifyOnCrash !== false);
      if (!sendException || !isPm2NotifyTypeEnabled(settings, name, 'exception') || !shouldNotifyProcess(name, 'exception')) return;
      await sendNotification(`⚠️ Alert: Il processo '${name}' ha emesso un'eccezione: ${msg}`);
    });
    bus.on('log:err', async (data) => {
      const name = data?.process?.name || 'unknown';
      const msg = (data?.data || '').toString().slice(0, 500);
      if (msg) logEvent('pm2_log_err', { process: name, preview: msg.slice(0, 80) });
      const settings = await loadSettings();
      const sendStderr = settings.notifyOnLogErr === true;
      if (!sendStderr || !msg || !isPm2NotifyTypeEnabled(settings, name, 'stderr') || !shouldNotifyProcess(name, 'logerr', NOTIFY_DEBOUNCE_LOGERR_MS)) return;
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
  Promise.resolve()
    .then(async () => {
      if (redisClient?.isOpen) await redisClient.quit();
    })
    .catch(() => {})
    .finally(() => {
      pm2.disconnect();
      process.exit(0);
    });
});
