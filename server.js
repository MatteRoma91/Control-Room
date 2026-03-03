/**
 * Control Room - PM2 Dashboard Avanzato
 * Node.js/Express dashboard per gestire processi PM2, Nginx e manutenzione server
 */
require('dotenv').config();
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

// Helmet - sicurezza headers
app.use(helmet({ contentSecurityPolicy: false })); // CSP disabilitato per CDN Tailwind/Alpine

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const sessionMiddleware = session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
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

// Auth middleware - redirect to login if not authenticated
function requireAuth(req, res, next) {
  if (req.session?.user) return next();
  res.redirect('/login');
}

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
app.post('/login', loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  if (username === AUTH_USER && password === AUTH_PASSWORD) {
    req.session.user = username;
    return res.redirect('/');
  }
  res.redirect('/login?error=1');
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
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
    res.json({ ok: true });
  } catch (err) {
    console.error(`PM2 ${action} error:`, err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// API: flush logs
app.post('/api/process/flush/:name', requireAuth, (req, res) => {
  const { name } = req.params;
  pm2.flush(name, (err) => {
    if (err) {
      console.error('PM2 flush error:', err);
      return res.status(500).json({ ok: false, error: err.message });
    }
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
    res.json({ ok: true, output });
  } catch (err) {
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

// API: system stats per Chart.js (CPU %, RAM MB)
app.get('/api/system/stats', requireAuth, async (req, res) => {
  try {
    const [load, mem] = await Promise.all([si.currentLoad(), si.mem()]);
    const usedMemMB = Math.round((mem.total - mem.free) / 1024 / 1024);
    res.json({
      cpuPercent: load.currentLoad ?? 0,
      memoryUsedMB: usedMemMB,
      memoryTotalMB: Math.round(mem.total / 1024 / 1024),
      timestamp: new Date().toISOString(),
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
    res.json({ ok: true });
  } catch (err) {
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
    res.json({ ok: true });
  } catch (err) {
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
    res.json({ ok: true });
  } catch (err) {
    console.error('Nginx reload error:', err);
    res.status(500).json({ ok: false, error: err.message });
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

io.on('connection', (socket) => {
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

  socket.on('disconnect', () => {
    const procs = tailProcesses.get(socket.id);
    if (procs) {
      procs.out?.kill();
      procs.err?.kill();
      tailProcesses.delete(socket.id);
    }
  });
});

// ============ STARTUP ============

pm2.connect((err) => {
  if (err) {
    console.error('PM2 connect failed:', err);
    process.exit(1);
  }
  httpServer.listen(PORT, () => {
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
