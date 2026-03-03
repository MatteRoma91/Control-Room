/**
 * Control Room - PM2 Dashboard
 * Node.js/Express dashboard for managing PM2 processes
 */
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs').promises;
const os = require('os');
const { execSync } = require('child_process');
const pm2 = require('pm2');

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

// Trust first proxy (Nginx) for X-Forwarded-Proto
app.set('trust proxy', 1);

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  })
);

// Auth middleware - redirect to login if not authenticated
function requireAuth(req, res, next) {
  if (req.session?.user) return next();
  res.redirect('/login');
}

// Login page (GET) - show form, or redirect if already logged in
app.get('/login', (req, res) => {
  if (req.session?.user) return res.redirect('/');
  res.render('login', { error: req.query.error === '1' });
});

// Login (POST) - validate credentials
app.post('/login', (req, res) => {
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

// Protected routes
app.get('/', requireAuth, async (req, res) => {
  try {
    const list = await pm2List();
    res.render('index', { processes: list });
  } catch (err) {
    console.error('PM2 list error:', err);
    res.render('index', { processes: [], error: err.message });
  }
});

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

// API: system info (uptime, CPU, RAM, disk)
app.get('/api/system', requireAuth, (req, res) => {
  try {
    const uptimeSec = os.uptime();
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    const loadAvg = os.loadavg();
    let disk = { used: 0, total: 0, percent: 0 };
    try {
      const out = execSync('df -B1 / 2>/dev/null | tail -1', { encoding: 'utf8' });
      const parts = out.trim().split(/\s+/);
      if (parts.length >= 5) {
        disk.total = parseInt(parts[1], 10) || 0;
        disk.used = parseInt(parts[2], 10) || 0;
        disk.percent = parseInt(parts[4], 10) || 0;
      }
    } catch (_) {}
    res.json({
      uptime: formatUptime(uptimeSec * 1000),
      uptimeSec,
      loadAvg1: loadAvg[0] != null ? loadAvg[0].toFixed(2) : '-',
      memoryUsedMB: Math.round(usedMem / 1024 / 1024),
      memoryTotalMB: Math.round(totalMem / 1024 / 1024),
      memoryPercent: totalMem ? Math.round(100 * usedMem / totalMem) : 0,
      diskUsedGB: (disk.used / 1024 / 1024 / 1024).toFixed(2),
      diskTotalGB: (disk.total / 1024 / 1024 / 1024).toFixed(2),
      diskPercent: disk.percent,
    });
  } catch (err) {
    console.error('System info error:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// API: restart all webapps (padel-tour + roma-buche, not control-room)
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

// API: restore all processes from ecosystem files if missing/stopped
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

// API: health check of webapps
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

// API: nginx reload (requires sudoers: ubuntu NOPASSWD: /bin/systemctl reload nginx)
app.post('/api/nginx-reload', requireAuth, (req, res) => {
  try {
    execSync('sudo /bin/systemctl reload nginx 2>/dev/null', { encoding: 'utf8' });
    res.json({ ok: true });
  } catch (err) {
    console.error('Nginx reload error:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// PM2 helpers - wrap callbacks in Promises
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
      // Exclude control-room from main list or show it (plan says optionally exclude - we'll show it)
      resolve(processes);
    });
  });
}

function pm2Action(action, name) {
  return new Promise((resolve, reject) => {
    const fn = pm2[action];
    if (!fn) return reject(new Error(`Unknown action: ${action}`));
    fn(name, (err) => (err ? reject(err) : resolve()));
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

// Connect to PM2 daemon and start server
pm2.connect((err) => {
  if (err) {
    console.error('PM2 connect failed:', err);
    process.exit(1);
  }
  app.listen(PORT, () => {
    console.log(`Control Room running on http://localhost:${PORT}`);
  });
});

// Graceful shutdown
process.on('SIGINT', () => {
  pm2.disconnect();
  process.exit(0);
});
