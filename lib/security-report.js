/**
 * Lettura sola dei log già sul server: SSH, Fail2ban, Nginx.
 * Non modifica ban e non scrive nulla. Il risultato resta in memoria per un minuto.
 */
const fs = require('fs');
const { execFileSync } = require('child_process');

const AUTH_LOG = '/var/log/auth.log';
const NGINX_LOGS = ['/var/log/nginx/access.log', '/var/log/nginx/access.log.1'];
const FAIL2BAN_LOG = '/var/log/fail2ban.log';

const KNOWN = {
  '80.180.75.73': 'tuo IP',
  '93.63.141.98': 'tuo IP',
};

const CRAWL_PATHS = new Set([
  '/',
  '/robots.txt',
  '/favicon.ico',
  '/sitemap.xml',
  '/.well-known/security.txt',
]);

let cache = { at: 0, data: null };

function labelFor(ip, ownIp) {
  if (KNOWN[ip]) return KNOWN[ip];
  if (ownIp && ip === ownIp) return 'questo server';
  return '';
}

function ownIp() {
  try {
    const raw = execFileSync('ip', ['-4', 'route', 'get', '1.1.1.1'], { encoding: 'utf8' });
    const m = raw.match(/\bsrc\s+(\d+\.\d+\.\d+\.\d+)/);
    return m ? m[1] : '';
  } catch {
    return '';
  }
}

function eachLine(file, onLine) {
  if (!fs.existsSync(file)) return;
  const text = fs.readFileSync(file, 'utf8');
  for (const line of text.split('\n')) {
    if (line) onLine(line);
  }
}

function acceptedSsh() {
  const rows = [];
  let raw = '';
  const plain = [AUTH_LOG, '/var/log/auth.log.1'].filter((file) => fs.existsSync(file));
  if (plain.length) {
    try {
      raw = execFileSync('grep', ['-h', 'Accepted ', ...plain], {
        encoding: 'utf8',
        maxBuffer: 2 * 1024 * 1024,
      });
    } catch (err) {
      if (err.status !== 1) throw err;
      raw = err.stdout || '';
    }
  }
  const zipped = ['/var/log/auth.log.2.gz', '/var/log/auth.log.3.gz', '/var/log/auth.log.4.gz'].filter((file) => fs.existsSync(file));
  if (zipped.length) {
    try {
      const z = execFileSync('zgrep', ['-h', 'Accepted ', ...zipped], {
        encoding: 'utf8',
        maxBuffer: 2 * 1024 * 1024,
      });
      raw += (raw && !raw.endsWith('\n') ? '\n' : '') + z;
    } catch (err) {
      if (err.status !== 1 && err.status !== 2) throw err;
      if (err.stdout) raw += err.stdout;
    }
  }
  const re = /^(\S+).*Accepted\s+(password|publickey)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)/;
  for (const line of raw.split('\n')) {
    const m = line.match(re);
    if (!m) continue;
    rows.push({ at: m[1], method: m[2], user: m[3], ip: m[4], port: m[5] });
  }
  rows.sort((a, b) => (a.at < b.at ? 1 : -1));
  return rows;
}

function isProbePath(rawPath) {
  const path = String(rawPath || '').split('?')[0].toLowerCase();
  if (!path || path === '/') return false;
  if (path.includes('../') || path.includes('..\\') || path.includes('%2e%2e')) return true;
  if (path.includes('.env') || path.includes('/.git') || path.includes('wp-config') || path.includes('wp-login') || path.includes('xmlrpc.php')) return true;
  if (path.includes('phpinfo') || path.includes('boaform') || path.includes('/sdk/')) return true;
  if (path.includes('/.aws') || path.includes('/.ssh/') || path.includes('id_rsa') || path.includes('id_ed25519')) return true;
  if (path.includes('.my.cnf') || path.includes('.pgpass') || path.includes('.netrc') || path.includes('terraform')) return true;
  if (/backup\.(tar|tgz|zip|sql)/.test(path) || path.includes('dump.sql') || path.includes('database.sql') || path.includes('database_backup.sql')) return true;
  if (path.includes('proc/self') || path.includes('/.bash_history')) return true;
  return false;
}

function isPhpShot(rawPath) {
  const path = String(rawPath || '').split('?')[0].toLowerCase();
  return path.endsWith('.php') && !path.endsWith('/index.php');
}

function isLoginPath(method, rawPath) {
  if (method !== 'POST') return false;
  const path = String(rawPath || '').split('?')[0].toLowerCase();
  return path === '/api/auth/login' || path === '/login' || path.includes('reset_password') || path.includes('xmlrpc.php');
}

function verdictFor(rec) {
  if (rec.note === 'tuo IP') return 'tuo';
  if (rec.note === 'questo server') return 'server';
  if (rec.probes >= 1 || rec.phpPaths >= 8) {
    if (rec.signed) return 'scanner firmato';
    return 'scanner';
  }
  if (rec.signed) return 'censimento';
  if (rec.loginFails > 0) return 'prova login';
  if (rec.requests > 0 && rec.otherPaths === 0) return 'crawler';
  return 'visita';
}

function fail2ban() {
  const out = { ok: true, currentlyFailed: 0, currentlyBanned: 0, totalBanned: 0, banned: [], recent: [] };
  try {
    const raw = execFileSync('sudo', ['-n', 'fail2ban-client', 'status', 'sshd'], { encoding: 'utf8' });
    const num = (label) => {
      const m = raw.match(new RegExp(label + ':\\s*(\\d+)'));
      return m ? Number(m[1]) : 0;
    };
    out.currentlyFailed = num('Currently failed');
    out.currentlyBanned = num('Currently banned');
    out.totalBanned = num('Total banned');
    const list = (raw.match(/Banned IP list:\s*(.*)$/m) || [])[1] || '';
    out.banned = list.trim().split(/\s+/).filter(Boolean);
  } catch (err) {
    out.ok = false;
    out.error = String(err.stderr || err.message || err).trim().slice(0, 200);
  }
  try {
    const stat = fs.statSync(FAIL2BAN_LOG);
    const start = Math.max(0, stat.size - 80_000);
    const fd = fs.openSync(FAIL2BAN_LOG, 'r');
    const buf = Buffer.alloc(stat.size - start);
    fs.readSync(fd, buf, 0, buf.length, start);
    fs.closeSync(fd);
    const rows = [];
    const re = /^(\S+ \S+).*\[sshd\] (Ban|Unban) (\S+)/;
    for (const line of buf.toString('utf8').split('\n')) {
      const m = line.match(re);
      if (!m) continue;
      rows.push({ at: m[1], action: m[2], ip: m[3] });
    }
    out.recent = rows.slice(-12).reverse();
  } catch {
    /* log assente */
  }
  return out;
}

function posture(serverIp) {
  const info = { passwordAuth: null, permitRoot: null, ufw: null, serverIp };
  try {
    const raw = execFileSync('sudo', ['-n', 'sshd', '-T'], { encoding: 'utf8' });
    const line = (key) => (raw.match(new RegExp('^' + key + '\\s+(\\S+)', 'm')) || [])[1] || '';
    info.passwordAuth = line('passwordauthentication');
    info.permitRoot = line('permitrootlogin');
  } catch {
    info.passwordAuth = '';
  }
  try {
    const raw = execFileSync('sudo', ['-n', 'ufw', 'status'], { encoding: 'utf8' });
    info.ufw = raw.split('\n')[0].trim();
  } catch {
    info.ufw = '';
  }
  return info;
}

function compute() {
  const errors = [];
  const serverIp = ownIp();
  const hourly = new Map();
  const failByIp = new Map();
  let sshFailed = 0;

  try {
    eachLine(AUTH_LOG, (line) => {
      if (!line.includes('Failed password') && !line.includes('Invalid user')) return;
      const ts = (line.match(/^(\d{4}-\d{2}-\d{2}T\d{2})/) || [])[1] || '';
      const ip = (line.match(/\bfrom\s+(\d+\.\d+\.\d+\.\d+)/) || [])[1] || '';
      if (!ip) return;
      if (line.includes('Invalid user') && !line.includes('Failed password')) {
        const rec = failByIp.get(ip) || { ip, count: 0, users: new Set() };
        const user = (line.match(/Invalid user\s+(\S+)\s+from\s+/) || [])[1];
        if (user && user !== 'from') rec.users.add(user);
        failByIp.set(ip, rec);
        return;
      }
      sshFailed += 1;
      if (ts) hourly.set(ts, (hourly.get(ts) || 0) + 1);
      const rec = failByIp.get(ip) || { ip, count: 0, users: new Set() };
      rec.count += 1;
      const user = (line.match(/Failed password for(?: invalid user)?\s+(\S+)\s+from\s+/) || [])[1];
      if (user && user !== 'from') rec.users.add(user);
      failByIp.set(ip, rec);
    });
  } catch (err) {
    errors.push('ssh: ' + err.message);
  }

  let accepted = [];
  try {
    accepted = acceptedSsh().map((row) => ({
      ...row,
      note: labelFor(row.ip, serverIp),
      unknown: !labelFor(row.ip, serverIp),
    }));
  } catch (err) {
    errors.push('ssh riusciti: ' + err.message);
  }

  const byIp = new Map();
  const logins = [];
  let probeRequests = 0;
  try {
    for (const file of NGINX_LOGS) {
      eachLine(file, (line) => {
        const m = line.match(/^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) ([^ ]*) [^"]*" (\d+) (\S+)/);
        if (!m) return;
        const ip = m[1];
        const at = m[2];
        const method = m[3];
        const reqPath = m[4];
        const status = m[5];
        const size = Number(m[6]);
        const bare = reqPath.split('?')[0];
        const quotes = line.match(/"([^"]*)"/g) || [];
        const ua = quotes.length ? quotes[quotes.length - 1].slice(1, -1) : '';
        const rec = byIp.get(ip) || {
          ip,
          requests: 0,
          probes: 0,
          php: new Set(),
          crawlOnly: true,
          otherPaths: 0,
          loginFails: 0,
          loginOk: 0,
          lastPath: '',
          lastStatus: '',
          signed: false,
          sizes: new Set(),
        };
        rec.requests += 1;
        const probe = isProbePath(bare);
        const php = isPhpShot(bare);
        if (probe) {
          rec.probes += 1;
          probeRequests += 1;
          if (status === '200' && Number.isFinite(size)) rec.sizes.add(size);
        }
        if (php) rec.php.add(bare);
        if (!CRAWL_PATHS.has(bare)) {
          rec.crawlOnly = false;
          if (!probe && !php) rec.otherPaths += 1;
        }
        if (/censys|leakix|l9scan/i.test(ua)) rec.signed = true;
        if (isLoginPath(method, bare)) {
          if (status.startsWith('2')) rec.loginOk += 1;
          else rec.loginFails += 1;
          logins.push({ at, ip, method, path: bare, status, note: labelFor(ip, serverIp) });
        }
        if (probe || php) {
          rec.lastPath = bare.slice(0, 100);
          rec.lastStatus = status;
        }
        byIp.set(ip, rec);
      });
    }
  } catch (err) {
    errors.push('nginx: ' + err.message);
  }

  const webRows = [...byIp.values()]
    .map((rec) => {
      const phpPaths = rec.php.size;
      const note = labelFor(rec.ip, serverIp);
      const shaped = {
        ip: rec.ip,
        requests: rec.requests,
        probes: rec.probes,
        phpPaths,
        loginFails: rec.loginFails,
        loginOk: rec.loginOk,
        otherPaths: rec.crawlOnly ? 0 : rec.otherPaths,
        lastPath: rec.lastPath,
        lastStatus: rec.lastStatus,
        signed: rec.signed,
        note,
        repeatedPage: rec.sizes.size > 0 && rec.sizes.size <= 2 && rec.probes >= 3,
      };
      shaped.verdict = verdictFor({ ...shaped, probes: rec.probes, phpPaths });
      return shaped;
    })
    .filter((row) => row.verdict === 'scanner' || row.verdict === 'scanner firmato' || row.verdict === 'prova login' || row.verdict === 'censimento')
    .sort((a, b) => (b.probes + b.phpPaths) - (a.probes + a.phpPaths) || b.loginFails - a.loginFails || b.requests - a.requests)
    .slice(0, 25);

  const sshTop = [...failByIp.values()]
    .filter((row) => row.count > 0)
    .sort((a, b) => b.count - a.count)
    .slice(0, 12)
    .map((row) => ({
      ip: row.ip,
      count: row.count,
      users: [...row.users].slice(0, 4).join(', '),
      note: labelFor(row.ip, serverIp),
    }));

  const sshHourly = [...hourly.entries()]
    .sort((a, b) => (a[0] < b[0] ? 1 : -1))
    .slice(0, 18)
    .reverse()
    .map(([hour, count]) => ({ hour: hour.slice(5).replace('T', ' ') + ':00', count }));

  const unknownAccepted = accepted.filter((row) => row.unknown).length;
  const loginFailsExternal = logins.filter((row) => !row.note && !String(row.status).startsWith('2')).length;

  return {
    ok: errors.length === 0,
    generatedAt: new Date().toISOString(),
    errors,
    window: {
      sshFailures: 'auth.log corrente, dal riavvio o dall’ultima rotazione',
      sshSuccess: 'auth.log corrente, il precedente e gli archivi .gz ancora sul disco',
      web: 'access.log di Nginx e il file ruotato precedente',
    },
    summary: {
      sshFailed,
      sshFailIps: [...failByIp.values()].filter((row) => row.count > 0).length,
      sshAccepted: accepted.length,
      sshAcceptedUnknown: unknownAccepted,
      webProbeRequests: probeRequests,
      webProbeIps: webRows.filter((row) => row.verdict.startsWith('scanner') || row.verdict === 'censimento').length,
      webLoginFailures: loginFailsExternal,
      bannedNow: 0,
    },
    posture: posture(serverIp),
    sshHourly,
    sshAccepted: accepted.slice(0, 20),
    sshTop,
    webRows,
    webLogins: logins.filter((row) => row.note !== 'tuo IP' || !String(row.status).startsWith('2')).slice(0, 30),
    fail2ban: fail2ban(),
  };
}

function buildSecurityReport() {
  const now = Date.now();
  if (cache.data && now - cache.at < 60_000) {
    return { ...cache.data, cached: true };
  }
  const data = compute();
  data.summary.bannedNow = data.fail2ban.currentlyBanned || 0;
  data.cached = false;
  cache = { at: now, data };
  return data;
}

function clearSecurityReportCache() {
  cache = { at: 0, data: null };
}

module.exports = { buildSecurityReport, clearSecurityReportCache };
