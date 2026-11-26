/**
 * Snapshot read-only: login SSH riusciti, sessioni aperte, ban fail2ban, top IP Nginx.
 * I log sono leggibili dal gruppo adm. fail2ban-client richiede sudo -n.
 */
const fs = require('fs');
const { execFileSync } = require('child_process');

const AUTH_LOG = '/var/log/auth.log';
const NGINX_LOG = '/var/log/nginx/access.log';
const FAIL2BAN_LOG = '/var/log/fail2ban.log';

const KNOWN = {
  '80.180.75.73': 'whitelist SSH',
  '93.63.141.98': 'whitelist SSH',
};

function labelFor(ip) {
  return KNOWN[ip] || '';
}

function tailText(file, maxBytes) {
  const stat = fs.statSync(file);
  const start = Math.max(0, stat.size - maxBytes);
  const fd = fs.openSync(file, 'r');
  try {
    const buf = Buffer.alloc(stat.size - start);
    fs.readSync(fd, buf, 0, buf.length, start);
    const text = buf.toString('utf8');
    const cut = text.indexOf('\n');
    return cut === -1 ? text : text.slice(cut + 1);
  } finally {
    fs.closeSync(fd);
  }
}

function sshLogins() {
  let raw = '';
  try {
    raw = execFileSync('grep', ['-E', 'Accepted (password|publickey) for ', AUTH_LOG], {
      encoding: 'utf8',
      maxBuffer: 4 * 1024 * 1024,
    });
  } catch (err) {
    if (err.status === 1) return [];
    throw err;
  }
  const rows = [];
  const re = /^(\S+)\s+\S+\s+sshd\[\d+\]:\s+Accepted\s+(password|publickey)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)/;
  for (const line of raw.split('\n')) {
    const m = line.match(re);
    if (!m) continue;
    rows.push({
      at: m[1],
      method: m[2],
      user: m[3],
      ip: m[4],
      port: m[5],
      note: labelFor(m[4]),
    });
  }
  return rows.reverse().slice(0, 40);
}

function sshSessions() {
  let raw = '';
  try {
    raw = execFileSync('ss', ['-Htn', 'state', 'established', '( sport = :22 )'], { encoding: 'utf8' });
  } catch {
    return [];
  }
  const rows = [];
  for (const line of raw.split('\n')) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 4) continue;
    const peer = parts[3];
    const ip = peer.replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
    const port = (peer.match(/:(\d+)$/) || [])[1] || '';
    if (!ip) continue;
    rows.push({ ip, port, note: labelFor(ip) });
  }
  return rows;
}

function fail2banStatus() {
  let raw = '';
  try {
    raw = execFileSync('sudo', ['-n', 'fail2ban-client', 'status', 'sshd'], { encoding: 'utf8' });
  } catch (err) {
    return { ok: false, error: String(err.stderr || err.message || err).trim().slice(0, 300) };
  }
  const num = (label) => {
    const m = raw.match(new RegExp(label + ':\\s*(\\d+)'));
    return m ? Number(m[1]) : 0;
  };
  const listMatch = raw.match(/Banned IP list:\s*(.*)$/m);
  const banned = (listMatch ? listMatch[1] : '')
    .trim()
    .split(/\s+/)
    .filter((ip) => /^\d{1,3}(\.\d{1,3}){3}$/.test(ip) || ip.includes(':'));
  return {
    ok: true,
    currentlyFailed: num('Currently failed'),
    totalFailed: num('Total failed'),
    currentlyBanned: num('Currently banned'),
    totalBanned: num('Total banned'),
    banned: banned.map((ip) => ({ ip, note: labelFor(ip) })),
  };
}

function fail2banEvents() {
  let text = '';
  try {
    text = tailText(FAIL2BAN_LOG, 200_000);
  } catch {
    return [];
  }
  const rows = [];
  const re = /^(\S+ \S+).*\[sshd\] (Ban|Unban) (\S+)/;
  for (const line of text.split('\n')) {
    const m = line.match(re);
    if (!m) continue;
    rows.push({ at: m[1], action: m[2], ip: m[3], note: labelFor(m[3]) });
  }
  return rows.slice(-30).reverse();
}

function nginxTop() {
  let text = '';
  try {
    text = fs.readFileSync(NGINX_LOG, 'utf8');
  } catch (err) {
    return { error: err.message, rows: [] };
  }
  const byIp = new Map();
  for (const line of text.split('\n')) {
    if (!line) continue;
    const ip = line.split(' ', 1)[0];
    if (!ip || ip === '-') continue;
    const quoted = line.match(/"([^"]*)"/);
    const req = quoted ? quoted[1] : '';
    const path = req.split(' ')[1] || '';
    const after = line.split('"')[2] || '';
    const status = (after.trim().split(/\s+/)[0] || '');
    const rec = byIp.get(ip) || { ip, requests: 0, ok: 0, denied: 0, lastPath: '', lastStatus: '' };
    rec.requests += 1;
    if (status.startsWith('2') || status.startsWith('3')) rec.ok += 1;
    else if (status === '403' || status === '401' || status === '404') rec.denied += 1;
    if (path) {
      rec.lastPath = path.slice(0, 120);
      rec.lastStatus = status;
    }
    byIp.set(ip, rec);
  }
  const rows = [...byIp.values()]
    .sort((a, b) => b.requests - a.requests)
    .slice(0, 25)
    .map((row) => ({ ...row, note: labelFor(row.ip) }));
  return { rows, lines: text.split('\n').length };
}

function buildAccessReport() {
  const errors = [];
  let logins = [];
  let sessions = [];
  let jail = { ok: false, error: 'non letto' };
  let bans = [];
  let web = { rows: [] };
  try { logins = sshLogins(); } catch (err) { errors.push('ssh: ' + err.message); }
  try { sessions = sshSessions(); } catch (err) { errors.push('sessioni: ' + err.message); }
  try { jail = fail2banStatus(); } catch (err) { errors.push('fail2ban: ' + err.message); }
  try { bans = fail2banEvents(); } catch (err) { errors.push('ban log: ' + err.message); }
  try { web = nginxTop(); } catch (err) { errors.push('nginx: ' + err.message); }
  return {
    ok: errors.length === 0,
    generatedAt: new Date().toISOString(),
    errors,
    ssh: { sessions, logins },
    fail2ban: { ...jail, recent: bans },
    web,
  };
}

module.exports = { buildAccessReport };
