/**
 * Lettura e modifica dei ban Fail2ban tramite fail2ban-client.
 * Gli argomenti sono una lista fissa: nessun shell, nessun input concatenato.
 */
const { execFile } = require('child_process');
const net = require('net');
const { promisify } = require('util');
const { isIpInCidr, normalizeIp } = require('../lib/ip-utils');

const execFileAsync = promisify(execFile);
const CLIENT = '/usr/bin/fail2ban-client';
const JAIL_RE = /^[a-zA-Z0-9_-]{1,64}$/;

function httpError(status, message) {
  const err = new Error(message);
  err.status = status;
  return err;
}

function run(args) {
  return execFileAsync('sudo', ['-n', CLIENT, ...args], {
    encoding: 'utf8',
    timeout: 15000,
    maxBuffer: 1024 * 1024,
  });
}

function assertJail(jail) {
  const name = String(jail || 'sshd').trim();
  if (!JAIL_RE.test(name)) throw httpError(400, 'Jail non valida');
  return name;
}

function assertIp(ip) {
  const value = normalizeIp(ip);
  if (!value || net.isIP(value) === 0) throw httpError(400, 'Indirizzo IP non valido');
  return value;
}

function parseIgnore(raw) {
  const entries = [];
  for (const token of String(raw || '').match(/\S+/g) || []) {
    const value = token.replace(/[|,`']/g, '');
    const slash = value.indexOf('/');
    if (slash > 0) {
      const host = value.slice(0, slash);
      const bits = Number(value.slice(slash + 1));
      const max = host.includes(':') ? 128 : 32;
      if (net.isIP(host) && Number.isInteger(bits) && bits >= 0 && bits <= max) entries.push(`${host}/${bits}`);
      continue;
    }
    if (net.isIP(value)) entries.push(value);
  }
  return entries;
}

function isLoopback(ip) {
  if (ip === '::1' || ip === '0:0:0:0:0:0:0:1') return true;
  return net.isIP(ip) === 4 && isIpInCidr(ip, '127.0.0.0/8');
}

function matchesIgnore(ip, entries) {
  for (const entry of entries) {
    if (entry.includes('/')) {
      if (entry.includes(':') || net.isIP(ip) !== 4) continue;
      if (isIpInCidr(ip, entry)) return true;
      continue;
    }
    if (normalizeIp(entry) === ip) return true;
  }
  return false;
}

function parseBanLines(raw) {
  const bans = [];
  for (const line of String(raw || '').split('\n')) {
    const text = line.trim();
    if (!text) continue;
    const timed = text.match(/^(\S+)\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+\+\s+(-?\d+)\s+=\s+(.+)$/);
    if (timed) {
      const permanent = timed[3] === '-1';
      bans.push({
        ip: timed[1],
        bannedAt: timed[2],
        permanent,
        until: permanent ? null : timed[4].trim(),
      });
      continue;
    }
    const ip = text.split(/\s+/)[0];
    if (net.isIP(ip)) bans.push({ ip, bannedAt: null, permanent: false, until: null });
  }
  return bans;
}

function numFrom(raw, label) {
  const m = String(raw).match(new RegExp(label + ':\\s*(\\d+)'));
  return m ? Number(m[1]) : 0;
}

async function listJails() {
  const { stdout } = await run(['status']);
  const line = (stdout.match(/Jail list:\s*(.*)/) || [])[1] || '';
  return line.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
}

async function snapshot(jailName) {
  const jails = await listJails();
  const jail = assertJail(jailName || jails[0] || 'sshd');
  if (jails.length && !jails.includes(jail)) throw httpError(404, 'Jail non attiva');

  const [status, times, bantimeRaw, findtimeRaw, maxretryRaw, ignoreRaw] = await Promise.all([
    run(['status', jail]).then((r) => r.stdout),
    run(['get', jail, 'banip', '--with-time']).then((r) => r.stdout).catch(() => ''),
    run(['get', jail, 'bantime']).then((r) => r.stdout.trim()),
    run(['get', jail, 'findtime']).then((r) => r.stdout.trim()),
    run(['get', jail, 'maxretry']).then((r) => r.stdout.trim()),
    run(['get', jail, 'ignoreip']).then((r) => r.stdout).catch(() => ''),
  ]);

  const bantime = Number(bantimeRaw);
  const findtime = Number(findtimeRaw);
  const maxretry = Number(maxretryRaw);
  return {
    ok: true,
    jail,
    jails,
    currentlyFailed: numFrom(status, 'Currently failed'),
    currentlyBanned: numFrom(status, 'Currently banned'),
    totalBanned: numFrom(status, 'Total banned'),
    policy: {
      maxretry: Number.isFinite(maxretry) ? maxretry : null,
      findtime: Number.isFinite(findtime) ? findtime : null,
      bantime: Number.isFinite(bantime) ? bantime : null,
      permanent: bantime === -1,
    },
    ignoreip: parseIgnore(ignoreRaw),
    bans: parseBanLines(times),
  };
}

async function banIp(ip, jailName, requestIp) {
  const jail = assertJail(jailName);
  const target = assertIp(ip);
  const state = await snapshot(jail);
  const own = normalizeIp(requestIp);
  const ownIp = own && net.isIP(own) ? own : '';
  if (isLoopback(target) || matchesIgnore(target, state.ignoreip) || (ownIp && target === ownIp)) {
    throw httpError(400, 'Questo IP è locale, è nella whitelist di Fail2ban, oppure è l’IP da cui stai usando la Control Room.');
  }
  await run(['set', jail, 'banip', target]);
  return snapshot(jail);
}

async function unbanIp(ip, jailName) {
  const jail = assertJail(jailName);
  const target = assertIp(ip);
  await run(['set', jail, 'unbanip', target]);
  return snapshot(jail);
}

module.exports = {
  snapshot,
  banIp,
  unbanIp,
};
