/**
 * Avvisa su Discord quando SSH accetta un login.
 * Il cursore del journal parte da "adesso": i login già passati non vengono rinotificati.
 * Se l'invio fallisce, il cursore non avanza e il tentativo si ripete.
 */
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');
const { loadSettings } = require('./settings');

const execFileAsync = promisify(execFile);
const CURSOR_PATH = path.join(__dirname, '..', 'logs', 'ssh-login.cursor');
const ACCEPTED = /^(\S+).*Accepted\s+(password|publickey)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)/;
const KNOWN = {
  '80.180.75.73': 'tuo IP',
  '93.63.141.98': 'tuo IP',
};

let running = false;

function journal(args) {
  return execFileAsync('journalctl', args, {
    encoding: 'utf8',
    timeout: 20000,
    maxBuffer: 1024 * 1024,
  }).then((r) => r.stdout || '');
}

function parseCursor(raw) {
  const line = String(raw).split('\n').find((row) => row.startsWith('-- cursor: '));
  return line ? line.slice('-- cursor: '.length).trim() : '';
}

async function readCursor() {
  try {
    return (await fs.promises.readFile(CURSOR_PATH, 'utf8')).trim();
  } catch {
    return '';
  }
}

async function writeCursor(cursor) {
  await fs.promises.mkdir(path.dirname(CURSOR_PATH), { recursive: true });
  await fs.promises.writeFile(CURSOR_PATH, cursor + '\n', 'utf8');
}

function webhookFor(settings) {
  return settings.discordWebhookSecurity || settings.webhookUrl || settings.discordWebhookOps || '';
}

function messageFor(hit) {
  const who = KNOWN[hit.ip] ? ` (${KNOWN[hit.ip]})` : '';
  const method = hit.method === 'publickey' ? 'chiave' : 'password';
  return [
    '**Login SSH riuscito**',
    `Utente: ${hit.user}`,
    `Metodo: ${method}`,
    `IP: ${hit.ip}${who}`,
    `Porta: ${hit.port}`,
    `Quando: ${hit.at}`,
  ].join('\n');
}

async function postDiscord(url, content) {
  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: content.slice(0, 1900) }),
  });
  if (!resp.ok) throw new Error(`Webhook HTTP ${resp.status}`);
}

async function pollSshLogins(logEvent = () => {}) {
  if (running) return;
  running = true;
  try {
    const settings = await loadSettings();
    let cursor = await readCursor();
    if (!cursor) {
      cursor = parseCursor(await journal(['-u', 'ssh.service', '-n', '0', '--show-cursor', '--no-pager', '-o', 'cat']));
      if (cursor) await writeCursor(cursor);
      return;
    }
    if (settings.notifyOnSshLogin === false) {
      const skipped = parseCursor(await journal([
        '-u', 'ssh.service',
        `--after-cursor=${cursor}`,
        '--show-cursor',
        '--no-pager',
        '-o', 'cat',
      ]));
      if (skipped) await writeCursor(skipped);
      return;
    }
    const raw = await journal([
      '-u', 'ssh.service',
      `--after-cursor=${cursor}`,
      '--show-cursor',
      '--no-pager',
      '-o', 'short-iso',
    ]);
    const next = parseCursor(raw);
    const hits = [];
    for (const line of raw.split('\n')) {
      const m = line.match(ACCEPTED);
      if (!m) continue;
      hits.push({ at: m[1], method: m[2], user: m[3], ip: m[4], port: m[5] });
    }
    if (!hits.length) {
      if (next) await writeCursor(next);
      return;
    }
    const url = webhookFor(settings);
    if (!url) {
      logEvent('ssh_login_notify_skipped', { reason: 'no_webhook', count: hits.length });
      if (next) await writeCursor(next);
      return;
    }
    for (const hit of hits) {
      await postDiscord(url, messageFor(hit));
      logEvent('ssh_login_notified', { user: hit.user, ip: hit.ip, method: hit.method });
    }
    if (next) await writeCursor(next);
  } catch (err) {
    logEvent('ssh_login_watch_error', { error: err.message });
  } finally {
    running = false;
  }
}

module.exports = { pollSshLogins, messageFor };
