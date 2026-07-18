/**
 * settings.json persistence + sanitization — behavior unchanged.
 */
const path = require('path');
const fs = require('fs').promises;

const SETTINGS_PATH = path.join(__dirname, '..', 'settings.json');

const MAX_PM2_NOTIFY_PER_APP_KEYS = 64;
const MAX_PM2_PROCESS_NAME_LEN = 200;

function sanitizePm2ProcessName(s) {
  const t = String(s || '')
    .trim()
    .slice(0, MAX_PM2_PROCESS_NAME_LEN);
  return t || null;
}

function sanitizeNotifyPm2OnlyApps(arr) {
  if (!Array.isArray(arr)) return [];
  const seen = new Set();
  const out = [];
  for (const x of arr) {
    const n = sanitizePm2ProcessName(x);
    if (n && !seen.has(n)) {
      seen.add(n);
      out.push(n);
    }
    if (out.length >= MAX_PM2_NOTIFY_PER_APP_KEYS) break;
  }
  return out;
}

function sanitizeNotifyPm2PerApp(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return {};
  const out = {};
  for (const k of Object.keys(obj)) {
    if (Object.keys(out).length >= MAX_PM2_NOTIFY_PER_APP_KEYS) break;
    const name = sanitizePm2ProcessName(k);
    if (!name) continue;
    const v = obj[k];
    if (!v || typeof v !== 'object') continue;
    const row = {};
    if (v.crash === false) row.crash = false;
    if (v.restartLoop === false) row.restartLoop = false;
    if (v.exception === false) row.exception = false;
    if (v.stderr === false) row.stderr = false;
    if (Object.keys(row).length) out[name] = row;
  }
  return out;
}

function sanitizeSettings(raw) {
  const source = raw && typeof raw === 'object' ? raw : {};
  const dailyRaw = source.dailyCheck || {};
  const panicExpiresAt = source.panicExpiresAt ? String(source.panicExpiresAt) : '';
  const safe = {
    schemaVersion: 1,
    ipWhitelistEnabled: source.ipWhitelistEnabled === true,
    ipWhitelist: Array.isArray(source.ipWhitelist) ? source.ipWhitelist.map((s) => String(s).trim()).filter(Boolean) : [],
    ipWhitelistTemporary: Array.isArray(source.ipWhitelistTemporary)
      ? source.ipWhitelistTemporary
          .map((e) => ({ ip: String(e?.ip || '').trim(), expiresAt: String(e?.expiresAt || '') }))
          .filter((e) => e.ip && e.expiresAt)
      : [],
    webhookType: ['discord', 'slack', 'telegram', 'teams', 'email', 'pagerduty'].includes(source.webhookType)
      ? source.webhookType
      : 'discord',
    webhookUrl: String(source.webhookUrl || ''),
    teamsWebhookUrl: String(source.teamsWebhookUrl || process.env.TEAMS_WEBHOOK_URL || ''),
    smtpHost: String(source.smtpHost || process.env.CR_SMTP_HOST || ''),
    smtpPort: parseInt(String(source.smtpPort || process.env.CR_SMTP_PORT || '587'), 10) || 587,
    smtpUser: String(source.smtpUser || process.env.CR_SMTP_USER || ''),
    smtpPass: String(source.smtpPass || process.env.CR_SMTP_PASS || ''),
    smtpFrom: String(source.smtpFrom || process.env.CR_SMTP_FROM || ''),
    smtpSecure: source.smtpSecure === true || process.env.CR_SMTP_SECURE === '1',
    alertEmail: String(source.alertEmail || process.env.CR_ALERT_EMAIL || ''),
    pagerdutyRoutingKey: String(source.pagerdutyRoutingKey || process.env.PAGERDUTY_ROUTING_KEY || ''),
    discordWebhookOps: String(source.discordWebhookOps || process.env.DISCORD_WEBHOOK_OPS || ''),
    discordWebhookIncidents: String(source.discordWebhookIncidents || process.env.DISCORD_WEBHOOK_INCIDENTS || ''),
    discordWebhookSecurity: String(source.discordWebhookSecurity || process.env.DISCORD_WEBHOOK_SECURITY || ''),
    telegramBotToken: String(source.telegramBotToken || ''),
    telegramChatId: String(source.telegramChatId || ''),
    notifyOnCrash: source.notifyOnCrash !== false,
    notifyOnRestart: source.notifyOnRestart !== false,
    notifyOnException: source.notifyOnException === true || (source.notifyOnException !== false && source.notifyOnCrash !== false),
    notifyOnLogErr: source.notifyOnLogErr === true,
    notifyOnRunbook: source.notifyOnRunbook === true,
    notifyOnIncident: source.notifyOnIncident !== false,
    notifyOnSecurity: source.notifyOnSecurity === true,
    notifyPm2Scope: source.notifyPm2Scope === 'onlyListed' ? 'onlyListed' : 'all',
    notifyPm2OnlyApps: sanitizeNotifyPm2OnlyApps(source.notifyPm2OnlyApps),
    notifyPm2PerApp: sanitizeNotifyPm2PerApp(source.notifyPm2PerApp),
    sshProfiles: Array.isArray(source.sshProfiles) ? source.sshProfiles : [],
    totpSecret: String(source.totpSecret || ''),
    totpEnabled: source.totpEnabled === true,
    cronJobs: Array.isArray(source.cronJobs) ? source.cronJobs : [],
    panicMode: source.panicMode === true,
    panicModeIp: String(source.panicModeIp || ''),
    panicExpiresAt,
    dailyCheck: {
      enabled: dailyRaw.enabled !== false,
      time: typeof dailyRaw.time === 'string' && /^\d{2}:\d{2}$/.test(dailyRaw.time) ? dailyRaw.time : '00:00',
    },
    autoRemediations: Array.isArray(source.autoRemediations) ? source.autoRemediations : [],
  };
  return safe;
}

async function loadSettings() {
  try {
    const data = await fs.readFile(SETTINGS_PATH, 'utf8');
    const s = sanitizeSettings(JSON.parse(data));
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
    return sanitizeSettings({});
  }
}

async function saveSettings(obj) {
  const validated = sanitizeSettings(obj);
  await fs.writeFile(SETTINGS_PATH, JSON.stringify(validated, null, 2), 'utf8');
  try {
    await fs.chmod(SETTINGS_PATH, 0o600);
  } catch (_) {}
}

function normalizeDailyCheckConfig(settings) {
  const raw = settings?.dailyCheck || {};
  const enabled = raw.enabled !== false;
  const time = typeof raw.time === 'string' && /^\d{2}:\d{2}$/.test(raw.time) ? raw.time : '00:00';
  return { enabled, time };
}

module.exports = {
  SETTINGS_PATH,
  sanitizeSettings,
  loadSettings,
  saveSettings,
  normalizeDailyCheckConfig,
};
