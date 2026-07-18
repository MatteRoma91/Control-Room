/**
 * Settings page/API, panic mode, 2FA setup — behavior unchanged.
 */
const { loadSettings, saveSettings, sanitizeSettings } = require('../services/settings');

function registerSettingsRoutes(app, ctx) {
  const {
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
  } = ctx;

  app.get('/settings', requireAuth, async (req, res) => {
    const settings = await loadSettings();
    let pm2Processes = [];
    try {
      pm2Processes = await pm2List();
    } catch (e) {
      logEvent('settings_pm2_list_error', { error: e.message });
    }
    res.render('layout', { contentPartial: 'settings', settings, pm2Processes });
  });

  app.get('/api/settings', requireAuth, async (req, res) => {
    const settings = await loadSettings();
    res.json(settings);
  });

  app.post('/api/settings', requireAuth, async (req, res) => {
    try {
      const body = sanitizeSettings({ ...(req.body || {}) });
      const current = await loadSettings();
      body.totpSecret = current.totpSecret;
      body.totpEnabled = current.totpEnabled;
      body.panicMode = current.panicMode;
      body.panicModeIp = current.panicModeIp;
      body.panicExpiresAt = current.panicExpiresAt;
      body.dailyCheck = current.dailyCheck;
      if (!Array.isArray(body.sshProfiles)) body.sshProfiles = current.sshProfiles || [];
      if (!Array.isArray(body.cronJobs)) body.cronJobs = current.cronJobs || [];
      if (!Array.isArray(body.ipWhitelist)) body.ipWhitelist = current.ipWhitelist || [];
      if (!Array.isArray(body.autoRemediations)) body.autoRemediations = current.autoRemediations || [];
      await saveSettings(body);
      registerAutoRemediationsFromSettings(body);
      await audit('settings_saved', { user: req.session?.user });
      res.json({ ok: true });
    } catch (err) {
      console.error('Settings save error:', err);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.post('/api/settings/panic-activate', requireAuth, async (req, res) => {
    try {
      if (!hasStrongConfirmation(req, 'panicActivate')) {
        return res.status(400).json({ ok: false, error: `Conferma richiesta. Frase: ${HIGH_RISK_PHRASES.panicActivate}` });
      }
      const clientIp = normalizeIp(req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '');
      const durationMin = Math.max(5, Math.min(240, parseInt(req.body?.durationMin || String(DEFAULT_PANIC_DURATION_MIN), 10)));
      const expiresAt = new Date(Date.now() + durationMin * 60 * 1000).toISOString();
      const current = await loadSettings();
      current.panicMode = true;
      current.panicModeIp = clientIp;
      current.panicExpiresAt = expiresAt;
      await saveSettings(current);
      await audit('panic_activate', { user: req.session?.user, ip: clientIp, expiresAt });
      res.json({ ok: true, panicModeIp: clientIp, expiresAt });
    } catch (err) {
      console.error('Panic activate error:', err);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.post('/api/settings/panic-disable', requireAuth, async (req, res) => {
    try {
      if (!hasStrongConfirmation(req, 'panicDisable')) {
        return res.status(400).json({ ok: false, error: `Conferma richiesta. Frase: ${HIGH_RISK_PHRASES.panicDisable}` });
      }
      const current = await loadSettings();
      current.panicMode = false;
      current.panicModeIp = '';
      current.panicExpiresAt = '';
      await saveSettings(current);
      await audit('panic_disable', { user: req.session?.user });
      res.json({ ok: true });
    } catch (err) {
      console.error('Panic disable error:', err);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.get('/settings/2fa-setup', requireAuth, async (req, res) => {
    const settings = await loadSettings();
    res.render('layout', { contentPartial: 'settings-2fa-setup', settings });
  });

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

  app.post('/api/2fa/disable', requireAuth, async (req, res) => {
    try {
      const { password, confirmPhrase } = req.body || {};
      if (String(confirmPhrase || '').trim() !== HIGH_RISK_PHRASES.disable2FA) {
        return res.status(400).json({ ok: false, error: `Conferma richiesta. Frase: ${HIGH_RISK_PHRASES.disable2FA}` });
      }
      if (password !== AUTH_PASSWORD) {
        return res.status(401).json({ ok: false, error: 'Password non valida' });
      }
      const current = await loadSettings();
      current.totpEnabled = false;
      current.totpSecret = '';
      await saveSettings(current);
      await audit('2fa_disabled', { user: req.session?.user });
      res.json({ ok: true });
    } catch (err) {
      console.error('2FA disable error:', err);
      res.status(500).json({ ok: false, error: err.message });
    }
  });
}

module.exports = { registerSettingsRoutes };
