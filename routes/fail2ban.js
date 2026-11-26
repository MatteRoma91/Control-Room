/**
 * Gestione ban Fail2ban dalla Control Room.
 */
const { normalizeIp } = require('../lib/ip-utils');
const { clearSecurityReportCache } = require('../lib/security-report');
const { snapshot, banIp, unbanIp } = require('../services/fail2ban');

function clientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const raw = (typeof forwarded === 'string' ? forwarded.split(',')[0] : '') || req.ip || '';
  return normalizeIp(raw);
}

function sendError(res, err) {
  const status = Number(err.status) || 500;
  const detail = String(err.stderr || '').trim().split('\n').filter(Boolean).pop() || '';
  const message = status === 500
    ? (detail || 'Fail2ban non ha risposto').slice(0, 240)
    : err.message;
  res.status(status).json({ ok: false, error: message });
}

function registerFail2banRoutes(app, ctx) {
  const { requireAuth, audit } = ctx;

  app.get('/api/fail2ban', requireAuth, async (req, res) => {
    try {
      const data = await snapshot(req.query.jail);
      res.json(data);
    } catch (err) {
      sendError(res, err);
    }
  });

  app.post('/api/fail2ban/ban', requireAuth, async (req, res) => {
    try {
      const data = await banIp(req.body?.ip, req.body?.jail || 'sshd', clientIp(req));
      clearSecurityReportCache();
      await audit('fail2ban_ban', {
        user: req.session?.user,
        ip: normalizeIp(req.body?.ip),
        jail: data.jail,
      });
      res.json(data);
    } catch (err) {
      sendError(res, err);
    }
  });

  app.post('/api/fail2ban/unban', requireAuth, async (req, res) => {
    try {
      const data = await unbanIp(req.body?.ip, req.body?.jail || 'sshd');
      clearSecurityReportCache();
      await audit('fail2ban_unban', {
        user: req.session?.user,
        ip: normalizeIp(req.body?.ip),
        jail: data.jail,
      });
      res.json(data);
    } catch (err) {
      sendError(res, err);
    }
  });
}

module.exports = { registerFail2banRoutes };
