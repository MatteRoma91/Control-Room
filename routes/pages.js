/**
 * HTML page routes — behavior unchanged.
 */
function registerPageRoutes(app, ctx) {
  const { requireAuth, pm2List, DB_CONFIGURED } = ctx;

  app.get('/', requireAuth, async (req, res) => {
    try {
      const list = await pm2List();
      res.render('layout', {
        contentPartial: 'dashboard',
        processes: list,
        dbConfigured: DB_CONFIGURED,
      });
    } catch (err) {
      console.error('PM2 list error:', err);
      res.render('layout', {
        contentPartial: 'dashboard',
        processes: [],
        error: err.message,
        dbConfigured: DB_CONFIGURED,
      });
    }
  });

  app.get('/index', requireAuth, (req, res) => res.redirect('/'));

  app.get('/process/:name', requireAuth, async (req, res) => {
    const { name } = req.params;
    try {
      const list = await pm2List();
      const proc = list.find((p) => p.name === name);
      if (!proc) {
        return res.status(404).render('layout', {
          contentPartial: 'dashboard',
          processes: list,
          error: 'Processo non trovato',
          dbConfigured: DB_CONFIGURED,
        });
      }
      const headExtra =
        '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css" />';
      res.render('layout', {
        contentPartial: 'process-detail',
        process: proc,
        headExtra,
      });
    } catch (err) {
      console.error('Process detail error:', err);
      res.redirect('/');
    }
  });

  app.get('/audit', requireAuth, async (req, res) => {
    res.render('layout', { contentPartial: 'audit', title: 'Audit log' });
  });

  app.get('/access', requireAuth, async (req, res) => {
    res.render('layout', { contentPartial: 'access', title: 'Accessi' });
  });

  app.get('/security', requireAuth, (req, res) => {
    res.render('layout', { contentPartial: 'security', title: 'Sicurezza' });
  });

  app.get('/api/security/overview', requireAuth, (req, res) => {
    try {
      const { buildSecurityReport } = require('../lib/security-report');
      res.json(buildSecurityReport());
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.get('/api/access/overview', requireAuth, (req, res) => {
    try {
      const { buildAccessReport } = require('../lib/access-report');
      res.json(buildAccessReport());
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.get('/incidents', requireAuth, async (req, res) => {
    res.render('layout', { contentPartial: 'incidents', title: 'Incident Center' });
  });

  app.get('/automation', requireAuth, async (req, res) => {
    res.render('layout', { contentPartial: 'automation', title: 'Automation' });
  });

  app.get('/analytics', requireAuth, async (req, res) => {
    res.render('layout', { contentPartial: 'analytics', title: 'Analytics' });
  });

  app.get('/maintenance', requireAuth, async (req, res) => {
    res.render('layout', { contentPartial: 'maintenance', title: 'Maintenance' });
  });
}

module.exports = { registerPageRoutes };
