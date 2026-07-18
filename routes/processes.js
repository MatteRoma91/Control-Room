/**
 * PM2 process control APIs — behavior unchanged.
 * Specific routes (flush/reset/git-pull/restart-all/restore-all) before :action/:name.
 */
const { execSync } = require('child_process');
const pm2 = require('pm2');

function registerProcessRoutes(app, ctx) {
  const {
    requireAuth,
    logEvent,
    audit,
    hasStrongConfirmation,
    getExpectedPhrase,
    HIGH_RISK_PHRASES,
    MANAGED_PM2_APPS,
    ECOSYSTEMS,
    pm2List,
    pm2Action,
    pm2ListRaw,
    pm2StartEcosystem,
    pm2GetLogs,
    resolveManagedProjectCwd,
  } = ctx;

  app.post('/api/process/flush/:name', requireAuth, (req, res) => {
    const { name } = req.params;
    pm2.flush(name, (err) => {
      if (err) {
        logEvent('process_flush_error', {
          process: name,
          user: req.session?.user,
          error: err.message,
        });
        console.error('PM2 flush error:', err);
        return res.status(500).json({ ok: false, error: err.message });
      }
      logEvent('process_flush', { process: name, user: req.session?.user });
      res.json({ ok: true });
    });
  });

  app.post('/api/process/reset/:name', requireAuth, (req, res) => {
    const { name } = req.params;
    if (!/^[a-zA-Z0-9_.-]+$/.test(name)) {
      return res.status(400).json({ ok: false, error: 'Nome processo non valido' });
    }
    pm2.reset(name, (err) => {
      if (err) {
        logEvent('process_reset_error', {
          process: name,
          user: req.session?.user,
          error: err.message || String(err),
        });
        console.error('PM2 reset error:', err);
        return res
          .status(500)
          .json({ ok: false, error: err.message || String(err) });
      }
      logEvent('process_reset', { process: name, user: req.session?.user });
      res.json({ ok: true });
    });
  });

  app.post('/api/process/git-pull/:name', requireAuth, async (req, res) => {
    const { name } = req.params;
    try {
      const cwd = await resolveManagedProjectCwd(name);
      if (!cwd)
        return res
          .status(400)
          .json({ ok: false, error: 'Processo non trovato o cwd non disponibile' });
      const output = execSync('git pull 2>&1', { encoding: 'utf8', cwd });
      await pm2Action('restart', name);
      logEvent('git_pull', { process: name, user: req.session?.user, cwd });
      res.json({ ok: true, output, cwd });
    } catch (err) {
      logEvent('git_pull_error', {
        process: name,
        user: req.session?.user,
        error: err.message,
      });
      console.error('Git pull error:', err);
      let output = '';
      if (err.stdout)
        output += Buffer.isBuffer(err.stdout) ? err.stdout.toString() : err.stdout;
      if (err.stderr)
        output +=
          (Buffer.isBuffer(err.stderr) ? err.stderr.toString() : err.stderr) || '';
      if (!output) output = err.message || String(err);
      res.status(500).json({ ok: false, error: err.message, output });
    }
  });

  app.post('/api/process/:action/:name', requireAuth, async (req, res) => {
    const { action, name } = req.params;
    if (!['restart', 'stop', 'start'].includes(action)) {
      return res.status(400).json({ ok: false, error: 'Invalid action' });
    }
    if (
      (action === 'stop' || action === 'restart') &&
      !hasStrongConfirmation(req, `process-${action}`, name)
    ) {
      return res.status(400).json({
        ok: false,
        error: `Conferma richiesta. Frase: ${getExpectedPhrase(req, `process-${action}`, name)}`,
      });
    }
    try {
      await pm2Action(action, name);
      await audit('process_action', {
        action,
        process: name,
        user: req.session?.user,
      });
      res.json({ ok: true });
    } catch (err) {
      await audit('process_action_error', {
        action,
        process: name,
        user: req.session?.user,
        error: err.message,
      });
      console.error(`PM2 ${action} error:`, err);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.get('/api/logs/:name', requireAuth, async (req, res) => {
    try {
      const logs = await pm2GetLogs(req.params.name);
      res.json(logs);
    } catch (err) {
      console.error('PM2 logs error:', err);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.get('/api/processes', requireAuth, async (req, res) => {
    try {
      const list = await pm2List();
      res.json({ processes: list });
    } catch (err) {
      console.error('PM2 processes error:', err);
      res.status(500).json({ ok: false, error: err.message, processes: [] });
    }
  });

  app.post('/api/process/restart-all', requireAuth, async (req, res) => {
    const apps = MANAGED_PM2_APPS.filter((name) => name !== 'control-room');
    if (!hasStrongConfirmation(req, 'restartAll')) {
      return res.status(400).json({
        ok: false,
        error: `Conferma richiesta. Frase: ${HIGH_RISK_PHRASES.restartAll}`,
      });
    }
    try {
      await Promise.all(apps.map((name) => pm2Action('restart', name)));
      await audit('restart_all', { processes: apps, user: req.session?.user });
      res.json({ ok: true });
    } catch (err) {
      await audit('restart_all_error', {
        user: req.session?.user,
        error: err.message,
      });
      console.error('Restart-all error:', err);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.post('/api/process/restore-all', requireAuth, async (req, res) => {
    if (!hasStrongConfirmation(req, 'restoreAll')) {
      return res.status(400).json({
        ok: false,
        error: `Conferma richiesta. Frase: ${HIGH_RISK_PHRASES.restoreAll}`,
      });
    }
    try {
      const list = await pm2ListRaw();
      const startedEcosystems = new Set();
      for (const { path: cfgPath, name } of ECOSYSTEMS) {
        const proc = list.find((p) => (p.pm2_env || p).name === name);
        const status = proc?.pm2_env?.status;
        if (!proc) {
          if (!startedEcosystems.has(cfgPath)) {
            await pm2StartEcosystem(cfgPath);
            startedEcosystems.add(cfgPath);
          }
        } else if (status && status !== 'online') {
          await pm2Action('restart', name);
        }
      }
      await audit('restore_all', { user: req.session?.user });
      res.json({ ok: true });
    } catch (err) {
      await audit('restore_all_error', {
        user: req.session?.user,
        error: err.message,
      });
      console.error('Restore-all error:', err);
      res.status(500).json({ ok: false, error: err.message });
    }
  });
}

module.exports = { registerProcessRoutes };
