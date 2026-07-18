/**
 * Runbook APIs — behavior unchanged.
 */
const fs = require('fs').promises;
const { RUNBOOK_HISTORY_PATH } = require('../lib/constants');
const { getManagedApps, executeRunbook } = require('../services/runbook');

function registerRunbookRoutes(app, ctx) {
  const { requireAuth, audit, sendNotificationEvent } = ctx;

  app.get('/api/runbook/apps', requireAuth, async (req, res) => {
    res.json({ apps: getManagedApps() });
  });

  app.get('/api/runbook/history', requireAuth, async (req, res) => {
    const raw = await fs.readFile(RUNBOOK_HISTORY_PATH, 'utf8').catch(() => '');
    const reports = raw
      .split('\n')
      .filter(Boolean)
      .slice(-200)
      .map((line) => {
        try { return JSON.parse(line); } catch { return null; }
      })
      .filter(Boolean)
      .reverse();
    res.json({ reports });
  });

  app.post('/api/runbook/recover-app/:name', requireAuth, async (req, res) => {
    const { name } = req.params;
    const mode = ['soft_recover', 'full_recover', 'safe_rollback'].includes(req.body?.mode) ? req.body.mode : 'full_recover';
    const dryRun = req.body?.dryRun === true;
    try {
      const report = await executeRunbook({
        processName: name,
        mode,
        dryRun,
        operator: req.session?.user || 'unknown',
      });
      await audit('runbook_recover_app', { user: req.session?.user, process: name, ok: report.ok, mode, dryRun, steps: report.steps });
      await sendNotificationEvent('runbook_recover_app', {
        channel: 'ops',
        severity: report.ok ? 'low' : 'high',
        process: name,
        note: `mode=${mode} dryRun=${dryRun} ok=${report.ok}`,
        actionHint: report.ok ? 'Nessuna azione richiesta' : 'Verifica logs e incident center',
      });
      res.json({ ok: report.ok, report });
    } catch (err) {
      await audit('runbook_recover_app_error', { user: req.session?.user, process: name, error: err.message });
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.post('/api/runbook/recover-batch', requireAuth, async (req, res) => {
    const apps = Array.isArray(req.body?.apps) ? req.body.apps : [];
    const mode = ['soft_recover', 'full_recover', 'safe_rollback'].includes(req.body?.mode) ? req.body.mode : 'full_recover';
    const stopOnFail = req.body?.stopOnFail !== false;
    const dryRun = req.body?.dryRun === true;
    const results = [];
    for (const appName of apps) {
      try {
        const report = await executeRunbook({
          processName: appName,
          mode,
          dryRun,
          operator: req.session?.user || 'unknown',
        });
        results.push(report);
        if (!report.ok && stopOnFail) break;
      } catch (err) {
        results.push({ process: appName, ok: false, error: err.message });
        if (stopOnFail) break;
      }
    }
    const ok = results.length > 0 && results.every((r) => r.ok);
    await audit('runbook_recover_batch', { user: req.session?.user, ok, mode, dryRun, count: results.length });
    await sendNotificationEvent('runbook_recover_batch', {
      channel: 'ops',
      severity: ok ? 'low' : 'high',
      note: `apps=${results.length} mode=${mode} ok=${ok}`,
    });
    res.json({ ok, results });
  });
}

module.exports = { registerRunbookRoutes };
