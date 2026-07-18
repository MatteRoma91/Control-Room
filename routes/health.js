/**
 * Health check API routes (extracted from server.js — behavior unchanged).
 * @param {import('express').Express} app
 * @param {{ requireAuth: Function, WEB_SITES: any[], getSiteHealthTarget: Function, pm2List: Function }} ctx
 */
function registerHealthRoutes(app, ctx) {
  const { requireAuth, WEB_SITES, getSiteHealthTarget, pm2List } = ctx;

  app.get('/api/health', requireAuth, async (req, res) => {
    const results = [];
    for (const site of WEB_SITES) {
      if (!site.url) continue;
      const checkUrl = getSiteHealthTarget(site);
      const start = Date.now();
      try {
        const resp = await fetch(checkUrl, {
          method: 'GET',
          signal: AbortSignal.timeout(10000),
        });
        const elapsed = Date.now() - start;
        results.push({
          url: site.url,
          checkUrl,
          name: site.name,
          kind: site.kind || 'app',
          status: resp.status,
          elapsed,
          ok: resp.ok,
        });
      } catch (err) {
        results.push({
          url: site.url,
          checkUrl,
          name: site.name,
          kind: site.kind || 'app',
          status: 0,
          elapsed: Date.now() - start,
          ok: false,
          error: err.message,
        });
      }
    }
    res.json({ results });
  });

  app.get('/api/health/summary', requireAuth, async (req, res) => {
    try {
      const [healthRes, processList] = await Promise.all([
        (async () => {
          const out = [];
          for (const site of WEB_SITES) {
            if (!site.url) continue;
            const checkUrl = getSiteHealthTarget(site);
            const start = Date.now();
            try {
              const resp = await fetch(checkUrl, {
                method: 'GET',
                signal: AbortSignal.timeout(6000),
              });
              out.push({
                name: site.name,
                ok: resp.ok,
                status: resp.status,
                elapsed: Date.now() - start,
                checkUrl,
              });
            } catch (err) {
              out.push({
                name: site.name,
                ok: false,
                status: 0,
                elapsed: Date.now() - start,
                error: err.message,
                checkUrl,
              });
            }
          }
          return out;
        })(),
        pm2List(),
      ]);

      const offline = processList.filter((p) => p.status !== 'online');
      const failing = healthRes.filter((h) => !h.ok);
      const severity = offline.length > 0 || failing.length > 0 ? 'critical' : 'ok';
      const incidents = [];
      for (const p of offline)
        incidents.push(`Processo ${p.name} in stato ${p.status}`);
      for (const h of failing)
        incidents.push(
          `Health check fallito: ${h.name} (${h.status || 'no-response'})`
        );

      res.json({
        severity,
        incidents,
        processSummary: { total: processList.length, offline: offline.length },
        healthSummary: { total: healthRes.length, failing: failing.length },
        generatedAt: new Date().toISOString(),
      });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });
}

module.exports = { registerHealthRoutes };
