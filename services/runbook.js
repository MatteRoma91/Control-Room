/**
 * Runbook recover helpers — behavior unchanged.
 */
const { execSync } = require('child_process');
const { WEB_SITES, RUNBOOK_HISTORY_PATH } = require('../lib/constants');
const { appendLine } = require('./incidents');
const { pm2Action } = require('./pm2');

function parseCheckResponseOk(status) {
  return Number.isFinite(status) && status >= 200 && status < 400;
}

async function fetchStatusCode(url, timeoutMs = 10000) {
  try {
    const resp = await fetch(url, { method: 'GET', signal: AbortSignal.timeout(timeoutMs) });
    return resp.status;
  } catch (_) {
    return 0;
  }
}

function getManagedApps() {
  return WEB_SITES.filter((s) => s.kind === 'app' && s.pm2).map((s) => ({
    name: s.pm2,
    label: s.name,
    port: s.port,
    url: s.url,
    kind: 'node',
  }));
}

async function executeRunbook({ processName, mode = 'full_recover', dryRun = false, operator = 'system' }) {
  const appMeta = getManagedApps().find((a) => a.name === processName);
  if (!appMeta) throw new Error('Processo non supportato');
  const startedAt = Date.now();
  const steps = [];

  const localUrl = `http://127.0.0.1:${appMeta.port}/`;
  const before = await fetchStatusCode(localUrl, 5000);
  steps.push({ step: 'local_health_before', status: before });
  if (!dryRun) {
    await pm2Action('restart', processName);
    steps.push({ step: 'pm2_restart', ok: true });
  } else {
    steps.push({ step: 'pm2_restart', ok: true, dryRun: true });
  }
  if (mode === 'full_recover' || mode === 'safe_rollback') {
    try {
      if (!dryRun) {
        execSync('sudo /bin/systemctl reload nginx 2>/dev/null', { encoding: 'utf8' });
      }
      steps.push({ step: 'nginx_reload', ok: true, dryRun });
    } catch (err) {
      steps.push({ step: 'nginx_reload', ok: false, error: err.message });
    }
  }
  await new Promise((r) => setTimeout(r, 1500));
  const after = await fetchStatusCode(localUrl, 5000);
  steps.push({ step: 'local_health_after', status: after });
  let ok = parseCheckResponseOk(after);
  if (!ok && mode === 'safe_rollback' && !dryRun) {
    await pm2Action('restart', processName);
    steps.push({ step: 'rollback_restart', ok: true });
    const rollbackCheck = await fetchStatusCode(localUrl, 5000);
    steps.push({ step: 'rollback_health', status: rollbackCheck });
    ok = parseCheckResponseOk(rollbackCheck);
  }
  const report = {
    id: `rb_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    process: processName,
    mode,
    dryRun,
    ok,
    durationMs: Date.now() - startedAt,
    operator,
    startedAt: new Date(startedAt).toISOString(),
    finishedAt: new Date().toISOString(),
    steps,
  };
  await appendLine(RUNBOOK_HISTORY_PATH, report);
  return report;
}

module.exports = {
  parseCheckResponseOk,
  fetchStatusCode,
  getManagedApps,
  executeRunbook,
};
