/**
 * PM2 helpers (extracted from server.js — behavior unchanged).
 */
const path = require('path');
const fs = require('fs').promises;
const pm2 = require('pm2');
const { WEB_SITES } = require('../lib/constants');
const { isPathAllowed } = require('../lib/path-utils');

function formatUptime(ms) {
  if (ms < 0) return '-';
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  const h = Math.floor(m / 60);
  const d = Math.floor(h / 24);
  if (d) return `${d}d ${h % 24}h`;
  if (h) return `${h}h ${m % 60}m`;
  if (m) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

/**
 * Preferisce WEB_SITES.repoRoot (es. Next standalone), altrimenti cwd PM2.
 */
async function resolveManagedProjectCwd(processName) {
  const meta = WEB_SITES.find((s) => s.pm2 === processName);
  if (meta?.repoRoot && isPathAllowed(meta.repoRoot)) {
    return path.resolve(meta.repoRoot);
  }
  return pm2GetCwd(processName);
}

function pm2List() {
  return new Promise((resolve, reject) => {
    pm2.list((err, list) => {
      if (err) return reject(err);
      const processes = list.map((p) => {
        const env = p.pm2_env || {};
        const monit = p.monit || {};
        const cwd = env.pm_cwd || env.exec_cwd || '';
        const isModule = !!(env.pmx_module || cwd.includes('.pm2/modules'));
        return {
          name: env.name || p.name,
          status: env.status,
          cpu: monit.cpu ?? 0,
          memory: Math.round((monit.memory || 0) / 1024 / 1024),
          uptime: env.pm_uptime ? formatUptime(Date.now() - env.pm_uptime) : '-',
          restart_time: env.restart_time ?? 0,
          isModule,
        };
      });
      resolve(processes);
    });
  });
}

function pm2Action(action, name) {
  return new Promise((resolve, reject) => {
    const fn = pm2[action];
    if (!fn) return reject(new Error(`Unknown action: ${action}`));
    fn.call(pm2, name, (err) => (err ? reject(err) : resolve()));
  });
}

function pm2ListRaw() {
  return new Promise((resolve, reject) => {
    pm2.list((err, list) => (err ? reject(err) : resolve(list || [])));
  });
}

function pm2StartEcosystem(ecosystemPath) {
  return new Promise((resolve, reject) => {
    pm2.start(ecosystemPath, (err) => (err ? reject(err) : resolve()));
  });
}

function pm2GetCwd(name) {
  return new Promise((resolve, reject) => {
    pm2.describe(name, (err, list) => {
      if (err) return reject(err);
      const proc = Array.isArray(list) ? list[0] : list;
      resolve(proc?.pm2_env?.pm_cwd || null);
    });
  });
}

function pm2GetLogPaths(name) {
  return new Promise((resolve, reject) => {
    pm2.describe(name, (err, list) => {
      if (err) return reject(err);
      const proc = Array.isArray(list) ? list[0] : list;
      if (!proc?.pm2_env) return reject(new Error('Process not found'));
      const env = proc.pm2_env;
      resolve({
        out: env.pm_out_log_path,
        err: env.pm_err_log_path,
      });
    });
  });
}

async function pm2GetLogs(name) {
  return new Promise((resolve, reject) => {
    pm2.describe(name, async (err, list) => {
      if (err) return reject(err);
      const proc = Array.isArray(list) ? list[0] : list;
      if (!proc?.pm2_env) return reject(new Error('Process not found'));
      const env = proc.pm2_env;
      const outPath = env.pm_out_log_path;
      const errPath = env.pm_err_log_path;
      const lines = 50;

      const readLastLines = async (filePath) => {
        try {
          const content = await fs.readFile(filePath, 'utf8');
          return content.split('\n').slice(-lines).join('\n');
        } catch {
          return '(file not found or empty)';
        }
      };

      try {
        const [stdout, stderr] = await Promise.all([
          readLastLines(outPath),
          readLastLines(errPath),
        ]);
        resolve({ stdout, stderr });
      } catch (e) {
        reject(e);
      }
    });
  });
}

module.exports = {
  formatUptime,
  resolveManagedProjectCwd,
  pm2List,
  pm2Action,
  pm2ListRaw,
  pm2StartEcosystem,
  pm2GetCwd,
  pm2GetLogPaths,
  pm2GetLogs,
};
