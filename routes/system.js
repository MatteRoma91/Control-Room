/**
 * System monitoring APIs — behavior unchanged.
 */
const os = require('os');
const si = require('systeminformation');

function getProcessDetail(name, params) {
  const p = (params || '').trim();
  const n = (name || '').toLowerCase();
  if (!p && n !== 'node') return null;

  if (n === 'next-server') return 'Next.js (Roma-Buche)';
  if (n === 'pm2') return 'Process Manager';
  if (n === 'nginx') return p.includes('worker') ? 'Worker' : 'Master';
  if (n.includes('tsserver')) return 'TypeScript Language Server';

  if (n === 'node') {
    if (p.includes('control-room')) return 'Control Room';
    if (p.includes('Sito-Padel')) return 'Sito Padel';
    if (p.includes('Roma-Buche')) return 'Roma-Buche';
    if (p.includes('Gestione-Veicoli')) return 'Gestione Veicoli';
    if (p.includes('JetHealth')) return 'JetHealth';
    if (p.includes('pm2-logrotate')) return 'PM2 Log Rotate';
    if (p.includes('extensionHost') || p.includes('--type=extensionHost'))
      return 'Cursor Extension Host';
    if (p.includes('fileWatcher') || p.includes('--type=fileWatcher'))
      return 'Cursor File Watcher';
    if (p.includes('server-main')) return 'Cursor Server';
    if (p.includes('ptyHost') || p.includes('--type=ptyHost'))
      return 'Cursor Terminal';
    if (p.includes('jsonServerMain')) return 'Cursor JSON Server';
    if (p.includes('markdown-language-features')) return 'Cursor Markdown Server';
    if (p.includes('typingsInstaller')) return 'TypeScript Typings';
    if (p.includes('multiplex-server')) return 'Cursor Multiplex';
    const scriptMatch = p.match(
      /\/home\/[^/]+\/([^/]+)\/(?:server\.js|\.cursor-server)/
    );
    if (scriptMatch) return scriptMatch[1];
  }
  return null;
}

function registerSystemRoutes(app, ctx) {
  const { requireAuth, formatUptime } = ctx;

  const statsHistory = [];
  const STATS_HISTORY_MAX = 100;
  const STATS_INTERVAL_MS = 3000;

  async function collectStatsPoint() {
    try {
      const [load, mem] = await Promise.all([si.currentLoad(), si.mem()]);
      const memUsedBytes =
        mem.available != null ? mem.total - mem.available : mem.total - mem.free;
      const ramPercent = mem.total ? (100 * memUsedBytes) / mem.total : 0;
      const now = new Date();
      statsHistory.push({
        label: now.toLocaleTimeString('it-IT', {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        }),
        cpu: load.currentLoad ?? 0,
        ram: ramPercent,
      });
      if (statsHistory.length > STATS_HISTORY_MAX) statsHistory.shift();
    } catch (_) {}
  }
  setInterval(collectStatsPoint, STATS_INTERVAL_MS);
  collectStatsPoint();

  app.get('/api/system/processes', requireAuth, async (req, res) => {
    try {
      const data = await si.processes();
      const list = (data.list || [])
        .filter((p) => p.pid && (p.cpu > 0 || (p.memRss || 0) > 0))
        .sort((a, b) => (b.memRss || 0) - (a.memRss || 0))
        .slice(0, 25)
        .map((p) => {
          const detail = getProcessDetail(p.name, p.params);
          return {
            pid: p.pid,
            name: p.name || '(unknown)',
            detail: detail || p.params?.slice(0, 80) || null,
            cpu: (p.cpu || 0).toFixed(1),
            memRss: Math.round((p.memRss || 0) / 1024),
            user: p.user || '-',
          };
        });
      res.json({ processes: list });
    } catch (err) {
      console.error('System processes error:', err);
      res.status(500).json({ ok: false, error: err.message, processes: [] });
    }
  });

  app.get('/api/system', requireAuth, async (req, res) => {
    try {
      const [load, mem, disk] = await Promise.all([
        si.currentLoad(),
        si.mem(),
        si.fsSize('/').catch(() => ({ used: 0, size: 0 })),
      ]);
      const diskInfo = Array.isArray(disk) ? disk[0] : disk;
      const uptimeSec = os.uptime();
      const memUsedBytes =
        mem.available != null ? mem.total - mem.available : mem.total - mem.free;
      res.json({
        uptime: formatUptime(uptimeSec * 1000),
        uptimeSec,
        loadAvg1: load.currentLoad != null ? load.currentLoad.toFixed(2) : '-',
        memoryUsedMB: Math.round(memUsedBytes / 1024 / 1024),
        memoryTotalMB: Math.round(mem.total / 1024 / 1024),
        memoryPercent: mem.total
          ? Math.round((100 * memUsedBytes) / mem.total)
          : 0,
        diskUsedGB: diskInfo?.used
          ? (diskInfo.used / 1024 / 1024 / 1024).toFixed(2)
          : '0',
        diskTotalGB: diskInfo?.size
          ? (diskInfo.size / 1024 / 1024 / 1024).toFixed(2)
          : '0',
        diskPercent: diskInfo?.use || 0,
        cpuPercent: load.currentLoad ?? 0,
        memUsedMB: Math.round(memUsedBytes / 1024 / 1024),
      });
    } catch (err) {
      console.error('System info error:', err);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.get('/api/system/stats', requireAuth, async (req, res) => {
    try {
      const [load, mem] = await Promise.all([si.currentLoad(), si.mem()]);
      const memUsedBytes =
        mem.available != null ? mem.total - mem.available : mem.total - mem.free;
      const usedMemMB = Math.round(memUsedBytes / 1024 / 1024);
      const memoryPercent = mem.total ? (100 * memUsedBytes) / mem.total : 0;
      const history = {
        labels: statsHistory.map((p) => p.label),
        cpu: statsHistory.map((p) => p.cpu),
        ram: statsHistory.map((p) => p.ram),
      };
      res.json({
        cpuPercent: load.currentLoad ?? 0,
        memoryPercent,
        memoryUsedMB: usedMemMB,
        memoryTotalMB: Math.round(mem.total / 1024 / 1024),
        timestamp: new Date().toISOString(),
        history,
      });
    } catch (err) {
      console.error('System stats error:', err);
      res.status(500).json({ ok: false, error: err.message });
    }
  });
}

module.exports = { registerSystemRoutes, getProcessDetail };
