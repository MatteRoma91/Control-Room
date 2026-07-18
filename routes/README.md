# Route modules

La logica HTTP di bootstrap (middleware, session, Socket.IO, cron) resta in [`../server.js`](../server.js). Route estratte:

| Modulo | Contenuto |
|--------|-----------|
| [`auth.js`](auth.js) | login, 2FA, logout |
| [`pages.js`](pages.js) | dashboard e pagine HTML (`/`, `/process/:name`, audit, …) |
| [`processes.js`](processes.js) | API PM2 (flush, reset, git-pull, start/stop/restart, logs, restart-all, restore-all) |
| [`system.js`](system.js) | API sistema (processes, overview, stats chart) |
| [`health.js`](health.js) | `GET /api/health`, `GET /api/health/summary` |
| [`runbook.js`](runbook.js) | recover-app / recover-batch / history |
| [`incidents.js`](incidents.js) | Incident Center CRUD status |
| [`nginx.js`](nginx.js) | status, reload, generate, preview, rollback |
| [`settings.js`](settings.js) | settings page/API, panic mode, 2FA setup/disable |

Services correlati:

- [`../services/pm2.js`](../services/pm2.js) — wrapper PM2 + `resolveManagedProjectCwd` + `formatUptime`
- [`../services/settings.js`](../services/settings.js) — `loadSettings` / `saveSettings` / `sanitizeSettings`
- [`../services/incidents.js`](../services/incidents.js) — store incident + `appendLine`
- [`../services/runbook.js`](../services/runbook.js) — `executeRunbook` + health fetch helpers

Path safety: [`../lib/path-utils.js`](../lib/path-utils.js).

Per aggiungere un gruppo: crea `nome.js` con `register*(app, ctx)` e montalo da `server.js` dopo i middleware condivisi.

**Deploy:** solo `pm2 restart control-room` (mai reload di tutto l’ecosystem).
