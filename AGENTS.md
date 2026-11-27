# AGENTS.md

## Cursor Cloud specific instructions

Control Room is a single Node.js/Express service (server.js) — a dashboard to manage PM2 processes. It renders EJS views and uses socket.io. It listens on port `3005` (see `PORT`). Node 22 is expected (see `.nvmrc`).

### Running the app (dev)
- Start command: `npm start` (runs `node server.js`). There is no separate dev/watch script and no hot reload — restart the process after code changes.
- There are no lint, test, or build scripts in `package.json` (only `start` and `pwa:icons`). Do not expect `npm test`/`npm run build` to exist.
- PM2 is used as a library. `pm2.connect()` at startup spawns a local PM2 daemon automatically if none is running; the dashboard simply shows an empty/available process list when nothing is managed. No manual PM2 setup is needed to run the app.

### Redis is required for sessions
- Sessions always use `connect-redis` (`RedisStore`) — there is no MemoryStore fallback. Login/session will not work unless Redis is reachable at `REDIS_URL` (default `redis://127.0.0.1:6379`).
- Redis is installed in the environment but is not started automatically. Start it before launching the app, e.g. `redis-server --daemonize yes`, and verify with `redis-cli ping` (expect `PONG`).
- In dev, startup does not abort if Redis is down (it only aborts when `NODE_ENV=production` and `SESSION_REDIS_REQUIRED` is not `false`), but login will still fail without Redis, so keep Redis running.

### `.env` is required
- The app aborts on startup unless `AUTH_USER` (min 3 chars), `AUTH_PASSWORD` (min 12 chars), and `SESSION_SECRET` (min 32 chars) are set. See `.env.example` for the full list of variables.
- `.env` is gitignored. For local/dev use `NODE_ENV=development` and `SESSION_REDIS_REQUIRED=false`. Generate a secret with `openssl rand -hex 32`.
- Log in with the `AUTH_USER` / `AUTH_PASSWORD` values from `.env`.
