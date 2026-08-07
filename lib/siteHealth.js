/**
 * Health URL e criteri di OK per Control Room / daily check.
 *
 * Priorità URL pubblico (getSiteHealthTarget / getSitePublicHealthUrl):
 *   healthPath su site.url > site.url
 *   (healthUrl è riservato al check locale / loopback)
 *
 * Priorità URL locale (getSiteLocalHealthUrl):
 *   healthUrl assoluto > http://127.0.0.1:port + healthPath (default /)
 *
 * healthMode: 'websocket' → HTTP 426 (Upgrade Required) conta come sano.
 * skipPublicCheck: true → il daily check non richiede reachability pubblica.
 */

function getSiteHealthPath(site) {
  if (site?.healthPath) {
    const p = String(site.healthPath).trim();
    return p.startsWith('/') ? p : `/${p}`;
  }
  return '/';
}

function getSiteLocalHealthUrl(site) {
  if (!site || site.port == null) return '';
  if (site.healthUrl) return String(site.healthUrl).trim();
  return `http://127.0.0.1:${site.port}${getSiteHealthPath(site)}`;
}

function getSitePublicHealthUrl(site) {
  if (!site || !site.url) return '';
  if (site.healthPath) {
    const base = String(site.url).replace(/\/$/, '');
    return base + getSiteHealthPath(site);
  }
  return site.url;
}

/**
 * URL usato dagli endpoint /api/health (smoke UI).
 * Per servizi solo-locali / WebSocket usa il target locale.
 */
function getSiteHealthTarget(site) {
  if (!site || !site.url) return '';
  if (site.healthMode === 'websocket' || site.skipPublicCheck) {
    return getSiteLocalHealthUrl(site);
  }
  if (site.healthUrl) return String(site.healthUrl).trim();
  return getSitePublicHealthUrl(site);
}

function isSiteHealthStatusOk(status, site = null) {
  const code = Number(status);
  if (!Number.isFinite(code) || code <= 0) return false;
  if (Array.isArray(site?.okStatuses) && site.okStatuses.includes(code)) return true;
  if (site?.healthMode === 'websocket' && code === 426) return true;
  return code >= 200 && code < 400;
}

module.exports = {
  getSiteHealthPath,
  getSiteLocalHealthUrl,
  getSitePublicHealthUrl,
  getSiteHealthTarget,
  isSiteHealthStatusOk,
};
