/**
 * URL usato per health HTTP (smoke / Control-Room).
 * Priorità: healthUrl assoluto > healthPath relativo a site.url > site.url.
 */
function getSiteHealthTarget(site) {
  if (!site || !site.url) return '';
  if (site.healthUrl) return String(site.healthUrl).trim();
  if (site.healthPath) {
    const base = String(site.url).replace(/\/$/, '');
    const p = String(site.healthPath).trim();
    const path = p.startsWith('/') ? p : `/${p}`;
    return base + path;
  }
  return site.url;
}

module.exports = { getSiteHealthTarget };
