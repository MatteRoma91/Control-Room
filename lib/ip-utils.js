function normalizeIp(ip) {
  return String(ip || '').replace(/^::ffff:/, '').trim();
}

function ipToInt(ip) {
  const parts = normalizeIp(ip).split('.');
  if (parts.length !== 4) return null;
  let out = 0;
  for (const p of parts) {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    out = (out << 8) + n;
  }
  return out >>> 0;
}

function isIpInCidr(ip, cidr) {
  const [base, bitsRaw] = String(cidr).split('/');
  const bits = Number(bitsRaw);
  const ipNum = ipToInt(ip);
  const baseNum = ipToInt(base);
  if (ipNum === null || baseNum === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  if (bits === 0) return true;
  const mask = bits === 32 ? 0xffffffff : (0xffffffff << (32 - bits)) >>> 0;
  return (ipNum & mask) === (baseNum & mask);
}

function isIpAllowedByEntries(ip, entries) {
  const normalizedIp = normalizeIp(ip);
  if (!normalizedIp) return false;
  for (const raw of entries || []) {
    const entry = String(raw || '').trim();
    if (!entry) continue;
    if (entry.includes('/')) {
      if (isIpInCidr(normalizedIp, entry)) return true;
      continue;
    }
    if (normalizeIp(entry) === normalizedIp) return true;
  }
  return false;
}

module.exports = {
  normalizeIp,
  ipToInt,
  isIpInCidr,
  isIpAllowedByEntries,
};
