import { httpRequest, readBodyCapped, mapLimit, SEVERITY } from '../util.js';

// Small, non-destructive wordlist of interesting paths (gobuster-lite).
const PATHS = [
  'admin', 'administrator', 'login', 'wp-admin', 'wp-login.php',
  'api', 'api/v1', 'graphql', 'actuator', 'actuator/health',
  'dashboard', 'phpmyadmin', 'adminer.php', 'debug', 'test',
  'uploads', 'backup', 'backups', 'old', 'tmp', 'private',
  'robots.txt', 'sitemap.xml', 'swagger', 'swagger-ui.html', 'api-docs',
  '.well-known/security.txt',
];

// Interesting = admin/management surfaces worth flagging when reachable.
const NOTEWORTHY = new Set([
  'admin', 'administrator', 'wp-admin', 'phpmyadmin', 'adminer.php',
  'actuator', 'actuator/health', 'debug', 'graphql', 'swagger', 'api-docs',
]);

async function probe(origin, p) {
  try {
    const res = await httpRequest(`${origin}/${p}`, { timeout: 8000, redirect: 'manual' });
    const body = await readBodyCapped(res, 32 * 1024);
    return { p, status: res.status, len: body.length };
  } catch {
    return { p, status: 0, len: -1 };
  }
}

export async function scanDirs(ctx) {
  const { url, log, finding } = ctx;
  const origin = url.origin;
  await log(`Content discovery: checking ${PATHS.length} common paths on ${origin}...`, 'info');

  // --- Pass 1: baseline. Probe 3 definitely-nonexistent random paths. ---
  const baselineProbes = await mapLimit(
    [0, 1, 2].map((i) => `zz-none-${i}-${Math.random().toString(36).slice(2)}`),
    3,
    (nonce) => probe(origin, nonce)
  );
  const baselineStatuses = baselineProbes.map((b) => b.status);

  // --- Pass 2: probe all real paths (collect, don't report yet). ---
  const results = await mapLimit(PATHS, 10, (p) => probe(origin, p));

  // --- Decide what's a real signal vs WAF/bot noise. ---
  // Count how many paths returned each status.
  const statusCounts = {};
  for (const r of results) statusCounts[r.status] = (statusCounts[r.status] || 0) + 1;

  // A status is "blanket" (WAF/bot/SPA catch-all, not real per-path signal) if:
  //   - a baseline (random) path also returned it, OR
  //   - it was returned by many paths (>=4) — real sites don't have 4+ distinct
  //     protected admin panels; that's a WAF answering everything the same way.
  const isBlanket = (status) =>
    baselineStatuses.includes(status) || (statusCounts[status] || 0) >= 4;

  const blocked = [401, 403].filter((s) => isBlanket(s));
  if (blocked.length) {
    await log(
      `Content discovery: site returns HTTP ${blocked.join('/')} for random/many paths (WAF or bot protection) — these are NOT real endpoints, suppressing to avoid false positives.`,
      'warning'
    );
  }

  const found = [];
  for (const r of results) {
    const { p, status, len } = r;

    let real = false;
    if (status === 200) {
      // 200 is real unless the site 200s for everything (SPA catch-all).
      real = !(baselineStatuses.includes(200) && baselineProbes.some((b) => Math.abs(len - b.len) < 64));
    } else if (status === 401 || status === 403) {
      real = !isBlanket(status); // genuine per-path protection, not a WAF wall
    }
    if (!real) continue;

    found.push({ p, status });
    await log(`Content discovery: /${p} -> HTTP ${status}`, status === 200 ? 'warning' : 'info');

    if (NOTEWORTHY.has(p)) {
      const accessible = status === 200;
      await finding({
        tool: 'dirscan',
        owasp_category: 'A01:2021-Broken Access Control',
        severity: accessible ? SEVERITY.MEDIUM : SEVERITY.LOW,
        title: `${accessible ? 'Accessible' : 'Discovered'} sensitive endpoint: /${p}`,
        description: accessible
          ? `The endpoint /${p} returned HTTP 200 and may expose an administrative or debug surface.`
          : `The endpoint /${p} exists (HTTP ${status}) — its presence is disclosed even though access is restricted.`,
        evidence: `GET ${origin}/${p} -> ${status}`,
        recommendation: `Verify authentication/authorisation on /${p}; restrict or remove if not required.`,
        affected_url: `${origin}/${p}`,
        parameters: [],
        cwe_id: 'CWE-284',
        cvss_score: accessible ? 5.3 : 3.1,
      });
    }
  }

  if (!found.length) await log('Content discovery: no notable paths found.', 'info');
  return found;
}
