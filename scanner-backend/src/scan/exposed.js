import { httpRequest, readBodyCapped, mapLimit, SEVERITY } from '../util.js';

// Sensitive paths to probe, with a content signature to reduce false positives
// and the severity if genuinely exposed.
const TARGETS = [
  { path: '/.git/config', sig: /\[core\]|repositoryformatversion/i, sev: SEVERITY.HIGH, cwe: 'CWE-527', title: 'Exposed .git repository', cat: 'A05:2021-Security Misconfiguration' },
  { path: '/.git/HEAD', sig: /ref:\s*refs\//i, sev: SEVERITY.HIGH, cwe: 'CWE-527', title: 'Exposed .git repository (HEAD)', cat: 'A05:2021-Security Misconfiguration' },
  { path: '/.env', sig: /[A-Z0-9_]+=/, sev: SEVERITY.CRITICAL, cwe: 'CWE-538', title: 'Exposed .env file (secrets)', cat: 'A05:2021-Security Misconfiguration' },
  { path: '/.env.local', sig: /[A-Z0-9_]+=/, sev: SEVERITY.CRITICAL, cwe: 'CWE-538', title: 'Exposed .env.local file (secrets)', cat: 'A05:2021-Security Misconfiguration' },
  { path: '/config.php.bak', sig: /<\?php/i, sev: SEVERITY.HIGH, cwe: 'CWE-530', title: 'Exposed PHP config backup', cat: 'A05:2021-Security Misconfiguration' },
  { path: '/wp-config.php.bak', sig: /DB_PASSWORD|<\?php/i, sev: SEVERITY.CRITICAL, cwe: 'CWE-530', title: 'Exposed WordPress config backup', cat: 'A05:2021-Security Misconfiguration' },
  { path: '/backup.zip', sig: null, sev: SEVERITY.MEDIUM, cwe: 'CWE-530', title: 'Exposed backup archive (backup.zip)', cat: 'A01:2021-Broken Access Control' },
  { path: '/backup.sql', sig: /CREATE TABLE|INSERT INTO/i, sev: SEVERITY.HIGH, cwe: 'CWE-530', title: 'Exposed database dump (backup.sql)', cat: 'A01:2021-Broken Access Control' },
  { path: '/.DS_Store', sig: null, sev: SEVERITY.LOW, cwe: 'CWE-527', title: 'Exposed .DS_Store file', cat: 'A05:2021-Security Misconfiguration' },
  { path: '/.svn/entries', sig: null, sev: SEVERITY.MEDIUM, cwe: 'CWE-527', title: 'Exposed SVN metadata', cat: 'A05:2021-Security Misconfiguration' },
  { path: '/server-status', sig: /Apache Server Status/i, sev: SEVERITY.MEDIUM, cwe: 'CWE-200', title: 'Apache server-status exposed', cat: 'A05:2021-Security Misconfiguration' },
  { path: '/phpinfo.php', sig: /phpinfo\(\)|PHP Version/i, sev: SEVERITY.MEDIUM, cwe: 'CWE-200', title: 'phpinfo() page exposed', cat: 'A05:2021-Security Misconfiguration' },
  { path: '/.htaccess', sig: /RewriteRule|Options/i, sev: SEVERITY.LOW, cwe: 'CWE-527', title: 'Exposed .htaccess', cat: 'A05:2021-Security Misconfiguration' },
];

// Detect servers that return 200 for everything (SPA catch-all), so we can
// avoid false positives.
async function getBaseline(origin) {
  const nonce = 'zz-nonexistent-' + Math.random().toString(36).slice(2);
  try {
    const res = await httpRequest(`${origin}/${nonce}`, { timeout: 8000 });
    const body = await readBodyCapped(res, 64 * 1024);
    return { status: res.status, len: body.length, always200: res.status === 200 };
  } catch {
    return { status: 0, len: -1, always200: false };
  }
}

export async function scanExposed(ctx) {
  const { url, log, finding } = ctx;
  const origin = url.origin;
  await log(`Exposed-files: probing ${TARGETS.length} sensitive paths on ${origin}...`, 'info');

  const baseline = await getBaseline(origin);

  await mapLimit(TARGETS, 8, async (t) => {
    let res, body;
    try {
      res = await httpRequest(`${origin}${t.path}`, { timeout: 8000, redirect: 'manual' });
      body = await readBodyCapped(res, 64 * 1024);
    } catch {
      return;
    }
    if (res.status !== 200) return;

    // If the server 200s for everything, require a real content signature.
    if (baseline.always200) {
      if (!t.sig || !t.sig.test(body)) return;
    } else if (t.sig && !t.sig.test(body)) {
      // Signature defined but not matched -> likely a soft 404, skip.
      return;
    }

    await log(`Exposed-files: FOUND ${t.path} (HTTP 200)`, 'error');
    await finding({
      tool: 'exposed-files',
      owasp_category: t.cat,
      severity: t.sev,
      title: t.title,
      description: `The path ${t.path} is publicly accessible and returned HTTP 200.`,
      evidence: `GET ${origin}${t.path} -> 200 (${body.length} bytes)${t.sig ? '; content signature matched' : ''}`,
      recommendation: `Block public access to ${t.path} at the web server / remove the file from the web root.`,
      affected_url: `${origin}${t.path}`,
      parameters: [],
      cwe_id: t.cwe,
      cvss_score: t.sev === SEVERITY.CRITICAL ? 9.1 : t.sev === SEVERITY.HIGH ? 7.5 : 5.0,
    });
  });
}
