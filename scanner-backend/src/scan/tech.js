import { httpRequest, readBodyCapped, SEVERITY } from '../util.js';

// Very small "retire.js-lite": detect a few common JS libraries and flag
// clearly outdated major versions with known vulns. Best-effort, real parsing
// of the served HTML/script references.
const LIBS = [
  {
    name: 'jQuery',
    re: /jquery[-.](\d+\.\d+\.\d+)(?:\.min)?\.js/i,
    vuln: (v) => cmp(v, '3.5.0') < 0,
    note: 'jQuery < 3.5.0 has known XSS issues (e.g. CVE-2020-11022/11023).',
    fix: 'Upgrade jQuery to 3.5.0+.',
  },
  {
    name: 'AngularJS',
    re: /angular[-.](\d+\.\d+\.\d+)(?:\.min)?\.js/i,
    vuln: (v) => v.startsWith('1.'),
    note: 'AngularJS 1.x is end-of-life and unpatched.',
    fix: 'Migrate off AngularJS 1.x.',
  },
  {
    name: 'Bootstrap',
    re: /bootstrap[-.](\d+\.\d+\.\d+)(?:\.min)?\.(?:js|css)/i,
    vuln: (v) => cmp(v, '4.3.1') < 0,
    note: 'Bootstrap < 4.3.1 has XSS vulnerabilities (CVE-2019-8331 et al).',
    fix: 'Upgrade Bootstrap to 4.3.1+.',
  },
  {
    name: 'Lodash',
    re: /lodash[-.](\d+\.\d+\.\d+)(?:\.min)?\.js/i,
    vuln: (v) => cmp(v, '4.17.21') < 0,
    note: 'Lodash < 4.17.21 is affected by prototype pollution (CVE-2020-8203 et al).',
    fix: 'Upgrade Lodash to 4.17.21+.',
  },
];

function cmp(a, b) {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
  }
  return 0;
}

export async function scanTech(ctx) {
  const { url, log, finding } = ctx;
  await log('Tech detection: analysing served HTML for JS libraries and generators...', 'info');

  let html = '';
  try {
    const res = await httpRequest(url.href, { timeout: 12000 });
    html = await readBodyCapped(res, 512 * 1024);
  } catch (e) {
    await log(`Tech detection: could not fetch page (${e.message}).`, 'warning');
    return;
  }

  // CMS / framework generator meta.
  const gen = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i);
  if (gen) {
    await log(`Tech detection: generator = ${gen[1]}`, 'info');
    await finding({
      tool: 'tech',
      owasp_category: 'A05:2021-Security Misconfiguration',
      severity: SEVERITY.INFO,
      title: `Technology disclosed via generator meta tag: ${gen[1]}`,
      description: `The page discloses the platform/version in a <meta name="generator"> tag.`,
      evidence: gen[0].slice(0, 200),
      recommendation: 'Remove the generator meta tag to reduce information disclosure.',
      affected_url: url.href,
      parameters: [],
      cwe_id: 'CWE-200',
      cvss_score: 0,
    });
  }

  let found = 0;
  for (const lib of LIBS) {
    const m = html.match(lib.re);
    if (!m) continue;
    const version = m[1];
    found++;
    const outdated = lib.vuln(version);
    await log(`Tech detection: ${lib.name} ${version}${outdated ? ' (OUTDATED)' : ''}`, outdated ? 'warning' : 'info');
    if (outdated) {
      await finding({
        tool: 'retire',
        owasp_category: 'A06:2021-Vulnerable and Outdated Components',
        severity: SEVERITY.MEDIUM,
        title: `Outdated ${lib.name} (${version})`,
        description: lib.note,
        evidence: `Reference found in page: ${m[0]}`,
        recommendation: lib.fix,
        affected_url: url.href,
        parameters: [],
        cwe_id: 'CWE-1104',
        cvss_score: 6.1,
      });
    }
  }

  if (!found) await log('Tech detection: no fingerprinted JS libraries found in page markup.', 'info');
}
