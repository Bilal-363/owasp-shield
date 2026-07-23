import { httpRequest, SEVERITY } from '../util.js';

// Real HTTP response: analyse security headers, server banner, and cookies.
export async function scanHeaders(ctx) {
  const { url, log, finding } = ctx;
  const target = url.href;
  await log(`HTTP: fetching ${target} and analysing response headers...`, 'info');

  let res;
  try {
    res = await httpRequest(target, { timeout: 12000 });
  } catch (e) {
    await log(`HTTP: request failed (${e.message}).`, 'error');
    return null;
  }

  const h = res.headers;
  await log(`HTTP: ${res.status} ${res.statusText || ''}`.trim(), 'info');

  // ---- Server / technology banner ----
  const server = h.get('server');
  const poweredBy = h.get('x-powered-by');
  if (server) await log(`Server banner: ${server}`, 'info');
  if (poweredBy) await log(`X-Powered-By: ${poweredBy}`, 'info');

  if (server || poweredBy) {
    await finding({
      tool: 'headers',
      owasp_category: 'A05:2021-Security Misconfiguration',
      severity: SEVERITY.LOW,
      title: 'Server software version disclosed in headers',
      description: `The server advertises its software${server ? ` (Server: ${server})` : ''}${poweredBy ? ` (X-Powered-By: ${poweredBy})` : ''}. Version banners help attackers match known exploits.`,
      evidence: [server && `Server: ${server}`, poweredBy && `X-Powered-By: ${poweredBy}`].filter(Boolean).join(' | '),
      recommendation: 'Suppress or genericise Server / X-Powered-By headers.',
      affected_url: target,
      parameters: [],
      cwe_id: 'CWE-200',
      cvss_score: 3.1,
    });
  }

  // ---- Security headers ----
  const checks = [
    {
      name: 'Content-Security-Policy',
      present: !!h.get('content-security-policy'),
      severity: SEVERITY.MEDIUM,
      cwe: 'CWE-693',
      cvss: 4.3,
      rec: 'Define a restrictive Content-Security-Policy to mitigate XSS and data injection.',
    },
    {
      name: 'Strict-Transport-Security',
      present: !!h.get('strict-transport-security'),
      severity: url.protocol === 'https:' ? SEVERITY.MEDIUM : SEVERITY.LOW,
      cwe: 'CWE-319',
      cvss: 4.3,
      rec: 'Send Strict-Transport-Security (HSTS) to force HTTPS and prevent downgrade attacks.',
    },
    {
      name: 'X-Frame-Options',
      present: !!h.get('x-frame-options') || /frame-ancestors/i.test(h.get('content-security-policy') || ''),
      severity: SEVERITY.LOW,
      cwe: 'CWE-1021',
      cvss: 3.1,
      rec: "Set X-Frame-Options: DENY (or CSP frame-ancestors 'none') to prevent clickjacking.",
    },
    {
      name: 'X-Content-Type-Options',
      present: (h.get('x-content-type-options') || '').toLowerCase() === 'nosniff',
      severity: SEVERITY.LOW,
      cwe: 'CWE-693',
      cvss: 2.6,
      rec: 'Set X-Content-Type-Options: nosniff to stop MIME sniffing.',
    },
    {
      name: 'Referrer-Policy',
      present: !!h.get('referrer-policy'),
      severity: SEVERITY.LOW,
      cwe: 'CWE-200',
      cvss: 2.0,
      rec: 'Set a Referrer-Policy (e.g. strict-origin-when-cross-origin) to limit referrer leakage.',
    },
  ];

  for (const c of checks) {
    if (!c.present) {
      await log(`Missing security header: ${c.name}`, 'warning');
      await finding({
        tool: 'headers',
        owasp_category: 'A05:2021-Security Misconfiguration',
        severity: c.severity,
        title: `Missing security header: ${c.name}`,
        description: `The response does not set the ${c.name} header.`,
        evidence: `GET ${target} -> response headers did not include ${c.name}.`,
        recommendation: c.rec,
        affected_url: target,
        parameters: [],
        cwe_id: c.cwe,
        cvss_score: c.cvss,
      });
    }
  }

  // ---- Cookie flags ----
  const setCookie = typeof h.getSetCookie === 'function' ? h.getSetCookie() : [];
  for (const cookie of setCookie) {
    const name = cookie.split('=')[0];
    const low = cookie.toLowerCase();
    const missing = [];
    if (!low.includes('httponly')) missing.push('HttpOnly');
    if (url.protocol === 'https:' && !low.includes('secure')) missing.push('Secure');
    if (!low.includes('samesite')) missing.push('SameSite');
    if (missing.length) {
      await finding({
        tool: 'headers',
        owasp_category: 'A05:2021-Security Misconfiguration',
        severity: SEVERITY.LOW,
        title: `Cookie "${name}" missing flags: ${missing.join(', ')}`,
        description: `Cookie ${name} is set without the ${missing.join('/')} attribute(s), increasing exposure to theft or CSRF.`,
        evidence: cookie.slice(0, 200),
        recommendation: 'Set HttpOnly, Secure and SameSite on session cookies.',
        affected_url: target,
        parameters: [name],
        cwe_id: 'CWE-1004',
        cvss_score: 3.1,
      });
    }
  }

  return { status: res.status, server, poweredBy };
}
