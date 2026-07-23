import { httpRequest, readBodyCapped, SEVERITY } from '../util.js';

// Passive subdomain enumeration via crt.sh certificate-transparency logs.
// No traffic to the target — safe and real.
export async function scanSubdomains(ctx) {
  const { hostname, log, finding } = ctx;
  const apex = hostname.replace(/^www\./, '');
  await log(`Subdomains: querying certificate-transparency logs for *.${apex}...`, 'info');

  let json;
  try {
    const res = await httpRequest(`https://crt.sh/?q=%25.${encodeURIComponent(apex)}&output=json`, {
      timeout: 20000,
    });
    if (res.status !== 200) {
      await log(`Subdomains: crt.sh returned HTTP ${res.status}.`, 'warning');
      return;
    }
    const text = await readBodyCapped(res, 2 * 1024 * 1024);
    json = JSON.parse(text);
  } catch (e) {
    await log(`Subdomains: lookup unavailable (${e.message}).`, 'warning');
    return;
  }

  const set = new Set();
  for (const row of json) {
    String(row.name_value || '')
      .split('\n')
      .forEach((n) => {
        const name = n.trim().toLowerCase().replace(/^\*\./, '');
        if (name.endsWith(apex)) set.add(name);
      });
  }
  set.delete(apex);
  const subs = [...set].sort();

  if (!subs.length) {
    await log('Subdomains: none found in CT logs.', 'info');
    return;
  }

  await log(`Subdomains: discovered ${subs.length} unique name(s): ${subs.slice(0, 25).join(', ')}${subs.length > 25 ? ' …' : ''}`, 'info');

  // Flag names that look like non-production surfaces.
  const risky = subs.filter((s) => /(^|\.)(staging|stage|dev|test|uat|qa|admin|internal|beta|preprod|jenkins|gitlab|vpn|db|api-dev)\./.test(s + '.'));
  for (const s of risky) {
    await finding({
      tool: 'subfinder',
      owasp_category: 'A05:2021-Security Misconfiguration',
      severity: SEVERITY.LOW,
      title: `Potentially sensitive subdomain exposed: ${s}`,
      description: `Certificate-transparency logs reveal ${s}, which looks like a non-production or administrative host.`,
      evidence: `crt.sh CT log entry for ${s}`,
      recommendation: 'Ensure non-production/administrative hosts are not publicly reachable (put them behind VPN/IP allowlist).',
      affected_url: s,
      parameters: [],
      cwe_id: 'CWE-200',
      cvss_score: 3.5,
    });
  }

  // Always record the enumeration itself as informational.
  await finding({
    tool: 'subfinder',
    owasp_category: 'A05:2021-Security Misconfiguration',
    severity: SEVERITY.INFO,
    title: `${subs.length} subdomain(s) discovered via certificate transparency`,
    description: 'Public CT logs expose the certificate history (and therefore subdomains) for this domain.',
    evidence: subs.slice(0, 100).join(', '),
    recommendation: 'Review the attack surface these subdomains represent; decommission unused ones.',
    affected_url: apex,
    parameters: [],
    cwe_id: 'CWE-200',
    cvss_score: 0,
  });
}
