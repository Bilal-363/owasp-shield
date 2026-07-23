import { spawn } from 'node:child_process';
import { readFile, unlink } from 'node:fs/promises';
import { config } from '../config.js';
import { SEVERITY } from '../util.js';

// ---------------------------------------------------------------------------
// Hybrid mode: run REAL Kali tools when they are installed on the host.
// Each wrapper streams the tool's output live into the scan log (so the UI
// shows a real terminal-like feed) and extracts structured findings.
// Nothing is fabricated — if a tool isn't installed, its step is skipped.
// ---------------------------------------------------------------------------

const isWin = process.platform === 'win32';

const BINARIES = ['nmap', 'nuclei', 'nikto', 'gobuster', 'ffuf', 'sslscan', 'wpscan', 'subfinder', 'whatweb', 'sqlmap', 'dalfox'];

function which(bin) {
  return new Promise((resolve) => {
    const cmd = isWin ? 'where' : 'which';
    const p = spawn(cmd, [bin], { shell: false });
    let out = '';
    p.stdout.on('data', (d) => (out += d));
    p.on('error', () => resolve(null));
    p.on('close', (code) => resolve(code === 0 && out.trim() ? out.trim().split(/\r?\n/)[0] : null));
  });
}

/** Which optional tools are available right now. */
export async function detectTools() {
  const disabled = {
    nmap: config.enableNmap === false,
    nuclei: config.enableNuclei === false,
  };
  const entries = await Promise.all(
    BINARIES.map(async (b) => [b, disabled[b] ? null : await which(b)])
  );
  return Object.fromEntries(entries);
}

/**
 * Run a tool, streaming stdout+stderr line-by-line to `onLine` (throttled by
 * maxStreamLines), and resolving with the full captured output.
 */
function runStreaming(bin, args, { timeout = 180000, onLine, maxStreamLines = 150, tag = bin } = {}) {
  return new Promise((resolve) => {
    let full = '';
    let streamed = 0;
    let buf = '';
    const p = spawn(bin, args, { shell: false });
    const timer = setTimeout(() => {
      try {
        p.kill('SIGKILL');
      } catch {
        /* ignore */
      }
    }, timeout);

    const handle = (chunk) => {
      const text = chunk.toString();
      full += text;
      if (full.length > 8 * 1024 * 1024) full = full.slice(-8 * 1024 * 1024); // cap memory
      buf += text;
      let idx;
      while ((idx = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, idx).replace(/\r$/, '');
        buf = buf.slice(idx + 1);
        if (line.trim() && onLine && streamed < maxStreamLines) {
          streamed++;
          onLine(`[${tag}] ${line}`.slice(0, 500));
        }
      }
    };

    p.stdout.on('data', handle);
    p.stderr.on('data', handle);
    p.on('error', (err) => {
      clearTimeout(timer);
      resolve({ ok: false, error: err.message, out: full });
    });
    p.on('close', (code) => {
      clearTimeout(timer);
      if (buf.trim() && onLine && streamed < maxStreamLines) onLine(`[${tag}] ${buf.trim()}`.slice(0, 500));
      resolve({ ok: code === 0, code, out: full });
    });
  });
}

const WORDLIST =
  process.env.DIR_WORDLIST || '/usr/share/wordlists/dirb/common.txt';

// ===========================================================================
// nmap
// ===========================================================================
export async function runNmap(ctx, bin) {
  const { hostname, log, finding, profile } = ctx;
  const topPorts = profile === 'deep' ? '1000' : '200';
  await log(`nmap: service/version scan (top ${topPorts} ports) on ${hostname}...`, 'info');

  const res = await runStreaming(bin, ['-Pn', '-sV', '-T4', '--top-ports', topPorts, '-oG', '-', hostname], {
    timeout: profile === 'deep' ? 300000 : 120000,
    onLine: (l) => log(l, 'debug'),
    tag: 'nmap',
  });

  const line = res.out.split(/\r?\n/).find((l) => l.includes('Ports:'));
  if (!line) return void (await log('nmap: no open ports parsed.', 'info'));
  const entries = (line.split('Ports:')[1] || '').split(',').map((s) => s.trim()).filter(Boolean);
  const open = [];
  for (const e of entries) {
    const f = e.split('/');
    if (f[1] === 'open') open.push({ port: f[0], service: f[4] || 'unknown', version: (f[6] || '').replace(/\|+/g, ' ').trim() });
  }
  if (!open.length) return void (await log('nmap: no open ports.', 'info'));
  await log(`nmap: open -> ${open.map((o) => `${o.port}/${o.service}`).join(', ')}`, 'warning');
  for (const o of open) {
    await finding({
      tool: 'nmap',
      owasp_category: 'A05:2021-Security Misconfiguration',
      severity: SEVERITY.INFO,
      title: `nmap: port ${o.port} open (${o.service}${o.version ? ' ' + o.version : ''})`,
      description: `nmap detected an open service on port ${o.port}.`,
      evidence: `${o.port} open ${o.service} ${o.version}`.trim(),
      recommendation: 'Confirm the service should be exposed and is patched.',
      affected_url: `${hostname}:${o.port}`,
      parameters: [],
      cwe_id: 'CWE-668',
      cvss_score: null,
    });
  }
}

// ===========================================================================
// nuclei
// ===========================================================================
const NUCLEI_SEV = { critical: SEVERITY.CRITICAL, high: SEVERITY.HIGH, medium: SEVERITY.MEDIUM, low: SEVERITY.LOW, info: SEVERITY.INFO, unknown: SEVERITY.INFO };

export async function runNuclei(ctx, bin) {
  const { url, log, finding, profile } = ctx;
  const sev = profile === 'deep' ? 'critical,high,medium,low,info' : 'critical,high,medium,low';
  await log(`nuclei: running templates (${sev}) against ${url.href}...`, 'info');

  // No -duc: allow nuclei to auto-download templates on first run if the image
  // didn't bake them in (self-healing), so it never fails with "no templates".
  const res = await runStreaming(
    bin,
    ['-u', url.href, '-jsonl', '-silent', '-severity', sev, '-timeout', '10', '-rate-limit', '80'],
    { timeout: profile === 'deep' ? 600000 : 240000, onLine: (l) => log(l, 'debug'), tag: 'nuclei' }
  );

  const lines = res.out.split(/\r?\n/).filter((l) => l.trim().startsWith('{'));
  let count = 0;
  for (const line of lines) {
    let j;
    try {
      j = JSON.parse(line);
    } catch {
      continue;
    }
    count++;
    const info = j.info || {};
    await finding({
      tool: 'nuclei',
      owasp_category: mapNucleiToOwasp(j),
      severity: NUCLEI_SEV[(info.severity || 'info').toLowerCase()] || SEVERITY.INFO,
      title: `nuclei: ${info.name || j['template-id'] || 'match'}`,
      description: (info.description || 'nuclei template matched.').slice(0, 1000),
      evidence: `template=${j['template-id'] || ''} matched=${j['matched-at'] || j.host || url.href}`,
      recommendation:
        (Array.isArray(info.remediation) ? info.remediation.join(' ') : info.remediation) ||
        'Review the matched nuclei template and remediate.',
      affected_url: j['matched-at'] || j.host || url.href,
      parameters: [],
      cwe_id: extractCwe(info),
      cvss_score: info?.classification?.['cvss-score'] || null,
    });
  }
  await log(`nuclei: ${count} finding(s).`, count ? 'warning' : 'info');
}

// ===========================================================================
// nikto
// ===========================================================================
export async function runNikto(ctx, bin) {
  const { url, hostname, log, finding, profile } = ctx;
  const port = url.port || (url.protocol === 'https:' ? '443' : '80');
  await log(`nikto: web server scan on ${hostname}:${port}...`, 'info');

  const args = ['-host', hostname, '-port', port, '-nointeractive', '-Format', 'json', '-output', '/dev/stdout'];
  if (url.protocol === 'https:') args.push('-ssl');
  if (profile !== 'deep') args.push('-maxtime', '120s');

  const res = await runStreaming(bin, args, { timeout: profile === 'deep' ? 420000 : 180000, onLine: (l) => log(l, 'debug'), tag: 'nikto' });

  const jsonStart = res.out.indexOf('{');
  let count = 0;
  if (jsonStart >= 0) {
    try {
      const parsed = JSON.parse(res.out.slice(jsonStart));
      const vulns = parsed.vulnerabilities || (parsed.host && parsed.host.vulnerabilities) || [];
      for (const v of vulns) {
        count++;
        await finding({
          tool: 'nikto',
          owasp_category: 'A05:2021-Security Misconfiguration',
          severity: SEVERITY.LOW,
          title: `nikto: ${(v.msg || v.id || 'finding').slice(0, 120)}`,
          description: v.msg || 'nikto reported an issue.',
          evidence: `${v.method || 'GET'} ${v.url || url.href} (id ${v.id || 'n/a'})`,
          recommendation: 'Review the nikto finding and harden the web server configuration.',
          affected_url: v.url ? `${url.origin}${v.url}` : url.href,
          parameters: [],
          cwe_id: null,
          cvss_score: null,
        });
      }
    } catch {
      /* fall through */
    }
  }
  await log(`nikto: ${count} finding(s).`, count ? 'warning' : 'info');
}

// ===========================================================================
// gobuster (directory brute force)
// ===========================================================================
export async function runGobuster(ctx, bin) {
  const { url, log, finding } = ctx;
  await log(`gobuster: directory brute force on ${url.origin} (wordlist: ${WORDLIST})...`, 'info');

  const res = await runStreaming(
    bin,
    ['dir', '-u', url.origin, '-w', WORDLIST, '-q', '-t', '30', '--no-error'],
    { timeout: 240000, onLine: (l) => log(l, 'debug'), tag: 'gobuster' }
  );

  if (res.error && /ENOENT|no such file/i.test(res.error + res.out)) {
    await log(`gobuster: wordlist not found at ${WORDLIST}. Set DIR_WORDLIST env.`, 'warning');
    return;
  }

  let count = 0;
  for (const line of res.out.split(/\r?\n/)) {
    const m = line.match(/^(\/\S+)\s+\(Status:\s*(\d+)\)/);
    if (!m) continue;
    const path = m[1];
    const status = Number(m[2]);
    if (![200, 201, 301, 302, 401, 403].includes(status)) continue;
    count++;
    await finding({
      tool: 'gobuster',
      owasp_category: 'A01:2021-Broken Access Control',
      severity: status === 200 ? SEVERITY.LOW : SEVERITY.INFO,
      title: `gobuster: discovered ${path} (HTTP ${status})`,
      description: `Path ${path} exists (HTTP ${status}).`,
      evidence: `${url.origin}${path} -> ${status}`,
      recommendation: 'Verify this path is meant to be public and properly access-controlled.',
      affected_url: `${url.origin}${path}`,
      parameters: [],
      cwe_id: 'CWE-284',
      cvss_score: null,
    });
  }
  await log(`gobuster: ${count} path(s) found.`, count ? 'warning' : 'info');
}

// ===========================================================================
// ffuf (fuzzing)
// ===========================================================================
export async function runFfuf(ctx, bin) {
  const { url, log, finding } = ctx;
  await log(`ffuf: fuzzing ${url.origin}/FUZZ...`, 'info');
  const res = await runStreaming(
    bin,
    ['-u', `${url.origin}/FUZZ`, '-w', WORDLIST, '-mc', '200,204,301,302,307,401,403', '-of', 'json', '-o', '/dev/stdout', '-s'],
    { timeout: 240000, onLine: (l) => log(l, 'debug'), tag: 'ffuf' }
  );
  const jsonStart = res.out.indexOf('{');
  let count = 0;
  if (jsonStart >= 0) {
    try {
      const parsed = JSON.parse(res.out.slice(jsonStart));
      for (const r of parsed.results || []) {
        count++;
        await finding({
          tool: 'ffuf',
          owasp_category: 'A01:2021-Broken Access Control',
          severity: r.status === 200 ? SEVERITY.LOW : SEVERITY.INFO,
          title: `ffuf: ${r.url} (HTTP ${r.status})`,
          description: `Fuzzing found ${r.url} (status ${r.status}, ${r.length} bytes).`,
          evidence: `${r.url} -> ${r.status}`,
          recommendation: 'Confirm this endpoint should be reachable.',
          affected_url: r.url,
          parameters: [],
          cwe_id: 'CWE-284',
          cvss_score: null,
        });
      }
    } catch {
      /* ignore */
    }
  }
  await log(`ffuf: ${count} hit(s).`, count ? 'warning' : 'info');
}

// ===========================================================================
// sslscan
// ===========================================================================
export async function runSslscan(ctx, bin) {
  const { url, hostname, log, finding } = ctx;
  if (url.protocol !== 'https:') return;
  const port = url.port || '443';
  await log(`sslscan: auditing TLS ciphers on ${hostname}:${port}...`, 'info');
  const res = await runStreaming(bin, ['--no-colour', `${hostname}:${port}`], {
    timeout: 90000,
    onLine: (l) => log(l, 'debug'),
    tag: 'sslscan',
  });

  const enabledLegacy = [];
  for (const line of res.out.split(/\r?\n/)) {
    const m = line.match(/(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1)\s+(enabled)/i);
    if (m) enabledLegacy.push(m[1]);
  }
  if (enabledLegacy.length) {
    await finding({
      tool: 'sslscan',
      owasp_category: 'A02:2021-Cryptographic Failures',
      severity: SEVERITY.MEDIUM,
      title: `sslscan: deprecated protocol(s) enabled (${[...new Set(enabledLegacy)].join(', ')})`,
      description: 'The server accepts deprecated SSL/TLS protocol versions.',
      evidence: [...new Set(enabledLegacy)].join(', '),
      recommendation: 'Disable SSLv2/SSLv3/TLS1.0/TLS1.1; require TLS 1.2+.',
      affected_url: url.href,
      parameters: [],
      cwe_id: 'CWE-326',
      cvss_score: 5.3,
    });
  }
  await log('sslscan: done.', 'info');
}

// ===========================================================================
// subfinder (active subdomain enumeration)
// ===========================================================================
export async function runSubfinder(ctx, bin) {
  const { hostname, log, finding } = ctx;
  const apex = hostname.replace(/^www\./, '');
  await log(`subfinder: enumerating subdomains for ${apex}...`, 'info');
  const res = await runStreaming(bin, ['-d', apex, '-silent'], { timeout: 120000, onLine: (l) => log(l, 'debug'), tag: 'subfinder' });
  const subs = [...new Set(res.out.split(/\r?\n/).map((s) => s.trim().toLowerCase()).filter((s) => s.endsWith(apex)))];
  if (!subs.length) return void (await log('subfinder: none found.', 'info'));
  await log(`subfinder: ${subs.length} subdomain(s): ${subs.slice(0, 30).join(', ')}${subs.length > 30 ? ' …' : ''}`, 'info');
  await finding({
    tool: 'subfinder',
    owasp_category: 'A05:2021-Security Misconfiguration',
    severity: SEVERITY.INFO,
    title: `subfinder: ${subs.length} subdomain(s) discovered`,
    description: 'Active subdomain enumeration results.',
    evidence: subs.slice(0, 100).join(', '),
    recommendation: 'Review the exposed attack surface; decommission unused hosts.',
    affected_url: apex,
    parameters: [],
    cwe_id: 'CWE-200',
    cvss_score: null,
  });
}

// ===========================================================================
// whatweb (technology fingerprinting)
// ===========================================================================
export async function runWhatweb(ctx, bin) {
  const { url, log, finding } = ctx;
  await log(`whatweb: fingerprinting ${url.href}...`, 'info');
  // whatweb can't write JSON to /dev/stdout inside the container — use a temp file.
  const outFile = `/tmp/whatweb-${Date.now()}-${Math.floor(Math.random() * 1e6)}.json`;
  await runStreaming(bin, ['--colour=never', `--log-json=${outFile}`, '-a', '3', url.href], {
    timeout: 90000,
    onLine: (l) => log(l, 'debug'),
    tag: 'whatweb',
  });

  let plugins = [];
  let isWordpress = false;
  try {
    const txt = await readFile(outFile, 'utf8');
    const parsed = JSON.parse(txt); // whatweb writes a JSON array
    const entries = Array.isArray(parsed) ? parsed : [parsed];
    const pluginSet = new Set();
    for (const e of entries) {
      Object.keys(e?.plugins || {}).forEach((p) => pluginSet.add(p));
    }
    plugins = [...pluginSet];
    isWordpress = plugins.some((p) => /wordpress/i.test(p));
  } catch {
    /* ignore parse/read errors */
  }
  try {
    await unlink(outFile);
  } catch {
    /* ignore */
  }
  if (plugins.length) {
    await log(`whatweb: ${plugins.join(', ')}`, 'info');
    await finding({
      tool: 'whatweb',
      owasp_category: 'A05:2021-Security Misconfiguration',
      severity: SEVERITY.INFO,
      title: `whatweb: detected ${plugins.length} technolog(ies)`,
      description: 'Technology fingerprint of the target.',
      evidence: plugins.slice(0, 60).join(', '),
      recommendation: 'Ensure detected components are patched and version banners minimised.',
      affected_url: url.href,
      parameters: [],
      cwe_id: 'CWE-200',
      cvss_score: null,
    });
  }
  return { isWordpress };
}

// ===========================================================================
// wpscan (only meaningful for WordPress targets)
// ===========================================================================
export async function runWpscan(ctx, bin) {
  const { url, log, finding, profile } = ctx;
  await log(`wpscan: scanning WordPress at ${url.href}...`, 'info');
  const args = ['--url', url.href, '--format', 'json', '--no-banner', '--random-user-agent', '--disable-tls-checks'];
  if (process.env.WPSCAN_API_TOKEN) args.push('--api-token', process.env.WPSCAN_API_TOKEN);
  if (profile !== 'deep') args.push('--enumerate', 'vp,vt,cb,dbe');

  const res = await runStreaming(bin, args, { timeout: profile === 'deep' ? 420000 : 180000, onLine: (l) => log(l, 'debug'), tag: 'wpscan' });
  const jsonStart = res.out.indexOf('{');
  if (jsonStart < 0) return void (await log('wpscan: no parseable output (target may not be WordPress).', 'info'));

  let count = 0;
  try {
    const j = JSON.parse(res.out.slice(jsonStart));
    const version = j.version?.number;
    if (version && j.version?.status === 'insecure') {
      count++;
      await finding({
        tool: 'wpscan',
        owasp_category: 'A06:2021-Vulnerable and Outdated Components',
        severity: SEVERITY.HIGH,
        title: `wpscan: outdated WordPress core (${version})`,
        description: 'The WordPress core version is flagged as insecure.',
        evidence: `WordPress ${version}`,
        recommendation: 'Update WordPress core to the latest version.',
        affected_url: url.href,
        parameters: [],
        cwe_id: 'CWE-1104',
        cvss_score: 7.5,
      });
    }
    const plugins = j.plugins || {};
    for (const [name, p] of Object.entries(plugins)) {
      const vulns = p.vulnerabilities || [];
      for (const v of vulns) {
        count++;
        await finding({
          tool: 'wpscan',
          owasp_category: 'A06:2021-Vulnerable and Outdated Components',
          severity: SEVERITY.HIGH,
          title: `wpscan: vulnerable plugin ${name} — ${(v.title || '').slice(0, 100)}`,
          description: v.title || 'Vulnerable WordPress plugin.',
          evidence: `plugin=${name} version=${p.version?.number || 'unknown'} refs=${JSON.stringify(v.references || {}).slice(0, 200)}`,
          recommendation: 'Update or remove the vulnerable plugin.',
          affected_url: url.href,
          parameters: [],
          cwe_id: null,
          cvss_score: null,
        });
      }
    }
  } catch {
    /* ignore */
  }
  await log(`wpscan: ${count} issue(s).`, count ? 'warning' : 'info');
}

// ===========================================================================
// sqlmap (ACTIVE SQL-injection testing) — lab / authorized targets only
// ===========================================================================
export async function runSqlmap(ctx, bin) {
  const { url, log, finding, profile } = ctx;
  const hasParams = [...url.searchParams.keys()].length > 0;
  await log(
    `sqlmap: testing for SQL injection on ${url.href}${hasParams ? '' : ' (crawling for parameters first)'}...`,
    'warning'
  );

  const args = [
    '-u', url.href,
    '--batch', // never prompt
    '--random-agent',
    '--flush-session',
    '-v', '1',
    '--level', profile === 'deep' ? '3' : '1',
    '--risk', profile === 'deep' ? '2' : '1',
  ];
  // If the URL has no parameters, let sqlmap crawl to find some.
  if (!hasParams) args.push('--crawl', profile === 'deep' ? '2' : '1', '--forms');

  const res = await runStreaming(bin, args, {
    timeout: profile === 'deep' ? 600000 : 240000,
    onLine: (l) => log(l, 'debug'),
    tag: 'sqlmap',
    maxStreamLines: 250,
  });

  const out = res.out;
  // sqlmap prints a "Parameter: X (METHOD)" + "Type:/Title:" block per hit.
  const blocks = out.split(/\n(?=Parameter:\s)/).filter((b) => /^Parameter:/.test(b.trim()));
  let count = 0;
  for (const b of blocks) {
    const param = (b.match(/Parameter:\s*([^\s(]+)/) || [])[1];
    const type = (b.match(/Type:\s*(.+)/) || [])[1];
    const title = (b.match(/Title:\s*(.+)/) || [])[1];
    if (!param) continue;
    count++;
    await finding({
      tool: 'sqlmap',
      owasp_category: 'A03:2021-Injection',
      severity: SEVERITY.CRITICAL,
      title: `SQL Injection in parameter "${param}"`,
      description: `sqlmap confirmed the parameter "${param}" is injectable${title ? ` (${title.trim()})` : ''}.`,
      evidence: b.trim().slice(0, 600),
      recommendation: 'Use parameterised queries / prepared statements; validate and least-privilege the DB account.',
      affected_url: url.href,
      parameters: [param],
      cwe_id: 'CWE-89',
      cvss_score: 9.8,
    });
  }
  // Also catch the generic confirmation if the block parse missed it.
  if (!count && /sqlmap identified the following injection point|is vulnerable/i.test(out)) {
    await finding({
      tool: 'sqlmap',
      owasp_category: 'A03:2021-Injection',
      severity: SEVERITY.CRITICAL,
      title: 'SQL Injection vulnerability',
      description: 'sqlmap identified an SQL injection point on the target.',
      evidence: (out.match(/sqlmap identified[\s\S]{0,400}/i) || [''])[0].slice(0, 600),
      recommendation: 'Use parameterised queries / prepared statements.',
      affected_url: url.href,
      parameters: [],
      cwe_id: 'CWE-89',
      cvss_score: 9.8,
    });
    count = 1;
  }
  await log(`sqlmap: ${count} injection point(s) found.`, count ? 'error' : 'info');
}

// ===========================================================================
// dalfox (ACTIVE XSS testing) — lab / authorized targets only
// ===========================================================================
export async function runDalfox(ctx, bin) {
  const { url, log, finding } = ctx;
  await log(`dalfox: testing for XSS on ${url.href}...`, 'warning');

  const res = await runStreaming(
    bin,
    ['url', url.href, '--format', 'json', '--silence', '--no-spinner', '--skip-bav'],
    { timeout: 240000, onLine: (l) => log(l, 'debug'), tag: 'dalfox' }
  );

  let pocs = [];
  const jsonStart = res.out.indexOf('[');
  if (jsonStart >= 0) {
    try {
      pocs = JSON.parse(res.out.slice(jsonStart, res.out.lastIndexOf(']') + 1)) || [];
    } catch {
      /* ignore */
    }
  }

  let count = 0;
  for (const p of pocs) {
    // dalfox type: "V" = verified, "R" = reflected, "G" = grep
    const verified = (p.type || '').toUpperCase() === 'V';
    count++;
    await finding({
      tool: 'dalfox',
      owasp_category: 'A03:2021-Injection',
      severity: verified ? SEVERITY.HIGH : SEVERITY.MEDIUM,
      title: `${verified ? 'Verified' : 'Reflected'} XSS${p.param ? ` in "${p.param}"` : ''}`,
      description: p.message_str || 'dalfox detected a cross-site scripting vector.',
      evidence: `${p.method || 'GET'} ${p.data || p.evidence || url.href}`.slice(0, 600),
      recommendation: 'Context-aware output encoding; a strict Content-Security-Policy; validate input.',
      affected_url: p.data || url.href,
      parameters: p.param ? [p.param] : [],
      cwe_id: p.cwe ? `CWE-${String(p.cwe).replace(/\D/g, '')}` : 'CWE-79',
      cvss_score: verified ? 7.4 : 6.1,
    });
  }
  await log(`dalfox: ${count} XSS vector(s) found.`, count ? 'error' : 'info');
}

// ---- helpers -------------------------------------------------------------
function extractCwe(info) {
  const cwe = info?.classification?.['cwe-id'];
  if (Array.isArray(cwe)) return cwe[0]?.toUpperCase() || null;
  if (typeof cwe === 'string') return cwe.toUpperCase();
  return null;
}
function mapNucleiToOwasp(j) {
  const tags = (j.info?.tags || []).join(',').toLowerCase();
  if (tags.includes('sqli') || tags.includes('xss') || tags.includes('lfi') || tags.includes('rfi') || tags.includes('ssrf')) return 'A03:2021-Injection';
  if (tags.includes('auth') || tags.includes('default-login')) return 'A07:2021-Identification and Authentication Failures';
  if (tags.includes('cve')) return 'A06:2021-Vulnerable and Outdated Components';
  if (tags.includes('exposure') || tags.includes('config') || tags.includes('misconfig')) return 'A05:2021-Security Misconfiguration';
  return 'A05:2021-Security Misconfiguration';
}
