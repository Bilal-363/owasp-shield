import tls from 'node:tls';
import { SEVERITY } from '../util.js';

function connectTls(host, port, opts, timeout = 8000) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      { host, port, servername: host, rejectUnauthorized: false, ...opts },
      () => {
        const info = {
          ok: true,
          protocol: socket.getProtocol(),
          cipher: socket.getCipher(),
          cert: socket.getPeerCertificate(),
        };
        socket.destroy();
        resolve(info);
      }
    );
    socket.setTimeout(timeout);
    socket.once('timeout', () => {
      socket.destroy();
      resolve({ ok: false });
    });
    socket.once('error', () => resolve({ ok: false }));
  });
}

/**
 * Real TLS analysis: negotiated version, certificate expiry, and an active
 * probe for legacy TLS 1.0/1.1 support.
 */
export async function scanTls(ctx) {
  const { url, hostname, log, finding } = ctx;
  if (url.protocol !== 'https:') {
    await log('TLS: target is HTTP (no transport encryption).', 'warning');
    await finding({
      tool: 'tls',
      owasp_category: 'A02:2021-Cryptographic Failures',
      severity: SEVERITY.MEDIUM,
      title: 'Site served over plain HTTP',
      description: 'Traffic is not encrypted in transit, allowing interception and tampering.',
      evidence: `Target scheme is ${url.protocol}`,
      recommendation: 'Serve the site over HTTPS and redirect HTTP to HTTPS.',
      affected_url: url.href,
      parameters: [],
      cwe_id: 'CWE-319',
      cvss_score: 5.9,
    });
    return;
  }

  const port = url.port ? Number(url.port) : 443;
  await log(`TLS: inspecting certificate and negotiating protocol on ${hostname}:${port}...`, 'info');

  const main = await connectTls(hostname, port, {});
  if (!main.ok) {
    await log('TLS: handshake failed.', 'error');
    return;
  }

  await log(`TLS: negotiated ${main.protocol}, cipher ${main.cipher?.name || 'unknown'}`, 'info');

  // Certificate expiry (real).
  const cert = main.cert || {};
  if (cert.valid_to) {
    const expiry = new Date(cert.valid_to);
    const daysLeft = Math.round((expiry - Date.now()) / (1000 * 60 * 60 * 24));
    if (daysLeft < 0) {
      await finding({
        tool: 'tls',
        owasp_category: 'A02:2021-Cryptographic Failures',
        severity: SEVERITY.HIGH,
        title: 'Expired TLS certificate',
        description: `The certificate expired ${Math.abs(daysLeft)} day(s) ago.`,
        evidence: `notAfter=${cert.valid_to}`,
        recommendation: 'Renew the TLS certificate immediately.',
        affected_url: url.href,
        parameters: [],
        cwe_id: 'CWE-295',
        cvss_score: 7.4,
      });
    } else if (daysLeft <= 14) {
      await finding({
        tool: 'tls',
        owasp_category: 'A02:2021-Cryptographic Failures',
        severity: SEVERITY.LOW,
        title: 'TLS certificate expiring soon',
        description: `The certificate expires in ${daysLeft} day(s).`,
        evidence: `notAfter=${cert.valid_to}`,
        recommendation: 'Renew / automate renewal of the TLS certificate.',
        affected_url: url.href,
        parameters: [],
        cwe_id: 'CWE-295',
        cvss_score: 2.0,
      });
    }
  }

  // Active probe: does the server still accept TLS 1.0 / 1.1?
  const legacy = [];
  for (const v of ['TLSv1', 'TLSv1.1']) {
    const r = await connectTls(hostname, port, { minVersion: v, maxVersion: v });
    if (r.ok) legacy.push(v);
  }
  if (legacy.length) {
    await log(`TLS: legacy protocol(s) still enabled -> ${legacy.join(', ')}`, 'warning');
    await finding({
      tool: 'tls',
      owasp_category: 'A02:2021-Cryptographic Failures',
      severity: SEVERITY.MEDIUM,
      title: 'Deprecated TLS version(s) enabled',
      description: `The server accepts ${legacy.join(' and ')}, which are deprecated and vulnerable to known downgrade/crypto attacks.`,
      evidence: `Successful handshake forcing ${legacy.join(', ')}.`,
      recommendation: 'Disable TLS 1.0 and 1.1; require TLS 1.2 or higher.',
      affected_url: url.href,
      parameters: [],
      cwe_id: 'CWE-326',
      cvss_score: 5.3,
    });
  } else {
    await log('TLS: legacy TLS 1.0/1.1 correctly disabled.', 'info');
  }
}
