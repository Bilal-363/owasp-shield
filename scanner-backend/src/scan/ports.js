import net from 'node:net';
import { mapLimit, SEVERITY } from '../util.js';

// Common ports + the service typically behind them. A real TCP connect scan.
const COMMON_PORTS = {
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  80: 'HTTP',
  110: 'POP3',
  135: 'MSRPC',
  139: 'NetBIOS',
  143: 'IMAP',
  443: 'HTTPS',
  445: 'SMB',
  1433: 'MSSQL',
  1521: 'Oracle DB',
  2049: 'NFS',
  3000: 'HTTP (dev)',
  3306: 'MySQL',
  3389: 'RDP',
  5432: 'PostgreSQL',
  5601: 'Kibana',
  5672: 'AMQP',
  5900: 'VNC',
  6379: 'Redis',
  8000: 'HTTP-alt',
  8080: 'HTTP-proxy',
  8443: 'HTTPS-alt',
  9200: 'Elasticsearch',
  27017: 'MongoDB',
};

// Ports that should essentially never be internet-exposed.
const SENSITIVE = {
  23: SEVERITY.HIGH,
  135: SEVERITY.MEDIUM,
  139: SEVERITY.MEDIUM,
  445: SEVERITY.HIGH,
  1433: SEVERITY.HIGH,
  1521: SEVERITY.HIGH,
  2049: SEVERITY.HIGH,
  3306: SEVERITY.HIGH,
  3389: SEVERITY.HIGH,
  5432: SEVERITY.HIGH,
  6379: SEVERITY.CRITICAL, // Redis, usually unauthenticated
  9200: SEVERITY.HIGH,
  27017: SEVERITY.HIGH,
};

function checkPort(host, port, timeout = 2500) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let done = false;
    const finish = (open) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(open);
    };
    socket.setTimeout(timeout);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
    socket.connect(port, host);
  });
}

/**
 * Real TCP connect scan against the resolved host.
 * ctx: { host, log, finding }
 */
export async function scanPorts(ctx) {
  const { host, log, finding } = ctx;
  await log(`Port scan: probing ${Object.keys(COMMON_PORTS).length} common TCP ports on ${host}...`, 'info');

  const ports = Object.keys(COMMON_PORTS).map(Number);
  const results = await mapLimit(ports, 30, async (port) => ({
    port,
    open: await checkPort(host, port),
  }));

  const open = results.filter((r) => r.open).map((r) => r.port).sort((a, b) => a - b);

  if (open.length === 0) {
    await log('Port scan: no common TCP ports responded (host may filter/deny connections).', 'info');
    return;
  }

  await log(`Port scan: OPEN ports -> ${open.map((p) => `${p}/${COMMON_PORTS[p]}`).join(', ')}`, 'warning');

  for (const port of open) {
    const service = COMMON_PORTS[port];
    const severity = SENSITIVE[port] || SEVERITY.INFO;

    if (severity === SEVERITY.INFO) {
      // Informational: expected web/mail ports being open is normal.
      await finding({
        tool: 'portscan',
        owasp_category: 'A05:2021-Security Misconfiguration',
        severity: SEVERITY.INFO,
        title: `Open port ${port} (${service})`,
        description: `TCP port ${port} is open and accepting connections.`,
        evidence: `TCP connect() to ${host}:${port} succeeded.`,
        recommendation: 'Confirm this service is intended to be internet-facing.',
        affected_url: `${host}:${port}`,
        parameters: [],
        cwe_id: 'CWE-668',
        cvss_score: 0,
      });
    } else {
      await finding({
        tool: 'portscan',
        owasp_category: 'A05:2021-Security Misconfiguration',
        severity,
        title: `Exposed ${service} port (${port}) reachable from the internet`,
        description: `TCP port ${port} (${service}) is open to the public. Database, remote-access and file-sharing services should not be internet-exposed.`,
        evidence: `TCP connect() to ${host}:${port} succeeded.`,
        recommendation: `Restrict access to port ${port} with a firewall / security group, or bind the service to localhost / a private network.`,
        affected_url: `${host}:${port}`,
        parameters: [],
        cwe_id: 'CWE-668',
        cvss_score: severity === SEVERITY.CRITICAL ? 9.1 : 7.5,
      });
    }
  }

  return open;
}
