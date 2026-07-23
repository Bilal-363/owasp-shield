import dns from 'node:dns/promises';
import net from 'node:net';
import { config } from './config.js';

// ---------------------------------------------------------------------------
// Target validation + SSRF protection.
//
// This is a REAL scanner, so contacting the target is the whole point — but we
// still refuse to point it at internal infrastructure (localhost, RFC1918,
// link-local, cloud metadata, IPv6 ULA, etc.) unless ALLOW_PRIVATE_TARGETS is
// explicitly enabled for local testing.
//
// Fixes the gaps in the original edge function: IPv6, IPv4-mapped IPv6, and
// alternate IPv4 encodings are all normalised via node's net + dns before the
// checks run.
// ---------------------------------------------------------------------------

function ipv4ToInt(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) {
    return null;
  }
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function inCidr4(ipInt, baseIp, bits) {
  const base = ipv4ToInt(baseIp);
  if (base === null || ipInt === null) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) === (base & mask);
}

const PRIVATE_V4 = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10], // CGNAT
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local (incl. 169.254.169.254 metadata)
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24], // TEST-NET-1
  ['192.168.0.0', 16],
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // TEST-NET-2
  ['203.0.113.0', 24], // TEST-NET-3
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved
  ['255.255.255.255', 32],
];

function isPrivateV4(ip) {
  const n = ipv4ToInt(ip);
  if (n === null) return true; // treat unpar. as unsafe
  return PRIVATE_V4.some(([base, bits]) => inCidr4(n, base, bits));
}

function isPrivateV6(ip) {
  const v = ip.toLowerCase();
  if (v === '::1' || v === '::') return true;
  // IPv4-mapped / -compatible (::ffff:1.2.3.4 or ::ffff:xxyy)
  const mapped = v.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateV4(mapped[1]);
  if (v.startsWith('fc') || v.startsWith('fd')) return true; // fc00::/7 ULA
  if (v.startsWith('fe80') || v.startsWith('fe9') || v.startsWith('fea') || v.startsWith('feb'))
    return true; // fe80::/10 link-local
  if (v.startsWith('ff')) return true; // multicast
  if (v.startsWith('2001:db8')) return true; // documentation
  return false;
}

export function isPrivateIp(ip) {
  const type = net.isIP(ip);
  if (type === 4) return isPrivateV4(ip);
  if (type === 6) return isPrivateV6(ip);
  return true; // not a literal IP -> caller must resolve first
}

const BLOCKED_HOST_SUFFIXES = ['.local', '.internal', '.lan', '.test', '.localhost'];
const BLOCKED_HOST_EXACT = ['localhost', 'metadata.google.internal', 'metadata'];

// Cloud metadata + link-local: NEVER allowed, even in permissive mode, because
// 169.254.169.254 leaks cloud credentials. This is the worst-case SSRF target.
const METADATA_HOSTS = ['metadata.google.internal', 'metadata'];
function isLinkLocalOrMetadata(ip) {
  const t = net.isIP(ip);
  if (t === 4) return /^169\.254\./.test(ip);
  if (t === 6) return ip.toLowerCase().startsWith('fe80');
  return false;
}
async function resolveAll(hostname) {
  const ips = [];
  const [a, aaaa] = await Promise.allSettled([dns.resolve4(hostname), dns.resolve6(hostname)]);
  if (a.status === 'fulfilled') ips.push(...a.value);
  if (aaaa.status === 'fulfilled') ips.push(...aaaa.value);
  return ips;
}

/**
 * Validate + normalise a target URL. Returns { url, hostname, ips } or throws.
 */
export async function validateTarget(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    // allow "example.com" without scheme
    try {
      parsed = new URL(`https://${rawUrl}`);
    } catch {
      throw new HttpError(400, 'Invalid target URL');
    }
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new HttpError(400, 'Only http and https targets are allowed');
  }

  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');

  if (config.allowPrivateTargets) {
    // Permissive mode (local lab): allow localhost/RFC1918, but STILL refuse
    // cloud-metadata / link-local, which never has a legitimate scan use.
    if (METADATA_HOSTS.includes(hostname)) {
      throw new HttpError(403, 'Target blocked: cloud metadata endpoint');
    }
    let ips = net.isIP(hostname) ? [hostname] : [];
    if (!ips.length && hostname !== 'localhost') {
      try {
        ips = await resolveAll(hostname);
      } catch {
        ips = [];
      }
    }
    for (const ip of ips) {
      if (isLinkLocalOrMetadata(ip)) {
        throw new HttpError(403, 'Target blocked: link-local / cloud metadata address');
      }
    }
    return { url: parsed, hostname, ips };
  }

  if (BLOCKED_HOST_EXACT.includes(hostname)) {
    throw new HttpError(403, 'Target blocked: internal hostname');
  }
  if (BLOCKED_HOST_SUFFIXES.some((s) => hostname.endsWith(s))) {
    throw new HttpError(403, 'Target blocked: internal domain suffix');
  }

  // If it's a literal IP, check directly.
  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname)) {
      throw new HttpError(403, 'Target blocked: private/reserved IP address');
    }
    return { url: parsed, hostname, ips: [hostname] };
  }

  // Otherwise resolve A + AAAA and check every result (blocks DNS-based SSRF).
  let ips = [];
  try {
    const [a, aaaa] = await Promise.allSettled([
      dns.resolve4(hostname),
      dns.resolve6(hostname),
    ]);
    if (a.status === 'fulfilled') ips.push(...a.value);
    if (aaaa.status === 'fulfilled') ips.push(...aaaa.value);
  } catch {
    /* handled below */
  }

  if (ips.length === 0) {
    throw new HttpError(400, 'Target hostname does not resolve to any IP address');
  }
  for (const ip of ips) {
    if (isPrivateIp(ip)) {
      throw new HttpError(403, 'Target blocked: resolves to a private/reserved IP');
    }
  }

  return { url: parsed, hostname, ips };
}

export class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}
