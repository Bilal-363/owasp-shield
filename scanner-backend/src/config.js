import 'dotenv/config';

function bool(v, fallback = false) {
  if (v === undefined || v === null || v === '') return fallback;
  return String(v).toLowerCase() === 'true';
}

function int(v, fallback) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : fallback;
}

export const config = {
  port: int(process.env.PORT, 8787),

  supabaseUrl: process.env.SUPABASE_URL || '',
  supabaseServiceKey: process.env.SUPABASE_SERVICE_ROLE_KEY || '',

  allowedOrigins: (process.env.ALLOWED_ORIGINS || 'http://localhost:8080')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),

  allowPrivateTargets: bool(process.env.ALLOW_PRIVATE_TARGETS, false),
  rateLimitPerHour: int(process.env.RATE_LIMIT_PER_HOUR, 5),
  maxScanDurationMs: int(process.env.MAX_SCAN_DURATION_MS, 30 * 60 * 1000),

  // Global cap on scans running at once (protects a shared host from overload).
  maxConcurrentScans: int(process.env.MAX_CONCURRENT_SCANS, 3),

  // Optional allowlist: if set, only these user emails may start scans.
  // Comma-separated, case-insensitive. Empty = any logged-in user (fine for
  // local use; SET THIS before hosting publicly).
  allowedEmails: (process.env.SCAN_ALLOWED_EMAILS || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean),

  enableNmap: bool(process.env.ENABLE_NMAP, true),
  enableNuclei: bool(process.env.ENABLE_NUCLEI, true),
};

export function assertConfig() {
  const missing = [];
  if (!config.supabaseUrl) missing.push('SUPABASE_URL');
  if (!config.supabaseServiceKey) missing.push('SUPABASE_SERVICE_ROLE_KEY');
  if (missing.length) {
    console.error(
      `\n[config] Missing required env vars: ${missing.join(', ')}\n` +
        `Copy .env.example to .env and fill them in.\n`
    );
    process.exit(1);
  }
}
