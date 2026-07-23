import express from 'express';
import cors from 'cors';
import { config, assertConfig } from './config.js';
import { requireAuth } from './auth.js';
import { validateTarget, HttpError } from './ssrf.js';
import { createScan, getScan, countRecentScans, sweepStaleScans } from './db.js';
import { supabase } from './supabase.js';
import { runScan } from './scan/orchestrator.js';
import { detectTools } from './scan/tools.js';

assertConfig();

// Global concurrency guard: how many scans are running right now.
let activeScans = 0;

const app = express();
app.use(express.json({ limit: '256kb' }));

// --- CORS (env-driven allowlist) ---
app.use(
  cors({
    origin(origin, cb) {
      // allow same-origin / curl (no origin) and any listed frontend origin
      if (!origin || config.allowedOrigins.includes(origin)) return cb(null, true);
      return cb(new Error('Not allowed by CORS'));
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Authorization', 'Content-Type'],
    maxAge: 3600,
  })
);

// --- Health check (used by hosting platforms) ---
app.get('/health', (_req, res) => res.json({ ok: true, service: 'owasp-shield-scanner' }));

app.get('/tools', requireAuth, async (_req, res) => {
  const t = await detectTools();
  res.json({ nmap: !!t.nmap, nuclei: !!t.nuclei });
});

// --- Start a scan ---
app.post('/scan/start', requireAuth, async (req, res) => {
  try {
    const { targetUrl, tools = [], profile = 'quick' } = req.body || {};
    if (!targetUrl || typeof targetUrl !== 'string') {
      return res.status(400).json({ error: 'targetUrl is required' });
    }
    if (!Array.isArray(tools)) {
      return res.status(400).json({ error: 'tools must be an array' });
    }
    const scanProfile = profile === 'deep' ? 'deep' : 'quick';

    // Optional email allowlist (lock down who can scan on a hosted instance).
    if (config.allowedEmails.length) {
      const email = (req.user.email || '').toLowerCase();
      if (!config.allowedEmails.includes(email)) {
        return res.status(403).json({ error: 'Your account is not permitted to run scans' });
      }
    }

    // Global concurrency cap (protects the host from overload).
    if (activeScans >= config.maxConcurrentScans) {
      return res
        .status(429)
        .json({ error: 'Server busy: too many scans running. Try again shortly.' });
    }

    // Rate limit (real, per user).
    const sinceIso = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    const recent = await countRecentScans(req.user.id, sinceIso);
    if (recent >= config.rateLimitPerHour) {
      return res
        .status(429)
        .json({ error: `Rate limit exceeded: max ${config.rateLimitPerHour} scans per hour` });
    }

    // Validate + SSRF-check the target (throws HttpError with a real status).
    const target = await validateTarget(targetUrl);

    // Create the scan row (running) and return immediately.
    const scan = await createScan(req.user.id, target.url.href, tools);

    // Fire-and-forget the real scan; results stream into Supabase.
    activeScans++;
    runScan({ scanId: scan.id, userId: req.user.id, target, tools, profile: scanProfile })
      .catch((e) => console.error('[scan] unhandled error:', e))
      .finally(() => {
        activeScans = Math.max(0, activeScans - 1);
      });

    return res.status(202).json({ scanId: scan.id, status: 'running' });
  } catch (e) {
    if (e instanceof HttpError) return res.status(e.status).json({ error: e.message });
    console.error('[scan/start]', e);
    return res.status(500).json({ error: 'Failed to start scan' });
  }
});

// --- Stop a scan (owner only) ---
app.post('/scan/stop', requireAuth, async (req, res) => {
  const { scanId } = req.body || {};
  if (!scanId) return res.status(400).json({ error: 'scanId is required' });

  const scan = await getScan(scanId, req.user.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });

  await supabase
    .from('scans')
    .update({ status: 'cancelled', completed_at: new Date().toISOString() })
    .eq('id', scanId)
    .eq('user_id', req.user.id);

  return res.json({ status: 'cancelled' });
});

// --- Status (owner only) ---
app.get('/scan/:id/status', requireAuth, async (req, res) => {
  const scan = await getScan(req.params.id, req.user.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  return res.json(scan);
});

// CORS errors -> 403 JSON instead of a stack trace.
app.use((err, _req, res, _next) => {
  if (err && err.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'Origin not allowed' });
  }
  console.error(err);
  return res.status(500).json({ error: 'Internal server error' });
});

app.listen(config.port, async () => {
  console.log(`\n🛡️  OWASP Shield scanner backend listening on http://localhost:${config.port}`);
  console.log(`    Allowed origins: ${config.allowedOrigins.join(', ')}`);
  console.log(`    Max concurrent scans: ${config.maxConcurrentScans} | rate limit: ${config.rateLimitPerHour}/hr`);
  console.log(
    `    Scan access: ${config.allowedEmails.length ? config.allowedEmails.length + ' allowlisted email(s)' : 'any logged-in user'}`
  );

  // Clean up scans orphaned by a previous crash/restart.
  try {
    const swept = await sweepStaleScans(0);
    if (swept) console.log(`    Recovered ${swept} orphaned 'running' scan(s) -> failed`);
  } catch {
    /* ignore */
  }

  if (config.allowPrivateTargets) {
    console.warn(
      '    ⚠️  ALLOW_PRIVATE_TARGETS=true — OK for local lab, but set it to false before hosting publicly!'
    );
  }
  if (!config.allowedEmails.length) {
    console.warn(
      '    ⚠️  No SCAN_ALLOWED_EMAILS set — any registered user can scan. Set an allowlist before hosting.'
    );
  }

  const t = await detectTools();
  const on = Object.entries(t).filter(([, v]) => v).map(([k]) => k);
  console.log(`    Real tools installed: ${on.length ? on.join(', ') : 'none (pure-Node checks only)'}\n`);
});
