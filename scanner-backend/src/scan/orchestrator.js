import { config } from '../config.js';
import { addLog, addFinding, setProgress, finalizeScan, isCancelled } from '../db.js';
import { scanPorts } from './ports.js';
import { scanHeaders } from './headers.js';
import { scanTls } from './tls.js';
import { scanExposed } from './exposed.js';
import { scanDirs } from './direnum.js';
import { scanTech } from './tech.js';
import { scanSubdomains } from './subdomains.js';
import {
  detectTools,
  runNmap,
  runNuclei,
  runNikto,
  runGobuster,
  runFfuf,
  runSslscan,
  runSubfinder,
  runWhatweb,
  runWpscan,
  runSqlmap,
  runDalfox,
} from './tools.js';

/**
 * Runs a real scan asynchronously. Pure-Node checks always run; real Kali
 * tools run when installed. Findings/logs stream into Supabase live.
 *
 * @param {{ scanId, userId, target: {url, hostname, ips}, tools: string[], profile?: 'quick'|'deep' }} p
 */
export async function runScan({ scanId, target, tools = [], profile = 'quick' }) {
  const startedAt = Date.now();
  let cancelled = false;

  const log = (message, level = 'info') => addLog(scanId, message, level);
  const finding = (f) => addFinding(scanId, f);
  const ctx = { url: target.url, hostname: target.hostname, host: target.hostname, profile, log, finding };

  const avail = await detectTools();
  const has = (t) => !!avail[t];
  // If the user selected specific tools, honour that; empty selection = run all.
  const wants = (t) => tools.length === 0 || tools.includes(t);

  // --- Always-on pure-Node core (never empty, never faked) ---
  const steps = [
    { name: 'Enumerating subdomains (certificate transparency)', run: () => scanSubdomains(ctx) },
    { name: 'Scanning open TCP ports', run: () => scanPorts(ctx) },
    { name: 'Analysing HTTP security headers', run: () => scanHeaders(ctx) },
    { name: 'Auditing TLS/SSL configuration', run: () => scanTls(ctx) },
    { name: 'Probing for exposed sensitive files', run: () => scanExposed(ctx) },
    { name: 'Discovering content / admin surfaces', run: () => scanDirs(ctx) },
    { name: 'Detecting technologies & outdated libraries', run: () => scanTech(ctx) },
  ];

  // --- Real Kali tools (when installed + selected) ---
  let wpDetected = false;
  if (has('whatweb') && wants('whatweb')) {
    steps.push({
      name: 'Fingerprinting technologies (whatweb)',
      run: async () => {
        const r = await runWhatweb(ctx, avail.whatweb);
        wpDetected = !!r?.isWordpress;
      },
    });
  }
  if (has('subfinder') && wants('subfinder')) steps.push({ name: 'Subdomain enumeration (subfinder)', run: () => runSubfinder(ctx, avail.subfinder) });
  if (has('nmap') && wants('nmap')) steps.push({ name: 'Deep port/service scan (nmap)', run: () => runNmap(ctx, avail.nmap) });
  if (has('sslscan') && wants('testssl')) steps.push({ name: 'TLS cipher audit (sslscan)', run: () => runSslscan(ctx, avail.sslscan) });
  if (has('gobuster') && wants('gobuster')) steps.push({ name: 'Directory brute force (gobuster)', run: () => runGobuster(ctx, avail.gobuster) });
  if (has('ffuf') && wants('ffuf')) steps.push({ name: 'Endpoint fuzzing (ffuf)', run: () => runFfuf(ctx, avail.ffuf) });
  if (has('nikto') && wants('nikto')) steps.push({ name: 'Web server scan (nikto)', run: () => runNikto(ctx, avail.nikto) });
  if (has('nuclei') && wants('nuclei')) steps.push({ name: 'Template-based vuln scan (nuclei)', run: () => runNuclei(ctx, avail.nuclei) });
  // Active injection testers (intrusive — lab / authorized targets only).
  if (has('dalfox') && wants('dalfox')) steps.push({ name: 'Active XSS testing (dalfox)', run: () => runDalfox(ctx, avail.dalfox) });
  if (has('sqlmap') && wants('sqlmap')) steps.push({ name: 'Active SQL-injection testing (sqlmap)', run: () => runSqlmap(ctx, avail.sqlmap) });
  // wpscan runs last, and ONLY when the target is actually WordPress — running
  // it on non-WP sites is pointless and noisy.
  if (has('wpscan')) {
    steps.push({
      name: 'WordPress scan (wpscan)',
      run: async () => {
        if (!wpDetected) {
          await log('wpscan: target is not WordPress — skipping.', 'info');
          return;
        }
        await runWpscan(ctx, avail.wpscan);
      },
    });
  }

  const total = steps.length;

  await log(`Real scan engine started for ${target.url.href} (profile: ${profile})`, 'info');
  const installed = Object.entries(avail).filter(([, v]) => v).map(([k]) => k);
  await log(`Installed tools: ${installed.length ? installed.join(', ') : 'none (pure-Node checks only)'}`, 'info');

  // Honesty: note requested tools we intentionally do NOT run (active
  // exploitation / brute force), instead of faking them.
  const NOT_IMPLEMENTED = ['hydra', 'metasploit', 'zap', 'wapiti', 'xsstrike'];
  const skipped = tools.filter((t) => NOT_IMPLEMENTED.includes(t));
  if (skipped.length) {
    await log(
      `Note: ${skipped.join(', ')} are not run (active exploitation / brute-force tools are intentionally excluded and never faked).`,
      'warning'
    );
  }

  await setProgress(scanId, 0, total);

  try {
    for (let i = 0; i < steps.length; i++) {
      if (Date.now() - startedAt > config.maxScanDurationMs) throw new Error('Scan exceeded maximum allowed duration');
      if (await isCancelled(scanId)) {
        cancelled = true;
        await log('Scan cancelled by user.', 'info');
        break;
      }
      const step = steps[i];
      await log(`[${i + 1}/${total}] ${step.name}...`, 'info');
      try {
        await step.run();
      } catch (e) {
        await log(`Step failed: ${step.name} (${e.message})`, 'error');
      }
      await setProgress(scanId, i + 1, total);
    }

    await finalizeScan(scanId, cancelled ? 'cancelled' : 'completed');
    if (!cancelled) await log('Scan complete.', 'info');
  } catch (e) {
    await log(`Scan failed: ${e.message}`, 'error');
    await finalizeScan(scanId, 'failed', e.message);
  }
}
