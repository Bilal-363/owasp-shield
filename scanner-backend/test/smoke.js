// Standalone smoke test for the scan modules — no Supabase required.
// Usage: node test/smoke.js [https://example.com]
import { validateTarget } from '../src/ssrf.js';
import { scanHeaders } from '../src/scan/headers.js';
import { scanTls } from '../src/scan/tls.js';
import { scanExposed } from '../src/scan/exposed.js';
import { scanDirs } from '../src/scan/direnum.js';
import { scanTech } from '../src/scan/tech.js';
import { scanSubdomains } from '../src/scan/subdomains.js';
import { scanPorts } from '../src/scan/ports.js';

const targetArg = process.argv[2] || 'https://example.com';

const findings = [];
const ctxFactory = (target) => ({
  url: target.url,
  hostname: target.hostname,
  host: target.hostname,
  log: async (m, l = 'info') => console.log(`  [${l}] ${m}`),
  finding: async (f) => {
    findings.push(f);
    console.log(`    ⮑  FINDING [${f.severity}] ${f.title}`);
  },
});

async function main() {
  console.log(`\n=== Validating target: ${targetArg} ===`);
  const target = await validateTarget(targetArg);
  console.log(`Resolved host=${target.hostname} ips=${target.ips.join(', ') || '(n/a)'}`);
  const ctx = ctxFactory(target);

  const steps = [
    ['headers', scanHeaders],
    ['tls', scanTls],
    ['tech', scanTech],
    ['exposed', scanExposed],
    ['dirs', scanDirs],
    ['subdomains', scanSubdomains],
    ['ports', scanPorts],
  ];

  for (const [name, fn] of steps) {
    console.log(`\n=== ${name} ===`);
    try {
      await fn(ctx);
    } catch (e) {
      console.log(`  !! ${name} threw: ${e.message}`);
    }
  }

  console.log(`\n=== DONE: ${findings.length} findings ===`);
  const bySev = findings.reduce((a, f) => ((a[f.severity] = (a[f.severity] || 0) + 1), a), {});
  console.log(bySev);
}

main().catch((e) => {
  console.error('FATAL', e);
  process.exit(1);
});
