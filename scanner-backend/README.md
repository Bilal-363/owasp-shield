# OWASP Shield Desk — Real Scanner Backend

The **real** scanning engine. The old Supabase Edge Function faked every finding
(it never contacted the target). This standalone Node server performs genuine
checks — and, in Docker, runs the **actual Kali tools** (nmap, nuclei, nikto,
gobuster, ffuf, sslscan, wpscan, subfinder, whatweb) — streaming real results
and live tool output into Supabase so the React frontend shows them in real time.

> ⚠️ **Legal / ethical use only.** Only scan systems you **own** or have
> **written permission** to test. Unauthorised scanning is illegal in most
> countries. For practice, use the bundled OWASP **Juice Shop**, **DVWA**, or
> **Metasploitable** — never a site you don't control.

---

## What actually runs (all real, nothing faked)

**Always on (pure Node — works even without Docker):**
port scan · HTTP security headers · TLS/SSL (with legacy-protocol probe) ·
exposed files (`.git`, `.env`, backups) · content discovery · outdated JS libs ·
subdomains via crt.sh.

**Real Kali tools (auto-used when installed — i.e. in the Docker image):**

| Tool | What it does |
|------|--------------|
| `nmap` | service/version port scan |
| `nuclei` | template-based CVE/misconfig scanning |
| `nikto` | web-server vulnerability scan |
| `gobuster` / `ffuf` | directory & endpoint discovery (real wordlists) |
| `sslscan` | TLS cipher/protocol audit |
| `whatweb` | technology fingerprinting |
| `subfinder` | active subdomain enumeration |
| `wpscan` | WordPress core/plugin vulns (auto-runs if WordPress detected) |
| `sqlmap` | **active SQL-injection testing** (A03) — lab/authorized only |
| `dalfox` | **active XSS testing** (A03) — lab/authorized only |

Each tool's live output streams into the scan log. Findings that can't be
verified are **not reported** — no fabrication.

> **⚠️ sqlmap & dalfox are active attacks.** sqlmap will attempt to dump data
> through an injectable parameter; dalfox fires real XSS payloads. Run them ONLY
> against targets you own (Juice Shop / DVWA). They run when selected, or when no
> specific tools are chosen (= "run everything").
>
> Still not included: `hydra` (brute-force), `metasploit`, ZAP. Ask if you want
> them for an isolated lab.

### OWASP Top 10 coverage

| OWASP | Covered by |
|---|---|
| A01 Broken Access Control | gobuster, ffuf, dir-scan, nuclei |
| A02 Cryptographic Failures | TLS module, sslscan |
| A03 Injection (SQLi/XSS/LFI) | **sqlmap, dalfox**, nuclei, nikto |
| A05 Security Misconfiguration | headers, exposed-files, nikto, whatweb, nmap, nuclei |
| A06 Vulnerable/Outdated Components | retire.js, wpscan, nuclei CVEs, nmap `-sV` |
| A07 Auth Failures | nuclei (default-login), dir-scan |
| A08 Integrity Failures | nuclei, exposed `.git` |
| A10 SSRF | nuclei |

(A04 Insecure Design and A09 Logging Failures aren't remotely auto-testable.)

---

## Recommended: run with Docker (all tools, one command)

Requires **Docker Desktop** (enable WSL2 on Windows).

```bash
cd scanner-backend
cp .env.example .env      # PowerShell: copy .env.example .env
#   → set SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, ALLOWED_ORIGINS
docker compose up --build
```

First build takes a while (it installs the tools + nuclei templates). After
that it starts fast. The API is on `http://localhost:8787`.

`.env` values:
- `SUPABASE_URL` — same as the frontend (`https://<ref>.supabase.co`)
- `SUPABASE_SERVICE_ROLE_KEY` — Supabase → Settings → API → **service_role**
  secret (⚠️ server-side only; never in the frontend or git)
- `ALLOWED_ORIGINS` — e.g. `http://localhost:8080,https://your-app.vercel.app`

### Spin up a legal practice target

Uncomment the `juice` service in `docker-compose.yml`, then scan
`http://juice:3000` (from the container) or `http://localhost:3000` (from your
host). Juice Shop is deliberately vulnerable — perfect for a demo.

---

## Alternative: run without Docker (pure-Node checks only)

No Kali tools, but the built-in checks are still real:

```bash
cd scanner-backend
npm install
cp .env.example .env      # fill in Supabase values
npm start                 # http://localhost:8787
node test/smoke.js https://example.com   # quick self-test, no Supabase needed
```

(To get the Kali tools this way you'd install them yourself in WSL2 Kali and run
`npm start` there — Docker is far easier and is what the frontend/hosting assume.)

---

## Point the frontend at it

Frontend `.env.local` (already added):

```
VITE_SCANNER_API_URL=http://localhost:8787
```

Restart Vite. Start a scan → backend runs it → findings + live tool logs appear
via Supabase realtime.

**Scan profiles:** the frontend sends `quick` (default, faster) or `deep` (more
templates, more ports, longer). Real deep scans take **minutes** — that's the
tools being thorough, not a bug. Output streams live so you always see progress.

---

## Apply the database fix

`supabase/migrations/20260723000000_fix_rls_severity_and_stats.sql` tightens RLS
(clients can no longer forge results), adds `Critical` severity + the
`critical_findings` column.

```bash
supabase db push           # or paste the SQL into the Supabase SQL editor
```

---

## Hosting (when you buy a domain)

Frontend stays on **Vercel**. This backend needs a host that allows Docker +
long-running processes + outbound TCP (Vercel/Supabase **cannot** port-scan):

- **Fly.io / Railway / Render** — deploy this Docker image directly.
- Any small **VPS** with Docker.

Then:
1. Set the backend env vars on the host; put your Vercel URL in `ALLOWED_ORIGINS`.
2. In **Vercel → Settings → Environment Variables** set
   `VITE_SCANNER_API_URL=https://your-backend-host` and redeploy.
3. Serve the backend over **HTTPS** (these hosts give free TLS) or the browser
   blocks your HTTPS site from calling an HTTP backend (mixed content).

⚠️ A public server full of scanning tools is an attack platform — keep auth, the
SSRF guard, and rate limits **on**, and consider restricting who can register.

---

## Security model

- **Auth**: every endpoint requires a valid Supabase user JWT (verified here).
  The service-role key never leaves this server.
- **SSRF guard**: refuses private/loopback/link-local/metadata/IPv6-ULA targets
  (A + AAAA resolved and checked). `ALLOW_PRIVATE_TARGETS=true` only for local
  lab testing (e.g. the Juice Shop container).
- **Rate limit**: `RATE_LIMIT_PER_HOUR` (default 5) per user.
- **Timeout**: `MAX_SCAN_DURATION_MS` (default 10 min).
- **Writes** happen only here (service role); clients can only **read** via RLS,
  so results can't be forged.
