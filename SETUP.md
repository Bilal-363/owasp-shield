# OWASP Shield Desk — Full Setup Guide (Windows 11)

This gets the **real** scanner running end-to-end on your PC: the React app +
the Docker scanner backend (with real Kali tools) + Supabase.

There are 3 pieces:

```
[ React frontend ]  →  [ Scanner backend (Docker, real tools) ]  →  [ Supabase (login + data) ]
   npm run dev              docker compose up                          cloud
```

---

## 0. What you need to install (once)

| Software | Why | Link |
|----------|-----|------|
| **Docker Desktop** | runs the scanner backend + all Kali tools | https://www.docker.com/products/docker-desktop/ |
| **Node.js 20 LTS** | runs the React frontend | https://nodejs.org/ (LTS) |
| **Git** (optional) | manage the code | https://git-scm.com/download/win |
| **VS Code** (optional) | edit files | https://code.visualstudio.com/ |

You already have a Supabase project (it's in `.env.local`). You only need its
**service_role** key later.

---

## 1. Install Docker Desktop (most important)

1. Download **Docker Desktop for Windows** and run the installer.
2. When asked, keep **“Use WSL 2 instead of Hyper-V”** checked.
3. Restart your PC if prompted.
4. Launch **Docker Desktop**. Wait until the bottom-left status says
   **“Engine running”** (green).
5. If it complains WSL2 is missing, open **PowerShell as Administrator** and run:
   ```powershell
   wsl --install
   ```
   then reboot and open Docker Desktop again.

**Verify** — open PowerShell and run:
```powershell
docker --version
docker compose version
```
Both should print a version. If “docker is not recognized”, make sure Docker
Desktop is open and finished starting.

---

## 2. Install Node.js

1. Download **Node.js 20 LTS** and install (accept defaults).
2. **Verify** in a *new* PowerShell window:
   ```powershell
   node --version   # should be v20.x or higher
   npm --version
   ```

---

## 3. Get your Supabase service_role key

1. Go to https://supabase.com/dashboard → your project.
2. **Project Settings → API**.
3. Copy the **`service_role`** secret (the long one marked *secret* — NOT the
   `anon` key).
   > ⚠️ Treat this like a password. It goes ONLY in the backend `.env`, never in
   > the frontend or Git.

---

## 4. Apply the database fix (one time)

This adds the `Critical` severity + tightens security. Easiest way (no CLI):

1. Supabase dashboard → **SQL Editor** → **New query**.
2. Open the file
   `supabase/migrations/20260723000000_fix_rls_severity_and_stats.sql`,
   copy everything, paste into the editor, click **Run**.

You should see “Success”. (If you use the Supabase CLI instead: `supabase db push`.)

---

## 5. Start the scanner backend (Docker)

In PowerShell:

```powershell
cd D:\owasp-shield-desk-main\owasp-shield-desk-main\scanner-backend

# create your .env from the template
copy .env.example .env
```

Open `.env` in a text editor and fill in:

```
SUPABASE_URL=https://nruwqevwimdgzgqiybyq.supabase.co
SUPABASE_SERVICE_ROLE_KEY=<paste the service_role secret from step 3>
ALLOWED_ORIGINS=http://localhost:8080,http://localhost:5173
```

Then build & run (first build downloads Kali tools — can take 10-20 min once):

```powershell
docker compose up --build
```

When you see `🛡️  OWASP Shield scanner backend listening on http://localhost:8787`
it’s ready. **Leave this window open** while you use the app.

**Verify** in another PowerShell window:
```powershell
curl http://localhost:8787/health
# → {"ok":true,"service":"owasp-shield-scanner"}
```

---

## 6. Start the frontend

Open a **new** PowerShell window:

```powershell
cd D:\owasp-shield-desk-main\owasp-shield-desk-main

npm install          # first time only
npm run dev
```

Check `.env.local` already contains:
```
VITE_SCANNER_API_URL=http://localhost:8787
```

Open the URL Vite prints (usually **http://localhost:8080**). Create an account
/ log in. Open **Guide** in the sidebar for how-to-use.

---

## 7. Set up a legal target to test (recommended)

Never scan a site you don’t own. Spin up **OWASP Juice Shop** (a deliberately
vulnerable app) in its own container:

```powershell
docker run -d -p 3000:3000 --name juice bkimminich/juice-shop
```

Now scan **http://localhost:3000** from the app.
> Note: to scan a `localhost` target, set `ALLOW_PRIVATE_TARGETS=true` in the
> backend `.env` and restart the backend (`Ctrl+C`, then `docker compose up`).

Stop it later with: `docker rm -f juice`.

---

## 8. Daily use (after first setup)

1. Start **Docker Desktop**.
2. Backend: `cd scanner-backend` → `docker compose up`
3. Frontend: `npm run dev`
4. Open the app → **Scanner** → enter your URL → pick tools → **Quick/Deep** → Start.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Scan fails instantly / “Could not reach the scanner backend” | The Docker backend isn’t running, or `VITE_SCANNER_API_URL` is wrong. Start it and check `curl http://localhost:8787/health`. |
| `401 / Not authenticated` | You’re not logged in, or the session expired — log in again. |
| `docker: command not found` | Docker Desktop isn’t open/finished starting. |
| First `docker compose up --build` is very slow | Normal — it installs all the Kali tools once. Later runs are fast. |
| Scan of `localhost:3000` is blocked | Set `ALLOW_PRIVATE_TARGETS=true` in backend `.env`, restart backend. |
| Deep scan “hangs” for minutes | Expected — real tools (nuclei/sqlmap) are thorough. Watch the live log on Results. |
| CORS error in browser console | Add your frontend origin to `ALLOWED_ORIGINS` in backend `.env`, restart. |

---

## Later: hosting on a domain

Frontend stays on **Vercel**. The backend needs a Docker host (Fly.io / Railway /
Render / a VPS) — **not** Vercel/Supabase (they can’t run these tools). Then set
`VITE_SCANNER_API_URL` in Vercel to your backend’s HTTPS URL. Details are in
`scanner-backend/README.md`.
