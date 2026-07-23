# Docker Guide — OWASP Shield Scanner Backend

Docker is how you install and run **all the real Kali security tools** (nmap,
nuclei, sqlmap, dalfox, nikto, gobuster, ffuf, sslscan, whatweb, subfinder,
wpscan) with a single command. Without Docker the backend still runs, but only
the built-in Node checks work — the Kali tools need this container.

---

## 1. Install Docker (Windows 11)

Docker needs **CPU virtualization** + **WSL2**.

### a. Check virtualization
```powershell
(Get-CimInstance Win32_Processor).VirtualizationFirmwareEnabled
```
- `True` → go to step **c**.
- `False` → do step **b** first.

### b. Enable virtualization in BIOS (only if it was False)
1. Restart, press the BIOS key during boot (Dell `F2`, HP `F10`/`Esc`, Lenovo `F1`, ASUS/MSI/Gigabyte `Del`, Acer `F2`).
2. Enable **Intel Virtualization Technology / VT-x** (Intel) or **SVM Mode / AMD-V** (AMD).
3. **Save & Exit** (`F10`), boot back to Windows.

### c. Enable WSL2 (PowerShell as Administrator)
```powershell
wsl --install
wsl --update
```
Reboot.

### d. Install Docker Desktop
Download from https://www.docker.com/products/docker-desktop/, install (keep
"Use WSL 2 based engine" checked), open it, wait for **"Engine running"**.

### e. Verify
```powershell
docker --version
docker run --rm hello-world
```
"Hello from Docker!" = success.

---

## 2. Run the scanner

All commands run from the backend folder:
```powershell
cd D:\owasp-shield-desk-main\owasp-shield-desk-main\scanner-backend
```

Make sure `.env` exists (copy from `.env.example` and fill in `SUPABASE_URL` +
`SUPABASE_SERVICE_ROLE_KEY`).

### Build + start (first time, or after code changes)
```powershell
docker compose up --build
```
First build takes 10–20 min (downloads Kali + tools). When ready you'll see:
```
🛡️  OWASP Shield scanner backend listening on http://localhost:8787
    Real tools installed: nmap, nuclei, nikto, gobuster, ffuf, sslscan, whatweb, subfinder, wpscan, sqlmap, dalfox
```

---

## 3. Everyday commands

| Task | Command |
|------|---------|
| Start (foreground, see logs) | `docker compose up` |
| Start in background | `docker compose up -d` |
| **Rebuild after changing code** | `docker compose up --build` |
| Stop (foreground) | `Ctrl + C` |
| Stop (background) | `docker compose down` |
| View live logs (background mode) | `docker compose logs -f` |
| See running containers | `docker ps` |
| Restart | `docker compose restart` |
| Full clean rebuild (no cache) | `docker compose build --no-cache` then `docker compose up` |
| Free up disk (old images) | `docker system prune` |

> ⚠️ **After editing any backend code or the Dockerfile, you MUST use
> `--build`** — a plain `docker compose up` reuses the old image and your changes
> won't take effect.

---

## 4. Scanning targets

- **Public sites** (your own domain, `https://scanme.nmap.org`): scan normally.
- **Something on your own PC** (e.g. Juice Shop at `localhost:3000`): the tools
  run *inside* the container, so `localhost` = the container, not your PC. Use
  **`http://host.docker.internal:3000`** instead.
- To also run a practice target in Docker, uncomment the `juice` service in
  `docker-compose.yml`.

⚠️ Only scan systems you own or are authorized to test.

---

## 5. Troubleshooting

| Problem | Fix |
|---------|-----|
| `cannot connect to the Docker daemon` | Docker Desktop isn't running — open it, wait for green "Engine running". |
| `Virtualization support not detected` | Enable VT-x/SVM in BIOS (step 1b) + `wsl --install`. |
| Build fails on an `apt`/download line | Usually a temporary network hiccup — re-run `docker compose up --build`. |
| Changes not taking effect | You forgot `--build`. Run `docker compose down` then `docker compose up --build`. |
| Port 8787 already in use | Stop the plain-Node backend (`Ctrl+C`), or change `PORT` in `.env`. |
| `no configuration file provided` | You're in the wrong folder — `cd` into `scanner-backend` first. |
