# ============================================================================
# OWASP Shield Desk — REAL scanner image (Kali base with real tools baked in)
# One `docker build` installs every tool; identical to running them on Kali.
# ============================================================================
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Core recon + vuln tools (the "Recommended" set) + Node.js + wordlists.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git tar unzip \
      nodejs npm \
      nmap nikto gobuster ffuf sslscan whatweb wpscan \
      nuclei subfinder \
      sqlmap \
      wordlists dirb dnsutils \
    && rm -rf /var/lib/apt/lists/*

# dalfox (XSS tester) isn't in the Kali apt repo — build it with Go, then
# remove Go so the image stays small. Non-fatal if it fails.
RUN apt-get update && apt-get install -y --no-install-recommends golang-go \
    && GOBIN=/usr/local/bin go install github.com/hahwul/dalfox/v2@latest \
    && apt-get purge -y golang-go && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* /root/go /root/.cache \
    && dalfox version \
    || echo "dalfox install skipped (scanner will run without it)"

# retire.js (npm) for outdated JS lib detection.
RUN npm install -g retire || true

# Pre-download nuclei templates so the first scan is fast. (No -duc here — that
# flag disables the update, which is what left the templates empty before.)
RUN nuclei -update-templates || nuclei -ut || true

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY src ./src
# Bundled wordlist — deterministic, no dependency on Kali package paths.
COPY wordlists ./wordlists

ENV PORT=8787
ENV DIR_WORDLIST=/app/wordlists/common.txt
EXPOSE 8787
CMD ["node", "src/index.js"]
