#!/usr/bin/env bash
# asynscan recipes — copy/paste starting points for authorised engagements.
# Every command prints its own report path; nothing here scans the internet.
set -euo pipefail

REPORTS="${REPORTS:-./reports}"
mkdir -p "$REPORTS"
# Concurrency is bounded by the descriptor limit; raise it for big sweeps.
ulimit -n 65535 || true

# 1. Fast LAN discovery: 100 most common ports, HTML for the client.
asynscan -t 192.168.1.0/24 --top-ports 100 -c 1000 --timeout 1 -oH "$REPORTS/lan.html"

# 2. Service inventory of a single host: fingerprints + TLS certificates.
asynscan -t example.com -p 21,22,25,80,443,3306,5432,6379,8080,8443 \
  --tls-all --timeout 2 -oA "$REPORTS/example.com"

# 3. Bulk engagement from a scope file, all three formats, rate-limited so the
#    client's IDS does not page anyone.
asynscan -iL examples/targets.txt --top-ports 1000 -c 500 --rate 300 \
  -oA "$REPORTS/scope-day1"

# 4. Stealth profile: shuffled ports, per-probe delay and jitter, no banners.
asynscan -t 10.0.0.0/24 -p 1-1024 -c 25 --delay 0.2 --jitter 0.3 --shuffle --seed 11 \
  --no-banner -q > "$REPORTS/stealth.txt"

# 5. Web hunting on non-standard ports of known hosts.
asynscan -iL examples/targets.txt -p 8000-8100,8080,8443,9000,9090 --aggressive \
  -oH "$REPORTS/web-ports.html"

# 6. Re-scan only the findings of a previous JSON report (pure discovery first).
asynscan -t 10.0.0.5 -p 1-65535 --no-banner --no-tls -oJ "$REPORTS/full.json"

# 7. Container run with reports written to the host.
docker run --rm --ulimit nofile=65535:65535 -v "$PWD/$REPORTS:/work" asynscan:1.0.0 \
  -t 172.17.0.0/24 --top-ports 100 -oA /work/docker-lan
