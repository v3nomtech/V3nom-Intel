#!/usr/bin/env bash
# update-data.sh — refresh local JSON snapshots used by VENOM/INTEL.
# Served same-origin to bypass CORS on the upstream feeds (CISA, abuse.ch, etc).
#
# This script does NOT self-schedule. Netlify only executes scripts at
# build time or inside serverless functions on request, so nothing here
# runs on a timer just by living in the repo. It's invoked by:
#
#   • .github/workflows/refresh-data.yml  — GitHub Actions cron (every 6h)
#     commits refreshed data/*.json back to the repo, which triggers a
#     Netlify redeploy via the git push webhook.
#   • Local dev — run manually:  ./update-data.sh
#
# Signed: CYbErXV3nOm

set -u
cd "$(dirname "$0")"
mkdir -p data
ok=0; fail=0

fetch() {
  local label="$1" url="$2" out="$3"
  printf "  %-12s " "$label"
  # Slow upstreams (URLhaus ~40KB/s) need a generous wall time. curl may exit
  # non-zero on timeout while still leaving partial bytes in $out.tmp — we run
  # the salvage path against whatever landed regardless of curl's exit code.
  curl -sL --http1.1 --max-time 300 "$url" -o "$out.tmp" || true

  if [ -s "$out.tmp" ] && python3 -c "import json; json.load(open('$out.tmp'))" 2>/dev/null; then
    mv "$out.tmp" "$out"
    echo "✓ $(wc -c < "$out") bytes"
    ok=$((ok+1)); return 0
  fi

  # Try salvaging URLhaus-style truncated JSON: keep all balanced "id":[...] batches.
  if [ -s "$out.tmp" ]; then
    python3 <<PY 2>/dev/null
import json
raw = open('$out.tmp', errors='ignore').read()
text = raw[raw.find('{')+1:]
parts = text.split('],')
keep = []
for p in parts[:-1]:
    try:
        json.loads('{' + p.strip() + ']}')
        keep.append(p.strip())
    except: pass
if keep:
    final = '{' + '],'.join(keep) + ']}'
    json.loads(final)
    open('$out', 'w').write(final)
    print(f'  (salvaged {len(keep)} batches)')
PY
    if [ -s "$out" ] && python3 -c "import json; json.load(open('$out'))" 2>/dev/null; then
      rm -f "$out.tmp"
      echo "✓ salvaged $(wc -c < "$out") bytes"
      ok=$((ok+1)); return 0
    fi
  fi

  rm -f "$out.tmp"
  echo "✗ failed"
  fail=$((fail+1)); return 1
}

echo "▸ Refreshing local threat-intel snapshots..."
fetch "KEV"        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"  data/kev.json
fetch "Feodo"      "https://feodotracker.abuse.ch/downloads/ipblocklist.json"                            data/feodo.json
fetch "ThreatFox"  "https://threatfox.abuse.ch/export/json/recent/"                                      data/threatfox.json
fetch "URLhaus"    "https://urlhaus.abuse.ch/downloads/json_online/"                                     data/urlhaus.json
fetch "Breaches"   "https://api.xposedornot.com/v1/breaches"                                              data/breaches.json
echo
echo "▸ Done. $ok ok / $fail failed."
ls -lh data/
