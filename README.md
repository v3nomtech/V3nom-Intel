# VENOM/INTEL

> Open-source threat intelligence console. A single-page, zero-auth, dark-mode dashboard that pulls live CVE, KEV, EPSS, IOC, C2, breach, and news data from public APIs and renders it in one clean view.

**Signature:** `CYbErXV3nOm`

---

## Table of contents

- [What it is](#what-it-is)
- [Feature tour](#feature-tour)
- [Live data sources](#live-data-sources)
- [Architecture](#architecture)
- [How it works — request flow](#how-it-works--request-flow)
- [File map (what every file does)](#file-map-what-every-file-does)
- [Local preview](#local-preview)
- [Refreshing local snapshots](#refreshing-local-snapshots)
- [Deploy to Netlify](#deploy-to-netlify)
- [How CORS is handled](#how-cors-is-handled)
- [Caching strategy](#caching-strategy)
- [Customization](#customization)
- [Privacy & legal](#privacy--legal)
- [Tech stack](#tech-stack)

---

## What it is

VENOM/INTEL is a **static threat-intelligence dashboard**. There is no backend database, no user account, no tracking. The page loads in a browser, calls a handful of public APIs and RSS feeds, normalizes the responses, and renders:

- the latest CVEs with EPSS exploit-probability scores
- the CISA Known Exploited Vulnerabilities (KEV) catalog
- a derived **Active Exploitation Tracker** that ranks "patch this first" using KEV ∩ EPSS ∩ ransomware usage
- an animated **Global Threat Map** plotting live C2 servers on a Leaflet map
- recent malware IOCs, malicious URLs, active botnet C2 IPs
- recent public data breaches
- aggregated infosec news + exploit publication feeds
- an **IOC reputation lookup** (paste an IP, domain, URL, hash, or CVE-ID)
- a curated OSINT directory (researchers and orgs worth following)
- live charts: severity distribution, KEV-over-time, top vendors, malware families, C2 by country, EPSS top 15

Everything updates automatically every 15 minutes (also on-demand via the per-section Refresh button or the top-bar **Refresh all**).

---

## Feature tour

| Section | What it shows | How it's built |
|---|---|---|
| **Hero / stats strip** | 8 live counters: CVEs (7d), KEV total, Critical (7d), KEV (30d), C2 countries, active IOCs, active C2, news (24h) | `updateStats()` + `countUp()` ease-out animation |
| **🎯 Active Exploitation Tracker** | Ranks every KEV CVE by a priority score: ransomware = +100, overdue = +60, freshness ≤ 30d = +40, EPSS ≥ 0.5 = +30. Chips filter by ransomware / overdue / fresh / high-EPSS | `buildExploitList()` joins KEV + EPSS, sorts by score |
| **🌐 Global Threat Map** | Leaflet dark-tile map (CARTO). Plots Feodo Tracker C2 IPs by country centroid. Pulsing markers (low/mid/high tiers), live attack feed (animated curved arcs), popup with top malware per country | `renderThreatMap()` + `COUNTRY_CENTROIDS` lookup table + `curvedPath()` bezier helper |
| **Quick tools — IOC lookup** | Paste IPv4/v6, domain, URL, MD5/SHA1/SHA256, or CVE-ID. Auto-detects type, cross-references the in-memory threat feeds, calls CIRCL for CVEs, calls URLhaus host API for domains/IPs | `IOC.detect()` + `IOC.lookup()` |
| **Threat metrics charts** | CVE severity doughnut, KEV-by-month bars (12mo), top vendors, top malware families (ThreatFox), C2 by country | Chart.js 4 |
| **CISA KEV** | Sortable table of all KEV vulnerabilities; filter box | `fetchKEV()` → local snapshot → live → proxy chain |
| **Latest CVEs (NVD)** | Card grid of last 7 days of NVD CVEs with EPSS badges and product chips. Filter by severity and product/vendor | `fetchCVEs()` + `enrichEPSS()` |
| **ThreatFox IOCs** | Recent malware IOCs from abuse.ch | `fetchThreatFox()` |
| **URLhaus URLs** | Recent malicious URLs (phishing, payload delivery, C2 panels) with cross-check links to VirusTotal & MalwareBazaar | `fetchURLhaus()` |
| **Feodo Tracker C2** | Table of active botnet C2 IPs (IP:port, malware family, country, ASN, first-seen, status) | `fetchFeodo()` |
| **Recent data breaches** | XposedOrNot breach feed: name, records, industry, date | `fetchBreaches()` |
| **Infosec news wire** | Aggregated RSS from Krebs, Bleeping, The Hacker News, SANS ISC, Dark Reading, The Register, Schneier | `fetchRssSet()` + `parseRss()` |
| **Exploit feeds** | Exploit-DB, PacketStorm, GitHub Security Advisories | Same RSS pipeline |
| **OSINT directory** | Curated cards for CISA, CERT-In, vx-underground, MalwareHunterTeam, Krebs, Beaumont, MSTIC, Google TAG, etc., with X / blog / Nitter links | `renderOsint()` over `CONFIG.OSINT_ACCOUNTS` |
| **Top-bar global search** | Searches across CVE, KEV, news, and exploits in one box | `globalSearch()` |
| **JSON export** | ⬇ JSON button dumps the entire in-memory `STATE` snapshot to a download | `exportAll()` |
| **Star / favorite** | ★ on a CVE card persists to `localStorage` | `getStars()` / `toggleStar()` |
| **Status pills + diagnostics panel** | Every section has a pill (loading / ok / cached / error). Click **Show diagnostics** for a per-feed timeline | `setStatus()` + `renderDiagnostic()` |

---

## Live data sources

All sources are public, no API keys required.

| Source | What it provides | Endpoint |
|---|---|---|
| **NIST NVD** | Latest CVEs (7-day window) | `services.nvd.nist.gov/rest/json/cves/2.0` |
| **CISA KEV** | Known Exploited Vulnerabilities catalog | `cisa.gov/.../known_exploited_vulnerabilities.json` |
| **FIRST EPSS** | Exploit Prediction Scoring System — probability a CVE will be exploited in the next 30 days | `api.first.org/data/v1/epss` |
| **CIRCL CVE-Search** | CVE detail lookup (CORS-friendly) | `cve.circl.lu/api/cve/...` |
| **URLhaus (abuse.ch)** | Malicious URLs | `urlhaus.abuse.ch/downloads/json_online/` |
| **ThreatFox (abuse.ch)** | Recent malware IOCs | `threatfox.abuse.ch/export/json/recent/` |
| **Feodo Tracker (abuse.ch)** | Active botnet C2 IPs (Emotet, Dridex, TrickBot, QakBot, etc.) | `feodotracker.abuse.ch/downloads/ipblocklist.json` |
| **XposedOrNot** | Data breach catalog | `api.xposedornot.com/v1/breaches` |
| **RSS feeds** | News & exploit publications | Krebs, Bleeping, THN, SANS, Dark Reading, Register, Schneier, Exploit-DB, PacketStorm, GitHub Advisories |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          BROWSER (index.html)                       │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  js/app.js   (IIFE — single ~1670-line module)              │    │
│  │                                                             │    │
│  │   CONFIG  ─── URLs, RSS list, OSINT accounts, TTLs          │    │
│  │   STATE   ─── { cves, kev, news, exploits, urlhaus,         │    │
│  │                 threatfox, feodo, breach, exploitItems }    │    │
│  │                                                             │    │
│  │   fetch layer:   timedFetch  →  proxyFetch  →  cache        │    │
│  │   render layer:  renderXxx()  +  Chart.js  +  Leaflet       │    │
│  │   orchestration: refreshAll() → critical path + onIdle()    │    │
│  └─────────────────────────────────────────────────────────────┘    │
└────────────┬────────────────────────────────────────────────────────┘
             │
   ┌─────────┼────────────────────────────────────────────┐
   ▼         ▼                                            ▼
[CORS-OK]   [Same-origin snapshots]                  [Proxy chain]
NVD, EPSS,  /data/kev.json                           1. /.netlify/functions/proxy   (whitelisted hosts)
CIRCL       /data/feodo.json                         2. api.allorigins.win/raw
            /data/urlhaus.json                       3. corsproxy.io
            /data/threatfox.json                     4. api.codetabs.com/v1/proxy
            /data/breaches.json
            (refreshed by update-data.sh)
```

The site is intentionally **dependency-free at runtime** except for three CDN-hosted libraries pulled with SRI hashes:

- **Chart.js 4.4.1** — all charts
- **Leaflet 1.9.4** — global threat map
- **Google Fonts** (Inter + JetBrains Mono) — typography

There is no npm install step, no bundler, no framework. `js/app.js` is one self-contained IIFE.

---

## How it works — request flow

When the page loads, `init()` runs:

1. Sets the year + a random build ID.
2. Wires the IntersectionObserver-based scroll reveal animation.
3. Starts the UTC clock.
4. Renders the OSINT cards (synchronous, from `CONFIG.OSINT_ACCOUNTS`).
5. Wires events (filters, search, refresh buttons, IOC lookup, star toggles).
6. Calls `refreshAll()`.
7. Schedules `refreshAll()` to re-run every 15 minutes.

`refreshAll()` is the orchestrator:

```js
// 1. Hydrate from localStorage cache (instant first paint)
['cves','kev','news','exploits','urlhaus','threatfox','feodo','breach']
  .forEach(k => { const c = cache.get(k); if (c) STATE[k] = c; });

// 2. Re-render everything we have cached
// 3. Critical path (above-the-fold): KEV + Feodo + CVE in parallel
const critical = Promise.all([refreshKEV(), refreshFeodo(), refreshCVE()]);

// 4. Below-the-fold deferred to requestIdleCallback
onIdle(() => {
  refreshNews(); refreshExploits();
  refreshURLhaus(); refreshThreatFox(); refreshBreaches();
});
```

Each `fetchXxx()` follows a 3-tier fallback (`tryLocalThenRemote()`):

1. **Local snapshot** (`data/*.json`) — same-origin, no CORS issues, always works.
2. **Direct remote** — works for CORS-friendly endpoints (NVD, EPSS, CIRCL).
3. **Proxy chain** (`proxyFetch`) — tries the Netlify function first, then three public CORS proxies in sequence.

Every fetch is wrapped in `timedFetch()` with a 20-second AbortController timeout, and every successful response is written to `localStorage` with a 30-minute TTL. The diagnostics panel (`Show diagnostics` button in Quick tools) shows the per-feed status pill, source ("live" / "local snapshot" / "live (proxied)" / "cached"), and time since last update.

### Active Exploitation Tracker scoring

`buildExploitList()` combines the KEV catalog with EPSS scores from the CVE feed and computes a priority score for each vulnerability:

```
score = 0
if knownRansomwareCampaignUse === "Known"  →  score += 100
if dueDate is past                          →  score += 60
if dateAdded within last 30 days            →  score += 40
if EPSS >= 0.5                              →  score += 30 + round(epss * 30)
score += max(0, 30 - ageDays)               // freshness boost
```

Cards are sorted descending and tagged with the chips that triggered (🦠 Ransomware, ⏰ Overdue, 🆕 fresh, 📈 EPSS%). The four summary cards at the top count items in each bucket.

### Global Threat Map

Built on Leaflet with the CARTO dark-no-labels tile set. The `COUNTRY_CENTROIDS` table maps ISO-2 country codes to `[lat, lon]` centroids. For each country with active C2s:

- A pulsing `divIcon` is layered for visual heartbeat (CSS animation, sized by `sqrt(count)`).
- A clickable `circleMarker` shows the count, top malware families, and ASN samples in its popup.
- The "Live attack feed" sidebar animates curved bezier arcs (`curvedPath()`) from a random origin to a C2 endpoint, prepending each event to the feed.

### IOC reputation lookup

`IOC.detect()` is a regex switchboard that classifies the input:

```
^[a-f0-9]{32}$              → md5
^[a-f0-9]{40}$              → sha1
^[a-f0-9]{64}$              → sha256
^\d{1,3}(\.\d{1,3}){3}$     → ipv4
^[a-fA-F0-9:]+$ with ":"    → ipv6
^https?://                  → url
^[\w.-]+\.[a-z]{2,}$        → domain
^CVE-\d{4}-\d{4,}$          → cve
```

Then `IOC.lookup()`:

- For CVEs: hits CIRCL CVE-Search directly (CORS-friendly).
- For everything else: cross-references the already-loaded URLhaus / ThreatFox / Feodo arrays in memory (zero-cost local matches), then issues a live POST to the URLhaus host endpoint via the Netlify proxy.
- Renders a verdict card plus quick cross-check links to AbuseIPDB, VirusTotal, Shodan, OTX, urlscan.io, MalwareBazaar, etc.

---

## File map (what every file does)

```
threat-intel-site/
├── index.html                    # Single-page HTML shell
├── css/
│   └── style.css                 # ~1500 lines of dark-mode UI (CSS vars, no framework)
├── js/
│   └── app.js                    # ~1670 lines — all logic, all rendering
├── data/                         # Same-origin JSON snapshots (CORS bypass)
│   ├── kev.json                  # CISA KEV catalog              (~1.5 MB)
│   ├── feodo.json                # Feodo Tracker C2 list         (~2 KB)
│   ├── threatfox.json            # Recent ThreatFox IOCs         (~2 MB)
│   ├── urlhaus.json              # Recent URLhaus URLs           (~70 KB)
│   └── breaches.json             # XposedOrNot breach catalog    (~575 KB)
├── netlify/
│   └── functions/
│       └── proxy.js              # Whitelisted CORS proxy (Netlify function)
├── netlify.toml                  # Netlify build + headers + cache rules
├── _redirects                    # SPA fallback (/* → /index.html 200)
├── update-data.sh                # Cron-able script to refresh data/*.json
└── README.md                     # You are here
```

### `index.html`

The HTML shell. ~420 lines. Defines every section and every empty container that `js/app.js` later fills:

- `<header>` topbar — brand, global search input, anchor nav, UTC clock, **Refresh all**, **⬇ JSON** buttons.
- `<section class="hero">` — title, tag pills, CTA buttons, 8-stat strip.
- `<section id="exploitation">` — Active Exploitation Tracker with summary cards, filter chips, grid, and 3 charts.
- `<section id="map">` — Leaflet container, top-attack-origins sidebar, live attack feed.
- `<section id="tools">` — IOC lookup form, diagnostics panel.
- `<section id="charts">` — 5 chart canvases.
- `<section id="kev">` — KEV table.
- `<section id="cve">` — CVE card grid + severity/product filters.
- `<section id="iocs">` — ThreatFox grid.
- `<section id="urlhaus">` — URLhaus grid.
- `<section id="c2">` — Feodo Tracker table.
- `<section id="breach">` — breach grid.
- `<section id="news">` — news grid.
- `<section id="exploits">` — exploit feeds grid.
- `<section id="osint">` — OSINT directory grid (populated from `CONFIG.OSINT_ACCOUNTS`).
- `<section id="about">` — attribution lists for every data source.
- `<footer>` — three-column footer with watermark.

CDN dependencies are loaded with SRI integrity hashes and the `defer` attribute.

### `css/style.css`

Single-file dark theme (~45 KB). Uses CSS custom properties for the palette:

```css
--bg: #0b0d10;  --panel: #12161c;  --border: #232a33;
--text: #e6edf3;  --text-dim: #9da7b3;
--accent: #3fb950;     /* green */
--accent-2: #58a6ff;   /* blue */
--critical: #f85149;  --high: #fb8500;  --medium: #d4a72c;  --low: #58a6ff;
--font-sans: 'Inter';  --font-mono: 'JetBrains Mono';
```

Includes section-reveal animations, status-pill styling, severity color coding, Chart.js dark theme overrides, Leaflet popup overrides, pulsing C2 markers, stagger-in card entrance, hero gradient, and responsive breakpoints.

### `js/app.js`

The brain. Organized into labeled sections:

| Section | Responsibility |
|---|---|
| `CONFIG` | All URLs, RSS feeds list, OSINT accounts, refresh interval, cache TTL, fetch timeout |
| `timedFetch` / `proxyFetch` | Fetch with AbortController timeout; proxy chain with HTML-error detection |
| `cache` | localStorage stale-while-revalidate, 30-min TTL, namespaced `vni:*` |
| `parseRss` | DOMParser-based RSS 2.0 + Atom parser |
| `STATUS` / `setStatus` / `renderDiagnostic` | Per-feed live status pills + diagnostics panel |
| `startClock` | UTC clock, pauses on hidden tab |
| NVD CVE | `fetchCVEs`, `extractProducts` (CPE 2.3 parsing), `enrichEPSS`, `renderCVEs` |
| CISA KEV | `tryLocalThenRemote`, `fetchKEV`, `renderKEV` |
| RSS aggregator | `fetchRssSet`, `renderNews`, `renderExploits` |
| Abuse.ch | `fetchURLhaus`, `fetchThreatFox`, `fetchFeodo` + renderers |
| Breaches | `fetchBreaches`, `renderBreaches` |
| IOC lookup | `IOC.detect`, `IOC.lookup`, `renderIocResult` |
| OSINT | `renderOsint` |
| Stars | `getStars`, `isStarred`, `toggleStar` (localStorage favorites) |
| Charts | `drawSeverity`, `drawKevTime`, `drawVendor`, `drawMalwareFamilies`, `drawC2Geo`, `drawExploitTimeline`, `drawExploitProducts`, `drawEpssTop` |
| Active Exploitation | `buildExploitList`, `renderExploitSummary`, `renderExploitList` |
| Threat map | `ensureMap`, `renderThreatMap`, `renderTopCountries`, attack feed animation, `curvedPath` bezier helper, `COUNTRY_CENTROIDS` lookup |
| `countUp` | Animated number transition (cubic ease-out, 700ms) |
| `initRevealObserver` | IntersectionObserver scroll reveal |
| `updateStats` | Hero strip counters |
| `globalSearch` | Cross-feed search across CVE/KEV/news/exploits |
| `exportAll` | Blob download of the in-memory `STATE` |
| `STATE` + orchestration | `refreshCVE`, `refreshKEV`, `refreshNews`, `refreshExploits`, `refreshURLhaus`, `refreshThreatFox`, `refreshFeodo`, `refreshBreaches`, `refreshAll` |
| `wireEvents` | All listeners (filter inputs, refresh buttons, IOC form, diagnostics toggle) |
| `init` | Entry point |

### `data/*.json`

Same-origin bundled snapshots of the abuse.ch + CISA + XposedOrNot feeds. Why? Because:

- These hosts don't all serve CORS headers.
- The Netlify function and public proxies are best-effort — abuse.ch frequently rate-limits or blocks them.
- Loading from `/data/` is fast (Cloudflare CDN-cached via `netlify.toml`) and never fails for CORS reasons.

These files are refreshed by `update-data.sh` — run it manually, on a cron, or as part of your Netlify build (`command = "./update-data.sh"`).

### `netlify/functions/proxy.js`

Serverless function that fetches arbitrary URLs from a **hostname allowlist** and returns the body with `Access-Control-Allow-Origin: *`. Supports both GET and POST (so the IOC lookup can POST to URLhaus's host API). The allowlist covers: `cisa.gov`, `cert-in.org.in`, `nvd.nist.gov`, `cve.circl.lu`, all `*.abuse.ch` (URLhaus / ThreatFox / Feodo / Bazaar), `otx.alienvault.com`, `api.first.org`, `api.xposedornot.com`, `haveibeenpwned.com`, and every RSS host (Krebs, Bleeping, FeedBurner, SANS, Dark Reading, Register, Schneier, Threatpost, Exploit-DB, PacketStorm, GitHub).

Identifies itself as `User-Agent: VENOM-INTEL/1.0` to upstream.

### `netlify.toml`

- `publish = "."` — serve from repo root
- `functions = "netlify/functions"` — discover the proxy
- Security headers on every route: `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: geolocation=(), microphone=(), camera=()`
- Cache rules: `css/*` and `js/*` → 1 day + 7-day SWR; `data/*.json` → 15 min + 1-hour SWR; functions → 5 min + always allow CORS
- `node_bundler = "esbuild"` for the function

### `_redirects`

```
/*    /index.html   200
```

SPA-style fallback so anchor links like `/#kev` always resolve.

### `update-data.sh`

Cron-friendly bash script that:

1. Curls each remote feed with `--max-time 90 --http1.1`.
2. Validates JSON with `python3 -c "import json; json.load(...)"` before swapping the file in (atomic via `.tmp` rename).
3. If validation fails — common with URLhaus's mid-stream truncation — runs a **salvage pass** that splits on `],`, attempts to parse each batch, and rebuilds the largest valid prefix.
4. Reports `✓` / `✗` per feed with byte counts.

Run it like:
```bash
./update-data.sh
# ▸ Refreshing local threat-intel snapshots...
#   KEV          ✓ 1484848 bytes
#   Feodo        ✓ 1763 bytes
#   ThreatFox    ✓ 2044024 bytes
#   URLhaus      ✓ 71307 bytes
#   Breaches     ✓ 574991 bytes
# ▸ Done. 5 ok / 0 failed.
```

---

## Local preview

The simplest way:

```bash
cd threat-intel-site
python3 -m http.server 8080
# → http://localhost:8080
```

You can also open `index.html` directly with `file://`, but the RSS feeds won't load because public CORS proxies reject `Origin: null`. Serve over HTTP for full functionality.

The Netlify proxy function won't run in `python3 -m http.server` — that's fine, the code falls back to `allorigins.win` / `corsproxy.io` / `codetabs.com`.

---

## Refreshing local snapshots

The `data/*.json` snapshots are what guarantee the dashboard works even when the live proxies are blocked.

```bash
./update-data.sh
```

For a continuously-fresh deploy, schedule it (cron, GitHub Actions, Netlify build hook):

```cron
# Refresh every 30 min
*/30 * * * * cd /path/to/threat-intel-site && ./update-data.sh
```

Or add it to your Netlify build:

```toml
# netlify.toml
[build]
  publish = "."
  functions = "netlify/functions"
  command = "./update-data.sh"
```

…and trigger periodic rebuilds via a scheduled Netlify build hook.

---

## Deploy to Netlify

### Option A — drag & drop

1. Zip the `threat-intel-site/` folder.
2. Go to https://app.netlify.com/drop and drop the zip.
3. Done.

### Option B — Git

1. Push this folder to a GitHub repo.
2. On Netlify: **Add new site → Import from Git → pick repo**.
3. Build settings auto-detect from `netlify.toml`:
   - publish dir: `.`
   - functions dir: `netlify/functions`
4. Deploy.

### Option C — CLI

```bash
npm i -g netlify-cli
cd threat-intel-site
netlify deploy --prod
```

After deploy, the proxy lives at `/.netlify/functions/proxy?url=<encoded-url>`.

---

## How CORS is handled

Three layers, tried in order per request:

1. **Direct fetch** — works for NVD, CISA KEV, FIRST EPSS, CIRCL CVE-Search.
2. **Same-origin snapshot** (`/data/*.json`) — always works; refreshed by `update-data.sh`.
3. **Proxy chain** (`proxyFetch`):
   - `/.netlify/functions/proxy?url=...` (your own whitelisted proxy)
   - `api.allorigins.win/raw?url=...`
   - `corsproxy.io/?...`
   - `api.codetabs.com/v1/proxy/?quest=...`

The chain detects HTML error pages (`<html`, `<!doctype`, "access denied" strings) and skips to the next proxy. If `expectJson: true` is passed, any HTML response is treated as a failure.

---

## Caching strategy

| Layer | TTL | Purpose |
|---|---|---|
| In-page `cache` (localStorage) | 30 min | Instant first paint on revisit; survives across tabs |
| `data/*.json` (Netlify edge) | 15 min + 1-hour SWR | Same-origin snapshots, CDN-cached |
| `css/*`, `js/*` (Netlify edge) | 1 day + 7-day SWR | Static assets |
| Netlify function response | 5 min | Reduces upstream pressure on abuse.ch |
| Auto-refresh interval | 15 min | `setInterval(refreshAll, ...)` in `init()` |

Cached responses are rendered immediately while a fresh fetch runs in parallel (stale-while-revalidate). The status pill shows `⊙ cached` while the revalidation request is in flight, and flips to `✓ live` when it completes.

---

## Customization

**Add a new RSS feed**

Edit `js/app.js`:

```js
CONFIG.RSS_FEEDS.news.push({
  name: 'My favorite blog',
  url:  'https://example.com/feed/',
});
```

Then add the hostname to the allowlist in `netlify/functions/proxy.js`:

```js
ALLOWED_HOSTS.add('example.com');
```

**Add an OSINT account**

Edit `CONFIG.OSINT_ACCOUNTS` in `js/app.js` — each entry is `{ handle, label, bio, site, tags }`.

**Change the theme**

Edit the CSS variables at the top of `css/style.css`. The whole palette is driven by `--bg`, `--panel`, `--accent`, `--critical`, `--high`, `--medium`, `--low`.

**Change the refresh interval**

`CONFIG.REFRESH_INTERVAL_MS` in `js/app.js` (default 15 min).

**Change the cache TTL**

`CONFIG.CACHE_TTL_MS` in `js/app.js` (default 30 min).

**Watermark / branding**

Search for `CYbErXV3nOm` in `index.html` and `js/app.js`. The brand text is in the `<header>` and `<footer>`.

---

## Privacy & legal

- **No tracking.** No analytics, no telemetry, no third-party fingerprinting. The only outbound requests go to the documented public APIs and (optionally) the proxy chain.
- **No login, no cookies.** The only persistent storage is `localStorage` for caches and starred CVEs.
- **No scraping.** All data is pulled from documented public APIs and RSS feeds intended for syndication.
- **Attribution preserved.** Every section links back to the original source, and the *About* section lists every API with credit.
- Data is aggregated under fair-use research provisions. CISA KEV, NVD, FIRST EPSS are open government / open community datasets. abuse.ch and XposedOrNot expose public JSON endpoints. RSS is by definition designed for public re-syndication.
- All trademarks belong to their respective owners.

---

## Tech stack

- **HTML5** — single-page shell, no template engine
- **CSS3** — custom properties, grid, flex, CSS animations (no Tailwind, no Bootstrap)
- **Vanilla ES2020 JavaScript** — single IIFE, no framework, no bundler, no transpilation
- **Chart.js 4.4.1** — bar / doughnut charts
- **Leaflet 1.9.4** — global threat map (CARTO dark tiles)
- **Netlify Functions** — Node.js whitelisted CORS proxy
- **Bash + curl + python3** — `update-data.sh` snapshot refresher

---

Built &amp; signed: **CYbErXV3nOm**
