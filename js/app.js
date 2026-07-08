/* ============================================================
   VENOM/INTEL :: app.js  ::  CYbErXV3nOm
   Open-source threat intelligence aggregator
   ============================================================ */

(() => {
'use strict';

/* -------- CONFIG ---------- */
const CONFIG = {
  NVD_URL: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
  CISA_KEV_URL: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  CIRCL_LAST: 'https://cve.circl.lu/api/last/50',
  EPSS_TOP:  'https://api.first.org/data/v1/epss?order=!epss&limit=30',
  EPSS_BY:   'https://api.first.org/data/v1/epss?cve=',
  URLHAUS_RECENT: 'https://urlhaus.abuse.ch/downloads/json_online/',
  THREATFOX_RECENT: 'https://threatfox.abuse.ch/export/json/recent/',
  FEODO_C2:  'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
  XPOSED_BREACHES: 'https://api.xposedornot.com/v1/breaches',

  // Local bundled snapshots — loaded same-origin so they work without proxies.
  // Refresh via: ./update-data.sh
  LOCAL_KEV:       'data/kev.json',
  LOCAL_FEODO:     'data/feodo.json',
  LOCAL_URLHAUS:   'data/urlhaus.json',
  LOCAL_THREATFOX: 'data/threatfox.json',
  LOCAL_BREACHES:  'data/breaches.json',

  RSS_FEEDS: {
    news: [
      { name: 'Krebs on Security',  url: 'https://krebsonsecurity.com/feed/' },
      { name: 'Bleeping Computer',  url: 'https://www.bleepingcomputer.com/feed/' },
      { name: 'The Hacker News',    url: 'https://feeds.feedburner.com/TheHackersNews' },
      { name: 'SANS ISC',           url: 'https://isc.sans.edu/rssfeed.xml' },
      { name: 'Dark Reading',       url: 'https://www.darkreading.com/rss.xml' },
      { name: 'The Register',       url: 'https://www.theregister.com/security/headlines.atom' },
      { name: 'Schneier',           url: 'https://www.schneier.com/feed/atom/' },
    ],
    exploits: [
      { name: 'Exploit-DB',         url: 'https://www.exploit-db.com/rss.xml' },
      { name: 'PacketStorm',        url: 'https://rss.packetstormsecurity.com/news/' },
      { name: 'GitHub Advisories',  url: 'https://github.com/advisories.atom' },
    ],
  },

  OSINT_ACCOUNTS: [
    { handle: 'CISAgov',         label: 'US Cybersecurity & Infrastructure Security Agency',
      bio: 'Official feed for KEV updates, advisories, and emergency directives.',
      site: 'https://www.cisa.gov/news', tags: ['🇺🇸 gov', 'advisories', 'KEV'] },
    { handle: 'IndianCERT',      label: 'CERT-In — Indian Emergency Response Team',
      bio: 'India\'s national CERT — alerts, advisories, malware analysis for Indian infrastructure.',
      site: 'https://www.cert-in.org.in/', tags: ['🇮🇳 gov', 'advisories'] },
    { handle: 'TheHackersNews',  label: 'The Hacker News',
      bio: 'High-volume infosec news — breaches, malware campaigns, vuln write-ups.',
      site: 'https://thehackernews.com/', tags: ['news', 'daily'] },
    { handle: 'vxunderground',   label: 'vx-underground — malware research collective',
      bio: 'Open malware sample library; daily threat actor / campaign / leak commentary.',
      site: 'https://vx-underground.org/', tags: ['malware', 'samples', 'leaks'] },
    { handle: 'malwrhunterteam', label: 'MalwareHunterTeam',
      bio: 'Live IOC dumps for new ransomware, stealers, RATs as they appear in the wild.',
      site: 'https://twitter.com/malwrhunterteam', tags: ['IOCs', 'malware'] },
    { handle: 'campuscodi',      label: 'Catalin Cimpanu — security journalist',
      bio: 'Risky Business News editor — daily breach / threat-actor reporting.',
      site: 'https://news.risky.biz/', tags: ['journalism', 'analysis'] },
    { handle: 'briankrebs',      label: 'Brian Krebs — investigative reporter',
      bio: 'Long-form investigations into cybercrime, fraud, and the people behind it.',
      site: 'https://krebsonsecurity.com/', tags: ['journalism', 'investigations'] },
    { handle: 'GossiTheDog',     label: 'Kevin Beaumont — threat researcher',
      bio: 'In-the-wild exploitation tracking, ransomware analysis, sharp commentary.',
      site: 'https://doublepulsar.com/', tags: ['research', 'ITW'] },
    { handle: 'MsftSecIntel',    label: 'Microsoft Threat Intelligence',
      bio: 'Microsoft Threat Intelligence Center — campaign analysis, named threat actors.',
      site: 'https://www.microsoft.com/security/blog/', tags: ['vendor TI', 'campaigns'] },
    { handle: 'GoogleTAG',       label: 'Google Threat Analysis Group',
      bio: 'Nation-state tracking, 0-day disclosure, election security research.',
      site: 'https://blog.google/threat-analysis-group/', tags: ['vendor TI', 'APT'] },
  ],

  REFRESH_INTERVAL_MS: 1000 * 60 * 15,
  CVE_RESULTS: 40,
  KEV_PAGE: 200,
  CACHE_TTL_MS: 1000 * 60 * 30,   // 30 min stale-while-revalidate
  FETCH_TIMEOUT_MS: 20000,
};

/* -------- TIMED FETCH + PROXY ---------- */
async function timedFetch(url, opts = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), opts.timeout || CONFIG.FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally { clearTimeout(t); }
}

function isHtmlResponse(text) {
  if (!text) return true;
  const t = text.trim().slice(0, 200).toLowerCase();
  return t.startsWith('<') || t.includes('<html') || t.includes('<!doctype') || t.includes('access denied');
}

async function proxyFetch(url, opts = {}) {
  // expectJson: when true, reject HTML error pages from proxies and try the next one
  const expectJson = !!opts.expectJson;
  const proxies = [
    `/.netlify/functions/proxy?url=${encodeURIComponent(url)}`,
    `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`,
    `https://corsproxy.io/?${encodeURIComponent(url)}`,
    `https://api.codetabs.com/v1/proxy/?quest=${encodeURIComponent(url)}`,
  ];
  let lastErr;
  for (const p of proxies) {
    try {
      const r = await timedFetch(p, { cache: 'no-store' });
      if (!r.ok) { lastErr = new Error('HTTP ' + r.status); continue; }
      const text = await r.text();
      if (expectJson && isHtmlResponse(text)) {
        lastErr = new Error('proxy returned HTML (likely access-denied)');
        continue;
      }
      if (!text || text.length < 10) {
        lastErr = new Error('empty body');
        continue;
      }
      return text;
    } catch (e) { lastErr = e; }
  }
  throw lastErr || new Error('all proxies failed');
}

/* -------- CACHE (localStorage + memory) ---------- */
const cache = {
  get(key) {
    try {
      const raw = localStorage.getItem('vni:' + key);
      if (!raw) return null;
      const { t, v } = JSON.parse(raw);
      if (Date.now() - t > CONFIG.CACHE_TTL_MS) return null;
      return v;
    } catch { return null; }
  },
  set(key, val) {
    try { localStorage.setItem('vni:' + key, JSON.stringify({ t: Date.now(), v: val })); }
    catch (_) {}
  },
};

/* -------- UTIL ---------- */
const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const escape = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmtDate = (d) => {
  if (!d) return '—';
  const dt = new Date(d);
  return isNaN(dt) ? '—' : dt.toISOString().slice(0, 10);
};
const timeAgo = (d) => {
  if (!d) return '';
  const sec = Math.floor((Date.now() - new Date(d).getTime()) / 1000);
  if (sec < 60) return sec + 's ago';
  if (sec < 3600) return Math.floor(sec/60) + 'm ago';
  if (sec < 86400) return Math.floor(sec/3600) + 'h ago';
  return Math.floor(sec/86400) + 'd ago';
};
const stripHtml = (html) => {
  if (!html) return '';
  // DOMParser doesn't execute scripts or load external resources (images, iframes)
  // when parsing text/html — safer than innerHTML on untrusted RSS content.
  try {
    const doc = new DOMParser().parseFromString(String(html), 'text/html');
    return (doc.body.textContent || '').replace(/\s+/g, ' ').trim();
  } catch {
    return String(html).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
  }
};
const truncate = (s, n) => s.length > n ? s.slice(0, n - 1) + '…' : s;
const unique = (a) => Array.from(new Set(a));
const asArr = (v) => Array.isArray(v) ? v : (typeof v === 'string' && v ? v.split(/[,\s]+/).filter(Boolean) : []);
const debounce = (fn, ms = 180) => {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
};
const onIdle = (fn) => (window.requestIdleCallback
  ? requestIdleCallback(fn, { timeout: 2000 })
  : setTimeout(fn, 1));

function parseRss(xmlText, sourceName) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xmlText, 'application/xml');
  if (doc.querySelector('parsererror')) return [];
  const items = [];
  doc.querySelectorAll('item').forEach((n) => {
    items.push({
      source: sourceName,
      title:  stripHtml(n.querySelector('title')?.textContent || ''),
      link:   n.querySelector('link')?.textContent?.trim() || '',
      desc:   stripHtml(n.querySelector('description')?.textContent || n.querySelector('content\\:encoded')?.textContent || ''),
      date:   n.querySelector('pubDate')?.textContent || n.querySelector('dc\\:date')?.textContent || '',
    });
  });
  if (!items.length) doc.querySelectorAll('entry').forEach((n) => {
    items.push({
      source: sourceName,
      title:  stripHtml(n.querySelector('title')?.textContent || ''),
      link:   n.querySelector('link')?.getAttribute('href') || '',
      desc:   stripHtml(n.querySelector('summary')?.textContent || n.querySelector('content')?.textContent || ''),
      date:   n.querySelector('updated')?.textContent || n.querySelector('published')?.textContent || '',
    });
  });
  return items;
}

/* ============================================================
   STATUS SYSTEM
   ============================================================ */
const STATUS = {};
function setStatus(section, state, msg = '') {
  STATUS[section] = { state, msg, t: Date.now() };
  const pill = $('#status-' + section);
  if (pill) {
    pill.className = 'status-pill st-' + state;
    pill.textContent = (state === 'ok' ? '✓ live' : state === 'loading' ? '◌ loading' : state === 'cache' ? '⊙ cached' : '✕ error') + (msg ? ' · ' + msg : '');
  }
  renderDiagnostic();
}
function renderDiagnostic() {
  const el = $('#diag-body');
  if (!el) return;
  el.innerHTML = Object.entries(STATUS).map(([k, v]) =>
    `<div class="diag-row"><span class="diag-key">${escape(k)}</span><span class="status-pill st-${v.state}">${escape(v.state.toUpperCase())}</span><span class="diag-msg">${escape(v.msg || '')}</span><span class="diag-time">${escape(timeAgo(v.t))}</span></div>`
  ).join('');
}

/* ============================================================
   CLOCK
   ============================================================ */
function startClock() {
  const el = $('#clock');
  if (!el) return;
  const tick = () => {
    if (document.hidden) return;
    // toISOString is stable across engines. slice(11,19) gives "HH:MM:SS".
    el.textContent = new Date().toISOString().slice(11, 19) + ' UTC';
  };
  tick();
  setInterval(tick, 1000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) tick(); });
}

/* ============================================================
   NVD CVE
   ============================================================ */
function extractProducts(cveItem) {
  const c = cveItem.cve || cveItem;
  const out = [];
  (c.configurations || []).forEach((cfg) => {
    (cfg.nodes || []).forEach((n) => {
      (n.cpeMatch || []).forEach((m) => {
        const parts = (m.criteria || m.cpe23Uri || '').split(':');
        if (parts.length > 5) out.push({ vendor: parts[3], product: parts[4] });
      });
    });
  });
  return out;
}

async function fetchCVEs() {
  setStatus('cve', 'loading');
  const cacheKey = 'cves';
  const cached = cache.get(cacheKey);
  if (cached) { setStatus('cve', 'cache', `${cached.length} cached`); }
  try {
    const since = new Date(Date.now() - 7 * 86400000);
    const url = `${CONFIG.NVD_URL}?pubStartDate=${since.toISOString().slice(0,-5)}.000&pubEndDate=${new Date().toISOString().slice(0,-5)}.000&resultsPerPage=${CONFIG.CVE_RESULTS}`;
    // Direct → proxy fallback: NVD frequently 403s / rate-limits.
    let data;
    try {
      const r = await timedFetch(url, { timeout: 25000 });
      if (!r.ok) throw new Error('NVD ' + r.status);
      data = await r.json();
    } catch (direct) {
      const text = await proxyFetch(url, { expectJson: true });
      data = JSON.parse(text);
    }
    const items = (data.vulnerabilities || []).map((v) => {
      const c = v.cve || {};
      const desc = (c.descriptions?.find((d) => d.lang === 'en') || c.descriptions?.[0])?.value || '';
      const metric =
        c.metrics?.cvssMetricV31?.[0]?.cvssData ||
        c.metrics?.cvssMetricV30?.[0]?.cvssData ||
        c.metrics?.cvssMetricV2?.[0]?.cvssData || {};
      const sev = metric.baseSeverity ||
                  c.metrics?.cvssMetricV31?.[0]?.baseSeverity ||
                  c.metrics?.cvssMetricV30?.[0]?.baseSeverity || 'NONE';
      const pp = extractProducts(v);
      const products = unique(pp.map((p) => p.product).filter((p) => p && p !== '*'));
      const vendors  = unique(pp.map((p) => p.vendor).filter((p) => p && p !== '*'));
      return {
        id: c.id,
        desc,
        score: metric.baseScore ?? null,
        sev: String(sev).toUpperCase(),
        published: c.published,
        modified:  c.lastModified,
        products, vendors,
        epss: null,
        searchBlob: (c.id + ' ' + desc + ' ' + vendors.join(' ') + ' ' + products.join(' ')).toLowerCase(),
      };
    });
    items.sort((a, b) => new Date(b.published) - new Date(a.published));
    cache.set(cacheKey, items);
    setStatus('cve', 'ok', `${items.length} CVEs`);
    return items;
  } catch (e) {
    setStatus('cve', cached ? 'cache' : 'error', e.message);
    return cached || [];
  }
}

async function enrichEPSS(cves) {
  if (!cves.length) return cves;
  setStatus('epss', 'loading');
  try {
    const ids = cves.map((c) => c.id).filter(Boolean).slice(0, 50).join(',');
    const r = await timedFetch(CONFIG.EPSS_BY + encodeURIComponent(ids));
    if (!r.ok) throw new Error('EPSS ' + r.status);
    const data = await r.json();
    const map = {};
    (data.data || []).forEach((e) => { map[e.cve] = e; });
    cves.forEach((c) => {
      if (map[c.id]) {
        c.epss = parseFloat(map[c.id].epss);
        c.percentile = parseFloat(map[c.id].percentile);
      }
    });
    setStatus('epss', 'ok', `${Object.keys(map).length} scored`);
  } catch (e) {
    setStatus('epss', 'error', e.message);
  }
  return cves;
}

/* EPSS scores for arbitrary CVE IDs (e.g. KEV entries older than 7 days).
   Results merged into a module-scoped Map so buildExploitList can look them up. */
const EPSS_KEV_MAP = new Map();
async function enrichEPSSforKEV(kev) {
  const cveIds = (kev?.vulnerabilities || []).map((v) => v.cveID).filter(Boolean);
  if (!cveIds.length) return;
  // Batch requests — EPSS caps CVE list length in the query string.
  const CHUNK = 100;
  for (let i = 0; i < cveIds.length; i += CHUNK) {
    const chunk = cveIds.slice(i, i + CHUNK).join(',');
    try {
      const r = await timedFetch(CONFIG.EPSS_BY + encodeURIComponent(chunk) + '&limit=' + CHUNK);
      if (!r.ok) continue;
      const data = await r.json();
      (data.data || []).forEach((e) => EPSS_KEV_MAP.set(e.cve, parseFloat(e.epss)));
    } catch (_) { /* keep going — best-effort enrichment */ }
    // Chunking too fast will 429 EPSS; a tiny pause smooths it out.
    await new Promise((res) => setTimeout(res, 120));
  }
}

function renderCVEs(items) {
  const grid = $('#cve-grid');
  const sevFilter = $('#cve-severity').value;
  const pFilter   = $('#cve-product').value.trim().toLowerCase();
  let filtered = items;
  if (sevFilter) filtered = filtered.filter((x) => x.sev === sevFilter);
  if (pFilter)   filtered = filtered.filter((x) => x.searchBlob.includes(pFilter));
  if (!filtered.length) {
    grid.innerHTML = '<div class="loading-card">No CVEs match the filter.</div>';
    return;
  }
  grid.innerHTML = filtered.map((x) => {
    const chips = x.products.slice(0, 6).map((p) => `<span class="product-chip">${escape(p)}</span>`).join('');
    const vendor = x.vendors[0] ? `<span>vendor: ${escape(x.vendors[0])}</span>` : '';
    const epssBadge = x.epss != null
      ? `<span class="epss-badge ${x.epss >= 0.5 ? 'hot' : x.epss >= 0.1 ? 'warm' : ''}">EPSS ${(x.epss*100).toFixed(1)}%</span>`
      : '';
    const star = `<button class="star-btn ${isStarred(x.id) ? 'on' : ''}" data-star="${escape(x.id)}" title="Star">★</button>`;
    return `
    <div class="intel-card sev-${escape(x.sev)}">
      <div class="card-head">
        <div class="card-id"><a href="https://nvd.nist.gov/vuln/detail/${escape(x.id)}" target="_blank" rel="noopener">${escape(x.id)}</a></div>
        <div style="display:flex;gap:6px;align-items:center">
          ${epssBadge}
          <div class="card-sev ${escape(x.sev)}">${escape(x.sev)} ${x.score ? '· ' + x.score : ''}</div>
          ${star}
        </div>
      </div>
      <div class="card-desc">${escape(truncate(x.desc, 300))}</div>
      ${chips ? `<div class="card-products">${chips}</div>` : ''}
      <div class="card-meta">
        ${vendor}
        <span>${escape(fmtDate(x.published))}</span>
        <span>${escape(timeAgo(x.published))}</span>
        <a href="https://nvd.nist.gov/vuln/detail/${escape(x.id)}" target="_blank" rel="noopener">NVD →</a>
        <a href="https://cve.circl.lu/cve/${escape(x.id)}" target="_blank" rel="noopener">CIRCL →</a>
      </div>
    </div>`;
  }).join('');
  $$('.star-btn').forEach((b) => b.addEventListener('click', () => {
    toggleStar(b.dataset.star);
    b.classList.toggle('on');
  }));
}

/* ============================================================
   CISA KEV
   ============================================================ */
// Snapshots baked into the Netlify deploy go stale until the next push.
// Only use the local file if its Last-Modified is within this window;
// otherwise fall through to direct/proxied live fetch.
const LOCAL_SNAPSHOT_TTL_MS = 6 * 60 * 60 * 1000;

async function tryLocalThenRemote(localPath, remoteUrl, label) {
  // Try same-origin local snapshot first (always works, no CORS) — but
  // only honor it when fresh, so a stale deploy can't pin old data forever.
  try {
    const r = await timedFetch(localPath, { cache: 'no-store' });
    if (r.ok) {
      const lastMod = r.headers.get('last-modified');
      const ageMs = lastMod ? Date.now() - new Date(lastMod).getTime() : 0;
      if (ageMs < LOCAL_SNAPSHOT_TTL_MS) {
        const text = await r.text();
        if (!isHtmlResponse(text) && text.length > 10) {
          const ageH = Math.round(ageMs / 3.6e6);
          return { text, source: `local snapshot (${ageH}h old)` };
        }
      }
    }
  } catch (_) {}
  // Then try direct (works if CORS allowed)
  try {
    const r = await timedFetch(remoteUrl);
    if (r.ok) {
      const text = await r.text();
      if (!isHtmlResponse(text) && text.length > 10) return { text, source: 'live' };
    }
  } catch (_) {}
  // Then proxy chain
  try {
    const text = await proxyFetch(remoteUrl, { expectJson: true });
    return { text, source: 'live (proxied)' };
  } catch (e) {
    // Last resort: stale local snapshot is better than nothing.
    try {
      const r = await timedFetch(localPath, { cache: 'no-store' });
      if (r.ok) {
        const text = await r.text();
        if (!isHtmlResponse(text) && text.length > 10) return { text, source: 'stale snapshot (live unreachable)' };
      }
    } catch (_) {}
    throw e;
  }
}

async function fetchKEV() {
  setStatus('kev', 'loading');
  const cached = cache.get('kev');
  if (cached) setStatus('kev', 'cache', `${cached.count} cached`);
  try {
    const { text, source } = await tryLocalThenRemote(CONFIG.LOCAL_KEV, CONFIG.CISA_KEV_URL, 'KEV');
    if (isHtmlResponse(text)) throw new Error('non-JSON response');
    const data = JSON.parse(text);
    if (!data || !Array.isArray(data.vulnerabilities)) throw new Error('invalid KEV shape');
    cache.set('kev', data);
    setStatus('kev', 'ok', `${data.count || data.vulnerabilities.length} vulns · ${source}`);
    return data;
  } catch (e) {
    setStatus('kev', cached ? 'cache' : 'error', e.message);
    return cached || { vulnerabilities: [], count: 0 };
  }
}

function renderKEV(kev) {
  const body = $('#kev-body');
  const vulns = (kev.vulnerabilities || []).slice().sort((a, b) => new Date(b.dateAdded) - new Date(a.dateAdded));
  const filter = $('#kev-search').value.trim().toLowerCase();
  const filtered = filter
    ? vulns.filter((v) => (v.cveID + ' ' + v.vendorProject + ' ' + v.product + ' ' + v.vulnerabilityName).toLowerCase().includes(filter))
    : vulns;
  const sliced = filtered.slice(0, CONFIG.KEV_PAGE);
  if (!sliced.length) {
    body.innerHTML = '<tr><td colspan="7" class="loading">No matches.</td></tr>';
    return;
  }
  body.innerHTML = sliced.map((v) => `
    <tr>
      <td class="cve"><a href="https://nvd.nist.gov/vuln/detail/${escape(v.cveID)}" target="_blank" rel="noopener">${escape(v.cveID)}</a></td>
      <td>${escape(v.vendorProject)}</td>
      <td>${escape(v.product)}</td>
      <td>${escape(truncate(v.vulnerabilityName || v.shortDescription || '', 120))}</td>
      <td>${escape(v.dateAdded)}</td>
      <td>${escape(v.dueDate || '—')}</td>
      <td>${v.knownRansomwareCampaignUse === 'Known' ? '<span class="pill pill-yes">YES</span>' : '<span class="pill pill-no">no</span>'}</td>
    </tr>
  `).join('');
}

/* ============================================================
   RSS aggregator
   ============================================================ */
async function fetchRssSet(feeds, sectionKey) {
  setStatus(sectionKey, 'loading');
  const cached = cache.get(sectionKey);
  if (cached) setStatus(sectionKey, 'cache', `${cached.length} cached`);
  const all = [];
  let okCount = 0;
  await Promise.all(feeds.map(async (f) => {
    try {
      const xml = await proxyFetch(f.url);
      const items = parseRss(xml, f.name).slice(0, 15);
      if (items.length) { all.push(...items); okCount++; }
    } catch (e) { console.warn(f.name, e); }
  }));
  all.sort((a, b) => (new Date(b.date || 0) - new Date(a.date || 0)));
  if (all.length) {
    cache.set(sectionKey, all);
    setStatus(sectionKey, 'ok', `${all.length} items from ${okCount}/${feeds.length}`);
    return all;
  } else {
    setStatus(sectionKey, cached ? 'cache' : 'error', 'no feeds responded');
    return cached || [];
  }
}

function renderNews(items) {
  const grid = $('#news-grid');
  if (!items.length) { grid.innerHTML = '<div class="loading-card">No news available.</div>'; return; }
  grid.innerHTML = items.slice(0, 36).map((x) => `
    <div class="news-card">
      <div class="news-source">${escape(x.source)}</div>
      <div class="news-title"><a href="${escape(x.link)}" target="_blank" rel="noopener">${escape(x.title)}</a></div>
      <div class="news-desc">${escape(truncate(x.desc, 220))}</div>
      <div class="news-date">${escape(fmtDate(x.date))} · ${escape(timeAgo(x.date))}</div>
    </div>
  `).join('');
}

function renderExploits(items) {
  const grid = $('#exploits-grid');
  if (!items.length) { grid.innerHTML = '<div class="loading-card">No exploit feeds available.</div>'; return; }
  grid.innerHTML = items.slice(0, 30).map((x) => `
    <div class="intel-card">
      <div class="card-head">
        <div class="card-id"><a href="${escape(x.link)}" target="_blank" rel="noopener">${escape(truncate(x.title, 80))}</a></div>
        <div class="card-sev HIGH">${escape(x.source)}</div>
      </div>
      <div class="card-desc">${escape(truncate(x.desc, 240))}</div>
      <div class="card-meta">
        <span>${escape(fmtDate(x.date))}</span>
        <span>${escape(timeAgo(x.date))}</span>
        <a href="${escape(x.link)}" target="_blank" rel="noopener">Open →</a>
      </div>
    </div>
  `).join('');
}

/* ============================================================
   ABUSE.CH FEEDS
   ============================================================ */
async function fetchURLhaus() {
  setStatus('urlhaus', 'loading');
  const cached = cache.get('urlhaus');
  if (cached) setStatus('urlhaus', 'cache', `${cached.length} cached`);
  try {
    const { text, source } = await tryLocalThenRemote(CONFIG.LOCAL_URLHAUS, CONFIG.URLHAUS_RECENT, 'URLhaus');
    const data = JSON.parse(text);
    const items = [];
    Object.values(data).forEach((arr) => { if (Array.isArray(arr)) items.push(...arr); });
    items.sort((a, b) => new Date(b.dateadded) - new Date(a.dateadded));
    const sliced = items.slice(0, 100);
    cache.set('urlhaus', sliced);
    setStatus('urlhaus', 'ok', `${sliced.length} URLs · ${source}`);
    return sliced;
  } catch (e) {
    setStatus('urlhaus', cached ? 'cache' : 'error', e.message);
    return cached || [];
  }
}

function renderURLhaus(items) {
  const grid = $('#urlhaus-grid');
  if (!items.length) { grid.innerHTML = '<div class="loading-card">URLhaus feed unavailable.</div>'; return; }
  const hostOf = (u) => { try { return new URL(u).hostname; } catch { return u.split('/')[2] || u; } };
  grid.innerHTML = items.slice(0, 30).map((x) => {
    const url = x.url || '';
    const host = hostOf(url);
    const detail = x.urlhaus_link || (x.id ? `https://urlhaus.abuse.ch/url/${encodeURIComponent(x.id)}/` : `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(host)}`);
    return `
    <div class="intel-card sev-HIGH">
      <div class="card-head">
        <div class="card-id" style="word-break:break-all;font-size:12px;" title="${escape(url)}">${escape(truncate(url, 90))}</div>
        <div class="card-sev HIGH">${escape(x.threat || 'malware')}</div>
      </div>
      <div class="card-meta">
        ${(() => { const t = asArr(x.tags); return t.length ? `<span>tags: ${escape(t.slice(0, 3).join(', '))}</span>` : ''; })()}
        <span>${escape(fmtDate(x.dateadded))}</span>
        <span>${escape(timeAgo(x.dateadded))}</span>
        <a href="${escape(detail)}" target="_blank" rel="noopener">URLhaus →</a>
        <a href="https://bazaar.abuse.ch/browse.php?search=${encodeURIComponent(host)}" target="_blank" rel="noopener">MalwareBazaar (sample)</a>
        <a href="https://www.virustotal.com/gui/search/${encodeURIComponent(host)}" target="_blank" rel="noopener">VirusTotal</a>
      </div>
    </div>`;
  }).join('');
}

async function fetchThreatFox() {
  setStatus('threatfox', 'loading');
  const cached = cache.get('threatfox');
  if (cached) setStatus('threatfox', 'cache', `${cached.length} cached`);
  try {
    const { text, source } = await tryLocalThenRemote(CONFIG.LOCAL_THREATFOX, CONFIG.THREATFOX_RECENT, 'ThreatFox');
    const data = JSON.parse(text);
    const items = [];
    Object.values(data).forEach((arr) => { if (Array.isArray(arr)) items.push(...arr); });
    // ThreatFox fields: ioc_value, first_seen_utc, etc. Normalize.
    items.forEach((x) => {
      x.ioc        = x.ioc        || x.ioc_value;
      x.first_seen = x.first_seen || x.first_seen_utc;
    });
    items.sort((a, b) => new Date(b.first_seen) - new Date(a.first_seen));
    const sliced = items.slice(0, 100);
    cache.set('threatfox', sliced);
    setStatus('threatfox', 'ok', `${sliced.length} IOCs · ${source}`);
    return sliced;
  } catch (e) {
    setStatus('threatfox', cached ? 'cache' : 'error', e.message);
    return cached || [];
  }
}

function renderThreatFox(items) {
  const grid = $('#threatfox-grid');
  if (!items.length) { grid.innerHTML = '<div class="loading-card">ThreatFox feed unavailable.</div>'; return; }
  grid.innerHTML = items.slice(0, 30).map((x) => `
    <div class="intel-card">
      <div class="card-head">
        <div class="card-id" style="font-size:12px;word-break:break-all;">${escape(truncate(x.ioc || '', 70))}</div>
        <div class="card-sev HIGH">${escape(x.ioc_type || '')}</div>
      </div>
      <div class="card-desc">
        <strong style="color:var(--text)">${escape(x.malware_printable || x.malware || 'unknown')}</strong> — ${escape(x.threat_type || '')}
      </div>
      <div class="card-meta">
        ${(() => { const t = asArr(x.tags); return t.length ? `<span>${escape(t.slice(0, 3).join(', '))}</span>` : ''; })()}
        <span>${escape(fmtDate(x.first_seen))}</span>
        <span>conf: ${escape(x.confidence_level ?? '?')}</span>
        <a href="https://threatfox.abuse.ch/browse.php?search=ioc%3A${encodeURIComponent(x.ioc || '')}" target="_blank" rel="noopener">ThreatFox →</a>
      </div>
    </div>
  `).join('');
}

async function fetchFeodo() {
  setStatus('feodo', 'loading');
  const cached = cache.get('feodo');
  if (cached) setStatus('feodo', 'cache', `${cached.length} cached`);
  try {
    const { text, source } = await tryLocalThenRemote(CONFIG.LOCAL_FEODO, CONFIG.FEODO_C2, 'Feodo');
    const parsed = JSON.parse(text);
    // Feodo occasionally wraps the array — normalise to a flat array.
    const items = Array.isArray(parsed)
      ? parsed
      : (Array.isArray(parsed?.data) ? parsed.data : Object.values(parsed).find(Array.isArray) || []);
    items.sort((a, b) => new Date(b.first_seen) - new Date(a.first_seen));
    cache.set('feodo', items);
    setStatus('feodo', 'ok', `${items.length} C2s · ${source}`);
    return items;
  } catch (e) {
    setStatus('feodo', cached ? 'cache' : 'error', e.message);
    return cached || [];
  }
}

function renderFeodo(items) {
  const tbody = $('#feodo-body');
  if (!items.length) { tbody.innerHTML = '<tr><td colspan="6" class="loading">Feodo Tracker unavailable.</td></tr>'; return; }
  tbody.innerHTML = items.slice(0, 50).map((x) => `
    <tr>
      <td class="cve">${escape(x.ip_address)}:${escape(x.port ?? '?')}</td>
      <td><span class="pill pill-yes">${escape(x.malware || '?')}</span></td>
      <td>${escape(x.country || '—')}</td>
      <td>${escape(x.as_name || '—')}</td>
      <td>${escape((x.first_seen || '').slice(0, 10))}</td>
      <td>${escape(x.status || '—')}</td>
    </tr>
  `).join('');
}

/* ============================================================
   BREACHES
   ============================================================ */
async function fetchBreaches() {
  setStatus('breach', 'loading');
  const cached = cache.get('breach');
  if (cached) setStatus('breach', 'cache', `${cached.length} cached`);
  try {
    const { text, source } = await tryLocalThenRemote(CONFIG.LOCAL_BREACHES, CONFIG.XPOSED_BREACHES, 'Breaches');
    const data = JSON.parse(text);
    const arr = Array.isArray(data) ? data : (data?.exposedBreaches || data?.breaches || []);
    arr.sort((a, b) => new Date(b.breachedDate || b.breached_date || 0) - new Date(a.breachedDate || a.breached_date || 0));
    const sliced = arr.slice(0, 30);
    cache.set('breach', sliced);
    setStatus('breach', 'ok', `${sliced.length} breaches · ${source}`);
    return sliced;
  } catch (e) {
    setStatus('breach', cached ? 'cache' : 'error', e.message);
    return cached || [];
  }
}

function renderBreaches(items) {
  const grid = $('#breach-grid');
  if (!items.length) { grid.innerHTML = '<div class="loading-card">Breach feed unavailable.</div>'; return; }
  grid.innerHTML = items.slice(0, 24).map((x) => {
    const name    = x.breachID || x.Name || '?';
    const records = x.exposedRecords ?? x.exposed_records ?? x.PwnCount ?? 0;
    const date    = x.breachedDate || x.breached_date || x.BreachDate;
    const domain  = x.domain || x.Domain || '';
    const desc    = x.exposureDescription || x.Description || (Array.isArray(x.exposedData) ? x.exposedData.join(', ') : x.exposed_data) || '';
    return `
    <div class="intel-card">
      <div class="card-head">
        <div class="card-id">${escape(name)}${domain ? ` <span style="color:var(--text-mute);font-size:11px">· ${escape(domain)}</span>` : ''}</div>
        <div class="card-sev CRITICAL">BREACH</div>
      </div>
      <div class="card-desc">${escape(truncate(stripHtml(desc), 220))}</div>
      <div class="card-meta">
        <span>records: <strong style="color:var(--text)">${escape(Number(records).toLocaleString())}</strong></span>
        <span>industry: ${escape(x.industry || '—')}</span>
        <span>${escape(fmtDate(date))}</span>
      </div>
    </div>`;
  }).join('');
}

/* ============================================================
   IOC LOOKUP
   ============================================================ */
const IOC = {
  detect(v) {
    v = v.trim();
    if (!v) return null;
    if (/^[a-f0-9]{32}$/i.test(v))   return 'md5';
    if (/^[a-f0-9]{40}$/i.test(v))   return 'sha1';
    if (/^[a-f0-9]{64}$/i.test(v))   return 'sha256';
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return 'ipv4';
    if (/^[a-fA-F0-9:]+$/.test(v) && v.includes(':')) return 'ipv6';
    if (/^https?:\/\//i.test(v))     return 'url';
    if (/^[\w.-]+\.[a-z]{2,}$/i.test(v)) return 'domain';
    if (/^CVE-\d{4}-\d{4,}$/i.test(v)) return 'cve';
    return null;
  },
  async lookup(value) {
    const type = IOC.detect(value);
    const out = { type, value, sources: [] };
    if (!type) { out.error = 'Unrecognized format. Try IP, domain, URL, MD5/SHA1/SHA256 hash, or CVE-ID.'; return out; }

    // CVE lookup via CIRCL (no auth, CORS-friendly)
    if (type === 'cve') {
      try {
        const r = await timedFetch(`https://cve.circl.lu/api/cve/${encodeURIComponent(value)}`);
        if (r.ok) {
          const d = await r.json();
          out.sources.push({ name: 'CIRCL CVE-Search', hit: !!d, data: d });
        }
      } catch (e) { out.sources.push({ name: 'CIRCL CVE-Search', error: e.message }); }
      return out;
    }

    // Cross-reference against currently-loaded threat feeds (no extra API calls — fast & offline-friendly)
    const matches = [];
    (STATE.urlhaus || []).forEach((u) => {
      if (u.url?.includes(value) || u.host === value) matches.push({ source: 'URLhaus', kind: 'url', data: u });
    });
    (STATE.threatfox || []).forEach((t) => {
      if (t.ioc === value || t.ioc?.includes(value)) matches.push({ source: 'ThreatFox', kind: 'ioc', data: t });
    });
    (STATE.feodo || []).forEach((f) => {
      if (f.ip_address === value) matches.push({ source: 'Feodo Tracker', kind: 'c2', data: f });
    });
    out.localMatches = matches;

    // Live lookups
    if (type === 'ipv4' || type === 'ipv6' || type === 'domain' || type === 'url') {
      // URLhaus host lookup (POST)
      try {
        const body = new URLSearchParams({ host: type === 'url' ? new URL(value).hostname : value }).toString();
        const r = await timedFetch('/.netlify/functions/proxy?url=' + encodeURIComponent('https://urlhaus-api.abuse.ch/v1/host/'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body,
          timeout: 15000,
        });
        if (r.ok) {
          const d = await r.json();
          out.sources.push({ name: 'URLhaus host', query_status: d.query_status, urls: d.urls?.slice?.(0, 5) });
        }
      } catch (e) { /* function unavailable in local server */ }
    }
    return out;
  },
};

function renderIocResult(r) {
  const out = $('#ioc-output');
  if (!r) { out.innerHTML = ''; return; }
  if (r.error) {
    out.innerHTML = `<div class="ioc-card err">${escape(r.error)}</div>`;
    return;
  }
  let html = `<div class="ioc-card">
    <div class="ioc-head"><strong>${escape(r.value)}</strong> <span class="status-pill st-ok">type: ${escape(r.type)}</span></div>`;

  if (r.localMatches?.length) {
    html += `<div class="ioc-section"><div class="ioc-section-title">⚠ Found in active threat feeds (${r.localMatches.length})</div>`;
    r.localMatches.slice(0, 5).forEach((m) => {
      const d = m.data || {};
      // Only surface the fields users actually care about, per source.
      const kv = [];
      if (m.source === 'URLhaus') {
        if (d.threat)     kv.push(['threat', d.threat]);
        if (d.url)        kv.push(['url', truncate(d.url, 90)]);
        if (d.dateadded)  kv.push(['first seen', d.dateadded]);
        if (d.tags?.length) kv.push(['tags', asArr(d.tags).slice(0,4).join(', ')]);
      } else if (m.source === 'ThreatFox') {
        if (d.malware_printable || d.malware) kv.push(['malware', d.malware_printable || d.malware]);
        if (d.threat_type) kv.push(['type', d.threat_type]);
        if (d.confidence_level != null) kv.push(['confidence', d.confidence_level + '%']);
        if (d.first_seen)  kv.push(['first seen', d.first_seen]);
      } else if (m.source === 'Feodo Tracker') {
        if (d.malware) kv.push(['malware', d.malware]);
        if (d.port)    kv.push(['port', d.port]);
        if (d.country) kv.push(['country', d.country]);
        if (d.as_name) kv.push(['ASN', d.as_name]);
        if (d.first_seen) kv.push(['first seen', d.first_seen]);
      }
      html += `<div class="ioc-row"><strong style="color:var(--critical)">${escape(m.source)}</strong></div>`;
      kv.forEach(([k, v]) => {
        html += `<div class="ioc-row" style="padding-left:12px;font-size:12px"><span style="color:var(--text-mute)">${escape(k)}:</span> <span style="color:var(--text)">${escape(String(v))}</span></div>`;
      });
    });
    html += `</div>`;
  } else if (r.type !== 'cve') {
    html += `<div class="ioc-section"><div class="status-pill st-ok">✓ Not found in current threat feeds (URLhaus / ThreatFox / Feodo)</div></div>`;
  }

  r.sources.forEach((s) => {
    html += `<div class="ioc-section"><div class="ioc-section-title">${escape(s.name)}</div>`;
    if (s.error) html += `<div class="ioc-row err">${escape(s.error)}</div>`;
    else if (s.data) {
      const d = s.data;
      if (d.summary)   html += `<div class="ioc-row">${escape(truncate(d.summary, 400))}</div>`;
      if (d.cvss)      html += `<div class="ioc-row">CVSS: <strong>${escape(d.cvss)}</strong></div>`;
      if (d.Published) html += `<div class="ioc-row">Published: ${escape(d.Published)}</div>`;
      if (s.urls?.length) {
        html += `<div class="ioc-row">URLhaus reports: ${s.urls.length}</div>`;
        s.urls.forEach((u) => { html += `<div class="ioc-row" style="font-size:11px;color:var(--text-mute)">${escape(u.url)}</div>`; });
      } else if (s.query_status) {
        html += `<div class="ioc-row">${escape(s.query_status)}</div>`;
      }
    }
    html += `</div>`;
  });

  // Cross-check links
  html += `<div class="ioc-section ioc-links"><div class="ioc-section-title">Quick cross-check</div>`;
  if (r.type === 'ipv4' || r.type === 'ipv6') {
    html += `<a href="https://www.abuseipdb.com/check/${encodeURIComponent(r.value)}" target="_blank" rel="noopener">AbuseIPDB</a>`;
    html += `<a href="https://www.virustotal.com/gui/ip-address/${encodeURIComponent(r.value)}" target="_blank" rel="noopener">VirusTotal</a>`;
    html += `<a href="https://www.shodan.io/host/${encodeURIComponent(r.value)}" target="_blank" rel="noopener">Shodan</a>`;
    html += `<a href="https://otx.alienvault.com/indicator/ip/${encodeURIComponent(r.value)}" target="_blank" rel="noopener">OTX</a>`;
  } else if (r.type === 'domain' || r.type === 'url') {
    const host = r.type === 'url' ? new URL(r.value).hostname : r.value;
    html += `<a href="https://www.virustotal.com/gui/domain/${encodeURIComponent(host)}" target="_blank" rel="noopener">VirusTotal</a>`;
    html += `<a href="https://urlscan.io/domain/${encodeURIComponent(host)}" target="_blank" rel="noopener">urlscan.io</a>`;
    html += `<a href="https://otx.alienvault.com/indicator/domain/${encodeURIComponent(host)}" target="_blank" rel="noopener">OTX</a>`;
    html += `<a href="https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(host)}" target="_blank" rel="noopener">URLhaus</a>`;
  } else if (r.type === 'md5' || r.type === 'sha1' || r.type === 'sha256') {
    html += `<a href="https://www.virustotal.com/gui/file/${encodeURIComponent(r.value)}" target="_blank" rel="noopener">VirusTotal</a>`;
    html += `<a href="https://bazaar.abuse.ch/sample/${encodeURIComponent(r.value)}/" target="_blank" rel="noopener">MalwareBazaar</a>`;
    html += `<a href="https://otx.alienvault.com/indicator/file/${encodeURIComponent(r.value)}" target="_blank" rel="noopener">OTX</a>`;
  } else if (r.type === 'cve') {
    html += `<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(r.value)}" target="_blank" rel="noopener">NVD</a>`;
    html += `<a href="https://cve.circl.lu/cve/${encodeURIComponent(r.value)}" target="_blank" rel="noopener">CIRCL</a>`;
    html += `<a href="https://www.exploit-db.com/search?cve=${encodeURIComponent(r.value)}" target="_blank" rel="noopener">Exploit-DB</a>`;
  }
  html += `</div></div>`;
  out.innerHTML = html;
}

/* ============================================================
   OSINT
   ============================================================ */
function renderOsint() {
  const grid = $('#osint-grid');
  if (!grid) return;
  grid.innerHTML = CONFIG.OSINT_ACCOUNTS.map((a) => {
    const tags = (a.tags || []).map((t) => `<span class="osint-tag">${escape(t)}</span>`).join('');
    const avatar = a.handle.slice(0, 2).toUpperCase();
    return `
    <div class="osint-card-v2">
      <div class="osint-v2-head">
        <div class="osint-avatar">${escape(avatar)}</div>
        <div class="osint-v2-meta">
          <div class="osint-v2-handle">@${escape(a.handle)}</div>
          <div class="osint-v2-name">${escape(a.label)}</div>
        </div>
      </div>
      <p class="osint-v2-bio">${escape(a.bio || '')}</p>
      <div class="osint-v2-tags">${tags}</div>
      <div class="osint-v2-actions">
        <a class="osint-v2-btn primary" href="https://x.com/${escape(a.handle)}" target="_blank" rel="noopener">𝕏 Profile</a>
        ${a.site ? `<a class="osint-v2-btn" href="${escape(a.site)}" target="_blank" rel="noopener">↗ Blog / site</a>` : ''}
        <a class="osint-v2-btn" href="https://nitter.net/${escape(a.handle)}" target="_blank" rel="noopener">🪞 Nitter</a>
      </div>
    </div>`;
  }).join('');
}

/* ============================================================
   STARS (localStorage favorites)
   ============================================================ */
const STAR_KEY = 'vni:stars';
function getStars() { try { return JSON.parse(localStorage.getItem(STAR_KEY) || '[]'); } catch { return []; } }
function isStarred(id) { return getStars().includes(id); }
function toggleStar(id) {
  const s = getStars();
  const i = s.indexOf(id);
  if (i >= 0) s.splice(i, 1); else s.push(id);
  localStorage.setItem(STAR_KEY, JSON.stringify(s));
}

/* ============================================================
   CHARTS
   ============================================================ */
let charts = {};
function destroyChart(k) { if (charts[k]) { charts[k].destroy(); delete charts[k]; } }
const CFONT = { family: 'Inter, sans-serif', size: 11 };
const TICK_COLOR = '#9da7b3';
const GRID_COLOR = 'rgba(255,255,255,0.05)';

function chartCommon() {
  return {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { labels: { color: TICK_COLOR, font: CFONT, boxWidth: 12 } },
      tooltip: {
        backgroundColor: '#161c24',
        borderColor: '#232a33',
        borderWidth: 1,
        titleColor: '#e6edf3',
        bodyColor: '#9da7b3',
        padding: 10,
        cornerRadius: 6,
      },
    },
  };
}

function drawSeverity(cves) {
  const ctx = $('#chart-severity');
  if (!ctx || !window.Chart) return;
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0 };
  cves.forEach((c) => { counts[c.sev] = (counts[c.sev] || 0) + 1; });
  destroyChart('sev');
  charts.sev = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: Object.keys(counts),
      datasets: [{
        data: Object.values(counts),
        backgroundColor: ['#f85149', '#fb8500', '#d4a72c', '#58a6ff', '#6b7480'],
        borderColor: '#12161c', borderWidth: 2,
      }],
    },
    options: { ...chartCommon(), cutout: '62%' },
  });
}

function drawKevTime(kev) {
  const ctx = $('#chart-kev-time');
  if (!ctx || !window.Chart) return;
  const now = new Date();
  const months = [], counts = [];
  for (let i = 11; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
    const key = d.toISOString().slice(0, 7);
    months.push(d.toLocaleString('en', { month: 'short', year: '2-digit' }));
    counts.push((kev.vulnerabilities || []).filter((v) => (v.dateAdded || '').startsWith(key)).length);
  }
  destroyChart('kevTime');
  charts.kevTime = new Chart(ctx, {
    type: 'bar',
    data: { labels: months, datasets: [{
      label: 'KEV added', data: counts,
      backgroundColor: 'rgba(63,185,80,0.55)', borderColor: '#3fb950', borderWidth: 1, borderRadius: 4,
    }]},
    options: { ...chartCommon(), scales: {
      x: { ticks: { color: TICK_COLOR, font: CFONT }, grid: { color: GRID_COLOR } },
      y: { ticks: { color: TICK_COLOR, font: CFONT }, grid: { color: GRID_COLOR }, beginAtZero: true }
    }},
  });
}

function drawVendor(kev) {
  const ctx = $('#chart-vendors');
  if (!ctx || !window.Chart) return;
  const m = {};
  (kev.vulnerabilities || []).forEach((v) => { m[v.vendorProject] = (m[v.vendorProject] || 0) + 1; });
  const top = Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 10);
  destroyChart('vendor');
  charts.vendor = new Chart(ctx, {
    type: 'bar',
    data: { labels: top.map(([v]) => v), datasets: [{
      label: 'CVEs', data: top.map(([, n]) => n),
      backgroundColor: 'rgba(88,166,255,0.5)', borderColor: '#58a6ff', borderWidth: 1, borderRadius: 4,
    }]},
    options: { ...chartCommon(), indexAxis: 'y', scales: {
      x: { ticks: { color: TICK_COLOR, font: CFONT }, grid: { color: GRID_COLOR }, beginAtZero: true },
      y: { ticks: { color: TICK_COLOR, font: CFONT }, grid: { color: GRID_COLOR } }
    }},
  });
}

function drawMalwareFamilies(threatfox) {
  const ctx = $('#chart-malware');
  if (!ctx || !window.Chart) return;
  const m = {};
  threatfox.forEach((t) => { const k = t.malware_printable || t.malware || 'unknown'; m[k] = (m[k] || 0) + 1; });
  const top = Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 10);
  destroyChart('mal');
  charts.mal = new Chart(ctx, {
    type: 'bar',
    data: { labels: top.map(([v]) => v), datasets: [{
      label: 'IOCs (last batch)', data: top.map(([, n]) => n),
      backgroundColor: 'rgba(248,81,73,0.5)', borderColor: '#f85149', borderWidth: 1, borderRadius: 4,
    }]},
    options: { ...chartCommon(), indexAxis: 'y', scales: {
      x: { ticks: { color: TICK_COLOR, font: CFONT }, grid: { color: GRID_COLOR }, beginAtZero: true },
      y: { ticks: { color: TICK_COLOR, font: CFONT }, grid: { color: GRID_COLOR } }
    }},
  });
}

function drawC2Geo(feodo) {
  const ctx = $('#chart-c2geo');
  if (!ctx || !window.Chart) return;
  const m = {};
  feodo.forEach((f) => { const k = f.country || 'unknown'; m[k] = (m[k] || 0) + 1; });
  const top = Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 12);
  destroyChart('c2');
  charts.c2 = new Chart(ctx, {
    type: 'bar',
    data: { labels: top.map(([v]) => v), datasets: [{
      label: 'Active C2 IPs', data: top.map(([, n]) => n),
      backgroundColor: 'rgba(212,167,44,0.5)', borderColor: '#d4a72c', borderWidth: 1, borderRadius: 4,
    }]},
    options: { ...chartCommon(), scales: {
      x: { ticks: { color: TICK_COLOR, font: CFONT }, grid: { color: GRID_COLOR } },
      y: { ticks: { color: TICK_COLOR, font: CFONT }, grid: { color: GRID_COLOR }, beginAtZero: true }
    }},
  });
}

/* ============================================================
   ACTIVE EXPLOITATION TRACKER
   ============================================================ */
const EXPLOIT_STATE = { filter: 'all', search: '' };

function buildExploitList() {
  // Combine KEV catalog with EPSS scores. Sources (in priority order):
  //   1. EPSS_KEV_MAP  — fetched specifically for KEV CVE IDs (covers all ages)
  //   2. STATE.cves    — the 7-day CVE feed already carries EPSS from enrichEPSS
  const kevVulns = STATE.kev?.vulnerabilities || [];
  const epssMap = {};
  STATE.cves.forEach((c) => { if (c.epss != null) epssMap[c.id] = c.epss; });

  const now = Date.now();
  const items = kevVulns.map((v) => {
    const added = new Date(v.dateAdded).getTime();
    const due   = v.dueDate ? new Date(v.dueDate).getTime() : null;
    const ageDays   = Math.floor((now - added) / 86400000);
    const dueDays   = due ? Math.floor((due - now) / 86400000) : null;
    const isRansom  = v.knownRansomwareCampaignUse === 'Known';
    const isOverdue = due && due < now;
    const isFresh   = ageDays <= 30;
    const epss      = EPSS_KEV_MAP.get(v.cveID) ?? epssMap[v.cveID] ?? null;
    const isHotEpss = epss != null && epss >= 0.5;

    // Priority score (higher = more urgent)
    let score = 0;
    if (isRansom)   score += 100;
    if (isOverdue)  score += 60;
    if (isFresh)    score += 40;
    if (isHotEpss)  score += 30 + Math.round(epss * 30);
    score += Math.max(0, 30 - ageDays);

    return {
      ...v,
      ageDays, dueDays,
      isRansom, isOverdue, isFresh, isHotEpss,
      epss,
      score,
      searchBlob: (v.cveID + ' ' + v.vendorProject + ' ' + v.product + ' ' + (v.vulnerabilityName||'')).toLowerCase(),
    };
  });

  items.sort((a, b) => b.score - a.score || new Date(b.dateAdded) - new Date(a.dateAdded));
  return items;
}

function renderExploitSummary(items) {
  const ransom  = items.filter((x) => x.isRansom).length;
  const overdue = items.filter((x) => x.isOverdue).length;
  const fresh   = items.filter((x) => x.isFresh).length;
  const hotEpss = items.filter((x) => x.isHotEpss).length;
  countUp($('#exp-ransomware'), ransom);
  countUp($('#exp-overdue'),    overdue);
  countUp($('#exp-fresh'),      fresh);
  countUp($('#exp-hot-epss'),   hotEpss);
}

function renderExploitList() {
  const grid = $('#exploit-grid');
  const all = buildExploitList();
  STATE.exploitItems = all;
  renderExploitSummary(all);

  // Apply filter
  let items = all;
  if (EXPLOIT_STATE.filter === 'ransomware') items = items.filter((x) => x.isRansom);
  else if (EXPLOIT_STATE.filter === 'overdue')   items = items.filter((x) => x.isOverdue);
  else if (EXPLOIT_STATE.filter === 'fresh')     items = items.filter((x) => x.isFresh);
  else if (EXPLOIT_STATE.filter === 'epss')      items = items.filter((x) => x.isHotEpss);

  if (EXPLOIT_STATE.search) items = items.filter((x) => x.searchBlob.includes(EXPLOIT_STATE.search));

  const sliced = items.slice(0, 60);
  setStatus('exploit', 'ok', `${all.length} tracked · ${items.length} shown`);

  if (!sliced.length) {
    grid.innerHTML = '<div class="loading-card">No CVEs match the current filter.</div>';
    return;
  }

  grid.classList.remove('in');
  grid.innerHTML = sliced.map((x) => {
    const tags = [];
    if (x.isRansom)   tags.push(`<span class="exploit-tag t-ransom">🦠 Ransomware</span>`);
    if (x.isOverdue)  tags.push(`<span class="exploit-tag t-overdue">⏰ Overdue ${Math.abs(x.dueDays)}d</span>`);
    else if (x.dueDays != null && x.dueDays <= 14) tags.push(`<span class="exploit-tag t-due-soon">⏱ Due in ${x.dueDays}d</span>`);
    if (x.isFresh)    tags.push(`<span class="exploit-tag t-fresh">🆕 ${x.ageDays}d ago</span>`);
    if (x.isHotEpss)  tags.push(`<span class="exploit-tag t-epss-hot">📈 EPSS ${(x.epss*100).toFixed(0)}%</span>`);
    const cardCls = `exploit-card ${x.isRansom ? 'ransomware' : ''} ${x.isOverdue ? 'overdue' : ''} ${x.isRansom ? 'pulse-critical' : ''}`;
    return `
      <div class="${cardCls}">
        <div class="exploit-head">
          <div class="exploit-cve"><a href="https://nvd.nist.gov/vuln/detail/${escape(x.cveID)}" target="_blank" rel="noopener">${escape(x.cveID)}</a></div>
          <div class="exploit-vendor">${escape(x.vendorProject)}<span class="sep">/</span>${escape(x.product)}</div>
        </div>
        <div class="exploit-name">${escape(truncate(x.vulnerabilityName || x.shortDescription || '', 180))}</div>
        <div class="exploit-tags">${tags.join('')}</div>
        <div class="exploit-meta">
          <span>Added: <strong>${escape(x.dateAdded)}</strong></span>
          <span>Due: <strong>${escape(x.dueDate || '—')}</strong></span>
          <span>Action required: <strong>${escape(truncate(x.requiredAction || '—', 60))}</strong></span>
          <span>Notes: <strong>${escape(truncate(x.notes || '—', 60))}</strong></span>
        </div>
        <div class="exploit-actions">
          <a href="https://nvd.nist.gov/vuln/detail/${escape(x.cveID)}" target="_blank" rel="noopener">NVD</a>
          <a href="https://cve.circl.lu/cve/${escape(x.cveID)}" target="_blank" rel="noopener">CIRCL</a>
          <a href="https://www.exploit-db.com/search?cve=${escape(x.cveID)}" target="_blank" rel="noopener">Exploit-DB</a>
          <a href="https://github.com/search?q=${escape(x.cveID)}&type=repositories" target="_blank" rel="noopener">GitHub PoC</a>
        </div>
      </div>
    `;
  }).join('');
  // Trigger stagger animation
  requestAnimationFrame(() => grid.classList.add('in'));

  drawExploitTimeline(all);
  drawExploitProducts(all);
  drawEpssTop();
}

function drawExploitTimeline(items) {
  const ctx = $('#chart-exploit-timeline');
  if (!ctx || !window.Chart) return;
  const days = 90;
  const labels = [];
  const totals = [];
  const ransoms = [];
  const today = new Date();
  today.setUTCHours(0, 0, 0, 0);
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(today.getTime() - i * 86400000);
    const key = d.toISOString().slice(0, 10);
    labels.push(i % 7 === 0 ? d.toLocaleString('en', { month: 'short', day: 'numeric' }) : '');
    const day = items.filter((x) => x.dateAdded === key);
    totals.push(day.length);
    ransoms.push(day.filter((x) => x.isRansom).length);
  }
  destroyChart('expTimeline');
  charts.expTimeline = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [
        { label: 'KEV added',  data: totals, backgroundColor: 'rgba(63,185,80,0.55)',  borderColor: '#3fb950', borderWidth: 1, borderRadius: 3 },
        { label: 'Ransomware', data: ransoms, backgroundColor: 'rgba(248,81,73,0.7)',  borderColor: '#f85149', borderWidth: 1, borderRadius: 3 },
      ],
    },
    options: { ...chartCommon(),
      scales: {
        x: { stacked: false, ticks: { color: TICK_COLOR, font: CFONT, autoSkip: false }, grid: { color: GRID_COLOR } },
        y: { ticks: { color: TICK_COLOR, font: CFONT, precision: 0 }, grid: { color: GRID_COLOR }, beginAtZero: true },
      },
    },
  });
}

function drawExploitProducts(items) {
  const ctx = $('#chart-exploit-products');
  if (!ctx || !window.Chart) return;
  const m = {};
  items.forEach((x) => {
    const k = (x.vendorProject || '') + ' ' + (x.product || '');
    m[k] = (m[k] || 0) + 1;
  });
  const top = Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 10);
  destroyChart('expProd');
  charts.expProd = new Chart(ctx, {
    type: 'bar',
    data: { labels: top.map(([v]) => v), datasets: [{
      label: 'KEV count', data: top.map(([, n]) => n),
      backgroundColor: 'rgba(251,133,0,0.55)', borderColor: '#fb8500', borderWidth: 1, borderRadius: 4,
    }]},
    options: { ...chartCommon(), indexAxis: 'y', scales: {
      x: { ticks: { color: TICK_COLOR, font: CFONT }, grid: { color: GRID_COLOR }, beginAtZero: true },
      y: { ticks: { color: TICK_COLOR, font: CFONT }, grid: { color: GRID_COLOR } },
    }},
  });
}

async function drawEpssTop() {
  const ctx = $('#chart-epss-top');
  if (!ctx || !window.Chart) return;
  try {
    const r = await timedFetch(CONFIG.EPSS_TOP);
    if (!r.ok) return;
    const data = await r.json();
    const top = (data.data || []).slice(0, 15);
    destroyChart('epssTop');
    charts.epssTop = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: top.map((d) => d.cve),
        datasets: [{
          label: 'EPSS probability',
          data: top.map((d) => parseFloat(d.epss) * 100),
          backgroundColor: top.map((d) => parseFloat(d.epss) >= 0.9 ? 'rgba(248,81,73,0.7)' : 'rgba(251,133,0,0.55)'),
          borderColor: '#f85149', borderWidth: 1, borderRadius: 3,
        }],
      },
      options: { ...chartCommon(), indexAxis: 'y',
        plugins: { ...chartCommon().plugins, tooltip: {
          ...chartCommon().plugins.tooltip,
          callbacks: { label: (c) => `EPSS: ${c.parsed.x.toFixed(2)}%` },
        }},
        scales: {
          x: { ticks: { color: TICK_COLOR, font: CFONT, callback: (v) => v + '%' }, grid: { color: GRID_COLOR }, beginAtZero: true, max: 100 },
          y: { ticks: { color: TICK_COLOR, font: { ...CFONT, family: 'JetBrains Mono, monospace' } }, grid: { color: GRID_COLOR } },
        },
      },
    });
  } catch (e) { /* silent */ }
}

/* ============================================================
   GLOBAL THREAT MAP — Leaflet
   ============================================================ */
const COUNTRY_CENTROIDS = {
  AD:[42.5,1.6],AE:[24,54],AF:[33,65],AG:[17.05,-61.8],AI:[18.25,-63.17],AL:[41,20],AM:[40,45],AO:[-12.5,18.5],
  AR:[-34,-64],AT:[47.33,13.33],AU:[-27,133],AZ:[40.5,47.5],BA:[44,18],BB:[13.17,-59.53],BD:[24,90],BE:[50.83,4],
  BF:[13,-2],BG:[43,25],BH:[26,50.55],BI:[-3.5,30],BJ:[9.5,2.25],BN:[4.5,114.67],BO:[-17,-65],BR:[-10,-55],
  BS:[24.25,-76],BT:[27.5,90.5],BW:[-22,24],BY:[53,28],BZ:[17.25,-88.75],CA:[60,-95],CD:[0,25],CF:[7,21],
  CG:[-1,15],CH:[47,8],CI:[8,-5],CL:[-30,-71],CM:[6,12],CN:[35,105],CO:[4,-72],CR:[10,-84],CU:[21.5,-80],
  CV:[16,-24],CY:[35,33],CZ:[49.75,15.5],DE:[51,9],DJ:[11.5,43],DK:[56,10],DO:[19,-70.67],DZ:[28,3],EC:[-2,-77.5],
  EE:[59,26],EG:[27,30],ER:[15,39],ES:[40,-4],ET:[8,38],FI:[64,26],FJ:[-18,178],FR:[46,2],GA:[-1,11.75],
  GB:[54,-2],GE:[42,43.5],GH:[8,-2],GM:[13.47,-16.57],GN:[11,-10],GQ:[2,10],GR:[39,22],GT:[15.5,-90.25],
  GW:[12,-15],GY:[5,-59],HK:[22.25,114.17],HN:[15,-86.5],HR:[45.17,15.5],HT:[19,-72.42],HU:[47,20],ID:[-5,120],
  IE:[53,-8],IL:[31.5,34.75],IN:[20,77],IQ:[33,44],IR:[32,53],IS:[65,-18],IT:[42.83,12.83],JM:[18.25,-77.5],
  JO:[31,36],JP:[36,138],KE:[1,38],KG:[41,75],KH:[13,105],KI:[1.42,173],KM:[-12.17,44.25],KP:[40,127],
  KR:[37,127.5],KW:[29.34,47.66],KZ:[48,68],LA:[18,105],LB:[33.83,35.83],LC:[13.88,-60.97],LI:[47.27,9.53],
  LK:[7,81],LR:[6.5,-9.5],LS:[-29.5,28.25],LT:[56,24],LU:[49.75,6.17],LV:[57,25],LY:[25,17],MA:[32,-5],
  MC:[43.73,7.4],MD:[47,29],ME:[42.5,19.3],MG:[-20,47],MH:[7.12,171.07],MK:[41.83,22],ML:[17,-4],MM:[22,98],
  MN:[46,105],MO:[22.17,113.55],MR:[20,-12],MT:[35.83,14.58],MU:[-20.28,57.55],MV:[3.25,73],MW:[-13.5,34],
  MX:[23,-102],MY:[2.5,112.5],MZ:[-18.25,35],NA:[-22,17],NC:[-21.5,165.5],NE:[16,8],NG:[10,8],NI:[13,-85],
  NL:[52.5,5.75],NO:[62,10],NP:[28,84],NR:[-0.53,166.92],NZ:[-41,174],OM:[21,57],PA:[9,-80],PE:[-10,-76],
  PG:[-6,147],PH:[13,122],PK:[30,70],PL:[52,20],PR:[18.25,-66.5],PS:[31.92,35.2],PT:[39.5,-8],PW:[7.5,134.5],
  PY:[-23,-58],QA:[25.5,51.25],RO:[46,25],RS:[44,21],RU:[60,100],RW:[-2,30],SA:[25,45],SB:[-8,159],
  SC:[-4.58,55.67],SD:[15,30],SE:[62,15],SG:[1.37,103.8],SI:[46.12,14.82],SK:[48.67,19.5],SL:[8.5,-11.5],
  SM:[43.93,12.42],SN:[14,-14],SO:[10,49],SR:[4,-56],SS:[7,30],ST:[1,7],SV:[13.83,-88.92],SY:[35,38],
  SZ:[-26.5,31.5],TD:[15,19],TG:[8,1.17],TH:[15,100],TJ:[39,71],TL:[-8.83,125.92],TM:[40,60],TN:[34,9],
  TO:[-20,-175],TR:[39,35],TT:[11,-61],TV:[-8,178],TW:[23.5,121],TZ:[-6,35],UA:[49,32],UG:[1,32],
  US:[38,-97],UY:[-33,-56],UZ:[41,64],VA:[41.9,12.45],VC:[13.25,-61.2],VE:[8,-66],VN:[16,106],VU:[-16,167],
  WS:[-13.58,-172.33],XK:[42.67,21.17],YE:[15,48],ZA:[-29,24],ZM:[-15,30],ZW:[-20,30],
};

let map_, mapLayer_, attackLayer_, arcsTimer_, attackBuffer_ = [];

function ensureMap() {
  if (map_) return map_;
  if (typeof L === 'undefined') return null;
  map_ = L.map('threat-map', {
    center: [25, 10],
    zoom: 2,
    minZoom: 2,
    maxZoom: 6,
    worldCopyJump: true,
    zoomControl: true,
    attributionControl: false,
    preferCanvas: true,
  });
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_nolabels/{z}/{x}/{y}{r}.png', {
    subdomains: 'abcd',
    maxZoom: 19,
  }).addTo(map_);
  mapLayer_   = L.layerGroup().addTo(map_);
  attackLayer_= L.layerGroup().addTo(map_);
  return map_;
}

function renderThreatMap(feodo) {
  if (typeof L === 'undefined') { setStatus('map', 'error', 'Leaflet not loaded'); return; }
  if (!feodo?.length) { setStatus('map', 'error', 'no C2 data'); return; }
  const m = ensureMap();
  if (!m) return;

  setStatus('map', 'loading', 'plotting');

  // Aggregate by country
  const byCountry = {};
  feodo.forEach((f) => {
    if (!f.country) return;
    const key = f.country.toUpperCase();
    byCountry[key] ??= { count: 0, malware: {}, samples: [] };
    byCountry[key].count++;
    byCountry[key].malware[f.malware] = (byCountry[key].malware[f.malware] || 0) + 1;
    if (byCountry[key].samples.length < 4) byCountry[key].samples.push(f);
  });

  // Clear existing
  mapLayer_.clearLayers();

  let plotted = 0;
  Object.entries(byCountry).forEach(([cc, info]) => {
    const ll = COUNTRY_CENTROIDS[cc];
    if (!ll) return;
    plotted++;
    const n = info.count;
    const tier = n >= 20 ? 'high' : n >= 5 ? 'mid' : 'low';
    const color = tier === 'high' ? '#f85149' : tier === 'mid' ? '#fb8500' : '#d4a72c';
    const radius = Math.min(28, 6 + Math.sqrt(n) * 3);

    // Outer pulse (decorative div icon)
    const pulse = L.divIcon({
      className: `c2-pulse pulse-${tier}`,
      iconSize: [radius * 2, radius * 2],
      iconAnchor: [radius, radius],
      html: `<span></span>`,
    });
    L.marker(ll, { icon: pulse, interactive: false, keyboard: false }).addTo(mapLayer_);

    // Inner clickable marker
    const dot = L.circleMarker(ll, {
      radius: 5,
      color, fillColor: color, fillOpacity: 0.95, weight: 2, opacity: 1,
    }).addTo(mapLayer_);

    const malwareList = Object.entries(info.malware).sort((a, b) => b[1] - a[1])
      .map(([k, v]) => `${k} (${v})`).join('<br/>');
    dot.bindPopup(`
      <div style="font-family:'JetBrains Mono',monospace;color:#e6edf3">
        <div style="font-size:14px;font-weight:700;margin-bottom:6px">${escape(cc)}</div>
        <div style="color:#9da7b3;margin-bottom:4px">${n} active C2 server${n>1?'s':''}</div>
        <div style="color:#9da7b3;font-size:11px;line-height:1.5">${malwareList}</div>
      </div>
    `);
  });

  // Side panel — top countries
  const top = Object.entries(byCountry).sort((a, b) => b[1].count - a[1].count).slice(0, 12);
  const topEl = $('#top-countries');
  if (topEl) {
    topEl.innerHTML = top.map(([cc, info], i) => {
      const tier = info.count >= 20 ? 'high' : info.count >= 5 ? 'mid' : 'low';
      return `<li class="tc-row" data-cc="${escape(cc)}">
        <span class="tc-rank">#${i+1}</span>
        <span class="tc-flag">${countryFlag(cc)}</span>
        <span class="tc-name">${escape(cc)}</span>
        <span class="tc-count tier-${tier}">${info.count}</span>
      </li>`;
    }).join('');
    $$('#top-countries .tc-row').forEach((row) => {
      row.addEventListener('click', () => {
        const cc = row.dataset.cc;
        const ll = COUNTRY_CENTROIDS[cc];
        if (ll && map_) map_.flyTo(ll, 5, { duration: 1.0 });
      });
    });
  }

  // Stats overlay
  $('#map-stat-c2')?.replaceChildren(document.createTextNode(feodo.length.toString()));
  $('#map-stat-countries')?.replaceChildren(document.createTextNode(Object.keys(byCountry).length.toString()));

  // Build attack pairs for animated arcs
  attackBuffer_ = [];
  feodo.slice(0, 100).forEach((f) => {
    const cc = (f.country || '').toUpperCase();
    if (COUNTRY_CENTROIDS[cc]) attackBuffer_.push({
      from: cc,
      to: pickTarget(cc),
      malware: f.malware,
      ip: f.ip_address,
    });
  });

  if (arcsTimer_) clearInterval(arcsTimer_);
  arcsTimer_ = setInterval(spawnArc, 1800);
  setStatus('map', 'ok', `${plotted} countries`);
}

const TARGETS = ['US','GB','DE','FR','JP','IN','AU','CA','BR','SG','KR','NL','IT','ES','MX','ZA','SE','NO','PL','TR'];
function pickTarget(notCc) {
  let p = TARGETS[Math.floor(Math.random() * TARGETS.length)];
  if (p === notCc) p = TARGETS[(TARGETS.indexOf(p) + 3) % TARGETS.length];
  return p;
}

function countryFlag(cc) {
  if (!cc || cc.length !== 2) return '🌐';
  const A = 0x1F1E6;
  const code = cc.toUpperCase();
  return String.fromCodePoint(A + code.charCodeAt(0) - 65, A + code.charCodeAt(1) - 65);
}

let attackCount_ = 0;
function spawnArc() {
  if (document.hidden) return;
  if (!map_ || !attackBuffer_.length || !attackLayer_) return;
  const a = attackBuffer_[Math.floor(Math.random() * attackBuffer_.length)];
  const from = COUNTRY_CENTROIDS[a.from];
  const to   = COUNTRY_CENTROIDS[a.to];
  if (!from || !to) return;

  // Build curved bezier via intermediate points
  const pts = curvedPath(from, to, 28);
  const line = L.polyline(pts, {
    color: '#f85149', weight: 1.4, opacity: 0.85,
    dashArray: '4 8', className: 'attack-arc',
  }).addTo(attackLayer_);

  // Endpoint flash
  const endDot = L.circleMarker(to, { radius: 4, color: '#f85149', fillColor: '#ff6b6b', fillOpacity: 1, weight: 0 }).addTo(attackLayer_);

  setTimeout(() => { attackLayer_.removeLayer(line); attackLayer_.removeLayer(endDot); }, 2600);

  attackCount_++;
  $('#map-stat-attacks')?.replaceChildren(document.createTextNode(attackCount_.toString()));

  // Live feed
  const feed = $('#attack-feed');
  if (feed) {
    const row = document.createElement('div');
    row.className = 'attack-row';
    row.innerHTML = `
      <span class="attack-time">${new Date().toISOString().slice(11,19)}</span>
      <span class="attack-flag">${countryFlag(a.from)}</span>
      <span class="attack-cc">${escape(a.from)}</span>
      <span class="attack-arrow">→</span>
      <span class="attack-flag">${countryFlag(a.to)}</span>
      <span class="attack-cc">${escape(a.to)}</span>
      <span class="attack-malware">${escape(a.malware || 'C2')}</span>
    `;
    // Remove placeholder
    const empty = feed.querySelector('.attack-empty');
    if (empty) empty.remove();
    feed.prepend(row);
    while (feed.children.length > 20) feed.removeChild(feed.lastChild);
  }
}

function curvedPath(from, to, steps) {
  // Quadratic bezier through a midpoint lifted perpendicular to the great-circle midpoint
  const [y1, x1] = from, [y2, x2] = to;
  const mx = (x1 + x2) / 2;
  const my = (y1 + y2) / 2;
  // perpendicular vector
  const dx = x2 - x1, dy = y2 - y1;
  const len = Math.hypot(dx, dy);
  const nx = -dy / (len || 1), ny = dx / (len || 1);
  // arc height proportional to distance
  const h = Math.min(40, len * 0.4);
  const cx = mx + nx * h;
  const cy = my + ny * h;
  const out = [];
  for (let i = 0; i <= steps; i++) {
    const t = i / steps;
    const lon = (1-t)*(1-t)*x1 + 2*(1-t)*t*cx + t*t*x2;
    const lat = (1-t)*(1-t)*y1 + 2*(1-t)*t*cy + t*t*y2;
    out.push([lat, lon]);
  }
  return out;
}

/* ============================================================
   COUNT-UP ANIMATION
   ============================================================ */
function countUp(el, target) {
  if (!el) return;
  if (target == null || target === '—' || isNaN(target)) { el.textContent = '—'; return; }
  const from = parseInt(el.textContent.replace(/\D/g, ''), 10) || 0;
  const to = Number(target);
  if (from === to) { el.textContent = to.toLocaleString(); return; }
  const dur = 700;
  const start = performance.now();
  function step(now) {
    const t = Math.min(1, (now - start) / dur);
    const eased = 1 - Math.pow(1 - t, 3);
    const v = Math.round(from + (to - from) * eased);
    el.textContent = v.toLocaleString();
    if (t < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

/* ============================================================
   SCROLL REVEAL
   ============================================================ */
function initRevealObserver() {
  if (!('IntersectionObserver' in window)) {
    // Fallback: just show everything
    $$('.section, .stat').forEach((s) => s.classList.add('reveal', 'in'));
    return;
  }
  const io = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (e.isIntersecting) {
        e.target.classList.add('in');
        io.unobserve(e.target);
      }
    });
  }, { threshold: 0, rootMargin: '0px 0px 200px 0px' });

  $$('.section').forEach((s) => { s.classList.add('reveal'); io.observe(s); });
  $$('.stat').forEach((s) => { s.classList.add('reveal'); io.observe(s); });
}

/* ============================================================
   STATS
   ============================================================ */
function updateStats(state) {
  countUp($('#stat-cve'),     state.cves?.length || 0);
  countUp($('#stat-kev'),     state.kev?.count   || 0);
  countUp($('#stat-crit'),    state.cves?.filter((c) => c.sev === 'CRITICAL').length || 0);
  countUp($('#stat-news'),    state.news?.filter((n) => n.date && (Date.now() - new Date(n.date).getTime()) < 86400000).length || 0);
  const countries = new Set((state.feodo || []).map((f) => f.country).filter(Boolean));
  countUp($('#stat-countries'), countries.size);
  const lastMonth = Date.now() - 30 * 86400000;
  countUp($('#stat-kev-new'), (state.kev?.vulnerabilities || []).filter((v) => new Date(v.dateAdded).getTime() > lastMonth).length);
  countUp($('#stat-iocs'),    (state.threatfox?.length || 0) + (state.urlhaus?.length || 0));
  countUp($('#stat-c2'),      state.feodo?.length || 0);
  // Keep the composite threat gauge and degraded banner in sync with any refresh.
  try { renderThreatGauge?.(); } catch (_) {}
  try { updateDegradedBanner?.(); } catch (_) {}
}

/* ============================================================
   GLOBAL SEARCH
   ============================================================ */
function globalSearch(q) {
  q = q.trim().toLowerCase();
  const out = $('#search-results');
  if (!q) { out.innerHTML = ''; out.style.display = 'none'; return; }
  const hits = [];
  STATE.cves.forEach((c) => { if (c.searchBlob.includes(q)) hits.push({ section: 'CVE', label: c.id + ' — ' + truncate(c.desc, 80), link: 'https://nvd.nist.gov/vuln/detail/' + c.id }); });
  (STATE.kev.vulnerabilities || []).forEach((v) => {
    if ((v.cveID + v.vendorProject + v.product + v.vulnerabilityName).toLowerCase().includes(q))
      hits.push({ section: 'KEV', label: v.cveID + ' — ' + v.vendorProject + '/' + v.product, link: 'https://nvd.nist.gov/vuln/detail/' + v.cveID });
  });
  STATE.news.forEach((n) => { if ((n.title + ' ' + n.desc).toLowerCase().includes(q)) hits.push({ section: 'News', label: n.title, link: n.link }); });
  STATE.exploits.forEach((n) => { if ((n.title + ' ' + n.desc).toLowerCase().includes(q)) hits.push({ section: 'Exploit', label: n.title, link: n.link }); });
  out.style.display = 'block';
  if (!hits.length) { out.innerHTML = '<div class="search-empty">No results across loaded feeds.</div>'; return; }
  out.innerHTML = hits.slice(0, 30).map((h) => `
    <a class="search-hit" href="${escape(h.link)}" target="_blank" rel="noopener">
      <span class="search-section">${escape(h.section)}</span>
      <span class="search-label">${escape(h.label)}</span>
    </a>
  `).join('');
}

/* ============================================================
   EXPORT
   ============================================================ */
function exportAll() {
  const blob = new Blob([JSON.stringify({ exportedAt: new Date().toISOString(), state: STATE }, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `venom-intel-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

/* ============================================================
   STATE + ORCHESTRATION
   ============================================================ */
const STATE = { cves: [], kev: { vulnerabilities: [], count: 0 }, news: [], exploits: [], urlhaus: [], threatfox: [], feodo: [], breach: [] };

async function refreshCVE() {
  STATE.cves = await fetchCVEs();
  drawSeverity(STATE.cves);
  updateStats(STATE);
  await enrichEPSS(STATE.cves);
  renderCVEs(STATE.cves);
  if (STATE.kev?.vulnerabilities?.length) renderExploitList();
}
async function refreshKEV() {
  STATE.kev = await fetchKEV();
  renderKEV(STATE.kev);
  drawKevTime(STATE.kev);
  drawVendor(STATE.kev);
  updateStats(STATE);
  renderExploitList();
  // Best-effort EPSS enrichment for the full KEV set. Runs in background so
  // it doesn't block the first render — re-renders when done.
  enrichEPSSforKEV(STATE.kev).then(() => renderExploitList()).catch(() => {});
}
async function refreshNews() {
  STATE.news = await fetchRssSet(CONFIG.RSS_FEEDS.news, 'news');
  renderNews(STATE.news);
  updateStats(STATE);
}
async function refreshExploits() {
  STATE.exploits = await fetchRssSet(CONFIG.RSS_FEEDS.exploits, 'exploits');
  renderExploits(STATE.exploits);
}
async function refreshURLhaus()   { STATE.urlhaus   = await fetchURLhaus();   renderURLhaus(STATE.urlhaus); updateStats(STATE); }
async function refreshThreatFox() { STATE.threatfox = await fetchThreatFox(); renderThreatFox(STATE.threatfox); drawMalwareFamilies(STATE.threatfox); updateStats(STATE); }
async function refreshFeodo()     { STATE.feodo     = await fetchFeodo();     renderFeodo(STATE.feodo); drawC2Geo(STATE.feodo); renderThreatMap(STATE.feodo); updateStats(STATE); }
async function refreshBreaches()  { STATE.breach    = await fetchBreaches();  renderBreaches(STATE.breach); }

async function refreshAll() {
  ['cves','kev','news','exploits','urlhaus','threatfox','feodo','breach'].forEach((k) => {
    const c = cache.get(k);
    if (c) STATE[k] = c;
  });
  if (STATE.cves.length) { renderCVEs(STATE.cves); drawSeverity(STATE.cves); }
  if (STATE.kev?.vulnerabilities?.length) { renderKEV(STATE.kev); drawKevTime(STATE.kev); drawVendor(STATE.kev); }
  if (STATE.news.length) renderNews(STATE.news);
  if (STATE.exploits.length) renderExploits(STATE.exploits);
  if (STATE.urlhaus.length) renderURLhaus(STATE.urlhaus);
  if (STATE.threatfox.length) { renderThreatFox(STATE.threatfox); drawMalwareFamilies(STATE.threatfox); }
  if (STATE.feodo.length) { renderFeodo(STATE.feodo); drawC2Geo(STATE.feodo); renderThreatMap(STATE.feodo); }
  if (STATE.breach.length) renderBreaches(STATE.breach);
  updateStats(STATE);

  // Above-the-fold / critical path: KEV (Exploitation Tracker) + Feodo (map) + CVE.
  const critical = Promise.all([refreshKEV(), refreshFeodo(), refreshCVE()]);

  // Below-the-fold: defer to idle so we don't fight first paint for bandwidth/CPU.
  onIdle(() => {
    refreshNews();
    refreshExploits();
    refreshURLhaus();
    refreshThreatFox();
    refreshBreaches();
  });

  await critical;
}

/* ============================================================
   EVENTS
   ============================================================ */
function wireEvents() {
  const dRenderKEV    = debounce(() => renderKEV(STATE.kev), 150);
  const dRenderCVEs   = debounce(() => renderCVEs(STATE.cves), 150);
  const dGlobalSearch = debounce((v) => globalSearch(v), 200);
  $('#kev-search')?.addEventListener('input',  dRenderKEV);
  $('#cve-severity')?.addEventListener('change', () => renderCVEs(STATE.cves));
  $('#cve-product')?.addEventListener('input', dRenderCVEs);
  $('#global-search')?.addEventListener('input', (e) => dGlobalSearch(e.target.value));
  // Click outside the search input + results panel closes the results.
  document.addEventListener('click', (e) => {
    const input = $('#global-search'), results = $('#search-results');
    if (!results || results.style.display === 'none') return;
    if (e.target === input || results.contains(e.target)) return;
    results.style.display = 'none';
  });
  // Esc while search input is focused clears + closes results.
  $('#global-search')?.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    e.target.value = '';
    const r = $('#search-results');
    if (r) { r.innerHTML = ''; r.style.display = 'none'; }
    e.target.blur();
  });
  $('#export-btn')?.addEventListener('click', exportAll);
  $('#refresh-all')?.addEventListener('click', () => {
    const b = $('#refresh-all');
    b.disabled = true; b.textContent = 'Refreshing…';
    refreshAll().finally(() => { b.disabled = false; b.textContent = 'Refresh all'; });
  });

  // Active Exploitation filters
  $$('#exploit-filters .chip-btn').forEach((b) => {
    b.addEventListener('click', () => {
      $$('#exploit-filters .chip-btn').forEach((x) => x.classList.remove('active'));
      b.classList.add('active');
      EXPLOIT_STATE.filter = b.dataset.filter;
      renderExploitList();
    });
  });
  const dExploitRender = debounce(() => renderExploitList(), 150);
  $('#exploit-search')?.addEventListener('input', (e) => {
    EXPLOIT_STATE.search = e.target.value.trim().toLowerCase();
    dExploitRender();
  });

  $('#ioc-go')?.addEventListener('click', async () => {
    const v = $('#ioc-input').value.trim();
    if (!v) return;
    $('#ioc-output').innerHTML = '<div class="ioc-card">Looking up…</div>';
    const r = await IOC.lookup(v);
    renderIocResult(r);
  });
  $('#ioc-input')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#ioc-go').click(); });

  $('#diag-toggle')?.addEventListener('click', () => {
    const d = $('#diag-panel');
    d.classList.toggle('open');
    $('#diag-toggle').textContent = d.classList.contains('open') ? 'Hide diagnostics' : 'Show diagnostics';
  });

  $$('[data-refresh]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const orig = btn.textContent;
      btn.textContent = 'Refreshing…';
      btn.disabled = true;
      const fn = {
        kev: refreshKEV, cve: refreshCVE, news: refreshNews,
        exploits: refreshExploits, urlhaus: refreshURLhaus, threatfox: refreshThreatFox,
        feodo: refreshFeodo, breach: refreshBreaches,
      }[btn.dataset.refresh];
      Promise.resolve(fn && fn()).finally(() => { btn.textContent = orig; btn.disabled = false; });
    });
  });
}

/* ============================================================
   FEATURE BLOCK — diff badges · per-section export · rule gen ·
   KEV watchlist + notifications · keyboard shortcuts.
   Added in june 2026. All client-side, no infra.
   ============================================================ */

/* ---- localStorage keys ---- */
const VISIT_KEY = 'vni:lastVisit';
const WATCH_KEY = 'vni:watchedCves';
const NOTIFY_PROMPTED_KEY = 'vni:notifyPrompted';
const KEV_SEEN_KEY = 'vni:kevSeenIds';

/* ---- 1. SINCE-LAST-VISIT DIFF ----
   Snapshot the stored timestamp ONCE at module load so concurrent
   render-after-fetch and the visit-bump don't race against each other. */
const SESSION_LAST_VISIT = parseInt(localStorage.getItem(VISIT_KEY) || '0', 10) || 0;
const bumpLastVisit = () => localStorage.setItem(VISIT_KEY, Date.now().toString());
function countSince(items, dateFn, since) {
  if (!since || !items?.length) return 0;
  return items.filter((x) => { try { return new Date(dateFn(x)).getTime() > since; } catch { return false; } }).length;
}
function renderDiffBadges() {
  const since = SESSION_LAST_VISIT;
  if (!since) return;
  const sinceStr = new Date(since).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  const diffs = {
    'status-kev':       countSince(STATE.kev?.vulnerabilities, (v) => v.dateAdded, since),
    'status-feodo':     countSince(STATE.feodo,                (f) => f.first_seen, since),
    'status-threatfox': countSince(STATE.threatfox,            (t) => t.first_seen_utc || t.first_seen, since),
    'status-urlhaus':   countSince(STATE.urlhaus,              (u) => u.dateadded, since),
    'status-breach':    countSince(STATE.breach,               (b) => b.breachedDate || b.date, since),
  };
  Object.entries(diffs).forEach(([id, n]) => {
    const anchor = document.getElementById(id);
    if (!anchor) return;
    anchor.parentElement?.querySelector('.diff-badge')?.remove();
    if (n > 0) {
      const b = document.createElement('span');
      b.className = 'diff-badge';
      b.title = `${n} new since you last visited (${sinceStr})`;
      b.textContent = `✨ ${n} new`;
      anchor.insertAdjacentElement('afterend', b);
    }
  });
}

/* ---- 2. PER-SECTION EXPORT ---- */
function csvCell(v) {
  if (v == null) return '';
  const s = String(v).replace(/"/g, '""');
  return /[",\n\r]/.test(s) ? `"${s}"` : s;
}
function toCSV(rows, cols) {
  if (!rows.length) return '';
  const head = cols.join(',');
  const body = rows.map((r) => cols.map((c) => csvCell(r[c])).join(',')).join('\n');
  return head + '\n' + body + '\n';
}
function downloadBlob(filename, mime, content) {
  const blob = new Blob([content], { type: mime });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 100);
}
const uuid = () => 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
  const r = (Math.random() * 16) | 0; return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
});
function nowISO() { return new Date().toISOString(); }

/* STIX 2.1 indicator pattern from raw value + type hint */
function stixPattern(value, hint) {
  if (hint === 'ipv4' || /^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return `[ipv4-addr:value = '${value}']`;
  if (hint === 'sha256' || /^[a-f0-9]{64}$/i.test(value)) return `[file:hashes.'SHA-256' = '${value}']`;
  if (hint === 'sha1' || /^[a-f0-9]{40}$/i.test(value)) return `[file:hashes.'SHA-1' = '${value}']`;
  if (hint === 'md5' || /^[a-f0-9]{32}$/i.test(value)) return `[file:hashes.MD5 = '${value}']`;
  if (hint === 'url' || /^https?:\/\//i.test(value)) return `[url:value = '${value.replace(/'/g, "\\'")}']`;
  if (hint === 'domain' || /^[\w.-]+\.[a-z]{2,}$/i.test(value)) return `[domain-name:value = '${value}']`;
  return `[x-unknown:value = '${value}']`;
}
function toSTIX(items, builder) {
  const objects = [{ type: 'identity', spec_version: '2.1', id: 'identity--' + uuid(), created: nowISO(), modified: nowISO(), name: 'VENOM/INTEL', identity_class: 'organization' }];
  items.forEach((row) => {
    const { value, type, name, description, labels } = builder(row);
    if (!value) return;
    objects.push({
      type: 'indicator', spec_version: '2.1', id: 'indicator--' + uuid(),
      created: nowISO(), modified: nowISO(),
      name: name || value, description: description || '',
      indicator_types: labels || ['malicious-activity'],
      pattern: stixPattern(value, type), pattern_type: 'stix', valid_from: nowISO(),
    });
  });
  return JSON.stringify({ type: 'bundle', id: 'bundle--' + uuid(), objects }, null, 2);
}
function toMISP(items, builder) {
  const attributes = items.map((row) => {
    const { value, type, description } = builder(row);
    const mispType = ({ ipv4: 'ip-dst', domain: 'domain', url: 'url', md5: 'md5', sha1: 'sha1', sha256: 'sha256' })[type] || 'text';
    return { type: mispType, category: 'Network activity', to_ids: true, value, comment: description || '' };
  }).filter((a) => a.value);
  return JSON.stringify({ Event: { info: 'VENOM/INTEL export ' + nowISO(), date: nowISO().slice(0, 10), Attribute: attributes } }, null, 2);
}

const EXPORT_SCHEMA = {
  kev: {
    label: 'KEV',
    items: () => STATE.kev?.vulnerabilities || [],
    csvCols: ['cveID', 'vendorProject', 'product', 'vulnerabilityName', 'dateAdded', 'dueDate', 'knownRansomwareCampaignUse'],
    stix: (r) => ({ value: r.cveID, type: 'cve', name: r.cveID, description: `${r.vendorProject}/${r.product} — ${r.vulnerabilityName}`, labels: ['exploited'] }),
    misp: (r) => ({ value: r.cveID, type: 'vulnerability', description: r.vulnerabilityName }),
  },
  feodo: {
    label: 'Feodo C2',
    items: () => STATE.feodo || [],
    csvCols: ['ip_address', 'port', 'malware', 'country', 'as_number', 'as_name', 'first_seen', 'last_online', 'status'],
    stix: (r) => ({ value: r.ip_address, type: 'ipv4', name: `${r.malware} C2 @ ${r.ip_address}:${r.port}`, description: `Feodo Tracker — ${r.as_name}, ${r.country}`, labels: ['c2', 'malicious-activity'] }),
    misp: (r) => ({ value: r.ip_address, type: 'ipv4', description: `${r.malware} C2 :${r.port}` }),
  },
  threatfox: {
    label: 'ThreatFox',
    items: () => STATE.threatfox || [],
    csvCols: ['ioc', 'threat_type', 'malware', 'confidence_level', 'first_seen_utc', 'tags'],
    stix: (r) => ({ value: r.ioc, type: r.ioc_type || 'domain', name: `${r.malware} — ${r.threat_type}`, description: `ThreatFox confidence ${r.confidence_level}%`, labels: [r.threat_type || 'malicious-activity'] }),
    misp: (r) => ({ value: r.ioc, type: r.ioc_type || 'text', description: `${r.malware} (conf ${r.confidence_level}%)` }),
  },
  urlhaus: {
    label: 'URLhaus',
    items: () => STATE.urlhaus || [],
    csvCols: ['url', 'host', 'threat', 'tags', 'dateadded', 'url_status'],
    stix: (r) => ({ value: r.url, type: 'url', name: r.threat || 'Malicious URL', description: (r.tags || []).join(', '), labels: ['malicious-activity'] }),
    misp: (r) => ({ value: r.url, type: 'url', description: r.threat }),
  },
  breach: {
    label: 'Breaches',
    items: () => STATE.breach || [],
    csvCols: ['breachID', 'breachedDate', 'exposedRecords', 'industry', 'domain'],
    stix: () => ({ value: '' }), // breaches aren't IOCs
    misp: () => ({ value: '' }),
  },
};

function exportSection(key, fmt) {
  const def = EXPORT_SCHEMA[key];
  if (!def) return;
  const items = def.items();
  if (!items.length) { alert(`No ${def.label} data loaded yet.`); return; }
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const base = `venom-intel-${key}-${stamp}`;
  if (fmt === 'csv')  return downloadBlob(base + '.csv',  'text/csv;charset=utf-8',     toCSV(items, def.csvCols));
  if (fmt === 'json') return downloadBlob(base + '.json', 'application/json;charset=utf-8', JSON.stringify(items, null, 2));
  if (fmt === 'stix') return downloadBlob(base + '.stix.json', 'application/json;charset=utf-8', toSTIX(items, def.stix));
  if (fmt === 'misp') return downloadBlob(base + '.misp.json', 'application/json;charset=utf-8', toMISP(items, def.misp));
}

function injectExportMenus() {
  const targets = { kev: '#kev', feodo: '#c2', threatfox: '#iocs', urlhaus: '#urlhaus', breach: '#breach' };
  Object.entries(targets).forEach(([key, sel]) => {
    const actions = document.querySelector(`${sel} .section-actions`);
    if (!actions || actions.querySelector('.export-wrap')) return;
    const wrap = document.createElement('div');
    wrap.className = 'export-wrap';
    wrap.innerHTML = `
      <button class="btn-sm export-btn" data-export-key="${key}">Export ▾</button>
      <div class="export-menu" role="menu">
        <button data-fmt="csv">CSV</button>
        <button data-fmt="json">JSON</button>
        <button data-fmt="stix">STIX 2.1</button>
        <button data-fmt="misp">MISP</button>
      </div>`;
    actions.appendChild(wrap);
    const btn  = wrap.querySelector('.export-btn');
    const menu = wrap.querySelector('.export-menu');
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      document.querySelectorAll('.export-menu.open').forEach((m) => m !== menu && m.classList.remove('open'));
      menu.classList.toggle('open');
    });
    menu.querySelectorAll('button').forEach((b) => b.addEventListener('click', () => {
      exportSection(key, b.dataset.fmt);
      menu.classList.remove('open');
    }));
  });
  document.addEventListener('click', () => document.querySelectorAll('.export-menu.open').forEach((m) => m.classList.remove('open')));
}

/* ---- 3. DETECTION-RULE GENERATOR ---- */
function ruleSigma(ctx) {
  const cve = ctx.cveID || 'CVE-XXXX-XXXX';
  return `title: Possible exploitation of ${cve}
id: ${uuid()}
status: experimental
description: Detection scaffold for ${ctx.vendor || 'vendor'}/${ctx.product || 'product'} — ${ctx.name || 'vulnerability'}
references:
  - https://nvd.nist.gov/vuln/detail/${cve}
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
author: VENOM/INTEL (generated)
date: ${nowISO().slice(0, 10)}
tags:
  - attack.initial_access
  - attack.t1190
  - cve.${cve.replace(/^CVE-/, '').toLowerCase()}
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - 'TODO_REPLACE_WITH_EXPLOIT_PATTERN'
    cs-method:
      - 'POST'
      - 'GET'
  condition: selection
falsepositives:
  - Legitimate admin traffic
  - Vulnerability scanners
level: high`;
}
function ruleSnort(ctx) {
  const v = ctx.value || '';
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) {
    return `alert ip any any -> ${v} any (msg:"VENOM/INTEL ${ctx.label || 'IOC'} ${ctx.malware || ''} C2 traffic"; sid:1000${Math.floor(Math.random() * 900 + 100)}; rev:1; classtype:trojan-activity;)`;
  }
  if (/^https?:\/\//i.test(v)) {
    const host = (() => { try { return new URL(v).hostname; } catch { return v; } })();
    const path = (() => { try { return new URL(v).pathname; } catch { return '/'; } })();
    return `alert tcp any any -> any 80 (msg:"VENOM/INTEL ${ctx.label || 'IOC'} URL hit"; content:"Host|3a 20|${host}"; http_header; content:"${path}"; http_uri; sid:1000${Math.floor(Math.random() * 900 + 100)}; rev:1; classtype:trojan-activity;)`;
  }
  if (/^[\w.-]+\.[a-z]{2,}$/i.test(v)) {
    return `alert udp any any -> any 53 (msg:"VENOM/INTEL ${ctx.label || 'IOC'} DNS query for ${v}"; content:"${v}"; nocase; sid:1000${Math.floor(Math.random() * 900 + 100)}; rev:1; classtype:trojan-activity;)`;
  }
  return `# Snort rule generation not supported for this IOC type.\n# Value: ${v}`;
}
function ruleYara(ctx) {
  const v = ctx.value || '';
  const malware = (ctx.malware || 'Unknown').replace(/[^A-Za-z0-9_]/g, '_');
  if (/^[a-f0-9]{64}$/i.test(v)) {
    return `rule VNI_${malware}_SHA256 {
  meta:
    author       = "VENOM/INTEL"
    description  = "Hash match for ${malware}"
    date         = "${nowISO().slice(0, 10)}"
    reference    = "https://threatfox.abuse.ch/browse/"
    sha256       = "${v}"
  condition:
    hash.sha256(0, filesize) == "${v}"
}`;
  }
  if (/^[a-f0-9]{40}$/i.test(v)) return `rule VNI_${malware}_SHA1 { meta: sha1 = "${v}" condition: hash.sha1(0, filesize) == "${v}" }`;
  if (/^[a-f0-9]{32}$/i.test(v)) return `rule VNI_${malware}_MD5  { meta: md5  = "${v}" condition: hash.md5(0, filesize) == "${v}" }`;
  return `// YARA only generated from file hashes (MD5/SHA1/SHA256). Got: ${v}`;
}

function openModal(title, panes) {
  let root = document.getElementById('vni-modal-root');
  if (!root) {
    root = document.createElement('div');
    root.id = 'vni-modal-root';
    document.body.appendChild(root);
  }
  const tabs = panes.map((p, i) => `<button class="tab ${i === 0 ? 'on' : ''}" data-tab="${i}">${escape(p.label)}</button>`).join('');
  const bodies = panes.map((p, i) => `<pre class="tab-pane ${i === 0 ? 'on' : ''}" data-tab="${i}"><code>${escape(p.body)}</code></pre>`).join('');
  root.innerHTML = `
    <div class="vni-modal-backdrop">
      <div class="vni-modal">
        <header><h3>${escape(title)}</h3><button class="vni-close" aria-label="close">×</button></header>
        <div class="vni-tabs">${tabs}</div>
        <div class="vni-body">${bodies}</div>
        <footer><button class="btn-sm vni-copy">📋 Copy active</button><span class="vni-hint">Esc to close</span></footer>
      </div>
    </div>`;
  root.hidden = false;
  const close = () => { root.hidden = true; root.innerHTML = ''; document.removeEventListener('keydown', onKey); };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey);
  root.querySelector('.vni-close').addEventListener('click', close);
  root.querySelector('.vni-modal-backdrop').addEventListener('click', (e) => { if (e.target.classList.contains('vni-modal-backdrop')) close(); });
  root.querySelectorAll('.vni-tabs .tab').forEach((t) => t.addEventListener('click', () => {
    root.querySelectorAll('.vni-tabs .tab, .tab-pane').forEach((x) => x.classList.remove('on'));
    t.classList.add('on');
    root.querySelector(`.tab-pane[data-tab="${t.dataset.tab}"]`).classList.add('on');
  }));
  root.querySelector('.vni-copy').addEventListener('click', async () => {
    const active = root.querySelector('.tab-pane.on code')?.textContent || '';
    try { await navigator.clipboard.writeText(active); root.querySelector('.vni-copy').textContent = '✓ Copied'; setTimeout(() => { const b = root.querySelector('.vni-copy'); if (b) b.textContent = '📋 Copy active'; }, 1200); }
    catch { alert('Clipboard write failed — select & copy manually.'); }
  });
}

function openRuleModal(ctx) {
  const panes = [];
  if (ctx.cveID) panes.push({ label: 'Sigma', body: ruleSigma(ctx) });
  if (ctx.value) {
    panes.push({ label: 'Snort', body: ruleSnort(ctx) });
    if (/^[a-f0-9]{32,64}$/i.test(ctx.value)) panes.push({ label: 'YARA', body: ruleYara(ctx) });
  }
  if (!panes.length) panes.push({ label: 'Info', body: 'No rule template available for this entry.' });
  openModal(`Detection rules — ${ctx.label || ctx.cveID || ctx.value}`, panes);
}

/* ---- 4. KEV WATCHLIST + DESKTOP NOTIFICATIONS ---- */
const getWatched = () => { try { return JSON.parse(localStorage.getItem(WATCH_KEY) || '[]'); } catch { return []; } };
const isWatched  = (id) => getWatched().includes(id);
function toggleWatch(id) {
  const w = getWatched();
  const i = w.indexOf(id);
  if (i >= 0) w.splice(i, 1); else w.push(id);
  localStorage.setItem(WATCH_KEY, JSON.stringify(w));
  return i < 0;
}
function maybeAskNotifyPermission() {
  if (!('Notification' in window)) return;
  if (Notification.permission !== 'default') return;
  if (localStorage.getItem(NOTIFY_PROMPTED_KEY)) return;
  localStorage.setItem(NOTIFY_PROMPTED_KEY, '1');
  Notification.requestPermission().catch(() => {});
}
// Same SVG data URI used for the browser tab favicon, reused for desktop notifications
// so we don't 404 on a missing /favicon.ico file.
const FAVICON_DATA = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='6' fill='%233fb950'/%3E%3Ctext x='50%25' y='53%25' font-family='monospace' font-size='14' font-weight='800' text-anchor='middle' dominant-baseline='middle' fill='%230b0d10'%3EV/N%3C/text%3E%3C/svg%3E";
function notify(title, body, url) {
  if (!('Notification' in window) || Notification.permission !== 'granted') return;
  try {
    const n = new Notification(title, { body, icon: FAVICON_DATA, tag: 'vni-watch-' + (url || title) });
    if (url) n.onclick = () => { window.focus(); window.open(url, '_blank'); };
  } catch {}
}
function checkWatchlistAgainstKEV() {
  const watched = getWatched();
  if (!watched.length) return;
  const seenIds = (() => { try { return new Set(JSON.parse(localStorage.getItem(KEV_SEEN_KEY) || '[]')); } catch { return new Set(); } })();
  const vulns = STATE.kev?.vulnerabilities || [];
  const allIds = vulns.map((v) => v.cveID);
  const watchedHits = vulns.filter((v) => watched.includes(v.cveID));
  watchedHits.forEach((v) => {
    if (!seenIds.has(v.cveID)) {
      notify(`KEV: ${v.cveID} now exploited`, `${v.vendorProject}/${v.product} — ${v.vulnerabilityName}`, `https://nvd.nist.gov/vuln/detail/${v.cveID}`);
    }
  });
  localStorage.setItem(KEV_SEEN_KEY, JSON.stringify(allIds));
}
function injectWatchStars() {
  document.querySelectorAll('#kev-body tr[data-cve]').forEach((tr) => {
    if (tr.querySelector('.watch-btn')) return;
    const cve = tr.dataset.cve;
    const td  = tr.querySelector('td:first-child');
    if (!td || !cve) return;
    const btn = document.createElement('button');
    btn.className = 'watch-btn' + (isWatched(cve) ? ' on' : '');
    btn.title = 'Add to watchlist (desktop notification on next KEV add)';
    btn.textContent = isWatched(cve) ? '⭐' : '☆';
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const nowOn = toggleWatch(cve);
      btn.classList.toggle('on', nowOn);
      btn.textContent = nowOn ? '⭐' : '☆';
      if (nowOn) maybeAskNotifyPermission();
    });
    td.prepend(btn, document.createTextNode(' '));
  });
}

/* Tag KEV rows with a data-cve attribute so we can decorate them */
function tagKevRows() {
  document.querySelectorAll('#kev-body tr').forEach((tr) => {
    if (tr.dataset.cve) return;
    const txt = tr.querySelector('td:first-child')?.textContent?.trim().match(/CVE-\d{4}-\d+/);
    if (txt) tr.dataset.cve = txt[0];
  });
}

/* Add 🛡 rule-gen buttons to KEV and IOC rows/cards */
function injectRuleButtons() {
  document.querySelectorAll('#kev-body tr[data-cve]').forEach((tr) => {
    if (tr.querySelector('.rule-btn')) return;
    const last = tr.querySelector('td:last-child');
    if (!last) return;
    const btn = document.createElement('button');
    btn.className = 'rule-btn';
    btn.title = 'Generate Sigma detection scaffold';
    btn.textContent = '🛡';
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const tds = tr.querySelectorAll('td');
      openRuleModal({
        cveID: tr.dataset.cve,
        vendor: tds[1]?.textContent?.trim(),
        product: tds[2]?.textContent?.trim(),
        name: tds[3]?.textContent?.trim(),
        label: tr.dataset.cve,
      });
    });
    last.appendChild(document.createTextNode(' '));
    last.appendChild(btn);
  });
  document.querySelectorAll('#feodo-body tr').forEach((tr) => {
    if (tr.querySelector('.rule-btn') || !tr.querySelector('td')) return;
    const tds = tr.querySelectorAll('td');
    const ipPort = tds[0]?.textContent?.trim() || '';
    const ip = ipPort.split(':')[0];
    if (!ip || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return;
    const btn = document.createElement('button');
    btn.className = 'rule-btn';
    btn.title = 'Generate Snort rule';
    btn.textContent = '🛡';
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      openRuleModal({ value: ip, malware: tds[1]?.textContent?.trim(), label: ipPort });
    });
    tds[tds.length - 1]?.appendChild(document.createTextNode(' '));
    tds[tds.length - 1]?.appendChild(btn);
  });
}

/* ---- 5. KEYBOARD SHORTCUTS + CHEATSHEET ---- */
const SHORTCUTS = [
  { key: '/', label: 'Focus search', desc: 'Jump to global search bar' },
  { key: '?', label: 'Show shortcuts', desc: 'This cheatsheet' },
  { key: 'r', label: 'Refresh all feeds', desc: 'Same as the Refresh button' },
  { key: 'g k', label: 'Go to KEV', desc: 'CISA known-exploited' },
  { key: 'g c', label: 'Go to CVE', desc: 'Latest NVD CVEs' },
  { key: 'g i', label: 'Go to IOCs', desc: 'ThreatFox' },
  { key: 'g u', label: 'Go to URLhaus', desc: 'Malicious URLs' },
  { key: 'g f', label: 'Go to C2', desc: 'Feodo Tracker' },
  { key: 'g m', label: 'Go to map', desc: 'Global threat map' },
  { key: 'g t', label: 'Go to tools', desc: 'IOC lookup' },
  { key: 'g n', label: 'Go to news', desc: 'Infosec newswire' },
  { key: 'g b', label: 'Go to breaches', desc: 'XposedOrNot' },
  { key: 'Esc', label: 'Close modal', desc: 'Or blur search' },
];
function showCheatsheet() {
  openModal('Keyboard shortcuts', [{
    label: 'Shortcuts',
    body: SHORTCUTS.map((s) => `${s.key.padEnd(8)}  ${s.label.padEnd(22)}  ${s.desc}`).join('\n'),
  }]);
}
let chordPending = false;
let chordTimer = null;
function inEditable(el) {
  if (!el) return false;
  const t = el.tagName;
  return t === 'INPUT' || t === 'TEXTAREA' || t === 'SELECT' || el.isContentEditable;
}
function wireKeyboard() {
  document.addEventListener('keydown', (e) => {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    if (inEditable(e.target)) {
      if (e.key === 'Escape') e.target.blur();
      return;
    }
    if (chordPending) {
      chordPending = false; clearTimeout(chordTimer);
      const targets = { k: '#kev', c: '#cve', i: '#iocs', u: '#urlhaus', f: '#c2', m: '#map', t: '#tools', n: '#news', b: '#breach' };
      const sel = targets[e.key.toLowerCase()];
      if (sel) { e.preventDefault(); document.querySelector(sel)?.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
      return;
    }
    if (e.key === '/') { e.preventDefault(); document.getElementById('global-search')?.focus(); return; }
    if (e.key === '?') { e.preventDefault(); showCheatsheet(); return; }
    if (e.key.toLowerCase() === 'r') { e.preventDefault(); document.getElementById('refresh-all')?.click(); return; }
    if (e.key.toLowerCase() === 'g') {
      chordPending = true;
      chordTimer = setTimeout(() => { chordPending = false; }, 1200);
      return;
    }
    if (e.key === 'Escape') {
      const m = document.getElementById('vni-modal-root');
      if (m && !m.hidden) { m.hidden = true; m.innerHTML = ''; }
    }
  });
}

/* ---- DECORATION ORCHESTRATOR ----
   Runs after each refresh to add badges, watchlist stars, rule buttons.
   Uses requestAnimationFrame so it batches with browser paint. */
let decoratePending = false;
function scheduleDecorate() {
  if (decoratePending) return;
  decoratePending = true;
  requestAnimationFrame(() => {
    decoratePending = false;
    tagKevRows();
    injectWatchStars();
    injectRuleButtons();
    renderDiffBadges();
  });
}

function initFeatures() {
  injectExportMenus();
  wireKeyboard();
  // Run decorations now (for any already-rendered content) and whenever data containers change.
  scheduleDecorate();
  ['kev-body', 'feodo-body', 'threatfox-grid', 'urlhaus-grid', 'breach-grid'].forEach((id) => {
    const el = document.getElementById(id);
    if (!el) return;
    new MutationObserver(scheduleDecorate).observe(el, { childList: true, subtree: false });
  });
  // Watch KEV state for version bumps and fire notifications on change.
  // Poll interval is cheap — the check itself is a string compare against STATE.kev.
  let lastKevVersion = '';
  setInterval(() => {
    const v = STATE.kev?.catalogVersion || STATE.kev?.dateReleased || '';
    if (v && v !== lastKevVersion) { lastKevVersion = v; checkWatchlistAgainstKEV(); }
  }, 60000);
  // Update lastVisit when the user leaves so the *next* visit sees a real diff window.
  // pagehide handles tab close, navigation, and mobile background more reliably than beforeunload.
  window.addEventListener('pagehide', bumpLastVisit);
  window.addEventListener('beforeunload', bumpLastVisit);
}

/* ============================================================
   THEME TOGGLE — dark (default) / light. Persists in localStorage,
   respects `prefers-color-scheme` on first visit.
   ============================================================ */
const THEME_KEY = 'vni:theme';
function applyTheme(mode) {
  const light = mode === 'light';
  document.documentElement.classList.toggle('theme-light', light);
  const btn = $('#theme-toggle');
  if (btn) {
    btn.textContent = light ? '☀' : '◐';
    btn.title = `Switch to ${light ? 'dark' : 'light'} theme (T)`;
  }
  // Chart.js re-render — tick/grid colors are read at construction, so redraw
  // with the current STATE if theme flipped and charts are already present.
  if (window.__vniChartsBuilt) {
    if (STATE.cves?.length) drawSeverity(STATE.cves);
    if (STATE.kev?.vulnerabilities?.length) { drawKevTime(STATE.kev); drawVendor(STATE.kev); }
    if (STATE.threatfox?.length) drawMalwareFamilies(STATE.threatfox);
    if (STATE.feodo?.length) drawC2Geo(STATE.feodo);
  }
}
function initTheme() {
  let mode = localStorage.getItem(THEME_KEY);
  if (!mode) {
    mode = window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }
  applyTheme(mode);
  $('#theme-toggle')?.addEventListener('click', () => {
    const next = document.documentElement.classList.contains('theme-light') ? 'dark' : 'light';
    localStorage.setItem(THEME_KEY, next);
    applyTheme(next);
  });
}

/* ============================================================
   GLOBAL THREAT LEVEL GAUGE
   Composite 0–100 score across four signals. Higher = worse.
     ransomWeight   — # of KEV entries flagged for known ransomware use (30d)
     overdueWeight  — # of KEV entries past their CISA-mandated due date
     epssWeight     — # of KEV/CVE entries with EPSS ≥ 0.5
     c2SpreadWeight — # of countries hosting active C2 infrastructure
   Weights are tuned so a "typical week" lands around 40–60.
   ============================================================ */
const THREAT_VERDICTS = [
  { max:  20, label: 'LOW',      cls: 'low' },
  { max:  40, label: 'MODERATE', cls: 'moderate' },
  { max:  60, label: 'ELEVATED', cls: 'elevated' },
  { max:  80, label: 'HIGH',     cls: 'high' },
  { max: 101, label: 'CRITICAL', cls: 'critical' },
];
function computeThreatLevel() {
  const kev = STATE.kev?.vulnerabilities || [];
  const cutoff30d = Date.now() - 30 * 86400000;
  const ransom = kev.filter((v) => v.knownRansomwareCampaignUse === 'Known' && new Date(v.dateAdded).getTime() > cutoff30d).length;
  const overdue = kev.filter((v) => v.dueDate && new Date(v.dueDate).getTime() < Date.now()).length;
  const highEpss = (STATE.exploitItems || []).filter((x) => x.isHotEpss).length
                 + STATE.cves.filter((c) => c.epss != null && c.epss >= 0.5).length;
  const c2Spread = new Set((STATE.feodo || []).map((f) => f.country).filter(Boolean)).size;

  // Normalise each signal to 0–25 then sum.
  const r = Math.min(25, ransom * 2.5);
  const o = Math.min(25, overdue * 0.35);
  const e = Math.min(25, highEpss * 1.2);
  const s = Math.min(25, c2Spread * 0.4);
  const score = Math.round(r + o + e + s);
  return { score, ransom, overdue, highEpss, c2Spread };
}
function renderThreatGauge() {
  const track = $('#gauge-track');
  const fill  = $('#gauge-fill');
  const val   = $('#gauge-value');
  const verdictEl = $('#gauge-verdict');
  const breakdown = $('#gauge-breakdown');
  if (!track || !fill || !val) return;
  const { score, ransom, overdue, highEpss, c2Spread } = computeThreatLevel();
  fill.style.width = score + '%';
  countUp(val, score);
  track.setAttribute('aria-valuenow', String(score));
  const verdict = THREAT_VERDICTS.find((v) => score < v.max) || THREAT_VERDICTS[0];
  if (verdictEl) {
    verdictEl.textContent = verdict.label;
    verdictEl.className = 'gauge-verdict ' + verdict.cls;
  }
  if (breakdown) {
    breakdown.innerHTML = `
      <span title="Ransomware CVEs in the last 30 days"><em>ransomware:</em> ${ransom}</span>
      <span title="CISA-overdue patches"><em>overdue:</em> ${overdue}</span>
      <span title="CVEs with EPSS ≥ 50%"><em>high EPSS:</em> ${highEpss}</span>
      <span title="Active C2 countries"><em>C2 spread:</em> ${c2Spread}</span>
    `;
  }
}

/* ============================================================
   DEGRADED-SERVICE BANNER — shows when >= N feeds are in error state.
   Silently hides once things recover.
   ============================================================ */
function updateDegradedBanner() {
  const banner = $('#degraded-banner');
  if (!banner) return;
  if (localStorage.getItem('vni:degradedDismissedAt') && Date.now() - Number(localStorage.getItem('vni:degradedDismissedAt')) < 3600_000) {
    banner.hidden = true;
    return;
  }
  const errored = Object.entries(STATUS).filter(([, v]) => v.state === 'error').map(([k]) => k);
  if (errored.length >= 2) {
    banner.hidden = false;
    const msg = $('#degraded-msg');
    if (msg) msg.textContent = `Feeds unavailable: ${errored.join(', ')}. Showing cached data where possible.`;
  } else {
    banner.hidden = true;
  }
}

/* ============================================================
   BULK IOC LOOKUP
   ============================================================ */
async function runBulkIocLookup(rawText) {
  const lines = rawText.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  const uniqueLines = Array.from(new Set(lines)).slice(0, 200); // cap to protect the UI
  const status = $('#ioc-bulk-status');
  const output = $('#ioc-output');
  const exportBtn = $('#ioc-bulk-export');
  if (!uniqueLines.length) {
    if (status) status.textContent = 'Paste at least one IOC.';
    return;
  }
  if (status) status.textContent = `Looking up ${uniqueLines.length} IOC${uniqueLines.length === 1 ? '' : 's'}…`;

  const results = [];
  for (const v of uniqueLines) {
    const type = IOC.detect(v);
    // For bulk, skip the network round-trip to CIRCL/URLhaus — we cross-reference
    // against the already-loaded threat feeds. Individual lookup is still one-off.
    const matches = [];
    (STATE.urlhaus || []).forEach((u) => { if (u.url?.includes(v) || u.host === v) matches.push('URLhaus'); });
    (STATE.threatfox || []).forEach((t) => { if (t.ioc === v || t.ioc?.includes(v)) matches.push('ThreatFox'); });
    (STATE.feodo || []).forEach((f) => { if (f.ip_address === v) matches.push('Feodo'); });
    results.push({ value: v, type: type || 'unknown', hits: unique(matches) });
  }
  if (status) status.textContent = `${results.length} scanned · ${results.filter((r) => r.hits.length).length} hit(s)`;
  if (exportBtn) exportBtn.hidden = false;
  // Store for CSV export.
  window.__vniBulkResults = results;

  if (output) {
    const rows = results.map((r) => {
      const verdictCls = r.hits.length ? 'hit' : (r.type === 'unknown' ? 'unknown' : 'clean');
      const verdictText = r.hits.length ? `⚠ ${r.hits.join(' + ')}` : (r.type === 'unknown' ? '?' : '✓ clean');
      return `<div class="ioc-bulk-row ${r.hits.length ? 'hit' : ''}">
        <span class="type-pill">${escape(r.type)}</span>
        <span class="value">${escape(r.value)}</span>
        <span class="verdict ${verdictCls}">${escape(verdictText)}</span>
      </div>`;
    }).join('');
    output.innerHTML = `<div class="ioc-bulk-results">${rows}</div>`;
  }
}
function exportBulkResults() {
  const rows = window.__vniBulkResults || [];
  if (!rows.length) return;
  const csv = 'ioc,type,hits\n' + rows.map((r) => [
    csvCell(r.value), csvCell(r.type), csvCell(r.hits.join('|'))
  ].join(',')).join('\n');
  downloadBlob(`venom-intel-bulk-ioc-${Date.now()}.csv`, 'text/csv;charset=utf-8', csv);
}

/* ============================================================
   PIN TRAY — persistent CVE pin/compare
   ============================================================ */
const PIN_KEY = 'vni:pinnedCves';
function getPins() {
  try { return JSON.parse(localStorage.getItem(PIN_KEY) || '[]'); }
  catch { return []; }
}
function setPins(list) {
  const trimmed = list.slice(0, 6); // cap the compare view at 6
  localStorage.setItem(PIN_KEY, JSON.stringify(trimmed));
  return trimmed;
}
function isPinned(id) { return getPins().includes(id); }
function togglePin(id) {
  const pins = getPins();
  const i = pins.indexOf(id);
  if (i >= 0) pins.splice(i, 1); else pins.push(id);
  setPins(pins);
  renderPinTray();
  scheduleDecorate();
  return i < 0;
}
function lookupCveMeta(id) {
  // Try KEV first (has vendor/product), then CVE feed (has severity/EPSS).
  const kev = (STATE.kev?.vulnerabilities || []).find((v) => v.cveID === id);
  const cve = STATE.cves.find((c) => c.id === id);
  return {
    id,
    vendor:   kev?.vendorProject || cve?.vendors?.[0] || '—',
    product:  kev?.product || cve?.products?.[0] || '—',
    severity: cve?.sev || (kev?.knownRansomwareCampaignUse === 'Known' ? 'CRITICAL' : 'HIGH'),
    epss:     cve?.epss ?? EPSS_KEV_MAP.get(id) ?? null,
    added:    kev?.dateAdded || cve?.published || '—',
    due:      kev?.dueDate || '—',
    ransom:   kev?.knownRansomwareCampaignUse === 'Known',
    name:     kev?.vulnerabilityName || truncate(cve?.desc || '', 140),
  };
}
function renderPinTray() {
  const tray = $('#pin-tray');
  if (!tray) return;
  const pins = getPins();
  const body = $('#pin-tray-body');
  const count = $('#pin-tray-count');
  if (count) count.textContent = String(pins.length);
  if (pins.length === 0) {
    tray.hidden = true;
    if (body) body.innerHTML = '<div class="pin-tray-empty">Pin CVEs to compare (📌 button next to any CVE)</div>';
    return;
  }
  tray.hidden = false;
  if (body) {
    body.innerHTML = pins.map((id) => {
      const m = lookupCveMeta(id);
      return `<div class="pin-row" data-id="${escape(id)}">
        <span class="pin-cve">${escape(id)}</span>
        <button class="pin-remove" data-remove="${escape(id)}" aria-label="Unpin ${escape(id)}">×</button>
        <span class="pin-sub">${escape(m.vendor)} · ${escape(m.product)}${m.ransom ? ' · 🦠' : ''}</span>
      </div>`;
    }).join('');
    body.querySelectorAll('[data-remove]').forEach((b) => {
      b.addEventListener('click', () => togglePin(b.dataset.remove));
    });
  }
}
function openCompareModal() {
  const pins = getPins();
  if (!pins.length) return;
  const columns = pins.map((id) => {
    const m = lookupCveMeta(id);
    const epssStr = m.epss != null ? (m.epss * 100).toFixed(1) + '%' : '—';
    return `<div class="compare-col">
      <h4>${escape(id)}</h4>
      <dl>
        <dt>vendor</dt><dd>${escape(m.vendor)}</dd>
        <dt>product</dt><dd>${escape(m.product)}</dd>
        <dt>severity</dt><dd>${escape(m.severity)}</dd>
        <dt>EPSS</dt><dd>${escape(epssStr)}</dd>
        <dt>added</dt><dd>${escape(m.added)}</dd>
        <dt>due</dt><dd>${escape(m.due)}</dd>
        <dt>ransomware</dt><dd>${m.ransom ? 'YES' : 'no'}</dd>
        <dt>name</dt><dd>${escape(m.name)}</dd>
      </dl>
    </div>`;
  }).join('');
  openModal('Compare pinned CVEs', [{ label: `${pins.length} pinned`, body: '' }]);
  // Replace the pane body with our HTML instead of pre/code.
  const root = document.getElementById('vni-modal-root');
  const pane = root?.querySelector('.tab-pane');
  if (pane) {
    pane.style.whiteSpace = 'normal';
    pane.innerHTML = `<div class="compare-grid">${columns}</div>`;
  }
}
function injectPinButtons() {
  document.querySelectorAll('#kev-body tr[data-cve]').forEach((tr) => {
    if (tr.querySelector('.pin-btn')) return;
    const cve = tr.dataset.cve;
    const td  = tr.querySelector('td:first-child');
    if (!td || !cve) return;
    const btn = document.createElement('button');
    btn.className = 'pin-btn' + (isPinned(cve) ? ' on' : '');
    btn.title = 'Pin CVE to compare tray';
    btn.setAttribute('aria-label', 'Pin ' + cve);
    btn.textContent = '📌';
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const nowOn = togglePin(cve);
      btn.classList.toggle('on', nowOn);
    });
    td.prepend(btn, document.createTextNode(' '));
  });
  document.querySelectorAll('#cve-grid .intel-card').forEach((card) => {
    if (card.querySelector('.pin-btn')) return;
    const link = card.querySelector('.card-id a');
    const cve = link?.textContent?.trim();
    if (!cve || !/^CVE-\d+-\d+$/.test(cve)) return;
    const btn = document.createElement('button');
    btn.className = 'pin-btn' + (isPinned(cve) ? ' on' : '');
    btn.title = 'Pin CVE to compare tray';
    btn.setAttribute('aria-label', 'Pin ' + cve);
    btn.textContent = '📌';
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const nowOn = togglePin(cve);
      btn.classList.toggle('on', nowOn);
    });
    (card.querySelector('.card-head > div:last-child') || card.querySelector('.card-head'))?.appendChild(btn);
  });
}
function wirePinTray() {
  renderPinTray();
  $('#pin-tray-clear')?.addEventListener('click', () => { setPins([]); renderPinTray(); scheduleDecorate(); });
  $('#pin-tray-close')?.addEventListener('click', () => {
    const t = $('#pin-tray');
    if (!t) return;
    t.classList.toggle('collapsed');
    $('#pin-tray-close').textContent = t.classList.contains('collapsed') ? '+' : '–';
  });
  $('#pin-compare')?.addEventListener('click', openCompareModal);
  $('#pin-copy')?.addEventListener('click', async () => {
    const ids = getPins().join('\n');
    try { await navigator.clipboard.writeText(ids); }
    catch { alert('Clipboard write failed — pinned IDs:\n' + ids); }
  });
  $('#pin-export')?.addEventListener('click', () => {
    const pins = getPins();
    if (!pins.length) return;
    const rows = pins.map(lookupCveMeta);
    const cols = ['id', 'vendor', 'product', 'severity', 'epss', 'added', 'due', 'ransom', 'name'];
    const csv = toCSV(rows, cols);
    downloadBlob(`venom-intel-pinned-${Date.now()}.csv`, 'text/csv;charset=utf-8', csv);
  });
}

/* ============================================================
   NEW-FEATURE WIRING
   ============================================================ */
function wireNewFeatures() {
  initTheme();

  // Extend the decorate pipeline to inject pin buttons after data renders.
  const origScheduleDecorate = scheduleDecorate;
  let pinPending = false;
  const withPin = () => {
    if (pinPending) return;
    pinPending = true;
    requestAnimationFrame(() => {
      pinPending = false;
      try { injectPinButtons(); } catch (_) {}
      try { renderThreatGauge(); } catch (_) {}
      try { updateDegradedBanner(); } catch (_) {}
    });
  };
  // Chain a second observer set: re-inject pins whenever kev-body / cve-grid update.
  ['kev-body', 'cve-grid'].forEach((id) => {
    const el = document.getElementById(id);
    if (!el) return;
    new MutationObserver(withPin).observe(el, { childList: true, subtree: false });
  });
  // Fire once at startup so pin state / gauge / banner reflect cached data.
  withPin();

  // Degraded banner dismiss — delegated so it survives DOM churn / late injection.
  document.addEventListener('click', (e) => {
    const closeBtn = e.target.closest?.('.degraded-close');
    if (!closeBtn) return;
    e.preventDefault();
    e.stopPropagation();
    const b = $('#degraded-banner');
    if (b) b.hidden = true;
    localStorage.setItem('vni:degradedDismissedAt', String(Date.now()));
  });

  // Bulk IOC UI
  $('#ioc-bulk-toggle')?.addEventListener('click', () => {
    const wrap = $('#ioc-bulk-wrap');
    if (!wrap) return;
    wrap.hidden = !wrap.hidden;
    $('#ioc-bulk-toggle').textContent = wrap.hidden ? 'Bulk ▾' : 'Bulk ▴';
    if (!wrap.hidden) $('#ioc-bulk-input')?.focus();
  });
  $('#ioc-bulk-go')?.addEventListener('click', () => {
    const v = $('#ioc-bulk-input')?.value || '';
    runBulkIocLookup(v);
  });
  $('#ioc-bulk-export')?.addEventListener('click', exportBulkResults);

  // Pin tray
  wirePinTray();

  // 'T' key toggles theme (avoid intercepting while typing).
  document.addEventListener('keydown', (e) => {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    if (inEditable(e.target)) return;
    if (e.key.toLowerCase() === 't') { e.preventDefault(); $('#theme-toggle')?.click(); }
  });

  // Recompute gauge every time a feed refresh completes.
  const wrappedUpdateStats = updateStats;
  window.__vniUpdateStats = wrappedUpdateStats;
  // Also recompute periodically as a safety net.
  setInterval(() => { try { renderThreatGauge(); updateDegradedBanner(); } catch (_) {} }, 15_000);
}

/* ============================================================
   INIT
   ============================================================ */
function init() {
  const yr = $('#year'); if (yr) yr.textContent = new Date().getFullYear();
  const bid = $('#build-id'); if (bid) bid.textContent = Math.random().toString(36).slice(2, 8).toUpperCase();
  initRevealObserver();
  renderOsint();
  wireEvents();
  initFeatures();
  wireNewFeatures();
  window.__vniChartsBuilt = true;
  refreshAll();
  setInterval(refreshAll, CONFIG.REFRESH_INTERVAL_MS);
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();
})();
