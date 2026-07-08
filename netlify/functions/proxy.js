// netlify/functions/proxy.js — VENOM/INTEL whitelisted CORS proxy
// Supports GET and POST. Sig: CYbErXV3nOm

const ALLOWED_HOSTS = new Set([
  // Vuln & advisory
  'www.cisa.gov', 'cisa.gov',
  'www.cert-in.org.in', 'cert-in.org.in',
  'nvd.nist.gov', 'services.nvd.nist.gov',
  'cve.circl.lu',
  // News aggregator
  'news.google.com',
  // Threat intel
  'urlhaus.abuse.ch', 'urlhaus-api.abuse.ch',
  'threatfox.abuse.ch', 'threatfox-api.abuse.ch',
  'feodotracker.abuse.ch',
  'bazaar.abuse.ch', 'mb-api.abuse.ch',
  'otx.alienvault.com',
  // EPSS / scoring
  'api.first.org',
  // Breach tracker
  'api.xposedornot.com',
  'haveibeenpwned.com',
  // News RSS
  'krebsonsecurity.com',
  'www.bleepingcomputer.com',
  'feeds.feedburner.com',
  'isc.sans.edu',
  'www.darkreading.com',
  'www.theregister.com',
  'www.schneier.com',
  'threatpost.com',
  // Exploits
  'www.exploit-db.com',
  'rss.packetstormsecurity.com',
  'github.com',
]);

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: CORS, body: '' };
  }

  const target = event.queryStringParameters?.url;
  if (!target) return { statusCode: 400, headers: CORS, body: 'Missing ?url=' };

  let u;
  try { u = new URL(target); }
  catch { return { statusCode: 400, headers: CORS, body: 'Invalid URL' }; }

  if (!ALLOWED_HOSTS.has(u.hostname)) {
    return { statusCode: 403, headers: CORS, body: `Host not allowed: ${u.hostname}` };
  }

  // Basic per-instance rate limit — cheap defence against abuse.
  const now = Date.now();
  globalThis.__vniRate = globalThis.__vniRate || [];
  globalThis.__vniRate = globalThis.__vniRate.filter((t) => now - t < 60_000);
  if (globalThis.__vniRate.length > 120) {
    return { statusCode: 429, headers: CORS, body: 'Rate limit — try again shortly.' };
  }
  globalThis.__vniRate.push(now);

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 25_000);

    const init = {
      method: event.httpMethod || 'GET',
      signal: controller.signal,
      headers: {
        'User-Agent': 'VENOM-INTEL/1.0 (+threat-intel aggregator)',
        Accept: 'application/json, application/rss+xml, application/atom+xml, application/xml, text/xml, text/csv, */*',
      },
      redirect: 'follow',
    };
    if (event.httpMethod === 'POST' && event.body) {
      init.body = event.body;
      init.headers['Content-Type'] = event.headers?.['content-type'] || 'application/x-www-form-urlencoded';
    }

    const r = await fetch(u.toString(), init);
    clearTimeout(timer);
    const body = await r.text();
    return {
      statusCode: r.status,
      headers: {
        'Content-Type': r.headers.get('content-type') || 'text/plain; charset=utf-8',
        ...CORS,
        'Cache-Control': 'public, max-age=180',
      },
      body,
    };
  } catch (e) {
    const isAbort = e.name === 'AbortError';
    return {
      statusCode: isAbort ? 504 : 502,
      headers: CORS,
      body: isAbort ? 'Upstream timeout' : ('Upstream error: ' + e.message),
    };
  }
};
