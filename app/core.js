/*
 * Is This A Scam? — scoring engine.
 *
 * Pure JS, no dependencies. Runs in Node 18+, Electron, and a browser/WebView
 * (fetch is available in all three). Every source is public and key-free.
 *
 * Sources:
 *   ScamAdviser 0-100 trust score (aggregates ~40 sources itself)   weight .55
 *   RDAP        domain registration age / registrar / status        weight .16
 *   OpenPhish   live phishing blacklist feed                        weight .13
 *   DNS (DoH)   does it resolve, MX/NS present                      weight .08
 *   TLS         valid certificate                                   weight .04
 *   Wayback     archive history                                     weight .04
 */

const SAFE_ALLOWLIST = new Set([
  'google.com', 'youtube.com', 'wikipedia.org', 'github.com', 'microsoft.com',
  'apple.com', 'amazon.com', 'cloudflare.com', 'mozilla.org', 'python.org',
  'facebook.com', 'instagram.com', 'linkedin.com', 'x.com', 'twitter.com',
  'netflix.com', 'paypal.com', 'stripe.com', 'reddit.com', 'stackoverflow.com',
  'openai.com', 'anthropic.com', 'nousresearch.com', 'orange.fr', 'free.fr',
]);

const TIMEOUT_MS = 18000;

/* ------------------------------------------------------------------ fetch */

/**
 * One HTTP entry point for all three runtimes.
 *
 * A browser page served from file:// (Electron) or a WebView cannot call
 * ScamAdviser or OpenPhish directly — those hosts send no CORS headers, so
 * fetch() is blocked. Both shells therefore expose a native transport:
 *   Electron  -> window.__net.fetch(url)   (main process, no CORS)
 *   Android   -> window.__ANDROID_PROXY    (WebView intercepts /proxy)
 * A plain browser falls back to direct fetch and simply loses those sources.
 */
async function httpGet(url, timeout = TIMEOUT_MS) {
  if (typeof window !== 'undefined' && window.__net && window.__net.fetch) {
    const r = await window.__net.fetch(url);
    if (!r || !r.ok) throw new Error('HTTP ' + ((r && r.status) || '?'));
    return r.text;
  }
  if (typeof window !== 'undefined' && window.__ANDROID_PROXY) {
    const proxied = window.__ANDROID_PROXY + encodeURIComponent(url);
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeout);
    try {
      const r = await fetch(proxied, { signal: ctrl.signal });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return await r.text();
    } finally { clearTimeout(t); }
  }
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {
    const r = await fetch(url, {
      signal: ctrl.signal,
      redirect: 'follow',
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; IsThisAScam/1.0)' },
    });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return await r.text();
  } finally {
    clearTimeout(t);
  }
}

async function getText(url, timeout = TIMEOUT_MS) {
  return httpGet(url, timeout);
}

async function getJSON(url, timeout = TIMEOUT_MS) {
  return JSON.parse(await httpGet(url, timeout));
}

function normalizeTarget(text) {
  let t = String(text || '').trim();
  if (!t) throw new Error('Empty input');
  if (t.includes('@') && !t.includes('://') && !t.includes('/')) t = t.split('@')[1];
  if (!t.includes('://')) t = 'http://' + t;
  let host;
  try {
    host = new URL(t).hostname.toLowerCase().replace(/^\.+|\.+$/g, '');
  } catch {
    throw new Error('Could not find a domain in: ' + text);
  }
  if (!host || !host.includes('.')) throw new Error('Could not find a domain in: ' + text);
  if (!/^[a-z0-9.\-]+$/.test(host)) throw new Error('Invalid domain: ' + host);
  return { url: t, host };
}

const MULTI_SUFFIX = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'co.nz',
  'co.jp', 'com.br', 'co.in', 'com.mx', 'co.za', 'com.tr', 'co.kr', 'com.cn']);

function registrableDomain(host) {
  const p = host.split('.');
  if (p.length <= 2) return host;
  const two = p.slice(-2).join('.');
  if (MULTI_SUFFIX.has(two)) return p.slice(-3).join('.');
  return two;
}

/* ---------------------------------------------------------------- sources */

async function srcScamAdviser(domain) {
  const w = 0.55;
  try {
    const raw = await getText(`https://www.scamadviser.com/check-website/${encodeURIComponent(domain)}`, 25000);
    const u = raw
      .replace(/&quot;/g, '"').replace(/&#39;/g, "'")
      .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>');
    let score = null;
    for (const re of [/"trustScore\\?"?\s*:\s*\\?"?(\d{1,3})/i,
                      /ratingValue\\?"?\s*:\s*\\?"?(\d{1,3})/i,
                      /trustScore\\?"?:\\?"?(\d{1,3})/i]) {
      const m = u.match(re);
      if (m) { score = parseInt(m[1], 10); break; }
    }
    let verdict = '';
    let m = u.match(/"hero"\s*:\s*\{[^}]*?"title"\s*:\s*"([^"]{2,60})"/);
    if (m) verdict = m[1];
    let desc = '';
    m = u.match(/scoreDescription\\?"?\s*:\s*\\?"?([\s\S]{0,300}?)"/);
    if (m) desc = m[1].replace(/<[^>]+>/g, '').trim().slice(0, 280);
    if (score === null) {
      return { name: 'ScamAdviser', ok: false, weight: w, score: null,
               detail: 'No score published for this domain', raw: {} };
    }
    return { name: 'ScamAdviser', ok: true, weight: w, score,
             detail: verdict || desc || `Trust score ${score}/100`,
             raw: { verdict, description: desc } };
  } catch (e) {
    return { name: 'ScamAdviser', ok: false, weight: w, score: null,
             detail: `unreachable (${e.name || 'error'})`, raw: {} };
  }
}

async function srcRdap(domain) {
  const w = 0.16;
  try {
    const d = await getJSON(`https://rdap.org/domain/${encodeURIComponent(domain)}`);
    const events = {};
    (d.events || []).forEach(e => { events[e.eventAction] = e.eventDate; });
    const created = events.registration;
    let ageDays = null;
    if (created) {
      ageDays = Math.floor((Date.now() - new Date(created).getTime()) / 86400000);
    }
    let registrar = '';
    for (const ent of d.entities || []) {
      if ((ent.roles || []).includes('registrar')) {
        const vc = (ent.vcardArray || [null, []])[1] || [];
        for (const item of vc) if (item && item[0] === 'fn') registrar = item[3];
      }
    }
    const status = (d.status || []).slice(0, 4).join(', ');
    if (ageDays === null) {
      return { name: 'Domain age (RDAP)', ok: false, weight: w, score: null,
               detail: 'No registration date published', raw: { registrar } };
    }
    let s, note;
    if (ageDays < 30)        { s = 15; note = `registered ${ageDays} days ago — extremely new`; }
    else if (ageDays < 180)  { s = 40; note = `registered ${ageDays} days ago — very new`; }
    else if (ageDays < 365)  { s = 62; note = `registered ${ageDays} days ago — under a year old`; }
    else if (ageDays < 1095) { s = 82; note = `registered ${Math.floor(ageDays / 365)} year(s) ago`; }
    else                     { s = 95; note = `registered ${Math.floor(ageDays / 365)} years ago`; }
    return { name: 'Domain age (RDAP)', ok: true, weight: w, score: s,
             detail: note + (registrar ? ` · registrar: ${registrar}` : ''),
             raw: { ageDays, created, registrar, status } };
  } catch (e) {
    return { name: 'Domain age (RDAP)', ok: false, weight: w, score: null,
             detail: `no registration data (${e.name || 'error'})`, raw: {} };
  }
}

async function srcDns(domain) {
  const w = 0.08;
  try {
    const out = {};
    for (const t of ['A', 'NS', 'MX']) {
      try {
        const d = await getJSON(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${t}`, 12000);
        out[t] = (d.Answer || []).map(a => a.data);
      } catch { out[t] = []; }
    }
    if (!out.A.length) {
      return { name: 'DNS records', ok: true, weight: w, score: 20,
               detail: 'domain does not resolve to any address', raw: out };
    }
    let s = 70;
    const bits = [`${out.A.length} A record(s)`];
    if (out.MX.length) { s += 12; bits.push(`${out.MX.length} MX`); }
    if (out.NS.length) { s += 18; bits.push(`${out.NS.length} NS`); }
    return { name: 'DNS records', ok: true, weight: w, score: Math.min(s, 100),
             detail: bits.join(' · '), raw: out };
  } catch (e) {
    return { name: 'DNS records', ok: false, weight: w, score: null,
             detail: `lookup failed (${e.name || 'error'})`, raw: {} };
  }
}

let _phishCache = null;

async function srcBlacklist(domain) {
  const w = 0.13;
  try {
    if (!_phishCache) {
      const txt = await getText('https://openphish.com/feed.txt', 25000);
      _phishCache = new Set(txt.split('\n').map(l => l.trim().toLowerCase()).filter(Boolean));
    }
    const listed = [..._phishCache].some(e => e.includes(domain));
    if (listed) {
      return { name: 'Phishing blacklist', ok: true, weight: w, score: 0,
               detail: 'LISTED in the live OpenPhish phishing feed',
               raw: { feedSize: _phishCache.size, listed: true } };
    }
    return { name: 'Phishing blacklist', ok: true, weight: w, score: 80,
             detail: `not present in the OpenPhish feed (${_phishCache.size} live entries)`,
             raw: { feedSize: _phishCache.size, listed: false } };
  } catch (e) {
    return { name: 'Phishing blacklist', ok: false, weight: w, score: null,
             detail: `feed unavailable (${e.name || 'error'})`, raw: {} };
  }
}

async function srcWayback(domain) {
  const w = 0.04;
  try {
    const d = await getJSON('https://archive.org/wayback/available?url=' + encodeURIComponent(domain), 15000);
    const snap = (d.archived_snapshots || {}).closest;
    if (snap && snap.available) {
      const ts = String(snap.timestamp || '');
      const pretty = ts.length >= 8 ? `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}` : ts;
      return { name: 'Archive history', ok: true, weight: w, score: 90,
               detail: `archived since ${pretty}`, raw: snap };
    }
    return { name: 'Archive history', ok: true, weight: w, score: 45,
             detail: 'never archived — little to no public history', raw: {} };
  } catch (e) {
    return { name: 'Archive history', ok: false, weight: w, score: null,
             detail: `archive lookup failed (${e.name || 'error'})`, raw: {} };
  }
}

/* ------------------------------------------------------------ aggregation */

const ORDER = { 'ScamAdviser': 0, 'Domain age (RDAP)': 1, 'Phishing blacklist': 2,
                'DNS records': 3, 'Archive history': 4 };

function verdictFor(score) {
  if (score >= 85) return ['Very likely safe', 'safe'];
  if (score >= 70) return ['Probably safe', 'likely_safe'];
  if (score >= 50) return ['Be careful', 'caution'];
  if (score >= 30) return ['Risky', 'risky'];
  return ['Likely a scam', 'danger'];
}

function summaryFor(score, domain, sources) {
  const [verdict] = verdictFor(score);
  const red = sources.filter(s => s.ok && s.score !== null && s.score < 45).map(s => s.detail);
  if (red.length) return `${verdict} — ${domain}. Warning signs: ${red.slice(0, 2).join('; ')}.`;
  const bad = sources.filter(s => s.ok && s.score !== null && s.score < 70).map(s => s.detail);
  if (bad.length) return `${verdict} — ${domain}. ${bad.slice(0, 2).join('; ')}.`;
  return `${verdict} — ${domain}. No significant warning signs found.`;
}

/**
 * Score a URL / domain / email.
 * @param {string} target
 * @returns {Promise<object>} report
 */
async function analyze(target) {
  const t0 = Date.now();
  const { url, host } = normalizeTarget(target);
  const domain = registrableDomain(host);

  const results = await Promise.all([
    srcScamAdviser(domain),
    srcRdap(domain),
    srcBlacklist(domain),
    srcDns(domain),
    srcWayback(domain),
  ]);
  results.sort((a, b) => (ORDER[a.name] ?? 99) - (ORDER[b.name] ?? 99));

  const dns = results.find(r => r.name === 'DNS records');
  const unresolved = !!(dns && dns.ok && dns.score === 20);
  const blk = results.find(r => r.name === 'Phishing blacklist');
  const blacklisted = !!(blk && blk.ok && blk.raw && blk.raw.listed);

  const live = results.filter(r => r.ok && r.score !== null);
  let score, verdict, key, summary;

  if (!live.length) {
    score = 50;
    [verdict, key] = ['Not enough data', 'unknown'];
    summary = `Could not reach any reputation source for ${domain}. Check your connection and try again.`;
  } else {
    const tw = live.reduce((a, r) => a + r.weight, 0);
    score = Math.round(live.reduce((a, r) => a + r.score * r.weight, 0) / tw);
    if (SAFE_ALLOWLIST.has(domain) && score < 85) score = Math.max(score, 92);

    if (blacklisted) {
      // a confirmed phishing listing outranks every other signal
      score = Math.min(score, 8);
      [verdict, key] = verdictFor(score);
      summary = `${verdict} — ${domain} appears in a live phishing blacklist. Do not enter any details on this site.`;
    } else if (unresolved) {
      // "we cannot check this" is not the same as "this is a scam"
      score = Math.min(score, 30);
      verdict = 'Cannot be verified';
      key = 'risky';
      summary = `${verdict} — ${domain} does not resolve to any address, so nothing about it can be confirmed. ` +
                `A dead domain is often a scam that was registered and abandoned, but it can also be parked, ` +
                `expired or simply misconfigured. Treat it as unverified rather than proven malicious.`;
    } else {
      [verdict, key] = verdictFor(score);
      summary = summaryFor(score, domain, results);
    }
  }

  return {
    target, domain, score, verdict, verdictKey: key, summary, sources: results,
    elapsedMs: Date.now() - t0,
    checkedAt: new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC',
  };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { analyze, normalizeTarget, registrableDomain, verdictFor };
}
