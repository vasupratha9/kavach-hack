'use strict';

/**
 * Link and domain intelligence.
 *
 * Security by design: Kavach never opens the suspicious link itself (no SSRF,
 * no malware download). It only inspects the address, asks the public RDAP
 * registry when the domain was registered, and optionally asks Google Safe
 * Browsing whether the URL is known to be dangerous.
 */

const BRANDS = Object.freeze({
  amazon: ['amazon.in', 'amazon.com'],
  flipkart: ['flipkart.com'],
  myntra: ['myntra.com'],
  meesho: ['meesho.com'],
  ajio: ['ajio.com'],
  nykaa: ['nykaa.com', 'nykaafashion.com'],
  snapdeal: ['snapdeal.com'],
  tatacliq: ['tatacliq.com'],
  paytm: ['paytm.com'],
  phonepe: ['phonepe.com'],
  sbi: ['sbi.co.in', 'onlinesbi.sbi', 'sbi.bank.in'],
  hdfc: ['hdfcbank.com', 'hdfc.bank.in'],
  icici: ['icicibank.com', 'icici.bank.in'],
  indiapost: ['indiapost.gov.in'],
  irctc: ['irctc.co.in'],
  instagram: ['instagram.com'],
  whatsapp: ['whatsapp.com'],
  zara: ['zara.com'],
  biba: ['biba.in'],
  fabindia: ['fabindia.com'],
  libas: ['libas.in'],
});

const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.ly', 'cutt.ly', 'rb.gy', 'is.gd', 'shorturl.at', 'goo.gl', 'ow.ly', 'tiny.cc', 'rebrand.ly', 'shorte.st', 'v.gd', 'surl.li', 'bit.do']);
const RISKY_TLDS = new Set(['xyz', 'top', 'shop', 'store', 'online', 'site', 'buzz', 'club', 'icu', 'live', 'click', 'fun', 'vip', 'cyou', 'sbs', 'cfd', 'rest', 'monster', 'lol']);
const TWO_PART_SUFFIXES = new Set(['co.in', 'org.in', 'net.in', 'gov.in', 'ac.in', 'co.uk', 'com.au', 'bank.in']);

/** Parses a user-supplied address into a URL, or returns null if it is not a web address. */
function parseLink(raw) {
  const text = String(raw || '').trim();
  if (!text || /\s/.test(text) || text.length > 300) return null;
  try {
    const url = new URL(/^https?:\/\//i.test(text) ? text : `https://${text}`);
    if (!['http:', 'https:'].includes(url.protocol) || !url.hostname.includes('.')) return null;
    return url;
  } catch {
    return null;
  }
}

function registrableDomain(hostname) {
  const parts = hostname.toLowerCase().replace(/\.$/, '').split('.');
  if (parts.length <= 2) return parts.join('.');
  const lastTwo = parts.slice(-2).join('.');
  return TWO_PART_SUFFIXES.has(lastTwo) ? parts.slice(-3).join('.') : lastTwo;
}

/** Undo the common digit swaps used in look-alike domains (amaz0n, fl1pkart). */
function deLeet(text) {
  return text.replace(/0/g, 'o').replace(/[1!|]/g, 'l').replace(/3/g, 'e').replace(/4/g, 'a').replace(/5/g, 's').replace(/7/g, 't');
}

/** Static checks on the address only: instant, offline, no network calls. */
function inspectLink(raw) {
  const url = parseLink(raw);
  if (!url) return null;
  const host = url.hostname.toLowerCase();
  const domain = registrableDomain(host);
  const tld = domain.split('.').pop();
  const hits = [];
  const add = (id, evidence) => hits.push({ id, source: 'link check', evidence: evidence || host });

  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[');
  if (isIp) add('ip_link');
  if (host.split('.').some((label) => label.startsWith('xn--'))) add('punycode_domain');
  if (SHORTENERS.has(domain) || SHORTENERS.has(host)) add('short_link');
  if (!isIp && RISKY_TLDS.has(tld)) add('risky_tld', `.${tld}`);
  if (/^http:\/\//i.test(String(raw).trim())) add('no_https');

  const flat = deLeet(host.replace(/[-.]/g, ''));
  for (const [brand, official] of Object.entries(BRANDS)) {
    const isOfficial = official.some((o) => host === o || host.endsWith(`.${o}`));
    if (!isOfficial && flat.includes(brand)) {
      add('lookalike_domain', `${host} is not ${official[0]}`);
      break;
    }
  }
  return { href: url.href.slice(0, 300), host, domain, isIp, hits };
}

/** Reads the domain's registration date from the public RDAP registry (ICANN's WHOIS replacement). */
async function domainAge(domain, { fetchImpl = globalThis.fetch, timeoutMs = 5000, cache = null, now = Date.now() } = {}) {
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(domain)) return null;
  const lookup = async () => {
    try {
      const res = await fetchImpl(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
        signal: AbortSignal.timeout(timeoutMs),
        headers: { accept: 'application/rdap+json, application/json', 'user-agent': 'kavach-scam-checker/1.0' },
        redirect: 'follow',
      });
      if (!res.ok) return null;
      const data = await res.json();
      const event = Array.isArray(data.events) ? data.events.find((e) => e && e.eventAction === 'registration') : null;
      const created = event ? Date.parse(event.eventDate) : NaN;
      if (!Number.isFinite(created)) return null;
      return { registered: new Date(created).toISOString().slice(0, 10) };
    } catch {
      return null;
    }
  };
  const result = cache ? await cache.wrap(`rdap:${domain}`, lookup) : await lookup();
  if (!result) return null;
  const ageDays = Math.max(0, Math.floor((now - Date.parse(result.registered)) / 86400000));
  return { registered: result.registered, ageDays };
}

function ageSignal(ageDays) {
  if (ageDays === null || ageDays === undefined) return null;
  if (ageDays < 30) return 'domain_very_new';
  if (ageDays < 183) return 'domain_new';
  if (ageDays < 365) return 'domain_young';
  if (ageDays > 3 * 365) return 'domain_established';
  return null;
}

/** Google Safe Browsing v4 lookup. Returns true / false, or null when unavailable. */
async function safeBrowsing(urls, { apiKey, fetchImpl = globalThis.fetch, timeoutMs = 5000 } = {}) {
  if (!apiKey || urls.length === 0) return null;
  try {
    const res = await fetchImpl('https://safebrowsing.googleapis.com/v4/threatMatches:find', {
      method: 'POST',
      signal: AbortSignal.timeout(timeoutMs),
      headers: { 'content-type': 'application/json', 'x-goog-api-key': apiKey },
      body: JSON.stringify({
        client: { clientId: 'kavach', clientVersion: '1.0.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: urls.map((url) => ({ url })),
        },
      }),
    });
    if (!res.ok) return null;
    const data = await res.json();
    return Array.isArray(data.matches) && data.matches.length > 0;
  } catch {
    return null;
  }
}

module.exports = { parseLink, registrableDomain, deLeet, inspectLink, domainAge, ageSignal, safeBrowsing, BRANDS };
