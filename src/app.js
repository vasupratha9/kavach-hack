'use strict';

/**
 * HTTP application: routing, security headers, body parsing, rate limiting and
 * structured logging (JSON lines that Google Cloud Logging parses natively).
 * All collaborators are injected, so the whole app is testable offline.
 */

const signals = require('./signals');
const links = require('./links');
const { validateCheck, validateRecovery, LANGUAGES } = require('./validate');
const { recoveryPlan, fallbackDrafts, OFFICIAL } = require('./recovery');
const { serveStatic } = require('./static');

const CSP = "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; img-src 'self' data: blob:; connect-src 'self'; font-src 'self' https://fonts.gstatic.com; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

const SECURITY_HEADERS = Object.freeze({
  'content-security-policy': CSP,
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'permissions-policy': 'microphone=(), camera=(), geolocation=(), payment=()',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
});

class HttpError extends Error {
  constructor(status, message, headers = {}) {
    super(message);
    this.status = status;
    this.headers = headers;
  }
}

const jsonLogger = {
  info: (entry) => console.log(JSON.stringify({ severity: 'INFO', ...entry })),
  warn: (entry) => console.warn(JSON.stringify({ severity: 'WARNING', ...entry })),
  error: (entry) => console.error(JSON.stringify({ severity: 'ERROR', ...entry })),
};

function sendJson(res, status, payload, headers = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'content-length': Buffer.byteLength(body), ...headers });
  res.end(body);
}

function clientId(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const first = typeof forwarded === 'string' ? forwarded.split(',')[0].trim() : '';
  return first || (req.socket && req.socket.remoteAddress) || 'unknown';
}

function readJsonBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const type = String(req.headers['content-type'] || '');
    if (!type.toLowerCase().startsWith('application/json')) {
      reject(new HttpError(415, 'Content-Type must be application/json'));
      return;
    }
    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > maxBytes) {
      reject(new HttpError(413, 'Request is too large. Try fewer or smaller screenshots.'));
      return;
    }
    const chunks = [];
    let size = 0;
    let failed = false;
    req.on('data', (chunk) => {
      if (failed) return;
      size += chunk.length;
      if (size > maxBytes) {
        failed = true;
        reject(new HttpError(413, 'Request is too large. Try fewer or smaller screenshots.'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (failed) return;
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'));
      } catch {
        reject(new HttpError(400, 'Request body is not valid JSON'));
      }
    });
    req.on('error', (err) => {
      if (!failed) reject(err);
    });
  });
}

const google = (q) => `https://www.google.com/search?q=${encodeURIComponent(q)}`;

/** One-tap searches so users can read real reviews themselves (never AI-generated). */
function researchLinks({ handles, domains, phones, upiIds }) {
  const out = [];
  for (const h of handles.slice(0, 2)) {
    const name = h.replace(/^@/, '');
    out.push({ label: `Open @${name} on Instagram`, url: `https://www.instagram.com/${encodeURIComponent(name)}/`, hint: 'Tap ⋯ → "About this account" to see the join date and old usernames' });
    out.push({ label: `Search complaints about @${name}`, url: google(`"${name}" scam OR fraud OR "not delivered" OR "not received"`) });
    out.push({ label: `Search reviews of @${name}`, url: google(`"${name}" reviews instagram`) });
  }
  for (const d of domains.slice(0, 2)) {
    out.push({ label: `Search complaints about ${d}`, url: google(`"${d}" scam OR fraud OR complaint OR "not delivered"`) });
  }
  for (const p of [...phones, ...upiIds].slice(0, 2)) {
    out.push({ label: `Search reports about ${p}`, url: google(`"${p}" fraud OR scam`) });
  }
  return out.slice(0, 7);
}

function nextSteps(level, mode) {
  if (mode === 'message') {
    return level === 'low'
      ? ['Still never share OTPs or PINs.', 'If unsure, contact the company through its official app or website, not the number in the message.']
      : ['Do not reply, click links, call back or pay.', 'Block the number and report it on Sanchar Saathi (Chakshu).', 'If you already shared details or paid, call 1930 immediately.', 'Warn your family: share this check with them.'];
  }
  return level === 'low'
    ? ['Prefer Cash on Delivery for your first order.', 'Pay through a checkout with a payment gateway, not a personal UPI ID.', 'Keep screenshots of the product, price and chat.']
    : ['Do not pay in advance.', 'Ask for Cash on Delivery or buy through a marketplace with buyer protection.', 'If you must pay, use a credit card (chargeback protection), never a personal UPI ID.', 'Report the profile so others are protected.'];
}

function createApp({ gemini, limiter, staticFiles, cache = null, fetchImpl = globalThis.fetch, safeBrowsingApiKey = '', lookupTimeoutMs = 5000, maxBodyBytes = 32 * 1024, maxUploadBytes = 4 * 1024 * 1024, logger = jsonLogger }) {
  async function safely(label, promise) {
    try {
      return await promise;
    } catch (err) {
      logger.warn({ message: `${label} failed, continuing without it`, error: err.message });
      return null;
    }
  }

  async function handleCheck(req, res) {
    const check = validateCheck(await readJsonBody(req, maxUploadBytes));
    const languageName = LANGUAGES[check.language];
    const hits = [];

    // 1. Instant rule-based findings from everything the user typed.
    const typed = `${check.subject}\n${check.text}`;
    hits.push(...signals.scanText(typed).map((h) => ({ ...h, source: 'message scan' })));
    const typedEntities = signals.extractEntities(typed);
    const subjectHandle = /^@?[a-z0-9._]{2,30}$/i.test(check.subject) && !check.subject.includes('.') ? [`@${check.subject.replace(/^@/, '').toLowerCase()}`] : [];
    typedEntities.handles = [...new Set([...subjectHandle, ...typedEntities.handles])];

    const inspectAll = (urls) => urls.slice(0, 3).map(links.inspectLink).filter(Boolean);
    let inspected = inspectAll(typedEntities.urls);
    inspected.forEach((l) => hits.push(...l.hits));

    const lookupDomains = (list) => [...new Set(list.filter((l) => !l.isIp).map((l) => l.domain))].slice(0, 2);
    const ageLookups = (domains) => Promise.all(domains.map((d) => links.domainAge(d, { fetchImpl, timeoutMs: lookupTimeoutMs, cache }).then((age) => ({ domain: d, age }))));
    const subjectsFor = (ents, domains) => [...ents.handles, ...domains, ...ents.phones, ...ents.upiIds].slice(0, 3);

    // 2. AI vision/text analysis, domain age, Safe Browsing and web reputation, all in parallel.
    const firstDomains = lookupDomains(inspected);
    const ruleFindings = signals.score(hits).redFlags.map((s) => s.label);
    const [ai, ages, unsafe, reputation] = await Promise.all([
      safely('gemini analysis', gemini.analyze(check, ruleFindings, languageName)),
      ageLookups(firstDomains),
      links.safeBrowsing(inspected.map((l) => l.href), { apiKey: safeBrowsingApiKey, fetchImpl, timeoutMs: lookupTimeoutMs }),
      safely('reputation', gemini.reputation(subjectsFor(typedEntities, firstDomains))),
    ]);

    // 3. Second pass for anything Gemini read from the screenshots (handles, links) that the user did not type.
    const entities = { ...typedEntities };
    let rep = reputation;
    if (ai) {
      const aiSource = check.images.length ? 'Gemini vision' : 'Gemini';
      ai.observations.forEach((id) => hits.push({ id, source: aiSource }));
      const normalize = { handles: (h) => `@${h.toLowerCase().replace(/^@+/, '')}`, urls: (u) => u.toLowerCase(), phones: (p) => p.replace(/[\s-]/g, ''), upiIds: (u) => u.toLowerCase() };
      for (const key of Object.keys(normalize)) entities[key] = [...new Set([...entities[key], ...ai.entities[key]].map(normalize[key]))].slice(0, 5);
      const newLinks = inspectAll(ai.entities.urls).filter((l) => !inspected.some((i) => i.domain === l.domain));
      newLinks.forEach((l) => hits.push(...l.hits.map((h) => ({ ...h, source: 'link in screenshot' }))));
      inspected = inspected.concat(newLinks);
      const extraDomains = lookupDomains(newLinks);
      const [extraAges, extraRep] = await Promise.all([
        ageLookups(extraDomains),
        rep ? null : safely('reputation', gemini.reputation(subjectsFor(entities, [...firstDomains, ...extraDomains]))),
      ]);
      ages.push(...extraAges);
      rep = rep || extraRep;
    }

    for (const { domain, age } of ages) {
      const id = age ? links.ageSignal(age.ageDays) : null;
      if (id) hits.push({ id, source: 'domain registry', evidence: `${domain} registered ${age.registered}` });
    }
    if (unsafe) hits.push({ id: 'safe_browsing_hit', source: 'Google Safe Browsing' });
    if (rep && rep.status === 'complaints_found') hits.push({ id: 'web_complaints', source: 'Google Search', evidence: rep.sources[0].title });
    if (rep && rep.status === 'positive') hits.push({ id: 'web_positive', source: 'Google Search' });

    const verdict = signals.score(hits);
    const domains = [...new Set(inspected.filter((l) => !l.isIp).map((l) => l.domain))];
    sendJson(res, 200, {
      verdict: { risk: verdict.risk, level: verdict.level, label: verdict.label },
      redFlags: verdict.redFlags,
      greenFlags: verdict.greenFlags,
      ai: ai ? { summary: ai.summary, scamType: ai.scamType, quotes: ai.redFlags, safeReply: ai.safeReply, advice: ai.advice } : null,
      domains: domains.map((d) => {
        const found = ages.find((a) => a.domain === d);
        return { domain: d, registered: found && found.age ? found.age.registered : null, ageDays: found && found.age ? found.age.ageDays : null };
      }),
      safeBrowsing: unsafe,
      reputation: rep,
      research: researchLinks({ handles: entities.handles, domains, phones: entities.phones, upiIds: entities.upiIds }),
      nextSteps: nextSteps(verdict.level, check.mode),
      entities,
      helpline: OFFICIAL.helpline,
      source: ai ? 'gemini' : 'rules',
      checkedAt: new Date().toISOString(),
    });
  }


  async function handleRecover(req, res) {
    const input = validateRecovery(await readJsonBody(req, maxBodyBytes));
    const plan = recoveryPlan(input);
    let drafts = await safely('gemini recovery', gemini.recovery(input, plan.steps, LANGUAGES[input.language]));
    const source = drafts ? 'gemini' : 'rules';
    drafts = drafts || fallbackDrafts(input);
    sendJson(res, 200, { ...plan, drafts, source });
  }

  const routes = {
    'GET /api/health': (req, res) => sendJson(res, 200, { status: 'ok', ai: gemini.enabled ? 'gemini' : 'rules-only', safeBrowsing: Boolean(safeBrowsingApiKey) }),
    'POST /api/check': handleCheck,
    'POST /api/recover': handleRecover,
  };

  return async function handler(req, res) {
    const started = Date.now();
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) res.setHeader(name, value);

    let pathname = '/';
    try {
      pathname = new URL(req.url || '/', 'http://localhost').pathname;
      if (pathname.startsWith('/api/')) {
        const route = routes[`${req.method} ${pathname}`];
        if (!route) {
          const known = Object.keys(routes).some((key) => key.endsWith(` ${pathname}`));
          throw known ? new HttpError(405, 'Method not allowed') : new HttpError(404, 'Not found');
        }
        if (req.method === 'POST') {
          const verdict = limiter.check(clientId(req));
          if (!verdict.allowed) {
            throw new HttpError(429, 'Too many checks. Please wait a moment and try again.', { 'retry-after': String(verdict.retryAfterSeconds) });
          }
        }
        await route(req, res);
      } else {
        serveStatic(req, res, pathname, staticFiles);
      }
    } catch (err) {
      const status = err.status || 500;
      if (status >= 500) logger.error({ message: 'unhandled error', path: pathname, error: err.message });
      if (!res.headersSent) {
        sendJson(res, status, { error: status >= 500 ? 'Something went wrong. Please try again.' : err.message }, err.headers || {});
      }
    } finally {
      if (pathname.startsWith('/api/')) {
        logger.info({ message: 'request', httpRequest: { requestMethod: req.method, requestUrl: pathname, status: res.statusCode, latency: `${(Date.now() - started) / 1000}s` } });
      }
    }
  };
}

module.exports = { createApp, readJsonBody, HttpError, SECURITY_HEADERS, CSP, researchLinks, nextSteps };
