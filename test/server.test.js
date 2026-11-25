'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const { createApp } = require('../src/app');
const { createRateLimiter } = require('../src/rateLimit');
const { loadStaticFiles } = require('../src/static');

const silent = { info() {}, warn() {}, error() {} };
const staticFiles = loadStaticFiles(path.join(__dirname, '..', 'public'));

function fakeGemini(overrides = {}) {
  return {
    enabled: true,
    analyze: async () => ({
      summary: 'Looks like a fake shop.', scamType: 'fake_online_shop', observations: ['comments_off'],
      redFlags: [{ flag: 'Comments off', evidence: 'Comments limited' }],
      entities: { handles: ['Shop_X'], urls: ['newshop.shop'], phones: [], upiIds: [] }, safeReply: 'Is COD available?', advice: ['Ask for COD.'],
    }),
    reputation: async () => null,
    recovery: async () => ({ explanation: 'Act now.', complaint: 'I was cheated.', bankMessage: 'Block it.', platformReport: 'Remove it.' }),
    ...overrides,
  };
}

/** RDAP stub: every domain was registered 10 days before "now". */
const rdapFetch = async () => ({ ok: true, json: async () => ({ events: [{ eventAction: 'registration', eventDate: new Date(Date.now() - 10 * 86400000).toISOString() }] }) });

async function withServer(options, fn) {
  const app = createApp({ gemini: fakeGemini(), limiter: createRateLimiter({ max: 100 }), staticFiles, fetchImpl: rdapFetch, logger: silent, ...options });
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  try {
    await fn(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

const postJson = (url, body, headers = {}) => fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: typeof body === 'string' ? body : JSON.stringify(body) });

test('health endpoint reports AI status with security headers', async () => {
  await withServer({}, async (base) => {
    const res = await fetch(`${base}/api/health`);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { status: 'ok', ai: 'gemini', safeBrowsing: false });
    assert.match(res.headers.get('content-security-policy'), /default-src 'self'/);
    assert.match(res.headers.get('content-security-policy'), /frame-ancestors 'none'/);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('x-frame-options'), 'DENY');
    assert.match(res.headers.get('permissions-policy'), /microphone=\(self\)/);
    assert.equal(res.headers.get('cache-control'), 'no-store');
  });
});

test('seller check merges rules, AI observations, screenshot links and domain age into one verdict', async () => {
  await withServer({}, async (base) => {
    const res = await postJson(`${base}/api/check`, { mode: 'seller', subject: '@shop_x', text: 'prepaid only, no COD. Order at amaz0n-deals.xyz', flags: ['price_too_low'] });
    assert.equal(res.status, 200);
    const data = await res.json();
    const flags = Object.fromEntries(data.redFlags.map((f) => [f.id, f.source]));
    assert.equal(flags.prepaid_only, 'message scan');
    assert.equal(flags.price_too_low, 'you');
    assert.equal(flags.comments_off, 'Gemini');
    assert.equal(flags.lookalike_domain, 'link check');
    assert.equal(flags.domain_very_new, 'domain registry');
    assert.equal(data.verdict.level, 'scam');
    assert.equal(data.source, 'gemini');
    assert.equal(data.ai.safeReply, 'Is COD available?');
    assert.deepEqual(data.entities.handles, ['@shop_x'], 'handles are normalised and de-duplicated');
    assert.ok(data.domains.some((d) => d.domain === 'newshop.shop' && d.ageDays === 10), 'link read from screenshot is checked too');
    assert.ok(data.research.some((r) => r.url.startsWith('https://www.instagram.com/shop_x/')));
    assert.ok(data.research.every((r) => r.url.startsWith('https://')));
  });
});

test('when Gemini fails the check still works on rules alone', async () => {
  const gemini = fakeGemini({ analyze: async () => { throw new Error('quota'); } });
  await withServer({ gemini }, async (base) => {
    const data = await (await postJson(`${base}/api/check`, { mode: 'message', text: 'You are under digital arrest. Share the OTP now.' })).json();
    assert.equal(data.source, 'rules');
    assert.equal(data.ai, null);
    assert.ok(['high', 'scam'].includes(data.verdict.level));
    assert.ok(data.nextSteps.some((s) => /1930/.test(s)));
  });
});

test('grounded web complaints raise the risk and are cited', async () => {
  const gemini = fakeGemini({ reputation: async () => ({ status: 'complaints_found', summary: 'Buyers report non-delivery.', sources: [{ title: 'Reddit thread', url: 'https://reddit.com/x' }], queries: [] }) });
  await withServer({ gemini }, async (base) => {
    const data = await (await postJson(`${base}/api/check`, { subject: '@shop_x' })).json();
    const web = data.redFlags.find((f) => f.id === 'web_complaints');
    assert.equal(web.source, 'Google Search');
    assert.equal(data.reputation.sources[0].url, 'https://reddit.com/x');
  });
});

test('live scan is instant and rule-based', async () => {
  await withServer({ gemini: fakeGemini({ analyze: async () => { throw new Error('must not be called'); } }) }, async (base) => {
    const data = await (await postJson(`${base}/api/scan`, { text: 'Sir install AnyDesk and tell me the OTP' })).json();
    assert.ok(data.risk >= 50);
    assert.deepEqual(data.redFlags.map((f) => f.id).sort(), ['otp_request', 'remote_access']);
    assert.ok(data.redFlags[0].tip);
  });
});

test('recovery returns ordered steps and AI drafts, with template fallback', async () => {
  await withServer({}, async (base) => {
    const data = await (await postJson(`${base}/api/recover`, { scamType: 'shopping', paidVia: 'upi', hoursAgo: 1, amount: 999 })).json();
    assert.equal(data.urgent, true);
    assert.equal(data.steps[0].title, 'Call 1930 now');
    assert.equal(data.source, 'gemini');
  });
  await withServer({ gemini: fakeGemini({ recovery: async () => { throw new Error('down'); } }) }, async (base) => {
    const data = await (await postJson(`${base}/api/recover`, { scamType: 'shopping', paidVia: 'upi', amount: 999 })).json();
    assert.equal(data.source, 'rules');
    assert.match(data.drafts.complaint, /Rs\. 999/);
  });
});

test('rejects bad input with clear 4xx errors', async () => {
  await withServer({ maxBodyBytes: 200, maxUploadBytes: 500 }, async (base) => {
    assert.equal((await postJson(`${base}/api/check`, {})).status, 400);
    assert.equal((await postJson(`${base}/api/check`, '{bad json')).status, 400);
    assert.equal((await postJson(`${base}/api/check`, { text: 'x', mode: 'evil' })).status, 400);
    assert.equal((await fetch(`${base}/api/check`, { method: 'POST', headers: { 'content-type': 'text/plain' }, body: 'x' })).status, 415);
    assert.equal((await postJson(`${base}/api/check`, { text: 'x'.repeat(2000) })).status, 413);
    assert.equal((await postJson(`${base}/api/scan`, { text: 'x'.repeat(500) })).status, 413, 'small routes have a small body limit');
    assert.equal((await fetch(`${base}/api/check`)).status, 405);
    assert.equal((await fetch(`${base}/api/nope`)).status, 404);
  });
});

test('rate limiting returns 429 with Retry-After', async () => {
  await withServer({ limiter: createRateLimiter({ max: 1 }) }, async (base) => {
    assert.equal((await postJson(`${base}/api/recover`, {})).status, 200);
    const blocked = await postJson(`${base}/api/recover`, {});
    assert.equal(blocked.status, 429);
    assert.ok(Number(blocked.headers.get('retry-after')) >= 1);
  });
});

test('serves the front-end with gzip and ETags, and never outside the allow-list', async () => {
  await withServer({}, async (base) => {
    const res = await fetch(`${base}/`);
    assert.equal(res.status, 200);
    assert.match(await res.text(), /Kavach/);
    const etag = res.headers.get('etag');
    assert.equal((await fetch(`${base}/`, { headers: { 'if-none-match': etag } })).status, 304);
    assert.equal((await fetch(`${base}/app.js`)).headers.get('content-type'), 'text/javascript; charset=utf-8');
    for (const evil of ['/../package.json', '/%2e%2e/server.js', '/.env', '/src/app.js']) {
      assert.equal((await fetch(`${base}${evil}`)).status, 404, evil);
    }
  });
});

test('internal errors are hidden from the client', async () => {
  const gemini = fakeGemini({ reputation: () => { throw new Error('secret stack detail'); } });
  await withServer({ gemini, fetchImpl: null }, async (base) => {
    const res = await postJson(`${base}/api/check`, { text: 'visit shop.example.com' });
    const body = await res.text();
    assert.ok(!body.includes('secret stack detail'));
  });
});
