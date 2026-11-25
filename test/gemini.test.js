'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createGeminiClient, sanitizeAnalysis, sanitizeRecovery, parseReputation, parseModels, DEFAULT_MODELS } = require('../src/gemini');
const { TtlCache } = require('../src/cache');
const { validateCheck } = require('../src/validate');

const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=';

const goodAnalysis = {
  summary: 'Prepaid-only offer with a very low price.',
  scamType: 'fake_online_shop',
  observations: { prepaid_only: true, price_too_low: true, cod_available: false, invented_flag: true },
  redFlags: [{ flag: 'Prepaid only', evidence: 'PREPAID ONLY' }],
  entities: { handles: ['@shop'], urls: [], phones: [], upiIds: [] },
  safeReply: 'Is COD available?',
  advice: ['Do not pay in advance.'],
};

function jsonResponse(payload, { status = 200 } = {}) {
  return { ok: status >= 200 && status < 300, status, json: async () => payload };
}
const modelReply = (obj) => jsonResponse({ candidates: [{ content: { parts: [{ text: JSON.stringify(obj) }] } }] });

test('client is disabled without an API key', async () => {
  const client = createGeminiClient({ apiKey: '' });
  assert.equal(client.enabled, false);
  assert.equal(await client.analyze(validateCheck({ text: 'x' }), [], 'English'), null);
  assert.equal(await client.reputation(['@shop']), null);
  assert.equal(await client.recovery({}, [], 'English'), null);
});

test('analyze sends screenshots as inline images, the key in a header and a strict schema', async () => {
  const calls = [];
  const client = createGeminiClient({ apiKey: 'test-key', fetchImpl: async (url, init) => { calls.push({ url, init }); return modelReply(goodAnalysis); } });
  const check = validateCheck({ subject: '@shop', images: [PNG], language: 'ta' });
  const result = await client.analyze(check, ['Prepaid only'], 'Tamil');

  assert.deepEqual(result.observations, ['prepaid_only', 'price_too_low'], 'only known, true observations are kept');
  const { url, init } = calls[0];
  assert.ok(!url.includes('test-key'), 'API key must never be in the URL');
  assert.equal(init.headers['x-goog-api-key'], 'test-key');
  const body = JSON.parse(init.body);
  assert.equal(body.contents[0].parts[1].inline_data.mime_type, 'image/png');
  assert.equal(body.generationConfig.responseMimeType, 'application/json');
  assert.ok(body.generationConfig.responseSchema.properties.observations.properties.prepaid_only);
  assert.match(body.systemInstruction.parts[0].text, /untrusted/);
  assert.match(body.systemInstruction.parts[0].text, /Never invent reviews/);
  assert.match(body.systemInstruction.parts[0].text, /Tamil/);
});

test('identical checks are served from cache', async () => {
  let calls = 0;
  const client = createGeminiClient({ apiKey: 'k', cache: new TtlCache(), fetchImpl: async () => { calls += 1; return modelReply(goodAnalysis); } });
  const check = validateCheck({ text: 'prepaid only' });
  await client.analyze(check, [], 'English');
  await client.analyze(check, [], 'English');
  assert.equal(calls, 1);
});

test('falls back to the next model on retryable errors but not on a bad key', async () => {
  const seen = [];
  const client = createGeminiClient({
    apiKey: 'k', model: 'old-model,new-model',
    fetchImpl: async (url) => { seen.push(url); return url.includes('/old-model:') ? jsonResponse({}, { status: 503 }) : modelReply(goodAnalysis); },
  });
  assert.equal((await client.analyze(validateCheck({ text: 'x' }), [], 'English')).scamType, 'fake_online_shop');
  assert.equal(seen.length, 2);

  let count = 0;
  const strict = createGeminiClient({ apiKey: 'k', model: ['a-model', 'b-model'], fetchImpl: async () => { count += 1; return jsonResponse({}, { status: 403 }); } });
  await assert.rejects(strict.analyze(validateCheck({ text: 'x' }), [], 'English'), /403/);
  assert.equal(count, 1);
});

test('sanitizeAnalysis caps output and rejects empty answers', () => {
  const clean = sanitizeAnalysis({ ...goodAnalysis, summary: 'x'.repeat(5000), scamType: 'made_up', redFlags: Array(20).fill({ flag: 'f', evidence: 'e' }) });
  assert.equal(clean.summary.length, 600);
  assert.equal(clean.scamType, 'unclear');
  assert.equal(clean.redFlags.length, 6);
  assert.throws(() => sanitizeAnalysis({ summary: '' }));
  assert.throws(() => sanitizeAnalysis(null));
});

test('reputation is accepted only with real cited sources (no invented reviews)', () => {
  const grounded = {
    candidates: [{
      content: { parts: [{ text: 'VERDICT: complaints_found\nSeveral buyers report non-delivery.' }] },
      groundingMetadata: {
        groundingChunks: [{ web: { uri: 'https://www.reddit.com/r/x', title: 'reddit.com' } }, { web: { uri: 'https://www.reddit.com/r/x', title: 'dup' } }, { web: { uri: 'javascript:alert(1)' } }],
        webSearchQueries: ['shop scam'],
      },
    }],
  };
  const rep = parseReputation(grounded);
  assert.equal(rep.status, 'complaints_found');
  assert.equal(rep.sources.length, 1, 'deduplicated, https only');
  assert.match(rep.summary, /non-delivery/);

  const ungrounded = { candidates: [{ content: { parts: [{ text: 'VERDICT: complaints_found\nMany complaints.' }] } }] };
  assert.equal(parseReputation(ungrounded), null, 'claims without sources are discarded');
  assert.equal(parseReputation({}), null);
});

test('reputation uses Google Search grounding and pauses after a quota error', async () => {
  let calls = 0;
  let body;
  let time = 0;
  const client = createGeminiClient({ apiKey: 'k', now: () => time, fetchImpl: async (url, init) => { calls += 1; body = JSON.parse(init.body); return jsonResponse({}, { status: 429 }); } });
  assert.equal(await client.reputation(['@shop']), null);
  assert.deepEqual(body.tools, [{ google_search: {} }]);
  assert.equal(await client.reputation(['@other']), null);
  assert.equal(calls, 1, 'no retry while paused');
  time = 11 * 60 * 1000;
  await client.reputation(['@third']);
  assert.equal(calls, 2, 'retries after the pause');
});

test('recovery drafts are validated', async () => {
  const drafts = { explanation: 'Act fast.', complaint: 'I was cheated.', bankMessage: 'Block my card.', platformReport: 'Remove this account.' };
  const client = createGeminiClient({ apiKey: 'k', fetchImpl: async () => modelReply(drafts) });
  assert.equal((await client.recovery({ scamType: 'shopping' }, [{ title: 'Call 1930 now' }], 'Hindi')).complaint, 'I was cheated.');
  assert.throws(() => sanitizeRecovery({ explanation: 'x' }));
});

test('parseModels cleans the model list and has a safe default', () => {
  assert.deepEqual(parseModels(' x-1 , x-1, bad/model, y-2 '), ['x-1', 'y-2']);
  assert.deepEqual(parseModels(''), [DEFAULT_MODELS[0]]);
});
