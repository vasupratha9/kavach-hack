'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { TtlCache } = require('../src/cache');
const { createRateLimiter } = require('../src/rateLimit');
const { loadConfig } = require('../src/config');

test('TtlCache expires entries and evicts least-recently-used', async () => {
  let now = 0;
  const cache = new TtlCache({ ttlMs: 100, maxEntries: 2, now: () => now });
  cache.set('a', 1);
  cache.set('b', 2);
  cache.get('a');
  cache.set('c', 3);
  assert.equal(cache.get('b'), undefined);
  assert.equal(cache.get('a'), 1);
  now = 200;
  assert.equal(cache.get('a'), undefined);

  let calls = 0;
  const producer = async () => { calls += 1; return 'v'; };
  await cache.wrap('k', producer);
  await cache.wrap('k', producer);
  assert.equal(calls, 1);
  await cache.wrap('nullish', async () => null);
  assert.equal(cache.get('nullish'), undefined, 'failures are not cached');
});

test('rate limiter blocks after the limit and resets after the window', () => {
  let now = 0;
  const limiter = createRateLimiter({ windowMs: 1000, max: 2, now: () => now });
  assert.equal(limiter.check('ip').allowed, true);
  assert.equal(limiter.check('ip').allowed, true);
  const blocked = limiter.check('ip');
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.retryAfterSeconds, 1);
  assert.equal(limiter.check('other').allowed, true, 'clients are isolated');
  now = 1500;
  assert.equal(limiter.check('ip').allowed, true);
  limiter.sweep();
  limiter.stop();
});

test('config reads environment overrides and ignores invalid numbers', () => {
  const config = loadConfig({ PORT: '9000', GEMINI_API_KEY: 'k', RATE_LIMIT_MAX: 'abc', GEMINI_SEARCH: 'off', SAFE_BROWSING_API_KEY: 's' });
  assert.equal(config.port, 9000);
  assert.equal(config.geminiApiKey, 'k');
  assert.equal(config.rateLimitMax, 40);
  assert.equal(config.geminiSearch, false);
  assert.equal(config.safeBrowsingApiKey, 's');
  assert.ok(Object.isFrozen(config));
  assert.equal(loadConfig({}).geminiSearch, true);
});

test('server starts on the configured port and shuts down cleanly', async () => {
  const { start } = require('../server');
  const server = start(loadConfig({ PORT: '18089' }));
  await new Promise((resolve) => server.once('listening', resolve));
  const res = await new Promise((resolve) => http.get('http://127.0.0.1:18089/api/health', resolve));
  assert.equal(res.statusCode, 200);
  res.resume();
  await new Promise((resolve) => server.close(resolve));
  process.removeAllListeners('SIGTERM');
  process.removeAllListeners('SIGINT');
});
