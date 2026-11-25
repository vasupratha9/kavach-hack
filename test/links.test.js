'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { parseLink, registrableDomain, inspectLink, domainAge, ageSignal, safeBrowsing } = require('../src/links');

const hitIds = (raw) => inspectLink(raw).hits.map((h) => h.id);

test('parseLink accepts web addresses and rejects everything else', () => {
  assert.equal(parseLink('meesho.com').hostname, 'meesho.com');
  assert.equal(parseLink('https://www.flipkart.com/x').hostname, 'www.flipkart.com');
  for (const bad of ['', 'hello world', 'javascript:alert(1)', 'ftp://x.com', 'nodot', 'a'.repeat(400)]) assert.equal(parseLink(bad), null, bad);
});

test('registrableDomain handles Indian two-part suffixes', () => {
  assert.equal(registrableDomain('shop.example.co.in'), 'example.co.in');
  assert.equal(registrableDomain('www.amazon.in'), 'amazon.in');
  assert.equal(registrableDomain('a.b.flipkart.com'), 'flipkart.com');
});

test('flags look-alike brand domains, including digit swaps', () => {
  assert.ok(hitIds('amaz0n-sale.xyz').includes('lookalike_domain'));
  assert.ok(hitIds('flipkart-bigbillion-offer.com').includes('lookalike_domain'));
  assert.ok(hitIds('sbi-kyc-update.online').includes('lookalike_domain'));
});

test('official brand domains are not flagged as look-alikes', () => {
  for (const ok of ['www.amazon.in', 'flipkart.com', 'www.myntra.com', 'onlinesbi.sbi']) {
    assert.ok(!hitIds(ok).includes('lookalike_domain'), ok);
  }
});

test('flags short links, raw IPs, disguised characters, risky endings and plain http', () => {
  assert.ok(hitIds('bit.ly/abc').includes('short_link'));
  assert.ok(hitIds('http://103.21.44.9/login').includes('ip_link'));
  assert.ok(hitIds('http://103.21.44.9/login').includes('no_https'));
  assert.ok(hitIds('аmazon.com').includes('punycode_domain'));
  assert.ok(hitIds('trendykurtis.shop').includes('risky_tld'));
  assert.equal(inspectLink('not a link'), null);
});

test('domainAge reads the RDAP registration date and caches nothing on failure', async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    return { ok: true, json: async () => ({ events: [{ eventAction: 'registration', eventDate: '2026-11-01T00:00:00Z' }] }) };
  };
  const age = await domainAge('newshop.shop', { fetchImpl, now: Date.parse('2026-11-25T00:00:00Z') });
  assert.deepEqual(age, { registered: '2026-11-01', ageDays: 24 });
  assert.match(calls[0].url, /^https:\/\/rdap\.org\/domain\/newshop\.shop$/);
  assert.ok(calls[0].init.headers['user-agent']);

  assert.equal(await domainAge('x.com', { fetchImpl: async () => ({ ok: false }) }), null);
  assert.equal(await domainAge('x.com', { fetchImpl: async () => { throw new Error('offline'); } }), null);
  assert.equal(await domainAge('bad domain', { fetchImpl }), null, 'invalid names are never sent');
});

test('ageSignal maps domain age to risk bands', () => {
  assert.equal(ageSignal(5), 'domain_very_new');
  assert.equal(ageSignal(90), 'domain_new');
  assert.equal(ageSignal(300), 'domain_young');
  assert.equal(ageSignal(600), null);
  assert.equal(ageSignal(2000), 'domain_established');
  assert.equal(ageSignal(null), null);
});

test('Safe Browsing sends the key in a header and reports matches', async () => {
  let seen;
  const fetchImpl = async (url, init) => { seen = { url, init }; return { ok: true, json: async () => ({ matches: [{ threatType: 'SOCIAL_ENGINEERING' }] }) }; };
  assert.equal(await safeBrowsing(['https://bad.example/'], { apiKey: 'sb-key', fetchImpl }), true);
  assert.ok(!seen.url.includes('sb-key'), 'API key must not be in the URL');
  assert.equal(seen.init.headers['x-goog-api-key'], 'sb-key');
  assert.equal(await safeBrowsing(['https://ok.example/'], { apiKey: 'k', fetchImpl: async () => ({ ok: true, json: async () => ({}) }) }), false);
  assert.equal(await safeBrowsing(['https://x/'], { apiKey: '' }), null, 'disabled without a key');
  assert.equal(await safeBrowsing(['https://x/'], { apiKey: 'k', fetchImpl: async () => { throw new Error('down'); } }), null);
});
