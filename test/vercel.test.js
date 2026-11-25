'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

// Every Vercel route module must export the same ready-to-use (req, res) handler.
const check = require('../api/check');
const recover = require('../api/recover');
const health = require('../api/health');

test('Vercel routes share one handler instance', () => {
  assert.equal(typeof check, 'function');
  for (const route of [recover, health]) assert.equal(route, check);
});

test('Vercel handler serves the API with security headers', async () => {
  const server = http.createServer(health);
  await new Promise((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const res = await fetch(`${base}/api/health`);
    assert.equal(res.status, 200);
    assert.equal((await res.json()).status, 'ok');
    assert.match(res.headers.get('content-security-policy'), /default-src 'self'/);
    const bad = await fetch(`${base}/api/check`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    assert.equal(bad.status, 400);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('vercel.json serves /public with the same CSP as the server', () => {
  const config = require('../vercel.json');
  const { CSP } = require('../src/app');
  assert.equal(config.outputDirectory, 'public');
  const headers = Object.fromEntries(config.headers.find((h) => h.source === '/(.*)').headers.map((h) => [h.key, h.value]));
  assert.equal(headers['Content-Security-Policy'], CSP);
  for (const key of ['X-Content-Type-Options', 'X-Frame-Options', 'Referrer-Policy', 'Permissions-Policy', 'Strict-Transport-Security']) assert.ok(headers[key], key);
});
