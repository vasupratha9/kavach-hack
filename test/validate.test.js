'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { validateCheck, validateRecovery, validateImages, cleanText, ValidationError } = require('../src/validate');

const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=';

test('validateCheck applies safe defaults and keeps allowed fields only', () => {
  const check = validateCheck({ subject: ' @seller ', text: 'hi', evil: 'x' });
  assert.deepEqual(Object.keys(check).sort(), ['images', 'language', 'mode', 'subject', 'text']);
  assert.equal(check.mode, 'seller');
  assert.equal(check.language, 'en');
  assert.equal(check.subject, '@seller');
});

test('validateCheck requires something to check', () => {
  assert.throws(() => validateCheck({}), ValidationError);
  assert.throws(() => validateCheck(null), ValidationError);
  assert.throws(() => validateCheck([]), ValidationError);
});

test('validateCheck rejects unknown modes and languages', () => {
  assert.throws(() => validateCheck({ text: 'x', mode: 'hack' }), /mode/);
  assert.throws(() => validateCheck({ text: 'x', language: 'xx' }), /language/);
});

test('text is stripped of markup and control characters and capped', () => {
  assert.equal(cleanText('<script>alert(1)</script>', 100, 'x'), 'script alert(1) /script');
  assert.equal(cleanText('a\u0000b', 10, 'x'), 'a b');
  assert.equal(cleanText('x'.repeat(50), 10, 'x').length, 10);
  assert.equal(cleanText('line1\n\n\n\nline2', 100, 'x', { multiline: true }), 'line1\n\nline2');
  assert.throws(() => cleanText(5, 10, 'x'), /must be text/);
});

test('images are accepted only when the real file signature matches', () => {
  const [img] = validateImages([PNG]);
  assert.equal(img.mimeType, 'image/png');
  // Claims to be JPEG but the bytes are PNG: detected from the bytes.
  assert.equal(validateImages([PNG.replace('image/png', 'image/jpeg')])[0].mimeType, 'image/png');
  const fake = `data:image/png;base64,${Buffer.from('<svg onload=alert(1)> not an image').toString('base64')}`;
  assert.throws(() => validateImages([fake]), /not a real image/);
  assert.throws(() => validateImages(['data:image/svg+xml;base64,PHN2Zz4=']), /not a supported image/);
  assert.throws(() => validateImages(['https://evil.example/a.png']), /not a supported image/);
  assert.throws(() => validateImages([PNG, PNG, PNG, PNG]), /up to 3/);
  assert.throws(() => validateImages('nope'), /must be a list/);
});

test('oversized images are rejected', () => {
  const big = `data:image/png;base64,${Buffer.alloc(2 * 1024 * 1024, 1).toString('base64')}`;
  assert.throws(() => validateImages([big]), /too large/);
});

test('validateRecovery checks types, ranges and defaults', () => {
  const r = validateRecovery({ amount: '1200.4', hoursAgo: '3' });
  assert.equal(r.scamType, 'shopping');
  assert.equal(r.paidVia, 'upi');
  assert.equal(r.amount, 1200);
  assert.equal(r.hoursAgo, 3);
  assert.throws(() => validateRecovery({ amount: -5 }), /amount/);
  assert.throws(() => validateRecovery({ hoursAgo: 'soon' }), /hoursAgo/);
  assert.throws(() => validateRecovery({ paidVia: 'gold' }), /paidVia/);
});
