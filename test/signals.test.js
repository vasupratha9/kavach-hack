'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { SIGNALS, scanText, extractEntities, score, quickScan } = require('../src/signals');

const ids = (text) => scanText(text).map((h) => h.id);

test('every signal has an id, a label, a tip and a non-zero weight', () => {
  const seen = new Set();
  for (const s of SIGNALS) {
    assert.ok(/^[a-z_]+$/.test(s.id), s.id);
    assert.ok(!seen.has(s.id), `duplicate ${s.id}`);
    seen.add(s.id);
    assert.ok(s.label && s.tip, s.id);
    assert.notEqual(s.weight, 0, s.id);
  }
});

test('detects the "digital arrest" call script', () => {
  const found = ids('This is Mumbai police. A parcel in your name with drugs was seized by customs. You are under digital arrest, do not tell anyone.');
  for (const id of ['authority_threat', 'parcel_threat', 'secrecy']) assert.ok(found.includes(id), id);
});

test('detects OTP, screen-sharing and "PIN to receive money" tricks', () => {
  assert.ok(ids('Please share the OTP you just received').includes('otp_request'));
  assert.ok(ids('Install AnyDesk so I can help you').includes('remote_access'));
  assert.ok(ids('Scan the QR and enter your UPI PIN to receive the cashback').includes('receive_pin'));
});

test('detects task jobs, investment, KYC and prepaid-only seller patterns', () => {
  assert.ok(ids('Part time job, earn daily by liking YouTube videos').includes('task_job'));
  assert.ok(ids('Guaranteed returns of 40% profit in our VIP group').includes('investment_returns'));
  assert.ok(ids('Your SBI KYC has expired, account will be blocked today').includes('kyc_block'));
  assert.ok(ids('3 kurtis 399, prepaid only, no COD').includes('prepaid_only'));
  assert.ok(ids('DM for price').includes('dm_for_price'));
});

test('understands common Hindi scam words', () => {
  assert.ok(ids('आपका ओटीपी बताइए').includes('otp_request'));
  assert.ok(ids('आपको डिजिटल अरेस्ट किया गया है').includes('authority_threat'));
});

test('ordinary messages raise no flags', () => {
  assert.deepEqual(ids('Hi, are we still meeting for lunch tomorrow at 1?'), []);
  assert.equal(quickScan('Your order from the shop was delivered today. Thanks!').level, 'low');
});

test('hits carry the matching phrase as evidence', () => {
  const [hit] = scanText('kindly share otp');
  assert.equal(hit.id, 'otp_request');
  assert.match(hit.evidence, /otp/i);
});

test('extracts handles, links, phone numbers and UPI IDs', () => {
  const e = extractEntities('Order from @Trendy_Kurtis, visit trendykurti.shop or https://bit.ly/x1. Pay rahul.k@ybl or call +91 98765 43210');
  assert.deepEqual(e.handles, ['@trendy_kurtis']);
  assert.ok(e.urls.includes('trendykurti.shop'));
  assert.ok(e.urls.includes('https://bit.ly/x1'));
  assert.deepEqual(e.upiIds, ['rahul.k@ybl']);
  assert.ok(e.phones.some((p) => p.endsWith('9876543210')));
});

test('score is explainable, deduplicated and bounded', () => {
  const result = score([
    { id: 'otp_request', source: 'message scan', evidence: 'otp' },
    { id: 'otp_request', source: 'Gemini' },
    { id: 'authority_threat' },
    { id: 'not_a_signal' },
  ]);
  assert.equal(result.redFlags.length, 2);
  assert.equal(result.redFlags[0].id, 'otp_request');
  assert.equal(result.redFlags[0].source, 'message scan', 'first source wins');
  assert.ok(result.risk > 50 && result.risk <= 100);
  assert.equal(result.level, 'high');
});

test('trust signals lower risk and are reported separately', () => {
  const risky = score([{ id: 'prepaid_only' }, { id: 'price_too_low' }]);
  const mixed = score([{ id: 'prepaid_only' }, { id: 'price_too_low' }, { id: 'cod_available' }, { id: 'tagged_customers' }]);
  assert.ok(mixed.risk < risky.risk);
  assert.equal(mixed.greenFlags.length, 2);
  assert.deepEqual(score([{ id: 'cod_available' }]).risk, 0);
  assert.equal(score([]).label, 'No major red flags found');
});

test('levels follow the risk bands', () => {
  assert.equal(score([{ id: 'urgency' }]).level, 'low');
  assert.equal(score([{ id: 'prepaid_only' }]).level, 'caution');
  assert.equal(score([{ id: 'otp_request' }, { id: 'urgency' }]).level, 'high');
});
