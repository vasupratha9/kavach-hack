'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { recoveryPlan, fallbackDrafts } = require('../src/recovery');

const titles = (plan) => plan.steps.map((s) => s.title);

test('recent UPI loss: calling 1930 is the first, critical step', () => {
  const plan = recoveryPlan({ scamType: 'shopping', paidVia: 'upi', hoursAgo: 2, amount: 1200 });
  assert.equal(plan.urgent, true);
  assert.equal(plan.steps[0].title, 'Call 1930 now');
  assert.equal(plan.steps[0].priority, 'critical');
  assert.equal(plan.steps[0].action.value, '1930');
  assert.ok(titles(plan).includes('Raise a dispute in your UPI app'));
  assert.ok(titles(plan).includes('Report the seller account and the ad'));
  assert.ok(titles(plan).includes('Complain to the National Consumer Helpline'));
});

test('older losses are still reported but not marked urgent', () => {
  const plan = recoveryPlan({ scamType: 'shopping', paidVia: 'upi', hoursAgo: 240, amount: 0 });
  assert.equal(plan.urgent, false);
  assert.equal(plan.steps[0].priority, 'high');
});

test('card payments get chargeback advice', () => {
  const plan = recoveryPlan({ scamType: 'shopping', paidVia: 'card', hoursAgo: 1, amount: 500 });
  assert.match(plan.steps[1].detail, /chargeback/);
});

test('OTP or impersonation scams lock accounts; no money lost skips 1930', () => {
  const plan = recoveryPlan({ scamType: 'otp', paidVia: 'none', hoursAgo: 1, amount: 0 });
  assert.ok(!titles(plan).includes('Call 1930 now'));
  assert.ok(titles(plan).includes('Lock your accounts'));
  assert.equal(plan.urgent, false);
});

test('task and investment scams warn against paying "withdrawal fees"', () => {
  const plan = recoveryPlan({ scamType: 'job', paidVia: 'upi', hoursAgo: 5, amount: 9000 });
  assert.ok(titles(plan).some((t) => /Stop paying/.test(t)));
});

test('every plan warns about fake recovery agents and lists evidence', () => {
  const plan = recoveryPlan({ scamType: 'other', paidVia: 'cash', hoursAgo: 1, amount: 0 });
  assert.ok(titles(plan).includes('Beware of "recovery agents"'));
  assert.ok(plan.evidence.length >= 4);
});

test('fallback drafts fill in known facts and leave placeholders for the rest', () => {
  const drafts = fallbackDrafts({ scamType: 'shopping', paidVia: 'upi', amount: 1200, seller: '@shop', details: '' });
  assert.match(drafts.complaint, /Rs\. 1200/);
  assert.match(drafts.complaint, /@shop/);
  assert.match(drafts.complaint, /\[Transaction ID\]/);
  const blank = fallbackDrafts({ scamType: 'upi', paidVia: 'upi', amount: 0, seller: '', details: '' });
  assert.match(blank.bankMessage, /Rs\. \[amount\]/);
});
