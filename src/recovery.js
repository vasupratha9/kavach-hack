'use strict';

/**
 * "I got scammed" recovery planner.
 * Deterministic, India-specific steps ordered by what saves money first.
 * The first hours matter: funds reported quickly to 1930 can often be frozen
 * before the scammer withdraws them.
 */

const OFFICIAL = Object.freeze({
  helpline: { number: '1930', label: 'National Cyber Crime Helpline' },
  portal: 'https://cybercrime.gov.in',
  consumer: { number: '1915', label: 'National Consumer Helpline', url: 'https://consumerhelpline.gov.in' },
  chakshu: 'https://sancharsaathi.gov.in',
  edaakhil: 'https://edaakhil.nic.in',
});

const MONEY_METHODS = new Set(['upi', 'card', 'netbanking', 'wallet']);

function step(priority, title, detail, action) {
  return { priority, title, detail, ...(action ? { action } : {}) };
}

/** Builds the ordered action plan for a scam that already happened. */
function recoveryPlan({ scamType, paidVia, hoursAgo, amount }) {
  const steps = [];
  const moneyLost = MONEY_METHODS.has(paidVia);
  const golden = hoursAgo <= 72;

  if (moneyLost) {
    steps.push(step(
      golden ? 'critical' : 'high',
      'Call 1930 now',
      golden
        ? 'Report the payment to the National Cyber Crime Helpline right away. In the first hours your money can often be frozen in the scammer\'s account before they withdraw it. Keep the transaction ID (UTR) ready.'
        : 'Report the payment to the National Cyber Crime Helpline. Even after a few days, the scammer\'s account can be flagged and frozen.',
      { type: 'tel', value: OFFICIAL.helpline.number, label: 'Call 1930' },
    ));
    steps.push(step('critical', 'Call your bank and block further payments',
      paidVia === 'card'
        ? 'Block the card in your bank app, then ask for a chargeback for "goods not received" or "fraud". Card disputes have time limits, so ask today.'
        : 'Use the number on the back of your card or in the official bank app. Ask them to raise a fraud complaint against the transaction ID and block UPI or net banking if needed.'));
  }

  if (scamType === 'otp' || scamType === 'impersonation' || paidVia === 'netbanking') {
    steps.push(step('critical', 'Lock your accounts',
      'Change your UPI PIN, net-banking password and email password. If you installed any app they asked for (AnyDesk, TeamViewer, an APK), uninstall it and restart the phone.'));
  }

  steps.push(step(moneyLost ? 'high' : 'medium', 'File a complaint on cybercrime.gov.in',
    'Choose "Report Cyber Crime" → "Financial Fraud" (or "Other cyber crime"). Upload your screenshots and payment proof. Note the acknowledgement number.',
    { type: 'link', value: OFFICIAL.portal, label: 'Open cybercrime.gov.in' }));

  if (paidVia === 'upi') {
    steps.push(step('high', 'Raise a dispute in your UPI app',
      'In GPay, PhonePe or Paytm open the payment → "Help" or "Report a problem" → raise a dispute. This creates an official NPCI record.'));
  }

  if (scamType === 'shopping') {
    steps.push(step('high', 'Report the seller account and the ad',
      'On Instagram open the profile → ⋯ → Report → "Scam, fraud or spam". If you saw an ad, tap ⋯ on the ad → "Report ad". Ask friends who saw it to report too, so it is taken down faster.'));
    steps.push(step('medium', 'Complain to the National Consumer Helpline',
      'Call 1915 or use the NCH app or website for non-delivery. If the seller is a registered business you can also file a consumer case online on e-Daakhil.',
      { type: 'tel', value: OFFICIAL.consumer.number, label: 'Call 1915' }));
  }

  if (scamType === 'job' || scamType === 'investment') {
    steps.push(step('high', 'Stop paying, even to "withdraw" your balance',
      'Task and trading scams show fake profits, then ask for "tax" or "unlock fees". Every extra payment is lost too. Leave the group.'));
  }

  steps.push(step('medium', 'Report the number or message on Sanchar Saathi (Chakshu)',
    'Report fraud calls, SMS and WhatsApp numbers so they can be blocked across networks.',
    { type: 'link', value: OFFICIAL.chakshu, label: 'Open Sanchar Saathi' }));

  steps.push(step('medium', 'Save every piece of evidence',
    'Screenshot the profile (with its @handle), the ad, the full chat, the payment receipt with the UTR / transaction ID, and any phone numbers or UPI IDs. Do not delete the chat.'));

  steps.push(step('medium', 'Beware of "recovery agents"',
    'People who promise to get your money back for a fee are a second scam. Only the police, your bank and the official portals can help.'));

  return {
    helpline: OFFICIAL.helpline,
    urgent: moneyLost && golden,
    amount,
    steps,
    evidence: ['Seller / caller profile link or @handle', 'Screenshots of the chat, ad and posts', 'Payment receipt with UTR or transaction ID', 'Phone numbers, UPI IDs and websites used', 'Date and time of each payment'],
  };
}

/** Template drafts used when Gemini is unavailable, so the user is never left with nothing. */
function fallbackDrafts({ scamType, paidVia, amount, seller, details }) {
  const who = seller || '[seller name / @handle / phone number]';
  const amt = amount ? `Rs. ${amount}` : 'Rs. [amount]';
  const what = scamType === 'shopping' ? 'paid for goods that were never delivered' : 'was cheated into making a payment';
  return {
    explanation: 'Act quickly: report the payment to 1930 and your bank first, then file the online complaint. Keep all screenshots.',
    complaint: `I wish to report an online fraud. On [Date] I ${what}. I paid ${amt} by ${paidVia.toUpperCase()} to ${who}. Transaction ID / UTR: [Transaction ID]. ${details ? `Details: ${details} ` : ''}After the payment the person stopped responding. I have attached screenshots of the profile, the chat and the payment receipt. I request you to freeze the beneficiary account and take action.`,
    bankMessage: `Dear Sir/Madam, I am a victim of online fraud. On [Date] a payment of ${amt} (Transaction ID: [Transaction ID]) was made from my account [Account number - last 4 digits] to ${who}. Please register a fraud complaint, block further debits and help recover the amount. Cyber complaint number: [Acknowledgement number].`,
    platformReport: `This account (${who}) is running a fraud. I paid ${amt} and received nothing; the seller then stopped replying. Please remove the account and its ads to protect other users.`,
  };
}

module.exports = { recoveryPlan, fallbackDrafts, OFFICIAL };
