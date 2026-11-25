'use strict';

/**
 * Kavach's deterministic scam-signal engine.
 *
 * Every red (or green) flag is a named, weighted signal with a plain-language
 * tip. Signals come from four places: text patterns in messages and call
 * transcripts, link and domain checks, observations about a seller (ticked
 * by the user or read from screenshots by Gemini), and real-world lookups.
 * The risk score is computed only from these signals, so every verdict can be
 * explained line by line, and the AI cannot inflate or hide risk on its own.
 */

/* Weight > 0 raises risk; weight < 0 is a trust signal that lowers it. */
const SIGNALS = Object.freeze([
  // --- Message and call patterns -------------------------------------------------
  { id: 'otp_request', weight: 40, label: 'Asks for an OTP, PIN or password', tip: 'No bank, courier or company ever needs your OTP or PIN. Never share it.',
    patterns: [/\b(otp|one[\s-]?time[\s-]?password|verification code|upi pin|atm pin|cvv)\b/i, /ओटीपी|पिन बताओ/] },
  { id: 'authority_threat', weight: 35, label: 'Claims to be police, CBI, customs or a court', tip: 'There is no such thing as a "digital arrest". Real police never question or arrest you on a video call. Hang up.',
    patterns: [/\b(digital arrest|cbi|narcotics|customs officer|cyber ?cell|crime branch|arrest warrant|money laundering|ed officer|enforcement directorate|trai|mumbai police|court notice)\b/i, /गिरफ्तार|डिजिटल अरेस्ट/] },
  { id: 'parcel_threat', weight: 30, label: 'Says a parcel in your name was seized or held', tip: 'Courier companies do not call about "illegal parcels". This is the start of the digital-arrest scam.',
    patterns: [/\b(parcel|courier|package|fedex|dhl|blue ?dart)\b[^.]{0,60}\b(seized|illegal|drugs|held|customs|blocked|stuck)\b/i, /पार्सल/] },
  { id: 'kyc_block', weight: 28, label: 'Says your account, KYC or SIM will be blocked', tip: 'Banks and telecoms never block you over a call or SMS link. Visit the branch or official app yourself.',
    patterns: [/\b(kyc|pan|aadhaar|sim)\b[^.]{0,40}\b(update|expir\w*|block\w*|suspend\w*|deactivat\w*)\b/i, /\baccount (will be |has been |is )?(blocked|suspended|frozen|closed)\b/i] },
  { id: 'remote_access', weight: 40, label: 'Asks you to install a screen-sharing app', tip: 'AnyDesk, TeamViewer and similar apps let a stranger control your phone and bank apps. Uninstall it now.',
    patterns: [/\b(anydesk|teamviewer|quick ?support|rustdesk|airdroid|screen ?shar\w*)\b/i] },
  { id: 'receive_pin', weight: 40, label: 'Asks you to scan a QR or enter a PIN to receive money', tip: 'You never need a UPI PIN or a QR scan to receive money. Entering a PIN always sends money out.',
    patterns: [/\b(scan|enter|use)\b[^.]{0,40}\b(qr|pin)\b[^.]{0,40}\b(receive|get|refund|credit|cashback)\b/i, /\b(receive|get|refund)\b[^.]{0,40}\b(enter|scan)\b[^.]{0,20}\b(pin|qr)\b/i] },
  { id: 'prize_lottery', weight: 28, label: 'Says you won a prize, lottery or lucky draw', tip: 'You cannot win a contest you never entered. Any "fee" to release a prize is the scam.',
    patterns: [/\b(lottery|lucky draw|you (have )?won|prize money|kbc|jackpot|winner of)\b/i, /लॉटरी|इनाम/] },
  { id: 'task_job', weight: 28, label: 'Easy job: likes, reviews or tasks for money', tip: 'Paid "like and review" tasks pay small amounts first, then ask you to deposit money. You will not get it back.',
    patterns: [/\b(work from home|part[\s-]?time (job|work)|daily (income|earning)|earn ₹?\s?\d+[\s,]*(per day|daily)|like (and|&) subscribe|youtube (likes|videos?)|rate (hotels|products)|prepaid task|telegram task|google map reviews?)\b/i] },
  { id: 'investment_returns', weight: 28, label: 'Promises guaranteed or very high returns', tip: 'Guaranteed high returns do not exist. Only invest through SEBI-registered apps you install yourself.',
    patterns: [/\b(double (your )?money|guaranteed (returns?|profit)|\d{2,3}\s?% (returns?|profit)|crypto (trading|investment)|stock tips|ipo allotment|trading group|vip group)\b/i] },
  { id: 'relative_emergency', weight: 22, label: 'A "friend or relative" needs money urgently from a new number', tip: 'Call the person on their old number before you pay anything. Scammers copy names and photos.',
    patterns: [/\b(new number|lost my phone|my phone is broken|in hospital,? send|send money urgently)\b/i] },
  { id: 'utility_cutoff', weight: 26, label: 'Threatens to cut electricity, gas or phone tonight', tip: 'Utilities send written notices. Pay only through the official app or website.',
    patterns: [/\b(electricity|bijli|power|gas|connection)\b[^.]{0,40}\b(disconnect\w*|cut|tonight)\b/i] },
  { id: 'refund_link', weight: 22, label: 'Refund or cashback through a link or form', tip: 'Refunds go back to your original payment method automatically. You never fill a form or enter a PIN.',
    patterns: [/\b(refund|cashback|reward points?)\b[^.]{0,50}\b(link|click|form|apk|claim)\b/i] },
  { id: 'apk_install', weight: 35, label: 'Asks you to install an app from a link (APK)', tip: 'Apps sent as links or files can read your SMS and OTPs. Install apps only from the Play Store.',
    patterns: [/\.apk\b/i, /\b(download|install) (this|the) app\b/i] },
  { id: 'loan_offer', weight: 18, label: 'Instant loan with no documents', tip: 'Fake loan apps steal contacts and photos to blackmail. Use only RBI-registered lenders.',
    patterns: [/\b(instant|pre-?approved) loan\b/i, /\bloan\b[^.]{0,30}\bno (documents?|cibil)\b/i] },
  { id: 'urgency', weight: 12, label: 'Pressure to act right now', tip: 'Scammers rush you so you cannot think. A real offer or problem can wait 10 minutes.',
    patterns: [/\b(urgent\w*|immediately|right now|within (24|12|2|1) ?(hours?|hrs?|minutes?|mins?)|today only|only today|last (\d+ )?(pieces?|left|chance)|limited stock|hurry|offer ends|few left)\b/i] },
  { id: 'secrecy', weight: 18, label: 'Tells you not to tell anyone', tip: 'Being told to keep it secret is a classic sign of a scam. Tell a family member now.',
    patterns: [/\b(don'?t tell|do not tell|keep (this|it) (secret|confidential)|don'?t disconnect|stay on (the )?(call|video))\b/i] },

  // --- Seller observations (Gemini reads these from screenshots and descriptions) ---
  { id: 'prepaid_only', weight: 20, observable: true, label: 'Prepaid only, no Cash on Delivery', tip: 'Insist on COD or a marketplace with buyer protection for a seller you have never bought from.',
    patterns: [/\b(prepaid only|only prepaid|no cod|cod (is )?not available|advance payment|full payment (first|in advance)|pay first)\b/i] },
  { id: 'personal_payment', weight: 18, observable: true, label: 'Payment to a personal UPI ID or phone number', tip: 'Real brands use a payment gateway. Paying a personal UPI ID gives you no buyer protection.' },
  { id: 'price_too_low', weight: 18, observable: true, label: 'Price far below the market price', tip: 'A ₹1,999 outfit for ₹399 usually means it will never arrive, or it is not what the photo shows.' },
  { id: 'comments_off', weight: 18, observable: true, label: 'Comments turned off or hidden', tip: 'Sellers hide comments when buyers complain about non-delivery.' },
  { id: 'new_account', weight: 22, observable: true, label: 'New account, or the username was changed recently', tip: 'On Instagram open the profile, tap ⋯ then "About this account" to see when it joined and its former usernames.' },
  { id: 'stolen_photos', weight: 16, observable: true, label: 'Product photos look copied from brands or models', tip: 'Search the photo with Google Lens. If it appears on a big brand\'s site, the seller does not own it.' },
  { id: 'dm_for_price', weight: 10, observable: true, label: '"DM for price" with no website or checkout', tip: 'Hidden prices and DM-only orders leave no record. Ask for a GST invoice and a business address.',
    patterns: [/\b(dm for (price|order)|price in dm|dm to order|inbox for price|whatsapp (to|for) order)\b/i] },
  { id: 'no_contact', weight: 12, observable: true, label: 'No address, GST number, or return policy', tip: 'Indian e-commerce rules require sellers to show contact details and a return policy.' },
  { id: 'off_platform', weight: 10, observable: true, label: 'Moves you to WhatsApp or Telegram to pay', tip: 'Moving off the platform removes your proof and the platform\'s protection.',
    patterns: [/\b(whatsapp|telegram)\b[^.]{0,40}\b(contact|message|join|chat|order|group)\b/i] },
  { id: 'bad_reviews_seen', weight: 30, observable: true, label: 'People in the comments say they did not receive orders', tip: 'Believe the complaints. Sellers cannot delete everyone\'s warnings in time.' },
  { id: 'fake_engagement', weight: 12, observable: true, label: 'Many followers but very few likes or real comments', tip: 'Bought followers make a page look trusted. Look for real customer photos and tags.' },
  // Trust signals
  { id: 'cod_available', weight: -15, observable: true, label: 'Offers Cash on Delivery', tip: 'COD protects you: you pay only when the parcel arrives.' },
  { id: 'verified_badge', weight: -10, observable: true, label: 'Verified badge on the profile', tip: 'A badge helps, but scammers also buy them. Check the other signals too.' },
  { id: 'tagged_customers', weight: -12, observable: true, label: 'Real customers tag the seller with photos', tip: 'Tagged posts from different real people are hard to fake.' },

  // --- Links and domains -----------------------------------------------------------
  { id: 'lookalike_domain', weight: 40, label: 'Website imitates a well-known brand', tip: 'Type the brand\'s address yourself or use its official app. Look-alike sites steal card details.' },
  { id: 'punycode_domain', weight: 30, label: 'Web address uses disguised characters', tip: 'Characters from other alphabets can make a fake address look real.' },
  { id: 'ip_link', weight: 25, label: 'Link is a raw number address, not a website name', tip: 'Real businesses do not send links like http://123.45.67.89.' },
  { id: 'short_link', weight: 14, label: 'Shortened link hides the real address', tip: 'Do not open shortened links from strangers. You cannot see where they lead.' },
  { id: 'risky_tld', weight: 10, label: 'Cheap web ending often used by scam shops', tip: 'Endings like .shop, .xyz or .top cost very little and are common for fake stores.' },
  { id: 'no_https', weight: 8, label: 'Link is not secure (no https)', tip: 'Never type card or UPI details on a page without https.' },
  { id: 'domain_very_new', weight: 40, label: 'Website was created in the last 30 days', tip: 'Scam shops appear before festival sales and vanish weeks later.' },
  { id: 'domain_new', weight: 25, label: 'Website is less than 6 months old', tip: 'Young shops are not always scams, but pay only with COD or protected methods.' },
  { id: 'domain_young', weight: 8, label: 'Website is less than a year old', tip: 'Check reviews from people outside the seller\'s own page.' },
  { id: 'domain_established', weight: -15, label: 'Website has existed for over 3 years', tip: 'An older domain is a good sign, but it does not prove the seller is honest.' },
  { id: 'safe_browsing_hit', weight: 60, label: 'Google Safe Browsing lists this link as dangerous', tip: 'Do not open this link. Google has flagged it for phishing or malware.' },
  { id: 'web_complaints', weight: 35, label: 'Complaints about this seller found on the web', tip: 'Read the cited complaints before you pay.' },
  { id: 'web_positive', weight: -10, label: 'Positive reviews found on independent sites', tip: 'Independent reviews help, but check that they are recent.' },
]);

const BY_ID = new Map(SIGNALS.map((s) => [s.id, s]));
const TEXT_SIGNALS = SIGNALS.filter((s) => s.patterns);

/** Finds message/call-script signals in free text. Returns hits with the matching phrase as evidence. */
function scanText(text) {
  if (!text) return [];
  const hits = [];
  for (const signal of TEXT_SIGNALS) {
    for (const pattern of signal.patterns) {
      const match = pattern.exec(text);
      if (match) {
        hits.push({ id: signal.id, evidence: match[0].slice(0, 80) });
        break;
      }
    }
  }
  return hits;
}

/** Pulls handles, links, phone numbers and UPI IDs out of free text. */
function extractEntities(text) {
  const src = String(text || '');
  const uniq = (list, max) => [...new Set(list)].slice(0, max);
  const upiIds = uniq((src.match(/\b[\w.-]{2,40}@(?:ybl|okaxis|oksbi|okhdfcbank|okicici|paytm|upi|ibl|axl|apl|yapl|ikwik|fbl|pthdfc|ptsbi|ptyes|ptaxis)\b/gi) || []).map((s) => s.toLowerCase()), 5);
  const withoutUpi = upiIds.reduce((acc, id) => acc.split(id).join(' '), src.toLowerCase());
  const urls = uniq(withoutUpi.match(/\b(?:https?:\/\/|www\.)[^\s"'<>]+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|in|co\.in|net|org|shop|store|online|site|xyz|top|club|live|buzz|icu|click|fun|vip|info|biz|me|io|app|ly|gd|at)(?:\/[^\s"'<>]*)?/gi) || [], 5)
    .map((u) => u.replace(/[).,;!?]+$/, ''));
  const handles = uniq((withoutUpi.match(/(?:^|[\s(])@([a-z0-9._]{2,30})/gi) || []).map((h) => h.trim().replace(/^\(/, '').replace(/\.$/, '').toLowerCase()), 5);
  const phones = uniq((src.match(/(?:\+\d{1,3}[\s-]?)?\b\d{5}[\s-]?\d{5}\b|\+\d{1,3}[\s-]?\d{3,4}[\s-]?\d{3,4}[\s-]?\d{3,4}/g) || []).map((p) => p.replace(/[\s-]/g, '')), 5);
  return { handles, urls, phones, upiIds };
}

const LEVELS = Object.freeze([
  { min: 75, level: 'scam', label: 'Very likely a scam' },
  { min: 50, level: 'high', label: 'High risk' },
  { min: 25, level: 'caution', label: 'Be careful' },
  { min: 0, level: 'low', label: 'No major red flags found' },
]);

/**
 * Turns raw hits into an explainable verdict.
 * Each signal counts once (strongest source wins). Risk saturates smoothly, so
 * several mild flags add up without a single weak flag dominating.
 */
function score(hits) {
  const merged = new Map();
  for (const hit of hits) {
    const signal = BY_ID.get(hit.id);
    if (!signal || merged.has(hit.id)) continue;
    merged.set(hit.id, {
      id: signal.id,
      label: signal.label,
      weight: signal.weight,
      tip: signal.tip,
      source: hit.source || 'rules',
      evidence: hit.evidence || '',
    });
  }
  const signals = [...merged.values()].sort((a, b) => b.weight - a.weight);
  const raw = signals.reduce((sum, s) => sum + s.weight, 0);
  const risk = raw <= 0 ? 0 : Math.min(100, Math.round(100 * (1 - Math.exp(-raw / 55))));
  const band = LEVELS.find((l) => risk >= l.min);
  return {
    risk,
    level: band.level,
    label: band.label,
    redFlags: signals.filter((s) => s.weight > 0),
    greenFlags: signals.filter((s) => s.weight < 0),
  };
}


module.exports = { SIGNALS, BY_ID, scanText, extractEntities, score, LEVELS };
