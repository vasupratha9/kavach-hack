'use strict';

/**
 * Strict allow-list validation for every request. Nothing reaches the engine,
 * Gemini or an upstream service without passing through here.
 */

const { SIGNALS } = require('./signals');

class ValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ValidationError';
    this.status = 400;
  }
}

const LANGUAGES = Object.freeze({
  en: 'English',
  hi: 'Hindi',
  ta: 'Tamil',
  te: 'Telugu',
  bn: 'Bengali',
  mr: 'Marathi',
  kn: 'Kannada',
  ml: 'Malayalam',
  gu: 'Gujarati',
  pa: 'Punjabi',
  ur: 'Urdu',
  es: 'Spanish',
  ar: 'Arabic',
});

const MODES = Object.freeze(['seller', 'message']);
const SCAM_TYPES = Object.freeze(['shopping', 'upi', 'card', 'otp', 'job', 'investment', 'impersonation', 'other']);
const PAID_VIA = Object.freeze(['upi', 'card', 'netbanking', 'wallet', 'cash', 'none']);

const LIMITS = Object.freeze({ subject: 200, text: 6000, notes: 1500, images: 3, imageBytes: 1.5 * 1024 * 1024 });

/** Image types we accept, identified by their real file signature, never by the claimed MIME type. */
const IMAGE_SIGNATURES = Object.freeze([
  { mime: 'image/jpeg', test: (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  { mime: 'image/png', test: (b) => b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47 },
  { mime: 'image/webp', test: (b) => b.toString('ascii', 0, 4) === 'RIFF' && b.toString('ascii', 8, 12) === 'WEBP' },
]);

function requireObject(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new ValidationError('Request body must be a JSON object');
  return input;
}

/** Removes control characters and markup brackets, collapses whitespace, caps length. */
function cleanText(value, maxLength, field, { multiline = false } = {}) {
  if (value === undefined || value === null) return '';
  if (typeof value !== 'string') throw new ValidationError(`${field} must be text`);
  // eslint-disable-next-line no-control-regex
  let text = value.replace(/[\u0000-\u0009\u000B-\u001F\u007F<>`]/g, ' ');
  text = multiline ? text.replace(/[ \t]+/g, ' ').replace(/\n{3,}/g, '\n\n') : text.replace(/\s+/g, ' ');
  return text.trim().slice(0, maxLength);
}

function oneOf(value, allowed, fallback, field) {
  if (value === undefined || value === null || value === '') return fallback;
  if (!allowed.includes(value)) throw new ValidationError(`${field} must be one of: ${allowed.join(', ')}`);
  return value;
}

function validateImages(value) {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw new ValidationError('images must be a list');
  if (value.length > LIMITS.images) throw new ValidationError(`You can add up to ${LIMITS.images} screenshots`);
  return value.map((item, i) => {
    const match = typeof item === 'string' && /^data:image\/(?:jpeg|png|webp);base64,([A-Za-z0-9+/]+={0,2})$/.exec(item);
    if (!match) throw new ValidationError(`Screenshot ${i + 1} is not a supported image (JPEG, PNG or WebP)`);
    const bytes = Buffer.from(match[1], 'base64');
    if (bytes.length > LIMITS.imageBytes) throw new ValidationError(`Screenshot ${i + 1} is too large`);
    const kind = IMAGE_SIGNATURES.find((sig) => bytes.length > 12 && sig.test(bytes));
    if (!kind) throw new ValidationError(`Screenshot ${i + 1} is not a real image file`);
    return { mimeType: kind.mime, data: match[1] };
  });
}

function validateFlags(value) {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw new ValidationError('flags must be a list');
  const allowed = new Set(SIGNALS.filter((s) => s.observable).map((s) => s.id));
  return [...new Set(value.filter((f) => typeof f === 'string' && allowed.has(f)))];
}

function validateCheck(input) {
  const body = requireObject(input);
  const check = {
    mode: oneOf(body.mode, MODES, 'seller', 'mode'),
    subject: cleanText(body.subject, LIMITS.subject, 'subject'),
    text: cleanText(body.text, LIMITS.text, 'text', { multiline: true }),
    images: validateImages(body.images),
    flags: validateFlags(body.flags),
    language: oneOf(body.language, Object.keys(LANGUAGES), 'en', 'language'),
  };
  if (!check.subject && !check.text && check.images.length === 0 && check.flags.length === 0) {
    throw new ValidationError('Add a profile handle, link, message or screenshot to check');
  }
  return check;
}

function validateScan(input) {
  const body = requireObject(input);
  const text = cleanText(body.text, LIMITS.text, 'text', { multiline: true });
  if (!text) throw new ValidationError('text is required');
  return { text };
}

function validateRecovery(input) {
  const body = requireObject(input);
  const hours = body.hoursAgo === undefined || body.hoursAgo === null || body.hoursAgo === '' ? 1 : Number(body.hoursAgo);
  if (!Number.isFinite(hours) || hours < 0 || hours > 24 * 365) throw new ValidationError('hoursAgo must be between 0 and 8760');
  const amount = body.amount === undefined || body.amount === null || body.amount === '' ? 0 : Number(body.amount);
  if (!Number.isFinite(amount) || amount < 0 || amount > 1e9) throw new ValidationError('amount must be a positive number');
  return {
    scamType: oneOf(body.scamType, SCAM_TYPES, 'shopping', 'scamType'),
    paidVia: oneOf(body.paidVia, PAID_VIA, 'upi', 'paidVia'),
    hoursAgo: hours,
    amount: Math.round(amount),
    seller: cleanText(body.seller, LIMITS.subject, 'seller'),
    details: cleanText(body.details, LIMITS.notes, 'details', { multiline: true }),
    language: oneOf(body.language, Object.keys(LANGUAGES), 'en', 'language'),
  };
}

module.exports = {
  LANGUAGES, MODES, SCAM_TYPES, PAID_VIA, LIMITS, ValidationError,
  cleanText, validateImages, validateFlags, validateCheck, validateScan, validateRecovery,
};
