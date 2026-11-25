'use strict';

/**
 * Central, immutable runtime configuration.
 * Every value can be overridden with an environment variable, so the same code
 * runs locally, in tests, on Google Cloud Run and on Vercel.
 */
function loadConfig(env = process.env) {
  const num = (value, fallback) => {
    const parsed = Number(value);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
  };

  return Object.freeze({
    port: num(env.PORT, 8080),
    geminiApiKey: env.GEMINI_API_KEY || '',
    geminiModel: env.GEMINI_MODEL || 'gemini-3.5-flash,gemini-3.5-flash-lite',
    // Google Search grounding for seller reputation (needs a key with grounding quota).
    geminiSearch: env.GEMINI_SEARCH !== 'off',
    // Optional Google Safe Browsing API key (free, from a Google Cloud project).
    safeBrowsingApiKey: env.SAFE_BROWSING_API_KEY || '',
    upstreamTimeoutMs: num(env.UPSTREAM_TIMEOUT_MS, 25000),
    lookupTimeoutMs: num(env.LOOKUP_TIMEOUT_MS, 5000),
    maxBodyBytes: num(env.MAX_BODY_BYTES, 32 * 1024),
    maxUploadBytes: num(env.MAX_UPLOAD_BYTES, 4 * 1024 * 1024),
    rateLimitWindowMs: num(env.RATE_LIMIT_WINDOW_MS, 60 * 1000),
    rateLimitMax: num(env.RATE_LIMIT_MAX, 40),
    cacheTtlMs: num(env.CACHE_TTL_MS, 15 * 60 * 1000),
    cacheMaxEntries: num(env.CACHE_MAX_ENTRIES, 300),
  });
}

module.exports = { loadConfig };
