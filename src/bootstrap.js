'use strict';

/**
 * Builds the Kavach request handler from configuration.
 * Shared by the long-running server (Google Cloud Run / local) and the
 * serverless entry points (Vercel functions in /api), so both run identical code.
 */

const { loadConfig } = require('./config');
const { TtlCache } = require('./cache');
const { createRateLimiter } = require('./rateLimit');
const { createGeminiClient } = require('./gemini');
const { createApp } = require('./app');

function createKavach({ config = loadConfig(), staticFiles = new Map(), fetchImpl = globalThis.fetch } = {}) {
  const cache = new TtlCache({ ttlMs: config.cacheTtlMs, maxEntries: config.cacheMaxEntries });
  return createApp({
    gemini: createGeminiClient({
      apiKey: config.geminiApiKey, model: config.geminiModel, search: config.geminiSearch, timeoutMs: config.upstreamTimeoutMs, fetchImpl, cache,
    }),
    limiter: createRateLimiter({ windowMs: config.rateLimitWindowMs, max: config.rateLimitMax }),
    scanLimiter: createRateLimiter({ windowMs: config.rateLimitWindowMs, max: config.rateLimitMax * 6 }),
    staticFiles,
    cache,
    fetchImpl,
    safeBrowsingApiKey: config.safeBrowsingApiKey,
    lookupTimeoutMs: config.lookupTimeoutMs,
    maxBodyBytes: config.maxBodyBytes,
    maxUploadBytes: config.maxUploadBytes,
  });
}

module.exports = { createKavach };
