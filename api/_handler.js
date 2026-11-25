'use strict';

/**
 * Shared Vercel serverless handler. Files starting with "_" are not routes.
 * Created once per warm instance, so the cache and rate limiter are reused
 * across requests. Static files are served by Vercel's CDN from /public.
 */
const { createKavach } = require('../src/bootstrap');

module.exports = createKavach();
