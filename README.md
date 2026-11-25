# Kavach: AI Scam Shield 🛡️

> **"I saw an Instagram ad for 3 kurtis at ₹399, paid by UPI, and nothing ever came. The page blocked me."**
>
> That story is now one of the most common in India. So is the "customs officer" who keeps a retired teacher on a video call for hours under "digital arrest", and the WhatsApp "part-time job" that empties a student's savings. Scams don't wait for you to prepare. They hit **in the moment you are about to pay**.

**Kavach** (Hindi for *armour*) is an AI scam shield for that moment. Paste a seller's @handle or website, drop in screenshots of their profile, ad or chat, paste a suspicious message, or switch on the **live call guard** during a phone call. Kavach tells you in seconds how risky it is, **exactly why**, and what to do next. If it's already too late, it gives you a minute-by-minute **recovery plan** with ready-to-send complaints.

**Live demo:** _add your deployed URL here_

---

## Chosen vertical

**Digital safety and consumer protection: real-time fraud prevention for everyday online buyers and phone users.**

Persona: a first-time online shopper, a parent or grandparent, or a student who meets sellers on Instagram or Facebook and gets calls and messages from strangers. They don't need a lecture on cyber-security. They need one clear answer: *"Is this safe to pay? If not, what do I do?"*

## What it does (4 modes)

| Mode | Real-life moment | What Kavach does |
|---|---|---|
| 🛍️ **Seller or ad check** | "Should I buy from this Instagram page?" | **Gemini vision** reads screenshots of the profile, ad, comments or chat. The **domain registry** (RDAP) reveals how old the shop's website is. **Look-alike brand domains** are caught (e.g. `amaz0n-sale.xyz`). Every red flag is shown with its source and evidence. |
| 💬 **Message or link check** | SMS, WhatsApp, email or a link | Detects 16 scam scripts (digital arrest, KYC block, OTP theft, "enter PIN to receive", task jobs, fake investments, lottery…) plus link tricks (short links, raw IPs, disguised characters) |
| 📞 **Live call guard** | A stranger on the phone right now | Put the call on speaker: speech is turned into text live and scanned in under 50 ms per phrase. Scam phrases light up, the risk meter climbs and the phone vibrates with a counter-tip ("Real police never arrest you on a video call. Hang up.") |
| 🆘 **I got scammed** | Money is already gone | An ordered recovery plan: **call 1930 first** (golden hour), bank block or chargeback, cybercrime.gov.in, UPI dispute, report the account and ad, National Consumer Helpline 1915, Sanchar Saathi (Chakshu), and a warning about fake "recovery agents". **Gemini drafts** the complaint, the bank message and the platform report. |

Plus: **"Warn family on WhatsApp"** turns any result into a shareable warning, and the **safe reply** helps the user test the seller safely (e.g. "Is Cash on Delivery available? Can you share a GST invoice?").

## Approach and logic

### Hybrid AI: Gemini sees, rules decide, sources prove

```
Browser (accessible PWA; screenshots resized on-device; live speech-to-text)
   │  POST /api/check  {subject, text, screenshots[], ticked flags, language}
   ▼
Node.js (zero dependencies) on Google Cloud Run or Vercel
   ├─ validate.js   allow-list validation; images verified by their real file bytes (magic numbers)
   ├─ signals.js    43 named, weighted signals → explainable risk score (0–100)
   ├─ links.js      look-alike / punycode / short-link / IP checks + RDAP domain age
   │                + Google Safe Browsing (optional). The suspicious link is NEVER opened.
   ├─ gemini.js     ① multimodal analysis → fixed yes/no observations + quoted evidence
   │                ② reputation via Google Search grounding, accepted ONLY with cited sources
   │                ③ recovery drafts
   └─ recovery.js   deterministic, India-specific recovery steps (1930, cybercrime.gov.in, NCH…)
```

1. **Gemini never sets the score.** It reports what it *sees* as a fixed set of yes/no observations (e.g. `prepaid_only`, `comments_off`, `new_account`), plus exact quotes. The deterministic engine converts every observation, rule hit and lookup into a weighted signal. The score is `100 × (1 − e^(−Σweights/55))`, so several mild flags add up but no single weak flag dominates. Trust signals (COD available, real tagged customers, a domain older than 3 years) lower the score.
2. **Every flag shows its source**: `message scan`, `you`, `Gemini vision`, `link check`, `domain registry`, `Google Safe Browsing` or `Google Search`, along with the evidence and a one-line counter-tip.
3. **No invented reviews.** During development, ungrounded Gemini confidently "found complaints" about a seller handle we had made up. So Kavach accepts web reputation **only** from Google Search grounding *with cited source URLs*. Claims without sources are thrown away. Without grounding, Kavach shows one-tap Google searches and the Instagram "About this account" tip, so users read real reviews themselves.
4. **Second pass:** handles and links that Gemini reads from screenshots are checked too (domain age, look-alikes, reputation), even when the user typed nothing.
5. **Always works:** if Gemini is down or out of quota, the rule engine, link checks and registry lookups still give a verdict, and recovery uses template drafts.

## Google services used
- **Google Gemini API** (`gemini-3.5-flash`, auto-fallback to `gemini-3.5-flash-lite`):
  - multimodal screenshot understanding
  - schema-constrained JSON output
  - answers in 13 languages
  - complaint drafting
- **Gemini with Google Search grounding**: cited, real-world seller reputation
- **Google Safe Browsing API** (optional `SAFE_BROWSING_API_KEY`): known phishing and malware links
- **Google Cloud Run + Cloud Build**: container deploy from source (`gcloud run deploy --source .`)
- **Google Cloud Logging**: structured JSON logs (`severity`, `httpRequest`)
- **Web Speech API** (Chrome's Google speech service): live call transcription
- **Google Fonts** and Google Search deep links

## Security
- API keys are **server-side only**, sent in the `x-goog-api-key` header and never in URLs or the browser
- **Never visits the suspicious link** (no SSRF, no malware download): only the address is inspected
- **Screenshots verified by file signature** (JPEG/PNG/WebP magic bytes), size-capped (1.5 MB each, max 3), never stored
- **Prompt-injection hardening:** screenshots and text are treated as untrusted evidence. The system instruction forbids following embedded instructions, output is schema-constrained, and unknown observation keys are dropped server-side.
- Strict **CSP** (no inline scripts or styles, no third-party scripts), `frame-ancestors 'none'`, `nosniff`, `Referrer-Policy: no-referrer`, HSTS, COOP/CORP; `Permissions-Policy` allows only the microphone, and only for this site
- All dynamic text is rendered with `textContent`/`createElement`, never `innerHTML`
- Per-client **rate limiting** (429 + `Retry-After`) with a separate, larger budget for the live call guard
- Per-route body limits (32 KB; 4 MB only for screenshot checks); upstream timeouts on every call
- Static files are served only from an in-memory allow-list, so path traversal is impossible; internal errors are never leaked to the client
- **Privacy:** no database, no accounts, nothing stored; audio never leaves the browser's speech service; Kavach never asks for OTPs, PINs or passwords

## Efficiency
- Zero runtime dependencies; cold start well under 1 s
- **Screenshots compressed on-device** (max 1400 px JPEG) before upload, about 10× smaller
- Gemini analysis, RDAP lookup, Safe Browsing and reputation run **in parallel**
- TTL + LRU cache for identical checks and domain lookups; grounding automatically pauses for 10 minutes after a quota error, so no time is wasted
- Live call scan is pure rules: under 1 ms on the server, debounced in the browser
- Static assets gzipped once at start-up and served from memory with ETags

## Accessibility (WCAG 2.2 AA minded)
- Proper WAI-ARIA **tabs** with full keyboard support (arrow keys, Home, End), skip link, landmarks, labelled fields
- `aria-live` status updates, **assertive alerts** in the call guard, focus moved to results
- 44 px+ touch targets, visible focus rings, automatic **dark mode**, `prefers-reduced-motion` and `forced-colors` support
- Risk shown as a number, a word *and* a colour (never colour alone); the dial has a text alternative
- 13 languages for AI answers (English, Hindi, Tamil, Telugu, Bengali, Marathi, Kannada, Malayalam, Gujarati, Punjabi, Urdu, Spanish, Arabic); speech recognition follows the chosen language
- Paste a screenshot with Ctrl+V; print the recovery plan for a paper copy

## Testing
**61 automated tests** with Node's built-in test runner (**~99% line coverage**). They cover:
- scam patterns, including Hindi
- entity extraction and scoring
- look-alike and punycode domains, RDAP and Safe Browsing (mocked)
- image signature checks (a fake "PNG" made of SVG is rejected)
- the Gemini client: key in header, inline images, schema, caching, model fallback, the "no sources = no reputation" rule, quota pause
- recovery plans
- full HTTP integration: security headers; 400/404/405/413/415/429; path traversal; ETag/304; AI-failure fallback; no leaked errors
- the Vercel handler

```bash
npm test
npm run test:coverage
```

## Run locally
Requires Node.js 20+. No `npm install` needed.
```bash
cp .env.example .env      # add GEMINI_API_KEY (works in rules-only mode without it)
npm run dev               # http://localhost:8080
```

## Deploy
**Google Cloud Run**
```bash
gcloud run deploy kavach --source . --region asia-south1 --allow-unauthenticated \
  --memory 256Mi --set-env-vars GEMINI_API_KEY=your_key
```
**Vercel:** import the repo (Framework preset **Other**), add `GEMINI_API_KEY`, then deploy. `api/*.js` become serverless functions and `public/` is served from the CDN with the same security headers (`vercel.json`).

## Assumptions
- India-first: helplines and portals are 1930, cybercrime.gov.in, NCH 1915, Sanchar Saathi and e-Daakhil. The AI still answers in 13 languages.
- Kavach can't log in to Instagram, so it does not scrape profiles. The user shares screenshots, which also respects platform rules and privacy.
- Signal weights are conservative and transparent. A low score is **not** a guarantee; Kavach never calls a seller "safe".
- Web reputation needs a Gemini key with Search-grounding quota. Without it, Kavach links to real searches instead of guessing.
- Live call guard needs a browser with the Web Speech API (Chrome or Edge); others can type what the caller says.
- Kavach gives guidance, not legal advice, and always points to official channels.

## Project structure
```
server.js            entry point for Cloud Run / Docker / local (graceful shutdown)
api/                 Vercel serverless routes (check, scan, recover, health)
vercel.json          Vercel config: static output, function limits, security headers
src/
  bootstrap.js       wires config + clients into the app (shared by all hosts)
  app.js             routing, check pipeline, security headers, logging
  signals.js         43 weighted scam signals, text patterns, explainable scoring
  links.js           look-alike / punycode / short-link checks, RDAP domain age, Safe Browsing
  gemini.js          Gemini multimodal analysis, grounded reputation, recovery drafts
  recovery.js        India-specific recovery steps + template drafts
  validate.js        input validation (incl. image magic-byte checks)
  cache.js · rateLimit.js · static.js · config.js
public/              accessible PWA front-end (HTML, CSS, JS, service worker)
test/                61 automated tests
```

## License
MIT
