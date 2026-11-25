'use strict';

/* Kavach front-end. Plain JS, no frameworks. All dynamic text is rendered with
   textContent / createElement (never innerHTML), so model or user text can never
   inject markup. */
(() => {
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

  /** Tiny DOM builder: el('p', { class: 'x' }, 'text', child) */
  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = value;
      else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value === true ? '' : value);
    }
    for (const child of children.flat()) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  const storage = {
    get(key) { try { return localStorage.getItem(key); } catch { return null; } },
    set(key, value) { try { localStorage.setItem(key, value); } catch { /* private mode */ } },
  };

  const SELLER_FLAGS = [
    ['prepaid_only', 'Prepaid only, no COD'],
    ['personal_payment', 'Pay to a personal UPI / number'],
    ['price_too_low', 'Price too good to be true'],
    ['comments_off', 'Comments turned off'],
    ['new_account', 'New or renamed account'],
    ['bad_reviews_seen', 'Comments say "not received"'],
    ['stolen_photos', 'Photos look copied'],
    ['dm_for_price', '"DM for price"'],
    ['off_platform', 'Moves chat to WhatsApp / Telegram'],
    ['no_contact', 'No address or return policy'],
    ['fake_engagement', 'Many followers, few real likes'],
  ];
  const GOOD_FLAGS = [
    ['cod_available', 'Offers Cash on Delivery'],
    ['tagged_customers', 'Real customers tag them'],
    ['verified_badge', 'Verified badge'],
  ];
  const SPEECH_LANG = { en: 'en-IN', hi: 'hi-IN', ta: 'ta-IN', te: 'te-IN', bn: 'bn-IN', mr: 'mr-IN', kn: 'kn-IN', ml: 'ml-IN', gu: 'gu-IN', pa: 'pa-IN', ur: 'ur-IN', es: 'es-ES', ar: 'ar-SA' };
  const SCAM_TYPE_LABEL = {
    fake_online_shop: 'Fake online shop', non_delivery_seller: 'Non-delivery seller', digital_arrest: '"Digital arrest" scam', bank_kyc: 'Bank / KYC scam',
    upi_payment: 'UPI payment trick', otp_theft: 'OTP theft', job_task: 'Job / task scam', investment: 'Investment scam', lottery_prize: 'Lottery / prize scam',
    relative_impersonation: 'Relative impersonation', phishing_link: 'Phishing link', loan_app: 'Loan app scam', romance: 'Romance scam', not_a_scam: 'No scam pattern', unclear: 'Unclear',
  };

  const languageSelect = $('#language');
  const statusBox = $('#status');
  const results = $('#results');
  const images = { seller: [], message: [] };
  let activeTab = 'seller';
  let lastCheck = null;

  /* ---------------- Language ---------------- */
  const savedLang = storage.get('kavach-lang');
  if (savedLang && SPEECH_LANG[savedLang]) languageSelect.value = savedLang;
  languageSelect.addEventListener('change', () => storage.set('kavach-lang', languageSelect.value));
  const lang = () => languageSelect.value;

  /* ---------------- Tabs (WAI-ARIA tabs pattern) ---------------- */
  const tabs = $$('[role="tab"]');
  function selectTab(name, { focus = false } = {}) {
    activeTab = name;
    for (const tab of tabs) {
      const on = tab.dataset.tab === name;
      tab.setAttribute('aria-selected', String(on));
      tab.tabIndex = on ? 0 : -1;
      $(`#${tab.getAttribute('aria-controls')}`).hidden = !on;
      if (on && focus) tab.focus();
    }
  }
  tabs.forEach((tab, i) => {
    tab.addEventListener('click', () => { selectTab(tab.dataset.tab); results.hidden = true; hideStatus(); });
    tab.addEventListener('keydown', (e) => {
      const move = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[e.key];
      if (move) {
        e.preventDefault();
        selectTab(tabs[(i + move + tabs.length) % tabs.length].dataset.tab, { focus: true });
      } else if (e.key === 'Home' || e.key === 'End') {
        e.preventDefault();
        selectTab(tabs[e.key === 'Home' ? 0 : tabs.length - 1].dataset.tab, { focus: true });
      }
    });
  });

  /* ---------------- Seller flag chips ---------------- */
  const flagBox = $('#seller-flags');
  const chip = ([id, label], good) => el('button', {
    type: 'button', class: good ? 'chip chip-good' : 'chip', 'aria-pressed': 'false', 'data-flag': id,
    onclick: (e) => e.currentTarget.setAttribute('aria-pressed', String(e.currentTarget.getAttribute('aria-pressed') !== 'true')),
  }, good ? '✓ ' : '', label);
  SELLER_FLAGS.forEach((f) => flagBox.append(chip(f, false)));
  GOOD_FLAGS.forEach((f) => flagBox.append(chip(f, true)));

  /* ---------------- Screenshots: pick, drop, paste; resized on-device ---------------- */
  async function toCompressedDataUrl(file) {
    if (!/^image\/(png|jpeg|webp)$/.test(file.type)) throw new Error('Please add a PNG, JPEG or WebP image.');
    const bitmap = await createImageBitmap(file);
    const scale = Math.min(1, 1400 / Math.max(bitmap.width, bitmap.height));
    const canvas = document.createElement('canvas');
    canvas.width = Math.round(bitmap.width * scale);
    canvas.height = Math.round(bitmap.height * scale);
    canvas.getContext('2d').drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    bitmap.close();
    return canvas.toDataURL('image/jpeg', 0.82);
  }

  function renderThumbs(kind) {
    const list = $(`[data-thumbs="${kind}"]`);
    list.replaceChildren(...images[kind].map((src, i) => el('li', {},
      el('img', { src, alt: `Screenshot ${i + 1}` }),
      el('button', { type: 'button', class: 'thumb-remove', 'aria-label': `Remove screenshot ${i + 1}`, onclick: () => { images[kind].splice(i, 1); renderThumbs(kind); } }, '×'))));
  }

  async function addFiles(kind, files) {
    for (const file of files) {
      if (images[kind].length >= 3) { showStatus('You can add up to 3 screenshots.', 'error'); break; }
      try {
        images[kind].push(await toCompressedDataUrl(file));
      } catch (err) {
        showStatus(err.message || 'That image could not be read.', 'error');
      }
    }
    renderThumbs(kind);
  }

  $$('[data-dropzone]').forEach((zone) => {
    const kind = zone.dataset.dropzone;
    const input = $('[data-file-input]', zone);
    zone.addEventListener('click', () => input.click());
    zone.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
    input.addEventListener('change', () => { addFiles(kind, [...input.files]); input.value = ''; });
    zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('is-over'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('is-over'));
    zone.addEventListener('drop', (e) => { e.preventDefault(); zone.classList.remove('is-over'); addFiles(kind, [...e.dataTransfer.files]); });
  });
  document.addEventListener('paste', (e) => {
    if (activeTab !== 'seller' && activeTab !== 'message') return;
    const files = [...(e.clipboardData ? e.clipboardData.files : [])].filter((f) => f.type.startsWith('image/'));
    if (files.length) { e.preventDefault(); addFiles(activeTab, files); }
  });

  /* ---------------- Status + API ---------------- */
  let statusTimer = null;
  function showStatus(message, kind = 'info', rotating = []) {
    clearInterval(statusTimer);
    statusBox.hidden = false;
    statusBox.classList.toggle('is-error', kind === 'error');
    const text = el('span', {}, message);
    statusBox.replaceChildren(...(kind === 'loading' ? [el('span', { class: 'spinner', 'aria-hidden': 'true' }), text] : [text]));
    if (rotating.length) {
      let i = 0;
      statusTimer = setInterval(() => { i = (i + 1) % rotating.length; text.textContent = rotating[i]; }, 2600);
    }
  }
  function hideStatus() { clearInterval(statusTimer); statusBox.hidden = true; }

  async function api(path, body) {
    const res = await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(65000) });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
    return data;
  }

  function setBusy(form, busy) {
    $$('button, input, textarea, select', form).forEach((n) => { n.disabled = busy; });
  }

  /* ---------------- Check seller / message ---------------- */
  async function runCheck(form, payload) {
    setBusy(form, true);
    results.hidden = true;
    const steps = payload.images.length
      ? ['Reading your screenshots with Gemini…', 'Looking for scam patterns…', 'Checking the website registry…', 'Weighing the evidence…']
      : ['Looking for scam patterns…', 'Asking Gemini to analyse…', 'Checking links and domains…', 'Weighing the evidence…'];
    showStatus(steps[0], 'loading', steps);
    try {
      const data = await api('/api/check', payload);
      lastCheck = { payload, data };
      hideStatus();
      renderCheck(data, payload);
    } catch (err) {
      showStatus(err.name === 'TimeoutError' ? 'This is taking too long. Please try again.' : err.message, 'error');
    } finally {
      setBusy(form, false);
    }
  }

  $('#seller-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const payload = {
      mode: 'seller',
      subject: $('#seller-subject').value.trim(),
      text: $('#seller-text').value.trim(),
      flags: $$('[data-flag][aria-pressed="true"]', flagBox).map((b) => b.dataset.flag),
      images: images.seller,
      language: lang(),
    };
    if (!payload.subject && !payload.text && !payload.images.length && !payload.flags.length) {
      showStatus('Add the seller\'s @handle, a website, a screenshot, or tick what you noticed.', 'error');
      $('#seller-subject').focus();
      return;
    }
    runCheck(e.currentTarget, payload);
  });

  $('#message-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const payload = { mode: 'message', subject: '', text: $('#message-text').value.trim(), flags: [], images: images.message, language: lang() };
    if (!payload.text && !payload.images.length) {
      showStatus('Paste the message or add a screenshot first.', 'error');
      $('#message-text').focus();
      return;
    }
    runCheck(e.currentTarget, payload);
  });

  $$('[data-example]').forEach((b) => b.addEventListener('click', () => { $('#message-text').value = b.dataset.example; $('#message-text').focus(); }));

  /* ---------------- Rendering helpers ---------------- */
  function dial(risk) {
    const r = 52;
    const c = 2 * Math.PI * r;
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 120 120');
    svg.setAttribute('aria-hidden', 'true');
    const mk = (cls) => {
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      for (const [k, v] of Object.entries({ cx: 60, cy: 60, r, fill: 'none', 'stroke-width': 12, 'stroke-linecap': 'round', class: cls })) circle.setAttribute(k, v);
      return circle;
    };
    const track = mk('dial-track');
    const arc = mk('dial-fill');
    arc.setAttribute('stroke-dasharray', c.toFixed(2));
    arc.setAttribute('stroke-dashoffset', c.toFixed(2));
    svg.append(track, arc);
    requestAnimationFrame(() => requestAnimationFrame(() => arc.setAttribute('stroke-dashoffset', (c * (1 - risk / 100)).toFixed(2))));
    return el('div', { class: 'dial', role: 'img', 'aria-label': `Scam risk ${risk} out of 100` }, svg,
      el('div', { class: 'dial-value' }, el('strong', {}, String(risk)), el('span', {}, 'RISK / 100')));
  }

  function flagItem(flag, good) {
    return el('li', { class: good ? 'flag is-good' : 'flag' },
      el('span', { class: 'flag-icon', 'aria-hidden': 'true' }, good ? '✓' : '!'),
      el('div', {},
        el('div', { class: 'flag-title' }, flag.label),
        el('div', { class: 'flag-meta' },
          el('span', { class: 'tag' }, `Source: ${flag.source}`),
          flag.evidence ? el('span', { class: 'tag tag-evidence' }, `“${flag.evidence}”`) : null),
        el('p', { class: 'flag-tip' }, flag.tip)));
  }

  function copyButton(getText, label = 'Copy') {
    return el('button', {
      type: 'button', class: 'btn btn-secondary btn-sm',
      onclick: async (e) => {
        const b = e.currentTarget;
        try { await navigator.clipboard.writeText(getText()); b.textContent = 'Copied ✓'; } catch { b.textContent = 'Select and copy'; }
        setTimeout(() => { b.textContent = label; }, 2000);
      },
    }, label);
  }

  function externalLink(item) {
    return el('li', {}, el('a', { href: item.url, target: '_blank', rel: 'noopener noreferrer' },
      el('span', {}, item.label || item.title, item.hint ? el('span', { class: 'link-hint' }, item.hint) : null)));
  }

  function shareText(data, payload) {
    const what = payload.subject || (payload.mode === 'seller' ? 'this seller' : 'this message');
    const flags = data.redFlags.slice(0, 3).map((f) => `• ${f.label}`).join('\n');
    return `⚠️ Kavach scam check: ${what}\n${data.verdict.label} (risk ${data.verdict.risk}/100)\n${flags}\nCheck before you pay: ${location.origin}`;
  }

  function showResults(nodes, focusTitle = true) {
    results.replaceChildren(...nodes);
    results.hidden = false;
    if (focusTitle) {
      results.focus({ preventScroll: true });
      results.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
    }
  }

  function renderCheck(data, payload) {
    const v = data.verdict;
    const ai = data.ai;
    const nodes = [];

    nodes.push(el('article', { class: 'card verdict', 'data-level': v.level },
      dial(v.risk),
      el('div', {},
        el('span', { class: 'verdict-label' }, v.label),
        el('h2', { id: 'results-title' }, ai ? SCAM_TYPE_LABEL[ai.scamType] || 'Scam check result' : (v.level === 'low' ? 'No major red flags found' : `${data.redFlags.length} red flag${data.redFlags.length === 1 ? '' : 's'} found`)),
        el('p', {}, ai ? ai.summary : 'AI analysis is unavailable right now, so this result uses Kavach\'s built-in scam rules and live lookups only.'),
        el('p', { class: 'source-line muted' }, `Checked with ${data.source === 'gemini' ? 'Google Gemini + ' : ''}Kavach scam rules${data.domains.length ? ' + domain registry' : ''}${data.safeBrowsing !== null ? ' + Google Safe Browsing' : ''}${data.reputation ? ' + Google Search' : ''}.`))));

    // Left column: why
    const left = [];
    if (data.redFlags.length || data.greenFlags.length) {
      left.push(el('section', { class: 'card section', 'aria-labelledby': 'why-title' },
        el('h3', { id: 'why-title' }, '🔎 Why Kavach says this'),
        el('ul', { class: 'flag-list' }, data.redFlags.map((f) => flagItem(f, false)), data.greenFlags.map((f) => flagItem(f, true)))));
    } else {
      left.push(el('section', { class: 'card section' }, el('h3', {}, '🔎 Why Kavach says this'),
        el('p', { class: 'muted' }, 'We did not find known scam signals. That is not a guarantee: add screenshots of the profile, ad or chat for a deeper check.')));
    }
    if (ai && ai.quotes.length) {
      left.push(el('section', { class: 'card section', 'aria-labelledby': 'quotes-title' },
        el('h3', { id: 'quotes-title' }, '🧠 What Gemini spotted'),
        ai.quotes.map((q) => el('blockquote', { class: 'quote' }, el('strong', {}, q.flag), q.evidence ? el('q', {}, q.evidence) : null))));
    }

    // Right column: what to do, reputation, research
    const right = [];
    const steps = [...(ai ? ai.advice : []), ...data.nextSteps].filter((s, i, arr) => arr.indexOf(s) === i).slice(0, 6);
    right.push(el('section', { class: 'card section', 'aria-labelledby': 'do-title' },
      el('h3', { id: 'do-title' }, '✅ What to do now'),
      el('ol', { class: 'steps' }, steps.map((s) => el('li', {}, s))),
      ai && ai.safeReply ? el('div', {}, el('h4', {}, 'Safe reply you can send'), el('p', { class: 'reply-box' }, ai.safeReply), copyButton(() => ai.safeReply, 'Copy reply')) : null));

    const repNodes = [];
    if (data.domains.length) {
      repNodes.push(el('dl', { class: 'facts' }, data.domains.map((d) => el('div', { class: 'fact' },
        el('dt', {}, d.domain),
        el('dd', {}, d.ageDays === null ? 'Age unknown' : d.ageDays < 365 ? `Created ${d.ageDays} days ago` : `Online since ${d.registered.slice(0, 4)}`)))));
    }
    if (data.reputation) {
      const statusText = { complaints_found: 'Complaints found on the web', positive: 'Mostly positive reviews found', mixed: 'Mixed reviews found', nothing_found: 'No reliable reviews found' }[data.reputation.status];
      repNodes.push(el('p', { class: 'rep', 'data-status': data.reputation.status }, statusText), el('p', {}, data.reputation.summary),
        el('ul', { class: 'link-list' }, data.reputation.sources.map(externalLink)));
    } else {
      repNodes.push(el('p', { class: 'muted' }, 'Kavach never lets AI guess reviews about a real seller. Read real ones in one tap:'));
    }
    if (data.research.length) repNodes.push(el('ul', { class: 'link-list' }, data.research.map(externalLink)));
    if (repNodes.length > 1 || data.research.length) {
      right.push(el('section', { class: 'card section', 'aria-labelledby': 'rep-title' }, el('h3', { id: 'rep-title' }, '🌐 Reputation check'), repNodes));
    }

    right.push(el('section', { class: 'card section', 'aria-labelledby': 'share-title' },
      el('h3', { id: 'share-title' }, '📣 Protect others'),
      el('div', { class: 'actions' },
        el('a', { class: 'btn btn-primary btn-sm', href: `https://wa.me/?text=${encodeURIComponent(shareText(data, payload))}`, target: '_blank', rel: 'noopener noreferrer' }, 'Warn family on WhatsApp'),
        copyButton(() => shareText(data, payload), 'Copy warning'),
        el('button', { type: 'button', class: 'btn btn-danger btn-sm', onclick: () => startRecovery(payload) }, 'I already paid'))));

    nodes.push(el('div', { class: 'two-col' }, el('div', { class: 'stack' }, left), el('div', { class: 'stack' }, right)));
    showResults(nodes);
  }

  /* ---------------- Recovery ---------------- */
  function startRecovery(payload) {
    selectTab('recover');
    if (payload && payload.subject) $('#r-seller').value = payload.subject;
    $('#r-type').value = payload && payload.mode === 'seller' ? 'shopping' : 'upi';
    results.hidden = true;
    $('#panel-recover').scrollIntoView({ block: 'start' });
    $('#r-type').focus();
  }

  $('#recover-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.currentTarget;
    const payload = {
      scamType: $('#r-type').value,
      paidVia: $('#r-paid').value,
      hoursAgo: Number($('#r-when').value),
      amount: $('#r-amount').value ? Number($('#r-amount').value) : 0,
      seller: $('#r-seller').value.trim(),
      details: $('#r-details').value.trim(),
      language: lang(),
    };
    setBusy(form, true);
    showStatus('Building your recovery plan…', 'loading', ['Building your recovery plan…', 'Drafting your complaint with Gemini…']);
    try {
      const data = await api('/api/recover', payload);
      hideStatus();
      renderRecovery(data);
    } catch (err) {
      showStatus(err.message, 'error');
    } finally {
      setBusy(form, false);
    }
  });

  function renderRecovery(data) {
    const nodes = [];
    if (data.urgent) {
      nodes.push(el('div', { class: 'urgent', role: 'alert' },
        el('div', {}, el('h2', { id: 'results-title' }, 'Call 1930 right now'), el('p', {}, 'Money reported quickly can often be frozen before the scammer withdraws it.')),
        el('a', { class: 'btn btn-lg', href: 'tel:1930' }, '📞 Call 1930')));
    }
    nodes.push(el('section', { class: 'card section', 'aria-labelledby': data.urgent ? null : 'results-title' },
      el('h3', { id: data.urgent ? 'rplan-title' : 'results-title' }, '🧭 Your recovery plan'),
      data.drafts.explanation ? el('p', {}, data.drafts.explanation) : null,
      el('ol', { class: 'rsteps' }, data.steps.map((s) => el('li', { class: 'rstep', 'data-priority': s.priority },
        el('div', {},
          el('h4', {}, s.title, el('span', { class: 'prio', 'data-priority': s.priority }, s.priority)),
          el('p', {}, s.detail),
          s.action ? el('a', { class: 'btn btn-secondary btn-sm', href: s.action.type === 'tel' ? `tel:${s.action.value}` : s.action.value, ...(s.action.type === 'link' ? { target: '_blank', rel: 'noopener noreferrer' } : {}) }, s.action.label) : null))))));

    const draft = (title, text) => el('div', { class: 'draft' }, el('h4', {}, title, copyButton(() => text)), el('pre', {}, text));
    nodes.push(el('div', { class: 'two-col' },
      el('section', { class: 'card section', 'aria-labelledby': 'drafts-title' },
        el('h3', { id: 'drafts-title' }, `✍️ Ready-to-send drafts${data.source === 'gemini' ? ' (by Gemini)' : ''}`),
        el('p', { class: 'muted' }, 'Replace the [brackets] with your details before sending.'),
        draft('Cyber crime complaint (cybercrime.gov.in)', data.drafts.complaint),
        draft('Message to your bank', data.drafts.bankMessage),
        draft('Report to the platform', data.drafts.platformReport)),
      el('section', { class: 'card section', 'aria-labelledby': 'evidence-title' },
        el('h3', { id: 'evidence-title' }, '🗂️ Keep this evidence'),
        el('ul', { class: 'steps' }, data.evidence.map((x) => el('li', {}, x))),
        el('div', { class: 'actions' }, el('button', { type: 'button', class: 'btn btn-ghost btn-sm', onclick: () => window.print() }, 'Print / save as PDF')))));
    showResults(nodes);
  }

  /* ---------------- Live call guard ---------------- */
  const Recognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  const callStart = $('#call-start');
  const callStop = $('#call-stop');
  const transcriptBox = $('#call-transcript');
  const alertsBox = $('#call-alerts');
  const analyseBtn = $('#call-analyse');
  let recognizer = null;
  let listening = false;
  let finalText = '';
  let seenAlerts = new Set();
  let lastEvidence = [];
  let scanTimer = null;

  if (!Recognition) {
    $('#call-support').textContent = 'Your browser cannot listen to calls (try Chrome or Edge). You can still type what the caller says below.';
    callStart.disabled = true;
  }

  function renderTranscript(interim = '') {
    transcriptBox.replaceChildren();
    if (!finalText && !interim) { transcriptBox.append(el('span', { class: 'placeholder' }, 'The conversation will appear here.')); return; }
    // Highlight matched scam phrases safely: split text into plain and <mark> nodes.
    const phrases = lastEvidence.filter(Boolean).map((p) => p.toLowerCase());
    let rest = finalText;
    while (rest) {
      const lower = rest.toLowerCase();
      let best = -1;
      let len = 0;
      for (const p of phrases) {
        const at = lower.indexOf(p);
        if (at !== -1 && (best === -1 || at < best)) { best = at; len = p.length; }
      }
      if (best === -1) { transcriptBox.append(rest); break; }
      transcriptBox.append(rest.slice(0, best), el('mark', {}, rest.slice(best, best + len)));
      rest = rest.slice(best + len);
    }
    if (interim) transcriptBox.append(' ', el('span', { class: 'interim' }, interim));
    transcriptBox.scrollTop = transcriptBox.scrollHeight;
  }

  async function scanCall() {
    if (!finalText.trim()) return;
    try {
      const data = await api('/api/scan', { text: finalText.slice(-6000) });
      $('#call-risk').textContent = data.risk;
      $('#call-risk-label').textContent = data.label;
      $('#call-risk-bar').style.width = `${data.risk}%`;
      $('#call-meter').dataset.level = data.level;
      lastEvidence = data.redFlags.map((f) => f.evidence);
      const fresh = data.redFlags.filter((f) => !seenAlerts.has(f.id));
      fresh.forEach((f) => {
        seenAlerts.add(f.id);
        alertsBox.prepend(el('div', { class: 'call-alert' }, el('strong', {}, `⚠️ ${f.label}`), el('p', {}, f.tip)));
      });
      if (fresh.length && data.level !== 'low' && navigator.vibrate) navigator.vibrate([250, 120, 250]);
      renderTranscript();
    } catch { /* the guard keeps listening even if one scan fails */ }
  }
  const queueScan = () => { clearTimeout(scanTimer); scanTimer = setTimeout(scanCall, 350); };

  function addSpeech(text) {
    finalText = `${finalText} ${text}`.trim();
    analyseBtn.disabled = false;
    renderTranscript();
    queueScan();
  }

  function startListening() {
    recognizer = new Recognition();
    recognizer.lang = SPEECH_LANG[lang()] || 'en-IN';
    recognizer.continuous = true;
    recognizer.interimResults = true;
    recognizer.onresult = (event) => {
      let interim = '';
      for (let i = event.resultIndex; i < event.results.length; i += 1) {
        const r = event.results[i];
        if (r.isFinal) addSpeech(r[0].transcript);
        else interim += r[0].transcript;
      }
      if (interim) renderTranscript(interim);
    };
    recognizer.onerror = (event) => {
      if (event.error === 'not-allowed' || event.error === 'service-not-allowed') {
        stopListening();
        $('#call-support').textContent = 'Microphone permission was denied. Allow the microphone for this site, or type what the caller says below.';
      }
    };
    // Browsers stop after silence; keep listening until the user presses Stop.
    recognizer.onend = () => { if (listening) { try { recognizer.start(); } catch { /* already started */ } } };
    recognizer.start();
    listening = true;
    callStart.hidden = true;
    callStop.hidden = false;
    $('#call-listening').hidden = false;
    $('#call-support').textContent = '';
  }

  function stopListening() {
    listening = false;
    if (recognizer) { try { recognizer.stop(); } catch { /* ignore */ } }
    callStart.hidden = false;
    callStop.hidden = true;
    $('#call-listening').hidden = true;
    renderTranscript();
  }

  callStart.addEventListener('click', () => {
    finalText = '';
    seenAlerts = new Set();
    lastEvidence = [];
    alertsBox.replaceChildren();
    try { startListening(); } catch { $('#call-support').textContent = 'Could not start the microphone. Type what the caller says below.'; }
  });
  callStop.addEventListener('click', stopListening);
  $('#call-type').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && e.currentTarget.value.trim()) {
      e.preventDefault();
      addSpeech(e.currentTarget.value.trim());
      e.currentTarget.value = '';
    }
  });
  analyseBtn.addEventListener('click', () => {
    stopListening();
    selectTab('message');
    $('#message-text').value = `Phone call transcript: ${finalText}`.slice(0, 6000);
    $('#message-form').requestSubmit();
  });

  /* ---------------- Offline shell ---------------- */
  if ('serviceWorker' in navigator && location.protocol === 'https:') {
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  }
})();
