'use strict';

/*
 * VibeGuard LLM Proxy — OpenAI-compatible runtime guard proxy.
 *
 * Any LLM client (OpenAI SDK, LangChain, Claude Code, Cursor, your own app)
 * points base_url at http://127.0.0.1:<port>/v1. VibeGuard scans every prompt
 * AND every response for prompt-injection, secrets, and PII, then either:
 *
 *   block  — reject violating requests with 403 (never forwarded upstream)
 *   redact — mask secrets/PII with [REDACTED:<ruleId>], forward everything
 *   report — never mutate; log every violation and pass through
 *
 * then forwards the (possibly mutated) request to the real upstream
 * (e.g. https://api.openai.com/v1). This is the runtime "AI agent firewall"
 * half of VibeGuard — Lakera Guard parity, 100% local, free, zero deps.
 *
 * Reuses VibeGuard's own detectors:
 *   - detectPII / redactText from ./pii (same as src/proxy.js)
 *   - secret.* rule regexes from ./rules (user prompt containing a hardcoded
 *     GitHub token is exfiltration)
 *   - the canonical prompt-injection regex from rules.js
 *     (ai.prompt-injection-marker) plus a few classic supplements.
 *
 * Zero runtime dependencies: only http/https from stdlib.
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');
const { detectPII } = require('./pii');
const rules = require('./rules');

const DEFAULT_PORT = 8443;
const DEFAULT_UPSTREAM = 'https://api.openai.com/v1';
const MODES = new Set(['block', 'redact', 'report']);
const IDLE_TIMEOUT_MS = 60000;

// ---------------------------------------------------------------------------
// Prompt-injection detection
// ---------------------------------------------------------------------------

// Extract prompt-injection regexes from src/rules.js: the canonical
// ai.prompt-injection-marker rule, plus any ai.* rule whose id mentions
// injection. (Code-oriented ai.* rules like ai.eval-llm-output are NOT
// text-injection patterns and are deliberately excluded.)
const INJECTION_FROM_RULES = [];
for (const r of rules.lineRules || []) {
  const id = r.id || '';
  if (!r.re || typeof r.re.test !== 'function') continue;
  if (id === 'ai.prompt-injection-marker' || (id.startsWith('ai.') && /injection/i.test(id))) {
    INJECTION_FROM_RULES.push({
      ruleId: id,
      severity: r.severity || 'high',
      message: r.message || r.title || id,
      re: r.re,
    });
  }
}

// Classic supplemental patterns (system-prompt override attempts, output
// format manipulation). These must be global-capable regexes — detectInjection
// clones them with the 'g' flag so exec() can find every hit.
const INJECTION_PATTERNS = [
  ...INJECTION_FROM_RULES,
  {
    ruleId: 'ai.system-prompt-reveal',
    severity: 'high',
    message: 'Request to reveal the system/developer prompt',
    re: /(?:reveal|show|print|display|output|leak|repeat)\s+(?:your|the)\s+(?:full\s+)?(?:system|developer|initial)\s+prompt/i,
  },
];

/**
 * Detect prompt-injection / jailbreak phrases in free text.
 * @param {string} text
 * @returns {Array<{type:'prompt-injection', ruleId, severity, match, start, end, message}>}
 */
function detectInjection(text) {
  const out = [];
  if (typeof text !== 'string' || text.length === 0) return out;
  for (const p of INJECTION_PATTERNS) {
    if (!p._g) {
      p._g = new RegExp(p.re.source, p.re.flags.includes('g') ? p.re.flags : p.re.flags + 'g');
    }
    p._g.lastIndex = 0;
    let m;
    while ((m = p._g.exec(text)) !== null) {
      out.push({
        type: 'prompt-injection',
        ruleId: p.ruleId,
        severity: p.severity || 'high',
        match: m[0],
        start: m.index,
        end: m.index + m[0].length,
        message: p.message || p.ruleId,
      });
      if (m.index === p._g.lastIndex) p._g.lastIndex++; // guard zero-width
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Secret detection (reuses secret.* regexes from src/rules.js, including
// their post-match filters)
// ---------------------------------------------------------------------------

/**
 * Scan text with every secret.* rule from rules.js.
 * @param {string} text
 * @returns {Array<{type:'secret', ruleId, severity, match, start, end, message}>}
 */
function scanSecrets(text) {
  const out = [];
  if (typeof text !== 'string' || text.length === 0) return out;
  for (const rule of rules.secretRules || []) {
    if (!rule.re) continue;
    let re;
    try {
      re = new RegExp(rule.re.source, rule.re.flags.includes('g') ? rule.re.flags : rule.re.flags + 'g');
    } catch {
      continue;
    }
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      const mm = { index: m.index, match: m[0], groups: m };
      if (typeof rule.filter === 'function') {
        try {
          if (!rule.filter(text, mm)) {
            if (m.index === re.lastIndex) re.lastIndex++;
            continue;
          }
        } catch {
          /* keep the match — never let a filter crash the guard */
        }
      }
      out.push({
        type: 'secret',
        ruleId: rule.id,
        severity: rule.severity || 'critical',
        match: m[0],
        start: m.index,
        end: m.index + m[0].length,
        message: rule.message || rule.title || rule.id,
      });
      if (m.index === re.lastIndex) re.lastIndex++;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// PII detection (reuses detectPII from ./pii)
// ---------------------------------------------------------------------------

/**
 * Scan text for PII via pii.js.
 * @param {string} text
 * @returns {Array<{type:'pii', ruleId, severity, match, start, end, token, message}>}
 */
function scanPII(text) {
  const out = [];
  if (typeof text !== 'string' || text.length === 0) return out;
  const det = detectPII(text);
  for (const m of det.matches) {
    out.push({
      type: 'pii',
      ruleId: 'pii.' + m.type,
      severity: m.severity,
      match: m.value,
      start: m.start,
      end: m.end,
      token: m.token,
      message: 'PII detected: ' + m.type,
    });
  }
  return out;
}

/**
 * All violations in one pass: prompt-injection + secrets + PII.
 * @param {string} text
 * @returns {Array}
 */
function scanText(text) {
  return detectInjection(text).concat(scanSecrets(text), scanPII(text));
}

/**
 * Redact secrets/PII from text, replacing each full match with
 * [REDACTED:<ruleId>] (pii.js-style). Injection is never redacted — it is
 * detected and reported, but passes through (redacting injection is
 * meaningless).
 * @param {string} text
 * @returns {{text: string, violations: Array}}
 */
function redactSensitive(text) {
  const violations = [];
  if (typeof text !== 'string' || text.length === 0) return { text: text || '', violations };

  const matches = [];
  for (const s of scanSecrets(text)) {
    matches.push({ start: s.start, end: s.end, token: '[REDACTED:' + s.ruleId + ']', violation: s });
  }
  for (const p of scanPII(text)) {
    matches.push({ start: p.start, end: p.end, token: '[REDACTED:' + p.ruleId + ']', violation: p });
  }
  if (matches.length === 0) return { text, violations };

  // Non-overlapping, longest-first at equal start (same policy as pii.js).
  matches.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
  const kept = [];
  let lastEnd = -1;
  for (const mm of matches) {
    if (mm.start < lastEnd) continue;
    kept.push(mm);
    lastEnd = mm.end;
  }

  let out = text;
  for (let i = kept.length - 1; i >= 0; i--) {
    const mm = kept[i];
    out = out.slice(0, mm.start) + mm.token + out.slice(mm.end);
    violations.push(mm.violation);
  }
  return { text: out, violations };
}

// ---------------------------------------------------------------------------
// Structured scanning helpers (messages / tool-call arguments)
// ---------------------------------------------------------------------------

// Recursively collect every string value in a parsed JSON structure
// (tool-call arguments — indirect injection lives in the string values).
function collectStringValues(node, out) {
  if (typeof node === 'string') {
    out.push(node);
  } else if (Array.isArray(node)) {
    for (const item of node) collectStringValues(item, out);
  } else if (node && typeof node === 'object') {
    for (const k of Object.keys(node)) collectStringValues(node[k], out);
  }
}

/**
 * Scan (and in redact mode, mutate) a tool-call arguments JSON string.
 * Falls back to scanning the raw string if it does not parse.
 * @returns {{violations: Array, text: string}}
 */
function scanToolArguments(argStr, mode) {
  const violations = [];
  let obj = null;
  try {
    obj = JSON.parse(argStr);
  } catch {
    obj = null;
  }
  if (obj && typeof obj === 'object') {
    const values = [];
    collectStringValues(obj, values);
    for (const v of values) {
      const r = scanTextMode(v, mode);
      violations.push(...r.violations);
    }
    if (mode === 'redact' && violations.length) {
      // Re-walk and mutate in place (only secret/PII violations mutate).
      mutateStrings(obj, mode);
      return { violations, text: JSON.stringify(obj) };
    }
    return { violations, text: argStr };
  }
  const r = scanTextMode(argStr, mode);
  return { violations: r.violations, text: r.text };
}

// Mutate string leaves in place (redact mode).
function mutateStrings(node, mode) {
  if (typeof node === 'string') {
    return redactSensitive(node).text;
  }
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) node[i] = mutateStrings(node[i], mode);
    return node;
  }
  if (node && typeof node === 'object') {
    for (const k of Object.keys(node)) node[k] = mutateStrings(node[k], mode);
    return node;
  }
  return node;
}

/**
 * Scan one piece of text in the given mode.
 * block/report: detect everything, no mutation.
 * redact: detect everything, mutate secrets/PII in place.
 * @returns {{violations: Array, text: string}}
 */
function scanTextMode(text, mode) {
  const violations = detectInjection(text);
  let out = text;
  if (mode === 'redact') {
    const r = redactSensitive(text);
    violations.push(...r.violations);
    out = r.text;
  } else {
    violations.push(...scanSecrets(text), ...scanPII(text));
  }
  return { violations, text: out };
}

/**
 * Scan a /v1/chat/completions request body. In redact mode the body is
 * mutated in place (message content + tool-call arguments).
 * @returns {Array} violations
 */
function scanChatCompletions(body, mode) {
  const violations = [];
  const messages = body && Array.isArray(body.messages) ? body.messages : [];
  for (const msg of messages) {
    if (!msg || typeof msg !== 'object') continue;

    if (typeof msg.content === 'string') {
      const r = scanTextMode(msg.content, mode);
      violations.push(...r.violations);
      if (mode === 'redact' && r.text !== msg.content) msg.content = r.text;
    } else if (Array.isArray(msg.content)) {
      // content as an array of parts ({type:'text', text:'...'})
      for (const part of msg.content) {
        if (part && typeof part.text === 'string') {
          const r = scanTextMode(part.text, mode);
          violations.push(...r.violations);
          if (mode === 'redact' && r.text !== part.text) part.text = r.text;
        }
      }
    }

    // Assistant tool_calls carry JSON-string arguments — indirect injection.
    if (Array.isArray(msg.tool_calls)) {
      for (const tc of msg.tool_calls) {
        const fn = tc && tc.function;
        if (fn && typeof fn.arguments === 'string') {
          const r = scanToolArguments(fn.arguments, mode);
          violations.push(...r.violations);
          if (mode === 'redact' && r.text !== fn.arguments) fn.arguments = r.text;
        }
      }
    }
  }
  return violations;
}

/**
 * Scan a string/array-of-strings field (prompt for /v1/completions, input
 * for /v1/embeddings). Redact mode mutates in place. Numeric arrays (token
 * ids) are ignored.
 * @returns {Array} violations
 */
function scanTextField(body, field, mode) {
  const violations = [];
  if (!body || body[field] === undefined) return violations;
  const value = body[field];
  const targets = [];
  if (typeof value === 'string') targets.push(value);
  else if (Array.isArray(value)) {
    for (const item of value) if (typeof item === 'string') targets.push(item);
  }
  if (mode === 'redact' && typeof value === 'string') {
    const r = scanTextMode(value, mode);
    violations.push(...r.violations);
    if (r.text !== value) body[field] = r.text;
  } else if (mode === 'redact' && Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      if (typeof value[i] === 'string') {
        const r = scanTextMode(value[i], mode);
        violations.push(...r.violations);
        if (r.text !== value[i]) value[i] = r.text;
      }
    }
  } else {
    for (const t of targets) violations.push(...scanTextMode(t, mode).violations);
  }
  return violations;
}

/**
 * Scan a chat-completion RESPONSE body (choices[].message.content +
 * tool_calls[].function.arguments — LLMs can leak secrets they were trained
 * on or received in context). Redact mode mutates in place.
 * @returns {Array} violations
 */
function scanChatResponse(body, mode, systemPromptLines) {
  const violations = [];
  const choices = body && Array.isArray(body.choices) ? body.choices : [];
  for (const choice of choices) {
    const message = choice && choice.message;
    if (!message || typeof message !== 'object') continue;
    if (typeof message.content === 'string') {
      const r = scanTextMode(message.content, mode);
      violations.push(...r.violations);
      if (mode === 'redact' && r.text !== message.content) message.content = r.text;
      violations.push(...detectSystemPromptLeak(message.content, systemPromptLines));
    }
    if (Array.isArray(message.tool_calls)) {
      for (const tc of message.tool_calls) {
        const fn = tc && tc.function;
        if (fn && typeof fn.arguments === 'string') {
          const r = scanToolArguments(fn.arguments, mode);
          violations.push(...r.violations);
          if (mode === 'redact' && r.text !== fn.arguments) fn.arguments = r.text;
          violations.push(...detectSystemPromptLeak(fn.arguments, systemPromptLines));
        }
      }
    }
  }
  return violations;
}

/**
 * System-prompt leakage: the model echoed a line from YOUR system prompt
 * (Lakera does this via custom guardrails; we do it deterministically).
 * Any trimmed line >= 16 chars from the system-prompt file that appears in
 * the output is a leak signal. FP-safe by construction (it's your own text).
 */
function detectSystemPromptLeak(text, systemPromptLines) {
  const violations = [];
  if (!Array.isArray(systemPromptLines) || systemPromptLines.length === 0) return violations;
  if (typeof text !== 'string' || text.length === 0) return violations;
  const textFlat = text.replace(/\s+/g, ' ');
  for (const line of systemPromptLines) {
    if (!line) continue;
    // exact hit on raw text, or whitespace-drift tolerant hit (both sides collapsed)
    const flat = line.replace(/\s+/g, ' ');
    const hit = text.includes(line) || (flat.length >= 16 && textFlat.includes(flat));
    if (hit) {
      violations.push({
        type: 'system-prompt-leak', ruleId: 'ai.system-prompt-leak', severity: 'high',
        start: textFlat.indexOf(flat), match: maskSnippet(flat),
        message: 'The model echoed a line from your system prompt — possible prompt-leakage exfiltration.',
      });
    }
  }
  return violations;
}

// ---------------------------------------------------------------------------
// Violation bookkeeping
// ---------------------------------------------------------------------------

function maskSnippet(s) {
  const str = String(s);
  if (str.length <= 12) return '***';
  return str.slice(0, 4) + '…' + str.slice(-4);
}

// ---------------------------------------------------------------------------
// The guard proxy server
// ---------------------------------------------------------------------------

/**
 * Create and start the guard proxy.
 * @param {object} opts
 * @param {number} [opts.port=0]            listen port (0 = ephemeral)
 * @param {string} [opts.upstream]          upstream base URL (default https://api.openai.com/v1)
 * @param {string} [opts.mode='block']      'block' | 'redact' | 'report'
 * @param {string} [opts.apiKey]            Bearer key sent to upstream (default: forward client's)
 * @param {Function} [opts.onViolation]     callback(violation)
 * @param {boolean} [opts.quiet]            suppress console.error violation logs
 * @returns {{server, port, close(), violations: Array}}
 */
function createGuardProxy(opts = {}) {
  const mode = MODES.has(opts.mode) ? opts.mode : 'block';
  const systemPromptLines = Array.isArray(opts.systemPromptLines) ? opts.systemPromptLines : [];
  const upstreamBase = (opts.upstream || DEFAULT_UPSTREAM).replace(/\/+$/, '');
  const apiKey = opts.apiKey || null;
  const quiet = !!opts.quiet;

  const violations = [];
  const inflight = new Set(); // upstream requests in flight (for close())

  function logViolation(base, location) {
    const v = Object.assign({}, base, {
      timestamp: new Date().toISOString(),
      location: location || 'request',
      snippet: maskSnippet(base.match),
    });
    violations.push(v);
    if (typeof opts.onViolation === 'function') {
      try {
        opts.onViolation(v);
      } catch {
        /* callback must never break the guard */
      }
    }
    if (!quiet) {
      console.error('[llm-proxy] ' + v.timestamp + ' ' + v.type + ' ' + v.ruleId + ' ' + v.snippet);
    }
  }

  function blockedMessage(v) {
    return 'vibeguard: blocked ' + v.type + ': ' + (v.ruleId || v.message || 'violation');
  }

  // Resolve the upstream target for a client request path. Upstream base may
  // end in /v1 (https://api.openai.com/v1) — in that case strip the client's
  // leading /v1 so the final path is /v1/chat/completions, not /v1/v1/...
  function upstreamTarget(clientPath) {
    let up;
    try {
      up = new URL(upstreamBase);
    } catch {
      return null;
    }
    let path = clientPath;
    if (up.pathname.replace(/\/+$/, '') === '/v1' && path.startsWith('/v1')) {
      path = path.slice(3) || '/';
    }
    const targetPath = up.pathname.replace(/\/+$/, '') + path;
    return {
      hostname: up.hostname,
      port: up.port ? Number(up.port) : up.protocol === 'https:' ? 443 : 80,
      path: targetPath || '/',
      transport: up.protocol === 'https:' ? https : http,
    };
  }

  function forwardHeaders(headers, withBody) {
    const out = {};
    for (const k of Object.keys(headers || {})) {
      const lk = k.toLowerCase();
      if (lk === 'host' || lk === 'connection' || lk === 'content-length' ||
          lk === 'transfer-encoding' || lk === 'accept-encoding' ||
          lk === 'content-encoding' || lk === 'expect') {
        continue;
      }
      out[k] = headers[k];
    }
    if (apiKey) out.authorization = 'Bearer ' + apiKey;
    else if (!out.authorization) delete out.authorization;
    if (withBody) out['content-type'] = 'application/json';
    return out;
  }

  function respondJson(res, status, obj) {
    res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify(obj));
  }

  // ── POST /v1/chat/completions | /v1/completions | /v1/embeddings ─────────
  function handlePost(req, res, urlPath) {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      let body = null;
      const raw = Buffer.concat(chunks).toString('utf8');
      try {
        body = JSON.parse(raw || '{}');
      } catch {
        respondJson(res, 400, { error: { message: 'vibeguard: invalid JSON body' } });
        return;
      }
      if (!body || typeof body !== 'object' || Array.isArray(body)) {
        respondJson(res, 400, { error: { message: 'vibeguard: invalid JSON body' } });
        return;
      }

      // ── REQUEST SCAN ──────────────────────────────────────────────────
      let reqViolations = [];
      if (urlPath === '/v1/chat/completions') reqViolations = scanChatCompletions(body, mode);
      else if (urlPath === '/v1/completions') reqViolations = scanTextField(body, 'prompt', mode);
      else if (urlPath === '/v1/embeddings') reqViolations = scanTextField(body, 'input', mode);

      for (const v of reqViolations) logViolation(v, 'request');

      if (mode === 'block' && reqViolations.length > 0) {
        // DO NOT call upstream.
        respondJson(res, 403, { error: { message: blockedMessage(reqViolations[0]) } });
        return;
      }

      // ── FORWARD ───────────────────────────────────────────────────────
      const target = upstreamTarget(req.url);
      if (!target) {
        respondJson(res, 502, { error: { message: 'vibeguard: invalid upstream URL' } });
        return;
      }

      const outBody = Buffer.from(JSON.stringify(body));
      const upstreamReq = target.transport.request(
        {
          hostname: target.hostname,
          port: target.port,
          path: target.path,
          method: req.method,
          headers: forwardHeaders(req.headers, true),
          agent: false, // one connection per request — no keep-alive reuse after stream destroys
        },
        (upstreamRes) => {
          inflight.delete(upstreamReq);
          const isSse = /text\/event-stream/i.test(upstreamRes.headers['content-type'] || '');
          if ((body.stream === true || isSse) && upstreamRes.statusCode >= 200 && upstreamRes.statusCode < 300) {
            handleStreamingResponse(upstreamReq, upstreamRes, res);
          } else if (upstreamRes.statusCode >= 200 && upstreamRes.statusCode < 300) {
            handleJsonResponse(upstreamReq, upstreamRes, res);
          } else {
            // Upstream error (4xx/5xx) — pass through untouched.
            const h = {};
            for (const k of Object.keys(upstreamRes.headers)) {
              if (k.toLowerCase() !== 'content-length') h[k] = upstreamRes.headers[k];
            }
            res.writeHead(upstreamRes.statusCode || 502, h);
            upstreamRes.pipe(res);
          }
        }
      );

      upstreamReq.setTimeout(IDLE_TIMEOUT_MS, () => {
        upstreamReq.destroy(new Error('vibeguard: upstream timeout'));
      });
      upstreamReq.on('error', (err) => {
        inflight.delete(upstreamReq);
        const timedOut = err && /timeout/i.test(err.message);
        if (res.headersSent) {
          res.destroy();
          return;
        }
        respondJson(res, timedOut ? 504 : 502, {
          error: { message: 'vibeguard: ' + (timedOut ? 'upstream timeout' : 'upstream error: ' + (err && err.message ? err.message : err)) },
        });
      });
      inflight.add(upstreamReq);
      upstreamReq.end(outBody);
    });
  }

  // ── Non-streaming upstream response: buffer, scan, maybe redact ────────
  function handleJsonResponse(upstreamReq, upstreamRes, res) {
    const chunks = [];
    upstreamRes.on('data', (c) => chunks.push(c));
    upstreamRes.on('end', () => {
      const raw = Buffer.concat(chunks);
      const outHeaders = {};
      for (const k of Object.keys(upstreamRes.headers)) {
        const lk = k.toLowerCase();
        if (lk !== 'content-length' && lk !== 'content-encoding' && lk !== 'transfer-encoding') {
          outHeaders[k] = upstreamRes.headers[k];
        }
      }
      outHeaders['Access-Control-Allow-Origin'] = '*';
      outHeaders['Content-Type'] = upstreamRes.headers['content-type'] || 'application/json';

      let outBody = raw;
      let parsed = null;
      try {
        parsed = JSON.parse(raw.toString('utf8'));
      } catch {
        parsed = null;
      }

      // ── RESPONSE SCAN ─────────────────────────────────────────────────
      if (parsed && parsed.choices) {
        const respViolations = scanChatResponse(parsed, mode, systemPromptLines);
        for (const v of respViolations) logViolation(v, 'response');

        if (mode === 'block' && respViolations.length > 0) {
          respondJson(res, 403, { error: { message: blockedMessage(respViolations[0]) } });
          return;
        }
        if (mode === 'redact' && respViolations.length > 0) {
          outBody = Buffer.from(JSON.stringify(parsed));
        }
      }
      outHeaders['Content-Length'] = outBody.length;
      res.writeHead(upstreamRes.statusCode || 200, outHeaders);
      res.end(outBody);
    });
    upstreamRes.on('error', () => {
      if (!res.headersSent) respondJson(res, 502, { error: { message: 'vibeguard: upstream response error' } });
      else res.destroy();
    });
  }

  // ── Streaming (SSE) upstream response: per-chunk scan + rewrite ────────
  function handleStreamingResponse(upstreamReq, upstreamRes, res) {
    const outHeaders = {};
    for (const k of Object.keys(upstreamRes.headers)) {
      const lk = k.toLowerCase();
      if (lk !== 'content-length' && lk !== 'content-encoding' && lk !== 'transfer-encoding') {
        outHeaders[k] = upstreamRes.headers[k];
      }
    }
    outHeaders['Access-Control-Allow-Origin'] = '*';
    outHeaders['Content-Type'] = upstreamRes.headers['content-type'] || 'text/event-stream';
    res.writeHead(upstreamRes.statusCode || 200, outHeaders);

    let buffer = '';
    let stopped = false;

    // Accumulated content (raw) + redacted output cursor, so secrets that
    // span chunk boundaries still get redacted.
    let accRaw = '';
    let accRed = '';
    let emittedLen = 0;
    const toolAcc = new Map(); // tool_call index -> { raw, red, emittedLen }
    const seen = new Set();    // violation keys already logged

    function keyOf(v) {
      return v.type + ':' + v.ruleId + ':' + v.start + ':' + v.match;
    }

    function scanDeltaText(deltaText) {
      // Returns violations not yet logged.
      const fresh = [];
      const all = scanText(deltaText);
      for (const v of all) {
        const k = keyOf(v);
        if (seen.has(k)) continue;
        seen.add(k);
        fresh.push(v);
      }
      return fresh;
    }

    function blockOn(violation) {
      if (stopped) return;
      stopped = true;
      logViolation(violation, 'stream');
      try {
        upstreamReq.destroy(); // cut the upstream socket
      } catch {
        /* already gone */
      }
      try {
        res.write('data: [DONE]\n\n');
      } catch {
        /* client gone */
      }
      try {
        res.end();
      } catch {
        /* ignore */
      }
    }

    function handleLine(line) {
      if (!line.startsWith('data:')) {
        res.write(line + '\n');
        return;
      }
      const payload = line.slice(5).trim();
      if (payload === '[DONE]') {
        res.write(line + '\n\n');
        return;
      }
      let evt = null;
      try {
        evt = JSON.parse(payload);
      } catch {
        res.write(line + '\n\n'); // unparseable — pass raw through
        return;
      }
      const choice = evt.choices && evt.choices[0];
      if (!choice || !choice.delta) {
        res.write(line + '\n\n');
        return;
      }
      const delta = choice.delta;
      let mutated = false;

      // content deltas
      if (typeof delta.content === 'string') {
        accRaw += delta.content;
        const fresh = scanDeltaText(accRaw);
        if (mode === 'block' && fresh.length > 0) {
          blockOn(fresh[0]);
          return;
        }
        for (const v of fresh) logViolation(v, 'stream');
        if (mode === 'redact') {
          accRed = redactSensitive(accRaw).text;
          const emit = accRed.slice(emittedLen);
          emittedLen = accRed.length;
          if (emit !== delta.content) {
            delta.content = emit;
            mutated = true;
          }
        }
      }

      // tool_call argument deltas (fragments per index)
      if (Array.isArray(delta.tool_calls)) {
        for (const tc of delta.tool_calls) {
          const fn = tc && tc.function;
          if (!fn || typeof fn.arguments !== 'string') continue;
          const idx = tc.index !== undefined ? tc.index : 0;
          let st = toolAcc.get(idx);
          if (!st) {
            st = { raw: '', red: '', emittedLen: 0 };
            toolAcc.set(idx, st);
          }
          st.raw += fn.arguments;
          const fresh = scanText(st.raw);
          if (mode === 'block' && fresh.length > 0) {
            blockOn(fresh[0]);
            return;
          }
          for (const v of fresh) logViolation(v, 'stream');
          if (mode === 'redact') {
            st.red = redactSensitive(st.raw).text;
            const emit = st.red.slice(st.emittedLen);
            st.emittedLen = st.red.length;
            if (emit !== fn.arguments) {
              fn.arguments = emit;
              mutated = true;
            }
          }
        }
      }

      if (mutated) res.write('data: ' + JSON.stringify(evt) + '\n\n');
      else res.write(line + '\n\n');
    }

    upstreamRes.on('data', (chunk) => {
      if (stopped) return;
      buffer += chunk.toString('utf8');
      let nl;
      while ((nl = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, nl);
        buffer = buffer.slice(nl + 1);
        if (line === '') continue;
        handleLine(line);
        if (stopped) return;
      }
    });
    const finish = () => {
      if (stopped) return;
      stopped = true;
      // System-prompt leak check on the fully accumulated stream (report +
      // block-mode kill; redaction of a leaked prompt line is meaningless).
      if (accRaw) {
        const leaked = detectSystemPromptLeak(accRaw, systemPromptLines);
        for (const v of leaked) logViolation(v, 'stream');
        if (mode === 'block' && leaked.length > 0) {
          try {
            res.write('data: [DONE]\n\n');
          } catch {
            /* client gone */
          }
        }
      }
      try {
        res.end();
      } catch {
        /* ignore */
      }
    };
    upstreamRes.on('end', finish);
    upstreamRes.on('close', finish);
    upstreamRes.on('error', finish);
  }

  // ── GET /v1/models (pass-through) ──────────────────────────────────────
  function handleModels(req, res) {
    const target = upstreamTarget(req.url);
    if (!target) {
      respondJson(res, 502, { error: { message: 'vibeguard: invalid upstream URL' } });
      return;
    }
    const upstreamReq = target.transport.request(
      {
        hostname: target.hostname,
        port: target.port,
        path: target.path,
        method: 'GET',
        headers: forwardHeaders(req.headers, false),
        agent: false,
      },
      (upstreamRes) => {
        inflight.delete(upstreamReq);
        const h = {};
        for (const k of Object.keys(upstreamRes.headers)) {
          if (k.toLowerCase() !== 'content-length') h[k] = upstreamRes.headers[k];
        }
        h['Access-Control-Allow-Origin'] = '*';
        res.writeHead(upstreamRes.statusCode || 200, h);
        upstreamRes.pipe(res);
      }
    );
    upstreamReq.setTimeout(IDLE_TIMEOUT_MS, () => upstreamReq.destroy(new Error('vibeguard: upstream timeout')));
    upstreamReq.on('error', (err) => {
      inflight.delete(upstreamReq);
      if (res.headersSent) {
        res.destroy();
        return;
      }
      respondJson(res, 502, { error: { message: 'vibeguard: upstream error: ' + (err && err.message ? err.message : err) } });
    });
    inflight.add(upstreamReq);
    upstreamReq.end();
  }

  // ── Server ─────────────────────────────────────────────────────────────
  const server = http.createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': req.headers['access-control-request-headers'] || 'Content-Type, Authorization',
        'Access-Control-Max-Age': '86400',
      });
      res.end();
      return;
    }

    const urlPath = (req.url || '/').split('?')[0];
    if (req.method === 'GET' && urlPath === '/v1/models') {
      handleModels(req, res);
      return;
    }
    if (req.method === 'POST' &&
        (urlPath === '/v1/chat/completions' || urlPath === '/v1/completions' || urlPath === '/v1/embeddings')) {
      handlePost(req, res, urlPath);
      return;
    }
    respondJson(res, 404, { error: { message: 'unknown endpoint' } });
  });

  server.requestTimeout = IDLE_TIMEOUT_MS;
  server.headersTimeout = IDLE_TIMEOUT_MS;
  server.keepAliveTimeout = IDLE_TIMEOUT_MS;
  server.timeout = IDLE_TIMEOUT_MS;

  server.listen(opts.port || 0, '127.0.0.1');

  const proxy = {
    server,
    mode,
    upstream: upstreamBase,
    violations,
    close() {
      for (const r of inflight) {
        try {
          r.destroy();
        } catch {
          /* ignore */
        }
      }
      inflight.clear();
      return new Promise((resolve) => {
        server.close(() => resolve());
        if (typeof server.closeAllConnections === 'function') {
          try {
            server.closeAllConnections();
          } catch {
            /* ignore */
          }
        }
      });
    },
  };
  Object.defineProperty(proxy, 'port', {
    get() {
      const a = server.address();
      return a ? a.port : null;
    },
  });
  return proxy;
}

module.exports = {
  createGuardProxy,
  detectInjection,
  scanSecrets,
  scanPII,
  scanText,
  redactSensitive,
  scanChatCompletions,
  scanChatResponse,
  detectSystemPromptLeak,
  INJECTION_PATTERNS,
  DEFAULT_PORT,
  DEFAULT_UPSTREAM,
  MODES,
};
