'use strict';

/*
 * Entropy-based high-entropy secret detection (TruffleHog-style).
 *
 * Pure functions, zero runtime deps. The idea: secrets are random-looking, so
 * a long string with unusually high Shannon entropy that sits on a key-like
 * line is a strong signal even when NO known scheme matches. The context gate
 * (a key-like identifier on the line / ±2 lines) is the FP killer — without it
 * every minified blob or hash would fire.
 *
 * Exposed:
 *   shannonEntropy(str)              -> bits/char (H = -Σ p(x) log2 p(x))
 *   findHighEntropyTokens(content)   -> [{ index, match, entropy, reason, line }]
 *                                      (line = 1-based, index = char offset)
 */

// Shannon entropy in bits/char over the string's character alphabet.
// A 32-char random alnum token ≈ 4.5-5.0+ bits/char; normal English ≈ 3.5-4.0.
function shannonEntropy(str) {
  const freq = Object.create(null);
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  let e = 0;
  const n = str.length;
  if (n === 0) return 0;
  for (const k in freq) {
    const p = freq[k] / n;
    e -= p * Math.log2(p);
  }
  return e;
}

const MIN_ENTROPY = 4.0;

// A key-like identifier that makes a high-entropy string look like a secret.
const KEY_CONTEXT_RE =
  /api[_-]?key|secret|token|password|passwd|credential|auth|bearer|private[_-]?key|access[_-]?key|client[_-]?secret|session[_-]?id/i;

// Token candidates: bare [A-Za-z0-9_-] runs, 24-80 chars, word-boundaried.
const TOKEN_RE = /\b[A-Za-z0-9_\-]{24,80}\b/g;

// Checksum-length hex (md5/sha1/sha256/sha512) — hashes, not secrets.
const CHECKSUM_HEX_RE = /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/i;
// UUIDs (8-4-4-4-12 hex) — structured ids, not secrets.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Pure hex 24-64 (ambiguous) — only flagged when the context gate passes.
const PURE_HEX_RE = /^[0-9a-f]+$/i;
// Version strings (semver-ish) — split on dots, so defensive only.
const SEMVER_RE = /^\d+\.\d+\.\d+/;
// JWT-shaped header.payload.signature — covered by the dedicated rule.
const JWT_RE = /^[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}/;
// URLs — path segments inside them are not secrets.
const URL_RE = /https?:\/\/\S+/g;
const BASE64_CHAR = /[A-Za-z0-9+/=]/;

// Expand to the maximal base64-ish run surrounding [start, end) on the line.
function base64RunOf(line, start, end) {
  let s = start;
  let e = end;
  while (s > 0 && BASE64_CHAR.test(line[s - 1])) s--;
  while (e < line.length && BASE64_CHAR.test(line[e])) e++;
  return line.slice(s, e);
}

// base64 of normal text: decode and re-check. If the decoded payload is mostly
// printable ASCII with LOW entropy (< 3.5), it is base64 of prose — not a
// secret. Binary or high-entropy payloads are kept (real secrets).
function isBase64OfPlainText(run) {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(run)) return false;
  if (run.length < 16) return false;
  let buf;
  try {
    buf = Buffer.from(run, 'base64');
  } catch {
    return false;
  }
  if (!buf || buf.length < 8) return false;
  let printable = 0;
  for (let i = 0; i < buf.length; i++) {
    const c = buf[i];
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127)) printable++;
  }
  if (printable / buf.length < 0.9) return false; // binary payload — keep
  return shannonEntropy(buf.toString('latin1')) < 3.5;
}

// Does any line in [i-2, i+2] carry a key-like identifier? The candidate token
// itself is removed first so a random string can't smuggle in its own context.
function contextPasses(lines, i, token) {
  const from = Math.max(0, i - 2);
  const to = Math.min(lines.length - 1, i + 2);
  for (let j = from; j <= to; j++) {
    if (KEY_CONTEXT_RE.test(lines[j].split(token).join(''))) return true;
  }
  return false;
}

// Find high-entropy tokens that look like hardcoded secrets.
// Returns [{ index, match, entropy, reason, line }]:
//   index  — char offset of the token in `content`
//   match  — the raw token string
//   entropy— shannonEntropy(match)
//   reason — why it was flagged
//   line   — 1-based line number (used by the rule for double-report suppression)
function findHighEntropyTokens(content) {
  const out = [];
  const lines = content.split(/\r?\n/);
  let lineStart = 0; // char offset of the current line inside `content`
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 2000) {
      // Minified/embedded blob line — same guard as the sibling rule.
      const nl = content.indexOf('\n', lineStart);
      lineStart = nl === -1 ? content.length : nl + 1;
      continue;
    }
    URL_RE.lastIndex = 0;
    TOKEN_RE.lastIndex = 0;
    let m;
    while ((m = TOKEN_RE.exec(line)) !== null) {
      const token = m[0];
      const absIndex = lineStart + m.index;
      const entropy = shannonEntropy(token);
      if (entropy < MIN_ENTROPY) continue;

      // Checksum-length hex and UUIDs — structured ids, not secrets.
      if (CHECKSUM_HEX_RE.test(token)) continue;
      if (UUID_RE.test(token)) continue;

      // JWT-shaped (header.payload.signature) — dedicated rule owns it.
      let s = m.index;
      let e = m.index + token.length;
      while (s > 0 && /[A-Za-z0-9_\-.]/.test(line[s - 1])) s--;
      while (e < line.length && /[A-Za-z0-9_\-.]/.test(line[e])) e++;
      if (JWT_RE.test(line.slice(s, e))) continue;

      // Inside a URL — path segments and query strings are not secrets.
      let um;
      let insideUrl = false;
      while ((um = URL_RE.exec(line)) !== null) {
        if (m.index >= um.index && m.index + token.length <= um.index + um[0].length) {
          insideUrl = true;
          break;
        }
      }
      if (insideUrl) continue;

      // File-path segment — slash or backslash adjacent to the token.
      if (
        (m.index > 0 && (line[m.index - 1] === '/' || line[m.index - 1] === '\\')) ||
        (m.index + token.length < line.length &&
          (line[m.index + token.length] === '/' || line[m.index + token.length] === '\\'))
      ) {
        continue;
      }

      // Semver / version-ish strings (defensive — dots split tokens anyway).
      if (SEMVER_RE.test(token)) continue;

      // base64 of plain text — decode and re-check.
      if (isBase64OfPlainText(base64RunOf(line, m.index, m.index + token.length))) continue;

      // Pure-hex 24-64 (non-checksum) is ambiguous: only flag it when the
      // context gate below ALSO passes (it must pass for every token anyway).
      const isAmbiguousHex = PURE_HEX_RE.test(token) && token.length >= 24 && token.length <= 64;

      // CONTEXT GATE — the FP killer: a key-like identifier on this line or
      // within ±2 lines.
      if (!contextPasses(lines, i, token)) continue;

      out.push({
        index: absIndex,
        match: token,
        entropy,
        reason: isAmbiguousHex
          ? 'high-entropy hex token on a key-like line'
          : 'high-entropy token on a key-like line',
        line: i + 1,
      });
    }
    const nl = content.indexOf('\n', lineStart);
    lineStart = nl === -1 ? content.length : nl + 1;
  }
  return out;
}

module.exports = { shannonEntropy, findHighEntropyTokens };
