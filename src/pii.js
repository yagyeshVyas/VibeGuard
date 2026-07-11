'use strict';

/*
 * VibeGuard PII guard.
 *
 * Detects and redacts personal / sensitive data in ARBITRARY TEXT — not code.
 * This is the piece that backs VibeGuard's core promise: an AI agent should be
 * able to scrub user text BEFORE it sends it to a model, a tool, a log, or any
 * external service. Runs 100% locally, zero network, zero dependencies.
 *
 * Design goals:
 *  - Low false positives. Credit cards are Luhn-validated; SSN/phone shapes are
 *    constrained; matches inside a longer digit run are rejected.
 *  - Deterministic, non-overlapping redaction (longest / highest-priority wins).
 *  - Format-preserving-ish output: cards/phones keep last 4 by default so the
 *    text stays readable ("****4242") while the sensitive part is gone.
 */

// Luhn check — real card numbers pass, random 16-digit strings almost never do.
function luhnValid(digits) {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (n < 0 || n > 9) return false;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function last4Mask(raw, digits) {
  return '****' + digits.slice(-4);
}

// Each detector: { type, severity, re, validate?(m), redact?(m) }
// `re` MUST be global. `validate` returns false to reject a candidate match.
// `redact` returns the replacement token (defaults to `[REDACTED_<TYPE>]`).
const DETECTORS = [
  {
    type: 'email',
    severity: 'high',
    re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  },
  {
    type: 'credit-card',
    severity: 'critical',
    // 13–19 digits, optionally split by spaces or dashes, not glued to more digits.
    re: /(?<![\d])(?:\d[ -]?){12,18}\d(?![\d])/g,
    validate(m) {
      const digits = m.replace(/[^\d]/g, '');
      if (digits.length < 13 || digits.length > 19) return false;
      return luhnValid(digits);
    },
    redact(m) {
      return last4Mask(m, m.replace(/[^\d]/g, ''));
    },
  },
  {
    type: 'ssn',
    severity: 'critical',
    // US SSN: 3-2-4 with separators. Reject obvious invalids (000 area, 00 group, 0000 serial).
    re: /(?<![\d-])\d{3}[ -]\d{2}[ -]\d{4}(?![\d-])/g,
    validate(m) {
      const d = m.replace(/[^\d]/g, '');
      const area = d.slice(0, 3);
      const group = d.slice(3, 5);
      const serial = d.slice(5);
      if (area === '000' || area === '666' || area[0] === '9') return false;
      if (group === '00' || serial === '0000') return false;
      return true;
    },
  },
  {
    type: 'phone',
    severity: 'medium',
    // Intl / US phone with separators or +country code. Requires structure so we
    // don't grab bare integers. 10–15 significant digits.
    re: /(?<![\w.])(?:\+?\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?)?\d{2,4}[ .-]\d{2,4}[ .-]\d{2,4}(?:[ .-]\d{2,4})?(?![\w])/g,
    validate(m) {
      const d = m.replace(/[^\d]/g, '');
      return d.length >= 10 && d.length <= 15;
    },
    redact(m) {
      return '[REDACTED_PHONE_' + m.replace(/[^\d]/g, '').slice(-4) + ']';
    },
  },
  {
    type: 'ipv4',
    severity: 'low',
    re: /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])/g,
  },
  {
    type: 'ipv6',
    severity: 'low',
    re: /\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b/g,
  },
  {
    type: 'jwt',
    severity: 'high',
    re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b/g,
  },
  {
    type: 'aws-access-key',
    severity: 'critical',
    re: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[A-Z0-9]{16}\b/g,
  },
  {
    type: 'private-key',
    severity: 'critical',
    re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
  },
  {
    type: 'iban',
    severity: 'high',
    re: /\b[A-Z]{2}\d{2}[ ]?(?:[A-Z0-9]{4}[ ]?){2,7}[A-Z0-9]{1,4}\b/g,
    validate(m) {
      const s = m.replace(/\s/g, '');
      return s.length >= 15 && s.length <= 34;
    },
  },
  {
    type: 'mac-address',
    severity: 'low',
    re: /\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b/g,
  },
];

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

/**
 * Detect PII in text.
 * @param {string} text
 * @param {{types?: string[]}} [opts] optional allowlist of entity types to scan for.
 * @returns {{matches: Array, counts: Object, types: string[], total: number}}
 */
function detectPII(text, opts = {}) {
  if (typeof text !== 'string' || text.length === 0) {
    return { matches: [], counts: {}, types: [], total: 0 };
  }
  const only = opts.types && opts.types.length ? new Set(opts.types) : null;
  const raw = [];
  for (const det of DETECTORS) {
    if (only && !only.has(det.type)) continue;
    det.re.lastIndex = 0;
    let m;
    while ((m = det.re.exec(text)) !== null) {
      const value = m[0];
      if (m.index === det.re.lastIndex) det.re.lastIndex++; // guard against zero-width
      if (det.validate && !det.validate(value)) continue;
      raw.push({
        type: det.type,
        severity: det.severity,
        value,
        start: m.index,
        end: m.index + value.length,
        token: det.redact ? det.redact(value) : `[REDACTED_${det.type.toUpperCase()}]`,
      });
    }
  }
  // Resolve overlaps: sort by start, then prefer higher severity, then longer.
  raw.sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    const sr = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (sr !== 0) return sr;
    return b.end - a.end - (a.end - a.start);
  });
  const matches = [];
  let lastEnd = -1;
  for (const r of raw) {
    if (r.start < lastEnd) continue; // overlaps a kept, higher-priority match
    matches.push(r);
    lastEnd = r.end;
  }
  const counts = {};
  for (const r of matches) counts[r.type] = (counts[r.type] || 0) + 1;
  return {
    matches,
    counts,
    types: Object.keys(counts),
    total: matches.length,
  };
}

/**
 * Redact PII from text. Non-overlapping, right-to-left splice so indices stay valid.
 * @param {string} text
 * @param {{types?: string[]}} [opts]
 * @returns {{redacted: string, matches: Array, counts: Object, total: number, clean: boolean}}
 */
function redactText(text, opts = {}) {
  const det = detectPII(text, opts);
  let out = text;
  // Apply from the end so earlier indices are unaffected by length changes.
  for (let i = det.matches.length - 1; i >= 0; i--) {
    const m = det.matches[i];
    out = out.slice(0, m.start) + m.token + out.slice(m.end);
  }
  return {
    redacted: out,
    matches: det.matches.map((m) => ({ type: m.type, severity: m.severity, token: m.token })),
    counts: det.counts,
    total: det.total,
    clean: det.total === 0,
  };
}

module.exports = { detectPII, redactText, luhnValid, DETECTORS };
