'use strict';

/*
 * Live-URL scan mode.
 *
 * Source code is only half the story — this checks what's ACTUALLY deployed by
 * fetching a URL and inspecting the real HTTP response: missing security headers,
 * insecure cookies, server/version leakage, and no-HTTPS. It cannot see logic
 * bugs or backend holes; it audits the response surface only. Same honest scope.
 *
 * Uses global fetch (Node 18+). No dependencies.
 */

const REQUIRED_HEADERS = [
  {
    name: 'strict-transport-security',
    severity: 'medium',
    title: 'Missing HSTS',
    message: 'No Strict-Transport-Security header — browsers may use http and be downgrade-attacked.',
    fix: 'Send Strict-Transport-Security: max-age=63072000; includeSubDomains; preload (HTTPS only).',
  },
  {
    name: 'content-security-policy',
    severity: 'medium',
    title: 'Missing Content-Security-Policy',
    message: 'No Content-Security-Policy — weaker defense against XSS and injected resources.',
    fix: "Add a Content-Security-Policy (start with default-src 'self' and tighten).",
  },
  {
    name: 'x-content-type-options',
    severity: 'low',
    title: 'Missing X-Content-Type-Options',
    message: 'No X-Content-Type-Options — browsers may MIME-sniff responses.',
    fix: 'Add X-Content-Type-Options: nosniff.',
  },
  {
    name: 'x-frame-options',
    severity: 'low',
    title: 'Missing X-Frame-Options',
    message: 'No X-Frame-Options (and no frame-ancestors CSP) — page can be clickjacked in an iframe.',
    fix: 'Add X-Frame-Options: DENY, or a Content-Security-Policy frame-ancestors directive.',
  },
];

function analyzeHeaders(url, status, headers) {
  const findings = [];
  const get = (n) => headers.get(n);
  const isHttps = url.startsWith('https://');

  if (!isHttps) {
    findings.push({
      ruleId: 'url.no-https',
      severity: 'high',
      confidence: 'high',
      title: 'Site served over http://',
      message: 'The URL is not HTTPS — traffic (including credentials) is unencrypted.',
      fix: 'Serve the site over HTTPS and redirect http to https.',
      file: url, line: 1, column: 1, snippet: `HTTP ${status}`,
    });
  }

  const cspFrameAncestors = /frame-ancestors/i.test(get('content-security-policy') || '');
  for (const h of REQUIRED_HEADERS) {
    if (h.name === 'strict-transport-security' && !isHttps) continue; // HSTS only meaningful on https
    if (h.name === 'x-frame-options' && cspFrameAncestors) continue; // covered by CSP
    if (!get(h.name)) {
      findings.push({
        ruleId: `url.missing-${h.name}`,
        severity: h.severity,
        confidence: 'high',
        title: h.title,
        message: h.message,
        fix: h.fix,
        file: url, line: 1, column: 1, snippet: `HTTP ${status}`,
      });
    }
  }

  // Server / framework version leakage.
  for (const leak of ['server', 'x-powered-by']) {
    const val = get(leak);
    if (val && /\d/.test(val)) {
      findings.push({
        ruleId: 'url.version-leak',
        severity: 'low',
        confidence: 'medium',
        title: 'Server/framework version disclosed',
        message: `${leak}: ${val} — discloses software/version, helping attackers target known CVEs.`,
        fix: `Remove or genericize the ${leak} header.`,
        file: url, line: 1, column: 1, snippet: `${leak}: ${val}`,
      });
    }
  }

  // Insecure cookies.
  const setCookie = headers.getSetCookie ? headers.getSetCookie() : (get('set-cookie') ? [get('set-cookie')] : []);
  for (const cookie of setCookie) {
    const name = (cookie.split('=')[0] || 'cookie').trim();
    const flags = [];
    if (isHttps && !/;\s*secure/i.test(cookie)) flags.push('Secure');
    if (!/;\s*httponly/i.test(cookie)) flags.push('HttpOnly');
    if (flags.length) {
      findings.push({
        ruleId: 'url.insecure-cookie',
        severity: 'medium',
        confidence: 'high',
        title: 'Cookie missing security flags',
        message: `Cookie "${name}" is missing ${flags.join(' and ')} — exposed to theft (XSS) or transport interception.`,
        fix: `Set ${flags.join(' and ')} on the "${name}" cookie${flags.includes('HttpOnly') ? ' (unless JS must read it)' : ''}.`,
        file: url, line: 1, column: 1, snippet: cookie.slice(0, 80),
      });
    }
  }

  return findings;
}

async function scanUrl(rawUrl, opts = {}) {
  let url = rawUrl;
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), opts.timeoutMs || 15000);
  let res;
  try {
    res = await fetch(url, {
      method: 'GET',
      redirect: 'manual',
      signal: controller.signal,
      headers: { 'user-agent': 'VibeGuard/urlscan' },
    });
  } catch (err) {
    clearTimeout(t);
    throw new Error(`could not fetch ${url}: ${err && err.message ? err.message : err}`);
  }
  clearTimeout(t);

  const findings = analyzeHeaders(url, res.status, res.headers);
  return { url, status: res.status, findings };
}

module.exports = { scanUrl, analyzeHeaders };
