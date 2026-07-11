'use strict';

/*
 * VibeGuard Network Auditor.
 *
 * Maps every outbound HTTP/HTTPS call in the codebase.
 * Shows exactly where your data goes — every fetch, axios, XHR, WebSocket.
 * Flags unknown/suspicious endpoints that are not in an allowlist.
 *
 * 100% local. Zero network. Zero dependencies.
 */

const fs = require('fs');
const path = require('path');

const URL_RE = /['"]https?:\/\/([^'"/]+)([^'"]*)['"]/g;
const FETCH_RE = /(?:fetch|axios\.(?:get|post|put|patch|delete)|axios\s*\(|http\.get|https\.get|http\.request|https\.request|got\(|superagent|XMLHttpRequest|\.open\s*\(\s*['"](?:GET|POST|PUT|PATCH|DELETE))\s*\(\s*['"]https?:\/\/([^'"/\s]+)/gi;
const WS_RE = /new\s+WebSocket\s*\(\s*['"]wss?:\/\/([^'"/]+)/gi;
const BEACON_RE = /sendBeacon\s*\(\s*['"]https?:\/\/([^'"/]+)/gi;
const DNS_RE = /dns\.lookup|dns\.resolve|child_process.*nslookup|child_process.*dig/gi;

const KNOWN_SAFE_DOMAINS = new Set([
  'localhost', '127.0.0.1', '0.0.0.0',
  'api.openai.com', 'api.anthropic.com', 'generativelanguage.googleapis.com',
  'api.stripe.com', 'connect.stripe.com',
  'api.github.com', 'github.com',
  'api.supabase.co', '*.supabase.co',
  '.googleapis.com', 'firestore.googleapis.com', 'identitytoolkit.googleapis.com',
  'api.resend.com', 'api.postmarkapp.com',
  'api.upstash.com', 'api.pinecone.io',
  'api.telegram.org', 'api.slack.com',
  'registry.npmjs.org', 'api.osv.dev',
  'api.cloudflare.com', 'api.datadoghq.com',
  'sentry.io', '*.sentry.io',
  'api.openai.com', 'api.anthropic.com',
  'api.mapbox.com', 'api.mapbox.ai',
  'api.openai.com',
]);

function isKnown(domain) {
  if (KNOWN_SAFE_DOMAINS.has(domain)) return true;
  for (const safe of KNOWN_SAFE_DOMAINS) {
    if (safe.startsWith('*.') && domain.endsWith(safe.slice(1))) return true;
  }
  // Local addresses are not suspicious
  if (/^(?:localhost|127\.|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|0\.0\.0\.0|::1|::)/.test(domain)) return true;
  // Example domains
  if (/example\.(com|org|net|io)$/.test(domain)) return true;
  return false;
}

function auditNetwork(dir, files) {
  const endpoints = [];
  const seen = new Set();

  for (const file of files) {
    let content;
    try { content = fs.readFileSync(file, 'utf8'); } catch { continue; }
    const rel = path.relative(dir, file).split(path.sep).join('/');
    const lines = content.split(/\r?\n/);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // All HTTP URLs
      let m;
      URL_RE.lastIndex = 0;
      while ((m = URL_RE.exec(line)) !== null) {
        const domain = m[1];
        const urlPath = m[2] || '/';
        const key = `${domain}${urlPath}`;
        if (seen.has(key)) continue;
        seen.add(key);
        endpoints.push({
          file: rel, line: i + 1, domain, path: urlPath,
          method: 'GET (URL only)',
          known: isKnown(domain),
          suspicious: !isKnown(domain) && !/^(?:www\.|api\.)?[a-z0-9-]+\.(?:com|org|net|io|dev|app|co|ai)$/i.test(domain),
        });
      }

      // fetch/axios calls
      FETCH_RE.lastIndex = 0;
      while ((m = FETCH_RE.exec(line)) !== null) {
        const domain = m[2] || m[1];
        if (!domain) continue;
        const key = `fetch:${domain}`;
        if (seen.has(key)) continue;
        seen.add(key);
        endpoints.push({
          file: rel, line: i + 1, domain,
          path: '/',
          method: 'fetch/axios',
          known: isKnown(domain),
          suspicious: !isKnown(domain),
        });
      }

      // WebSocket
      WS_RE.lastIndex = 0;
      while ((m = WS_RE.exec(line)) !== null) {
        const domain = m[1];
        endpoints.push({
          file: rel, line: i + 1, domain,
          path: '/ws',
          method: 'WebSocket',
          known: isKnown(domain),
          suspicious: !isKnown(domain),
        });
      }

      // Beacon
      BEACON_RE.lastIndex = 0;
      while ((m = BEACON_RE.exec(line)) !== null) {
        const domain = m[1];
        endpoints.push({
          file: rel, line: i + 1, domain,
          path: '/beacon',
          method: 'sendBeacon',
          known: isKnown(domain),
          suspicious: !isKnown(domain),
        });
      }
    }
  }

  const known = endpoints.filter(e => e.known);
  const unknown = endpoints.filter(e => !e.known);
  const suspicious = endpoints.filter(e => e.suspicious);
  const domains = [...new Set(endpoints.map(e => e.domain))];

  return {
    endpoints,
    known,
    unknown,
    suspicious,
    domains,
    summary: {
      totalEndpoints: endpoints.length,
      knownDomains: known.length,
      unknownDomains: unknown.length,
      suspiciousDomains: suspicious.length,
      uniqueDomains: domains.length,
    },
  };
}

function renderNetworkReport(result) {
  const C = {
    red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
    cyan: '\x1b[36m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m',
  };

  const lines = [];
  lines.push(`${C.bold}VibeGuard Network Audit${C.reset}`);
  lines.push(`${C.dim}${'─'.repeat(60)}${C.reset}`);
  lines.push('');

  lines.push(`${C.bold}Summary${C.reset}`);
  lines.push(`  Total endpoints:    ${result.summary.totalEndpoints}`);
  lines.push(`  Unique domains:     ${result.summary.uniqueDomains}`);
  lines.push(`  Known safe:         ${C.green}${result.summary.knownDomains}${C.reset}`);
  lines.push(`  Unknown:            ${C.yellow}${result.summary.unknownDomains}${C.reset}`);
  lines.push(`  Suspicious:         ${C.red}${result.summary.suspiciousDomains}${C.reset}`);
  lines.push('');

  if (result.domains.length > 0) {
    lines.push(`${C.bold}All Domains${C.reset}`);
    for (const d of result.domains.sort()) {
      const isKnown = result.known.some(e => e.domain === d);
      const isSuspicious = result.suspicious.some(e => e.domain === d);
      const color = isKnown ? C.green : isSuspicious ? C.red : C.yellow;
      const tag = isKnown ? 'known' : isSuspicious ? 'SUSPICIOUS' : 'unknown';
      lines.push(`  ${color}${tag.padEnd(12)}${C.reset} ${d}`);
    }
    lines.push('');
  }

  if (result.suspicious.length > 0) {
    lines.push(`${C.red}${C.bold}Suspicious Endpoints${C.reset}`);
    for (const e of result.suspicious) {
      lines.push(`  ${C.red}[!]${C.reset} ${e.method} ${e.domain}${e.path}`);
      lines.push(`      ${C.dim}${e.file}:${e.line}${C.reset}`);
    }
    lines.push('');
  }

  if (result.unknown.length > 0 && result.suspicious.length === 0) {
    lines.push(`${C.yellow}${C.bold}Unknown Endpoints (review)${C.reset}`);
    for (const e of result.unknown.slice(0, 15)) {
      lines.push(`  ${C.yellow}[?]${C.reset} ${e.method} ${e.domain}${e.path}`);
      lines.push(`      ${C.dim}${e.file}:${e.line}${C.reset}`);
    }
    if (result.unknown.length > 15) {
      lines.push(`  ${C.dim}... and ${result.unknown.length - 15} more${C.reset}`);
    }
    lines.push('');
  }

  if (result.endpoints.length === 0) {
    lines.push(`  ${C.green}No outbound HTTP calls detected${C.reset}`);
    lines.push('');
  }

  return lines.join('\n');
}

module.exports = { auditNetwork, renderNetworkReport, isKnown, KNOWN_SAFE_DOMAINS };