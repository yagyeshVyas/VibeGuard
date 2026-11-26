'use strict';

/*
 * Safe, read-only active web checks (`vibeguard webscan <url>`).
 *
 * Nuclei-class live testing needs a template engine, but 80% of the value for an
 * AI-built app is a small, fixed set of NON-DESTRUCTIVE probes: security headers
 * on the real response, HTTPS enforcement, CORS misconfig, cookie flags, method
 * exposure, exposed config/backup files, directory listing, and framework error
 * leakage. This module sends GET/OPTIONS requests only — no payload injection,
 * no state changes, no brute force — and caps every request by size, count and
 * timeout.
 *
 * Honest scope: this audits the deployed HTTP surface. It cannot prove the app
 * safe, and it cannot find logic bugs. `--allow-private` is required to probe a
 * loopback/RFC1918 target (the default blocks it so a scan cannot be aimed at
 * metadata endpoints or internal services).
 */

const dns = require('dns').promises;
const net = require('net');
const tls = require('tls');
const { analyzeHeaders } = require('./urlscan');

const UA = 'VibeGuard/webscan';
const MAX_BODY = 64 * 1024;
const DEFAULT_TIMEOUT = 8000;
const DEFAULT_MAX_REQUESTS = 16;

const PRIVATE_V4 = [
  /^0\./, /^10\./, /^127\./, /^169\.254\./,
  /^172\.(1[6-9]|2\d|3[01])\./, /^192\.168\./, /^192\.0\.0\./,
];

function isPrivateAddress(ip) {
  if (net.isIPv4(ip)) return PRIVATE_V4.some((re) => re.test(ip));
  if (net.isIPv6(ip)) {
    const low = ip.toLowerCase();
    return low === '::1' || low === '::' || low.startsWith('fe80:') ||
      low.startsWith('fc') || low.startsWith('fd') || low.includes('169.254');
  }
  return false;
}

function isPrivateName(host) {
  return host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') ||
    host === 'metadata.google.internal' || host === '169.254.169.254';
}

async function assertSafeTarget(rawUrl, opts) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error(`not a valid URL: ${rawUrl}`);
  }
  if (!/^https?:$/.test(url.protocol)) throw new Error('webscan only supports http(s) URLs');
  if (opts.allowPrivate) return url;
  if (isPrivateName(url.hostname) || isPrivateAddress(url.hostname)) {
    throw new Error(`refusing to probe private/metadata target ${url.hostname} — pass --allow-private to override`);
  }
  let addrs;
  try {
    addrs = await dns.lookup(url.hostname, { all: true });
  } catch (err) {
    throw new Error(`could not resolve ${url.hostname}: ${err.message}`);
  }
  const privateAddr = addrs.find((a) => isPrivateAddress(a.address));
  if (privateAddr) {
    throw new Error(`refusing to probe ${url.hostname} (resolves to private ${privateAddr.address}) — pass --allow-private to override`);
  }
  return url;
}

function finding(ruleId, severity, title, message, fix, file, snippet, confidence = 'high') {
  return { ruleId, severity, confidence, title, message, fix, file, line: 1, column: 1, snippet };
}

async function request(url, opts = {}) {
  // Deliberately the core http/https modules instead of fetch(): webscan fires
  // a dozen short requests, and undici's keep-alive sockets still have async
  // teardown queued when the CLI exits, which trips a libuv assertion on Windows
  // ("!(handle->flags & UV_HANDLE_CLOSING)"). agent:false forces one socket per
  // request that is fully closed before the promise resolves.
  const httpMod = require('http');
  const httpsMod = require('https');
  const target = new URL(url);
  const mod = target.protocol === 'https:' ? httpsMod : httpMod;
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const req = mod.request(target, {
      method: opts.method || 'GET',
      agent: false,
      timeout: opts.timeoutMs || DEFAULT_TIMEOUT,
      headers: Object.assign({ 'user-agent': UA, accept: '*/*', connection: 'close' }, opts.headers || {}),
    }, (res) => {
      const chunks = [];
      let size = 0;
      const cap = opts.readBody === false ? 0 : (opts.maxBody || MAX_BODY);
      res.on('data', (chunk) => {
        size += chunk.length;
        if (cap && size <= cap) chunks.push(chunk);
      });
      res.on('end', () => {
        const headers = new Headers();
        for (const [key, value] of Object.entries(res.headers || {})) {
          if (Array.isArray(value)) for (const v of value) headers.append(key, v);
          else if (value !== undefined) headers.append(key, value);
        }
        resolve({
          status: res.statusCode,
          headers,
          location: res.headers.location || '',
          body: Buffer.concat(chunks).toString('utf8'),
          ms: Date.now() - started,
        });
      });
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('request timed out')));
    req.on('error', reject);
    req.end();
  });
}

function checkHttpRedirect(baseUrl, httpResult) {
  const findings = [];
  if (baseUrl.protocol !== 'http:') return findings;
  const loc = httpResult.location || '';
  const setsHttps = httpResult.status >= 300 && httpResult.status < 400 && /^https:/i.test(loc);
  if (!setsHttps) {
    findings.push(finding(
      'web.no-https-redirect', 'medium',
      'HTTP does not redirect to HTTPS',
      `http:// responds with status ${httpResult.status}${loc ? ` to ${loc}` : ' and no Location'} — traffic to this host can be intercepted or downgraded.`,
      'Redirect all http:// traffic to https:// with a 301 and enable HSTS.',
      baseUrl.href, `HTTP ${httpResult.status}`,
    ));
  }
  return findings;
}

function checkCors(baseUrl, res) {
  const findings = [];
  const acao = res.headers.get('access-control-allow-origin') || '';
  const acac = (res.headers.get('access-control-allow-credentials') || '').toLowerCase() === 'true';
  if (acao === '*' && acac) {
    findings.push(finding(
      'web.cors-wildcard-credentials', 'high',
      'CORS allows any origin with credentials',
      'Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true — a browser will not send credentials to *, but misconfigured proxies/frameworks often reflect origins next; this is a rejected combination that signals a broken or unsafe CORS policy.',
      "Never combine '*' with credentials; echo only an explicit allowlist of origins.",
      baseUrl.href, `ACAO: ${acao}, ACAC: ${acac}`,
    ));
  }
  return findings;
}

function checkMethods(baseUrl, res) {
  const findings = [];
  const allow = (res.headers.get('allow') || '').toUpperCase();
  if (/\bTRACE\b/.test(allow)) {
    findings.push(finding(
      'web.trace-enabled', 'medium',
      'TRACE method advertised',
      'The Allow header lists TRACE — cross-site tracing can leak credentials/cookies in some proxy setups.',
      'Disable the TRACE method at the server/proxy.',
      baseUrl.href, `Allow: ${allow}`,
    ));
  }
  return findings;
}

function checkSameSite(baseUrl, res) {
  const findings = [];
  const setCookie = res.headers.getSetCookie ? res.headers.getSetCookie() : (res.headers.get('set-cookie') ? [res.headers.get('set-cookie')] : []);
  for (const cookie of setCookie) {
    const name = (cookie.split('=')[0] || 'cookie').trim();
    if (/;\s*(?:secure|httponly)/i.test(cookie) === false) continue; // handled by urlscan.analyzeHeaders
    if (!/;\s*samesite=/i.test(cookie)) {
      findings.push(finding(
        'web.cookie-no-samesite', 'low',
        'Cookie without SameSite',
        `Cookie "${name}" sets no SameSite attribute — modern browsers default to Lax, but older clients may attach it cross-site.`,
        `Add SameSite=Lax (or Strict for auth cookies) to "${name}".`,
        baseUrl.href, cookie.slice(0, 80),
      ));
    }
  }
  return findings;
}

// Paths that must never be web-reachable. Each probe only counts when the body
// carries that file's own signature — a generic 200 or a custom 404 page is not
// treated as exposure.
const FILE_PROBES = [
  { path: '/.env', rule: 'web.exposed-env', severity: 'critical', title: '.env file exposed',
    test: (b) => /(?:^|\n)\s*[A-Z][A-Z0-9_]{2,}=/m.test(b) && !/<html/i.test(b.slice(0, 400)),
    why: 'Environment files carry database/Stripe/OpenAI credentials.' },
  { path: '/.git/config', rule: 'web.exposed-git', severity: 'critical', title: '.git/config exposed',
    test: (b) => /\[core\]/.test(b) && /repositoryformatversion/i.test(b),
    why: 'Exposed .git lets an attacker reconstruct the whole source history.' },
  { path: '/.DS_Store', rule: 'web.exposed-dsstore', severity: 'low', title: '.DS_Store exposed',
    test: (b) => b.includes('Bud1'),
    why: '.DS_Store leaks directory/file names.' },
  { path: '/server-status', rule: 'web.exposed-server-status', severity: 'medium', title: 'Apache server-status exposed',
    test: (b) => /Apache Server Status/i.test(b),
    why: 'Reveals live requests, client IPs and internal URLs.' },
  { path: '/phpinfo.php', rule: 'web.exposed-phpinfo', severity: 'high', title: 'phpinfo() exposed',
    test: (b) => /PHP Version/i.test(b) && /php\.ini/i.test(b),
    why: 'Reveals PHP version, modules, paths and environment variables.' },
  { path: '/actuator/env', rule: 'web.exposed-actuator', severity: 'high', title: 'Spring actuator /env exposed',
    test: (b) => /"propertySources"|"activeProfiles"/.test(b),
    why: 'Actuator /env can expose secrets and connection strings.' },
  { path: '/debug/vars', rule: 'web.exposed-debug-vars', severity: 'medium', title: 'Go expvar /debug/vars exposed',
    test: (b) => /"cmdline"|"memstats"/.test(b),
    why: 'Exposes runtime internals and build command lines.' },
];

async function checkExposedFiles(baseUrl, opts) {
  const findings = [];
  for (const probe of FILE_PROBES) {
    if (opts.budget.requests >= opts.budget.maxRequests) break;
    const target = new URL(probe.path, baseUrl.origin).href;
    let res;
    try {
      opts.budget.requests++;
      res = await request(target, { timeoutMs: opts.timeoutMs, maxBody: 16 * 1024 });
    } catch {
      continue;
    }
    if (res.status !== 200) continue;
    if (!probe.test(res.body)) continue;
    findings.push(finding(
      probe.rule, probe.severity, probe.title,
      `${target} returned HTTP 200 with ${probe.title.replace(/^\./, 'the expected ')} signature. ${probe.why}`,
      `Block ${probe.path} at the server/proxy and remove it from the deploy artifact.`,
      target, `HTTP 200, ${res.body.length} bytes`,
    ));
  }
  return findings;
}

async function checkDirectoryListing(baseUrl, opts) {
  const findings = [];
  for (const dir of ['/', '/uploads/', '/static/']) {
    if (opts.budget.requests >= opts.budget.maxRequests) break;
    const target = new URL(dir, baseUrl.origin).href;
    let res;
    try {
      opts.budget.requests++;
      res = await request(target, { timeoutMs: opts.timeoutMs, maxBody: 32 * 1024 });
    } catch {
      continue;
    }
    if (res.status === 200 && /<title>\s*Index of\s*\//i.test(res.body) && /<a href="[^"]+">/i.test(res.body)) {
      findings.push(finding(
        'web.directory-listing', 'medium',
        'Directory listing enabled',
        `${target} serves an auto-generated "Index of" page — directory contents are enumerable.`,
        'Disable autoindex / directory listing in the server config.',
        target, 'Index of /',
      ));
      break;
    }
  }
  return findings;
}

const ERROR_SIGNATURES = [
  { re: /at\s+\w+\s+\([^)]*:\d+:\d+\)/, name: 'Node.js/Express stack trace' },
  { re: /Traceback \(most recent call last\)/, name: 'Python traceback' },
  { re: /(?:ActionController|ActiveRecord)::\w+/, name: 'Rails exception page' },
  { re: /System\.(?:NullReferenceException|InvalidOperationException)/, name: '.NET exception' },
  { re: /<b>Fatal error<\/b>:\s*Uncaught/i, name: 'PHP fatal error' },
];

async function checkErrorLeak(baseUrl, opts) {
  if (opts.budget.requests >= opts.budget.maxRequests) return [];
  const target = new URL(`/vibeguard-probe-${Math.random().toString(36).slice(2, 10)}`, baseUrl.origin).href;
  let res;
  try {
    opts.budget.requests++;
    res = await request(target, { timeoutMs: opts.timeoutMs, maxBody: 32 * 1024 });
  } catch {
    return [];
  }
  for (const sig of ERROR_SIGNATURES) {
    if (sig.re.test(res.body)) {
      return [finding(
        'web.stack-trace-leak', 'high',
        'Error page leaks a stack trace',
        `404 responses render a ${sig.name}. Stack traces disclose file paths, framework versions and internal call structure.`,
        'Serve a generic error page in production and log details server-side.',
        target, `HTTP ${res.status}: ${sig.name}`,
      )];
    }
  }
  return [];
}

function checkTls(baseUrl, opts) {
  if (baseUrl.protocol !== 'https:') return Promise.resolve([]);
  return new Promise((resolve) => {
    const findings = [];
    let settled = false;
    const done = () => { if (!settled) { settled = true; resolve(findings); } };
    let socket;
    try {
      socket = tls.connect({
        host: baseUrl.hostname,
        port: Number(baseUrl.port || 443),
        servername: baseUrl.hostname,
        rejectUnauthorized: false,
        timeout: opts.timeoutMs,
      }, () => {
        const cert = socket.getPeerCertificate() || {};
        const protocol = socket.getProtocol() || '';
        if (/TLSv1(?:\.[01])?$/.test(protocol)) {
          findings.push(finding('web.tls-legacy', 'high', 'Legacy TLS version negotiated',
            `${baseUrl.hostname} negotiated ${protocol} — deprecated and attackable.`,
            'Require TLS 1.2+ (prefer 1.3) and remove legacy protocol support.', baseUrl.href, protocol));
        }
        if (cert.valid_to) {
          const days = Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86400000);
          if (days < 0) {
            findings.push(finding('web.tls-expired', 'critical', 'TLS certificate expired',
              `Certificate for ${baseUrl.hostname} expired ${Math.abs(days)} day(s) ago.`,
              'Renew the certificate and automate renewal.', baseUrl.href, `expired ${cert.valid_to}`));
          } else if (days < 14) {
            findings.push(finding('web.tls-expiring', 'medium', 'TLS certificate expiring soon',
              `Certificate for ${baseUrl.hostname} expires in ${days} day(s) — an expired cert breaks the site and trains users to click through warnings.`,
              'Renew now; automate renewal and monitor expiry.', baseUrl.href, `expires ${cert.valid_to}`));
          }
        }
        socket.end();
        done();
      });
      socket.on('error', done);
      socket.on('timeout', () => { socket.destroy(); done(); });
      setTimeout(() => { try { socket.destroy(); } catch { /* already closed */ } done(); }, opts.timeoutMs || DEFAULT_TIMEOUT);
    } catch {
      done();
    }
  });
}

async function scanWeb(rawTarget, opts = {}) {
  const started = Date.now();
  const base = await assertSafeTarget(rawTarget, opts);
  const budget = { requests: 0, maxRequests: Number(opts.maxRequests || DEFAULT_MAX_REQUESTS) };
  const ctx = { allowPrivate: !!opts.allowPrivate, timeoutMs: opts.timeoutMs || DEFAULT_TIMEOUT, budget };
  const findings = [];
  const checks = {};

  const root = await request(base.href, { timeoutMs: ctx.timeoutMs, maxBody: MAX_BODY });
  budget.requests++;
  findings.push(...analyzeHeaders(base.href, root.status, root.headers));
  findings.push(...checkCors(base, root));
  findings.push(...checkMethods(base, root));
  findings.push(...checkSameSite(base, root));
  checks.headers = true;

  if (base.protocol === 'http:') {
    findings.push(...checkHttpRedirect(base, root));
    checks.httpsRedirect = true;
  }
  if (base.protocol === 'https:') {
    try {
      const httpTarget = new URL(base.href);
      httpTarget.protocol = 'http:';
      if (budget.requests < budget.maxRequests) {
        budget.requests++;
        const httpRes = await request(httpTarget.href, { timeoutMs: ctx.timeoutMs, readBody: false });
        findings.push(...checkHttpRedirect(httpTarget, httpRes));
        checks.httpsRedirect = true;
      }
    } catch { /* http leg is best-effort */ }
    findings.push(...await checkTls(base, ctx));
    checks.tls = true;
  }

  try {
    findings.push(...await checkExposedFiles(base, ctx));
    checks.exposedFiles = FILE_PROBES.length;
  } catch { /* a probe failure must not abort the scan */ }
  try {
    findings.push(...await checkDirectoryListing(base, ctx));
    findings.push(...await checkErrorLeak(base, ctx));
    checks.probes = true;
  } catch { /* best-effort */ }

  return {
    root: base.href,
    findings,
    requests: budget.requests,
    durationMs: Date.now() - started,
    checks,
  };
}

module.exports = { scanWeb, FILE_PROBES, assertSafeTarget, isPrivateAddress };
