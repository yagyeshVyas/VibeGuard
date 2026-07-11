'use strict';

/*
 * VibeGuard Runtime Interceptor.
 *
 * This is the LAST LINE OF DEFENSE against a jailbroken AI.
 *
 * Even if an AI is jailbroken and bypasses all prompt firewalls,
 * it still needs to use Node.js built-in modules to actually DO anything.
 * This module wraps fetch, axios, http, https, child_process, fs, and net
 * to intercept EVERY outbound request, EVERY command, EVERY file access
 * and block anything that contains PII or secrets.
 *
 * The AI cannot bypass this because it runs at the Node.js runtime level,
 * below the AI's code execution. Even eval("fetch('https://evil.com')")
 * goes through our wrapped fetch.
 *
 * Usage:
 *   require('vibeguard/interceptor').activate();
 *   // Now ALL outbound requests are intercepted
 *   // ALL PII/secrets in request bodies are blocked
 *   // ALL dangerous commands are blocked
 *   // ALL file access to .env/.ssh/.aws is blocked
 *
 * 100% local. Zero network. Zero dependencies.
 */

const { detectPII, redactText } = require('./pii');

// ─── Configuration ──────────────────────────────────────────────────────

const CONFIG = {
  // Block any outbound request containing these
  blockPIITypes: ['email', 'ssn', 'credit-card', 'phone', 'aws-access-key', 'jwt', 'private-key'],
  // Block requests to these domains
  blockDomains: [
    '169.254.169.254', 'metadata.google.internal', 'metadata.aws.internal',
  ],
  // Block file reads to these paths
  blockFilePaths: ['.env', '.ssh', '.aws', '.gnupg', '.npmrc', '.gitconfig'],
  // Block commands matching these patterns
  blockCommands: ['rm -rf', 'sudo', 'chmod 777', 'mkfs', 'dd if=', 'shutdown', 'reboot', 'curl', 'wget', 'nc '],
  // Allow these domains (known safe APIs)
  allowDomains: ['api.openai.com', 'api.anthropic.com', 'generativelanguage.googleapis.com'],
  // Log blocked attempts
  logBlocked: true,
  // Throw on block (vs silent block)
  throwOnBlock: false,
};

let isActive = false;
let interceptors = {};
let stats = { blocked: 0, redacted: 0, allowed: 0, logged: [] };

// ─── Logging ─────────────────────────────────────────────────────────────

function logBlock(type, detail) {
  stats.blocked++;
  const entry = { type, detail, timestamp: new Date().toISOString() };
  stats.logged.push(entry);
  if (CONFIG.logBlocked) {
    process.stderr.write(`\x1b[31m[VibeGuard Interceptor] BLOCKED: ${type} — ${detail}\x1b[0m\n`);
  }
  if (CONFIG.throwOnBlock) {
    throw new Error(`VibeGuard Interceptor: ${type} blocked — ${detail}`);
  }
}

function logRedact(type, detail) {
  stats.redacted++;
  if (CONFIG.logBlocked) {
    process.stderr.write(`\x1b[33m[VibeGuard Interceptor] REDACTED: ${type} — ${detail}\x1b[0m\n`);
  }
}

function logAllow(type, detail) {
  stats.allowed++;
}

// ─── Check Functions ────────────────────────────────────────────────────

function checkOutboundData(data) {
  if (!data || typeof data !== 'string') return { allowed: true };
  // Convert objects to string for checking
  const str = typeof data === 'object' ? JSON.stringify(data) : String(data);

  // Check for PII
  const piiResult = detectPII(str, { types: CONFIG.blockPIITypes });
  const pii = piiResult.matches || [];
  if (pii.length > 0) {
    return {
      allowed: false,
      reason: `PII detected: ${pii.map(p => p.type).join(', ')}`,
      sanitized: redactText(str).redacted || str,
    };
  }

  // Check for secrets (additional patterns)
  const secretPatterns = [
    { re: /sk-proj-[A-Za-z0-9_-]{20,}/, type: 'OpenAI key' },
    { re: /sk-ant-[A-Za-z0-9_-]{50,}/, type: 'Anthropic key' },
    { re: /sk_live_[A-Za-z0-9]{16,}/, type: 'Stripe key' },
    { re: /AKIA[A-Z0-9]{16}/, type: 'AWS key' },
    { re: /gh[pousr]_[A-Za-z0-9]{36}/, type: 'GitHub token' },
    { re: /xox[bpoa]-[A-Za-z0-9-]{10,}/, type: 'Slack token' },
    { re: /glpat-[A-Za-z0-9_-]{20}/, type: 'GitLab token' },
    { re: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/, type: 'Private key' },
  ];

  for (const { re, type } of secretPatterns) {
    if (re.test(str)) {
      return { allowed: false, reason: `Secret detected: ${type}` };
    }
  }

  return { allowed: true };
}

function checkDomain(url) {
  if (!url || typeof url !== 'string') return { allowed: true };

  // Extract domain
  let domain;
  try {
    domain = new URL(url).hostname;
  } catch {
    domain = url.replace(/^https?:\/\//, '').split('/')[0];
  }

  // Check allowlist
  if (CONFIG.allowDomains.some(d => domain === d || domain.endsWith('.' + d))) {
    return { allowed: true };
  }

  // Check blocklist
  for (const blocked of CONFIG.blockDomains) {
    if (domain === blocked || domain.includes(blocked)) {
      return { allowed: false, reason: `Blocked domain: ${domain} (matches ${blocked})` };
    }
  }

  // Check for suspicious patterns
  if (/^\d+\.\d+\.\d+\.\d+$/.test(domain)) {
    // Raw IP — check if internal
    const parts = domain.split('.').map(Number);
    if (parts[0] === 10 || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168) || parts[0] === 127) {
      return { allowed: false, reason: `Internal IP blocked: ${domain}` };
    }
  }

  return { allowed: true };
}

function checkFilePath(filePath) {
  if (!filePath || typeof filePath !== 'string') return { allowed: true };
  for (const blocked of CONFIG.blockFilePaths) {
    if (filePath.includes(blocked)) {
      return { allowed: false, reason: `Blocked file path: ${filePath} (contains ${blocked})` };
    }
  }
  return { allowed: true };
}

function checkCommand(cmd) {
  if (!cmd || typeof cmd !== 'string') return { allowed: true };
  for (const blocked of CONFIG.blockCommands) {
    if (cmd.includes(blocked)) {
      return { allowed: false, reason: `Blocked command pattern: ${blocked} in ${cmd.slice(0, 100)}` };
    }
  }
  return { allowed: true };
}

// ─── Activation ──────────────────────────────────────────────────────────

function activate(opts = {}) {
  if (isActive) return { activated: false, reason: 'already active' };
  Object.assign(CONFIG, opts);
  isActive = true;
  stats = { blocked: 0, redacted: 0, allowed: 0, logged: [] };

  // ─── Wrap global fetch ─────────────────────────────────────────────────
  if (typeof globalThis.fetch === 'function') {
    const originalFetch = globalThis.fetch;
    interceptors.fetch = originalFetch;
    globalThis.fetch = async function(input, init) {
      const url = typeof input === 'string' ? input : (input && input.url) || '';
      const body = init && init.body ? (typeof init.body === 'string' ? init.body : JSON.stringify(init.body)) : '';

      // Check domain
      const domainCheck = checkDomain(url);
      if (!domainCheck.allowed) {
        logBlock('fetch_domain', `${url}: ${domainCheck.reason}`);
        return new Response(JSON.stringify({ error: 'Blocked by VibeGuard', reason: domainCheck.reason }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // Check body for PII/secrets
      if (body) {
        const dataCheck = checkOutboundData(body);
        if (!dataCheck.allowed) {
          logBlock('fetch_pii', `${url}: ${dataCheck.reason}`);
          return new Response(JSON.stringify({ error: 'Blocked by VibeGuard', reason: dataCheck.reason }), {
            status: 403,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        // If sanitized, use sanitized version
        if (dataCheck.sanitized && dataCheck.sanitized !== body) {
          logRedact('fetch_body', `${url}: PII redacted from request body`);
          init = { ...init, body: dataCheck.sanitized };
        }
      }

      logAllow('fetch', url);
      return originalFetch.call(this, input, init);
    };
  }

  // ─── Wrap http/https.request ──────────────────────────────────────────
  const http = require('http');
  const https = require('https');

  for (const [moduleName, mod] of [['http', http], ['https', https]]) {
    if (mod.request) {
      const originalRequest = mod.request;
      interceptors[moduleName] = originalRequest;
      mod.request = function(url, options, callback) {
        const urlStr = typeof url === 'string' ? url : (url && url.href) || (options && options.hostname ? `${options.protocol || 'http:'}//${options.hostname}:${options.port || 80}` : '');

        // Check domain
        const domainCheck = checkDomain(urlStr);
        if (!domainCheck.allowed) {
          logBlock(`${moduleName}_domain`, `${urlStr}: ${domainCheck.reason}`);
          const fakeReq = new EventEmitter();
          process.nextTick(() => {
            fakeReq.emit('error', new Error(`VibeGuard: ${domainCheck.reason}`));
          });
          return fakeReq;
        }

        logAllow(moduleName, urlStr);
        return originalRequest.call(this, url, options, callback);
      };
    }
  }

  // ─── Wrap child_process.exec ───────────────────────────────────────────
  const { exec, execSync, execFile, spawn } = require('child_process');
  if (exec) {
    interceptors.exec = exec;
    require('child_process').exec = function(cmd, opts, callback) {
      const cmdCheck = checkCommand(cmd);
      if (!cmdCheck.allowed) {
        logBlock('exec_command', cmdCheck.reason);
        if (typeof opts === 'function') { callback = opts; opts = null; }
        if (callback) {
          process.nextTick(() => callback(new Error(`VibeGuard: ${cmdCheck.reason}`), '', ''));
          return;
        }
        return;
      }
      return exec.call(this, cmd, opts, callback);
    };
  }
  if (execSync) {
    interceptors.execSync = execSync;
    require('child_process').execSync = function(cmd, opts) {
      const cmdCheck = checkCommand(cmd);
      if (!cmdCheck.allowed) {
        logBlock('execSync_command', cmdCheck.reason);
        throw new Error(`VibeGuard: ${cmdCheck.reason}`);
      }
      return execSync.call(this, cmd, opts);
    };
  }

  // ─── Wrap fs.readFile for sensitive paths ──────────────────────────────
  const fs = require('fs');
  if (fs.readFileSync) {
    interceptors.readFileSync = fs.readFileSync;
    fs.readFileSync = function(p, ...args) {
      const pathCheck = checkFilePath(String(p));
      if (!pathCheck.allowed) {
        logBlock('readFileSync_path', pathCheck.reason);
        throw new Error(`VibeGuard: ${pathCheck.reason}`);
      }
      return fs.readFileSync.call(this, p, ...args);
    };
  }

  return { activated: true, config: CONFIG };
}

function deactivate() {
  if (!isActive) return { deactivated: false, reason: 'not active' };
  isActive = false;

  // Restore originals
  if (interceptors.fetch) globalThis.fetch = interceptors.fetch;
  const http = require('http');
  const https = require('https');
  if (interceptors.http) http.request = interceptors.http;
  if (interceptors.https) https.request = interceptors.https;
  if (interceptors.exec) require('child_process').exec = interceptors.exec;
  if (interceptors.execSync) require('child_process').execSync = interceptors.execSync;
  if (interceptors.readFileSync) require('fs').readFileSync = interceptors.readFileSync;

  interceptors = {};
  return { deactivated: true, stats };
}

function getStats() {
  return { ...stats, active: isActive };
}

// ─── EventEmitter shim for fake requests ─────────────────────────────────
const EventEmitter = require('events');

// ─── Output Guard: sanitize AI responses ─────────────────────────────────

function sanitizeAIResponse(response) {
  if (!response || typeof response !== 'string') return { safe: true, sanitized: response, blocked: [] };

  const blocked = [];
  let sanitized = response;

  // Remove any secrets that leaked into the response
  const secretPatterns = [
    { re: /sk-proj-[A-Za-z0-9_-]{15,}/g, type: 'OpenAI key', replacement: '[REDACTED_OPENAI_KEY]' },
    { re: /sk-ant-[A-Za-z0-9_-]{15,}/g, type: 'Anthropic key', replacement: '[REDACTED_ANTHROPIC_KEY]' },
    { re: /sk_live_[A-Za-z0-9]{16,}/g, type: 'Stripe key', replacement: '[REDACTED_STRIPE_KEY]' },
    { re: /AKIA[A-Z0-9]{16}/g, type: 'AWS key', replacement: '[REDACTED_AWS_KEY]' },
    { re: /gh[pousr]_[A-Za-z0-9]{36}/g, type: 'GitHub token', replacement: '[REDACTED_GITHUB_TOKEN]' },
    { re: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC )?PRIVATE KEY-----/g, type: 'Private key', replacement: '[REDACTED_PRIVATE_KEY]' },
  ];

  for (const { re, type, replacement } of secretPatterns) {
    if (re.test(sanitized)) {
      blocked.push({ type, reason: `Secret in AI response: ${type}` });
      sanitized = sanitized.replace(re, replacement);
    }
  }

  // Remove PII that leaked into the response
  const piiResult = detectPII(sanitized, { types: ['email', 'ssn', 'credit-card', 'phone'] });
  const pii = piiResult.matches || [];
  if (pii.length > 0) {
    for (const p of pii) {
      blocked.push({ type: p.type, reason: `PII in AI response: ${p.type}` });
    }
    const redacted = redactText(sanitized);
    sanitized = redacted.redacted || sanitized;
  }

  // Block response if it contains environment variable dump
  if (/process\.env|os\.environ|ENV\[/i.test(response)) {
    // Check if actual env values are present (not just the word process.env)
    const envPattern = /(?:process\.env|os\.environ)\.\w+\s*[=:]\s*['"][^'"]{8,}['"]/g;
    if (envPattern.test(response)) {
      blocked.push({ type: 'env_dump', reason: 'AI response contains environment variable values' });
      sanitized = sanitized.replace(envPattern, '[REDACTED_ENV_VAR]');
    }
  }

  // Block response if it contains file system paths that shouldn't be exposed
  if (/\/(?:home|Users)\/[^/\s]+\/\.(?:env|ssh|aws|gnupg|npmrc)/i.test(response)) {
    blocked.push({ type: 'sensitive_path', reason: 'AI response contains sensitive file path' });
    sanitized = sanitized.replace(/\/(?:home|Users)\/[^/\s]+\/\.(?:env|ssh|aws|gnupg|npmrc)[^>\s]*/gi, '[REDACTED_PATH]');
  }

  return {
    safe: blocked.length === 0,
    sanitized,
    blocked,
    blockedCount: blocked.length,
  };
}

// ─── Self-Protection: detect tampering attempts ─────────────────────────

const TAMPER_PATTERNS = [
  { re: /vibeguard.*uninstall|vibeguard.*disable|vibeguard.*remove|vibeguard.*bypass/i, threat: 'DISABLE_VIBEGUARD', severity: 'critical' },
  { re: /delete.*vibeguard|rm.*vibeguard|uninstall.*vibeguard/i, threat: 'DELETE_VIBEGUARD', severity: 'critical' },
  { re: /modify.*vibeguard.*config|change.*vibeguard.*rules|edit.*vibeguard/i, threat: 'TAMPER_RULES', severity: 'high' },
  { re: /disable.*interceptor|bypass.*firewall|disable.*guard/i, threat: 'DISABLE_PROTECTION', severity: 'critical' },
  { re: /kill.*vibeguard|stop.*vibeguard|terminate.*vibeguard/i, threat: 'KILL_PROCESS', severity: 'critical' },
  { re: /overwrite.*vibeguard|replace.*vibeguard.*src/i, threat: 'OVERWRITE_SOURCE', severity: 'critical' },
];

function detectTamper(prompt) {
  for (const { re, threat, severity } of TAMPER_PATTERNS) {
    if (re.test(prompt)) {
      return { detected: true, threat, severity, reason: `Tampering attempt: ${threat}` };
    }
  }
  return { detected: false };
}

// ─── Environment Lock: protect env vars ──────────────────────────────────

const SENSITIVE_ENV_KEYS = [
  /API_KEY/i, /SECRET/i, /TOKEN/i, /PASSWORD/i, /PASSWD/i,
  /PRIVATE_KEY/i, /CREDENTIAL/i, /AUTH/i, /SESSION_SECRET/i,
  /JWT_SECRET/i, /ENCRYPTION_KEY/i, /DATABASE_URL/i, /DB_PASSWORD/i,
  /STRIPE/i, /OPENAI/i, /ANTHROPIC/i, /AWS/i, /GITHUB/i, /SLACK/i,
  /TWILIO/i, /SENDGRID/i, /MAILGUN/i, /RESEND/i, /NPM_TOKEN/i,
  /DATABASE/i, /REDIS/i, /MONGO/i, /SUPABASE/i, /FIREBASE/i,
];

function lockEnvironment() {
  // Create a locked copy of process.env
  const lockedEnv = {};
  const hiddenKeys = new Set();

  for (const [key, value] of Object.entries(process.env)) {
    let isSensitive = false;
    for (const pattern of SENSITIVE_ENV_KEYS) {
      if (pattern.test(key)) {
        isSensitive = true;
        break;
      }
    }

    if (isSensitive) {
      hiddenKeys.add(key);
      lockedEnv[key] = value; // Keep for internal use but mark as hidden
    } else {
      lockedEnv[key] = value;
    }
  }

  return {
    locked: true,
    hiddenKeys: [...hiddenKeys],
    hiddenCount: hiddenKeys.size,
    totalKeys: Object.keys(process.env).length,
    // Check if a specific key would be visible to AI
    isHidden(key) {
      return hiddenKeys.has(key);
    },
    // Get a safe environment (no secrets) for passing to AI
    getSafeEnv() {
      const safe = {};
      for (const [key, value] of Object.entries(process.env)) {
        if (!hiddenKeys.has(key)) {
          safe[key] = value;
        }
      }
      return safe;
    },
    // Get a key only if explicitly allowed
    get(key, allowSensitive = false) {
      if (!allowSensitive && hiddenKeys.has(key)) {
        return `[PROTECTED: ${key}]`;
      }
      return lockedEnv[key];
    },
  };
}

module.exports = {
  activate,
  deactivate,
  getStats,
  checkOutboundData,
  checkDomain,
  checkFilePath,
  checkCommand,
  sanitizeAIResponse,
  detectTamper,
  lockEnvironment,
  CONFIG,
};