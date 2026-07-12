'use strict';

/*
 * VibeGuard AI Firewall.
 *
 * A real-time prompt firewall that analyzes AI requests BEFORE they are sent
 * to the LLM. It blocks, warns, or sanitizes requests that contain:
 * - Prompt injection attempts
 * - Requests for dangerous capabilities (file deletion, code execution, etc.)
 * - Attempts to access secrets or environment variables
 * - Attempts to bypass safety restrictions
 * - Data exfiltration patterns (sending PII to external endpoints)
 * - Jailbreak patterns
 *
 * This is a LOCAL firewall — it runs on your machine, between your AI client
 * and the LLM API. Zero network. Zero dependencies.
 *
 * Usage:
 *   const { inspectPrompt } = require('./firewall');
 *   const verdict = inspectPrompt(userPrompt, context);
 *   if (verdict.action === 'block') return 'Request blocked by VibeGuard Firewall';
 *   if (verdict.action === 'warn') console.warn(verdict.reason);
 *   // proceed with verdict.sanitizedPrompt
 */

const { detectPII, redactText } = require('./pii');

// Threat patterns — each is a category of attack
const THREATS = [
  // ─── Prompt Injection ──────────────────────────────────────────────
  {
    id: 'INJECT.IGNORE_INSTRUCTIONS',
    severity: 'critical',
    re: /(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|system|initial)\s+(?:instructions?|prompts?|rules?|guidelines?|directives?)/i,
    action: 'block',
    reason: 'Prompt injection: attempting to override system instructions',
    fix: 'This is a prompt injection attack. Do not process this request.',
  },
  {
    id: 'INJECT.NEW_ROLE',
    severity: 'critical',
    re: /(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|from\s+now\s+on|new\s+(?:instructions?|role|persona))/i,
    action: 'block',
    reason: 'Prompt injection: attempting to assign new role or instructions',
    fix: 'This request tries to override the AI role. Block it.',
  },
  {
    id: 'INJECT.REVEAL_SYSTEM',
    severity: 'high',
    re: /(?:show|reveal|display|print|output|dump|tell\s+me|what\s+(?:are|is))\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?|directives?|system\s+message|initial\s+message)/i,
    action: 'block',
    reason: 'Prompt extraction: attempting to reveal system prompt',
    fix: 'This request tries to extract the system prompt. Block it.',
  },
  {
    id: 'INJECT.ENCODED',
    severity: 'high',
    re: /(?:base64|atob|btoa|fromCharCode|String\.fromCharCode|\\x[0-9a-f]{2}|\\u[0-9a-f]{4})/i,
    action: 'warn',
    reason: 'Encoded payload in prompt — possible obfuscated injection',
    fix: 'Decode and inspect the payload before processing.',
  },
  {
    id: 'INJECT.MARKUP_INJECTION',
    severity: 'high',
    re: /<\s*(?:system|assistant|user|im_start|im_end|endoftext|tool|function)/i,
    action: 'block',
    reason: 'Markup injection: attempting to inject chat markup tags',
    fix: 'This request contains chat markup tags that could override message roles.',
  },

  // ─── Dangerous Capabilities ────────────────────────────────────────
  {
    id: 'CAP.DELETE_FILES',
    severity: 'critical',
    re: /(?:delete|remove|rm\s+-rf|unlink|shutil\.rmtree|rmdir|fs\.unlink)\s+(?:all\s+)?(?:files?|directories?|folders?|\.env|secrets?|config)/i,
    action: 'block',
    reason: 'Dangerous request: asking AI to delete files or directories',
    fix: 'Do not allow AI to delete files. This is destructive.',
  },
  {
    id: 'CAP.EXEC_CODE',
    severity: 'high',
    re: /(?:execute|run|eval|exec)\s+(?:this\s+)?(?:code|script|command|bash|shell|python|node)/i,
    action: 'warn',
    reason: 'Code execution request — verify this is intended',
    fix: 'Only allow code execution in a sandboxed environment.',
  },
  {
    id: 'CAP.INSTALL_PACKAGES',
    severity: 'high',
    re: /(?:install|npm\s+install|pip\s+install|yarn\s+add|apt\s+install|brew\s+install)\s+/i,
    action: 'warn',
    reason: 'Package installation request — supply chain risk',
    fix: 'Verify package name against typosquat and slopsquat databases before installing.',
  },
  {
    id: 'CAP.ACCESS_SECRETS',
    severity: 'critical',
    re: /(?:show|read|display|output|print|get|access|fetch|tell\s+me)\s+(?:me\s+)?(?:my\s+|the\s+|all\s+)?(?:secrets?|\.env|environment\s+variables?|API\s+keys?|tokens?|passwords?|credentials?|private\s+keys?)/i,
    action: 'block',
    reason: 'Secret access request: asking AI to reveal secrets or env vars',
    fix: 'Never allow AI to access or reveal secrets. This is a data breach risk.',
  },
  {
    id: 'CAP.NETWORK_REQUEST',
    severity: 'high',
    re: /(?:fetch|curl|wget|http\.get|axios|request)\s+(?:https?:)?\/\//i,
    action: 'warn',
    reason: 'Network request in prompt — possible SSRF or data exfiltration',
    fix: 'Verify the target URL. Block internal IPs and metadata services.',
  },
  {
    id: 'CAP.MODIFY_AUTH',
    severity: 'critical',
    re: /(?:change|modify|reset|bypass|disable|remove)\s+(?:the\s+)?(?:authentication|authorization|password|login|security|2fa|mfa|guard|middleware)/i,
    action: 'block',
    reason: 'Auth modification request: asking AI to disable or bypass security',
    fix: 'Never allow AI to modify authentication or security controls.',
  },
  {
    id: 'CAP.DATABASE_DROP',
    severity: 'critical',
    re: /(?:drop|truncate|delete\s+from|wipe|clear)\s+(?:table|database|collection|all\s+data|production)/i,
    action: 'block',
    reason: 'Database destruction request: asking AI to drop/truncate tables',
    fix: 'Never allow AI to drop tables or delete all data.',
  },
  {
    id: 'CAP.PRIVILEGE_ESCALATION',
    severity: 'critical',
    re: /(?:sudo|su\s+root|chmod\s+777|chown|admin\s+access|root\s+access|elevate|privilege\s+escalat)/i,
    action: 'block',
    reason: 'Privilege escalation request',
    fix: 'Never allow AI to escalate privileges.',
  },

  // ─── Jailbreak Patterns ────────────────────────────────────────────
  {
    id: 'JAILBREAK.DAN',
    severity: 'high',
    re: /DAN|do\s+anything\s+now|jailbreak|developer\s+mode|unrestricted\s+mode|god\s+mode/i,
    action: 'block',
    reason: 'Jailbreak attempt: DAN or similar jailbreak pattern',
    fix: 'This is a known jailbreak pattern. Block it.',
  },
  {
    id: 'JAILBREAK.HYPOTHETICAL',
    severity: 'medium',
    re: /(?:hypothetically|imagine|suppose|let'?s\s+pretend|in\s+a\s+fictional\s+world|for\s+educational\s+purposes?\s+only|theoretically)/i,
    action: 'warn',
    reason: 'Hypothetical framing — common jailbreak technique',
    fix: 'Be cautious. Hypothetical framing is often used to bypass safety restrictions.',
  },
  {
    id: 'JAILBREAK.ROLEPLAY',
    severity: 'medium',
    re: /(?:roleplay|role.?play|act\s+out|pretend\s+you\s+are\s+(?:a\s+)?(?:hacker|attacker|malicious|unrestricted))/i,
    action: 'warn',
    reason: 'Roleplay framing — possible jailbreak attempt',
    fix: 'Be cautious. Roleplay framing can be used to bypass safety restrictions.',
  },
  {
    id: 'JAILBREAK.TRANSITION',
    severity: 'high',
    re: /(?:now\s+that\s+we\s+(?:have|had)|switching\s+(?:to|gears)|moving\s+on\s+to|let'?s\s+(?:try|move|switch)\s+(?:to|something|a\s+different))/i,
    action: 'warn',
    reason: 'Topic transition — possible bait-and-switch jailbreak',
    fix: 'Verify the new topic is not an attempt to bypass previous safety constraints.',
  },

  // ─── Data Exfiltration ─────────────────────────────────────────────
  {
    id: 'EXFIL.SEND_DATA',
    severity: 'critical',
    re: /(?:send|post|upload|transmit|exfiltrate|webhook|callback)\s+(?:the\s+)?(?:data|file|content|user\s+data|database|secrets?|tokens?)/i,
    action: 'block',
    reason: 'Data exfiltration: requesting AI to send data externally',
    fix: 'Block this request. AI should never send user data to external endpoints.',
  },
  {
    id: 'EXFIL.SEND_TO_URL',
    severity: 'critical',
    re: /(?:send|post|upload)\s+(?:to|at|via)\s+(?:https?:)?\/\/[^.\s]+\.[^.\s]+/i,
    action: 'block',
    reason: 'Data exfiltration: specifying external URL to send data to',
    fix: 'Block this request. This is data exfiltration to an external server.',
  },
  {
    id: 'EXFIL.BASE64_DATA',
    severity: 'high',
    re: /(?:base64\s+encode|btoa|encode)\s+(?:the\s+)?(?:data|file|secrets?|\.env|tokens?|passwords?)/i,
    action: 'block',
    reason: 'Data encoding for exfiltration: encoding secrets/data before sending',
    fix: 'Block this request. This is preparing data for exfiltration.',
  },

  // ─── PII in Prompt ─────────────────────────────────────────────────
  {
    id: 'PII.IN_PROMPT',
    severity: 'high',
    re: null, // handled specially with detectPII
    action: 'redact',
    reason: 'PII detected in prompt — redacting before sending to AI',
    fix: 'PII has been redacted. Review the redacted version before proceeding.',
  },
];

// Action levels: block > redact > warn > allow
const ACTION_PRIORITY = { block: 4, redact: 3, warn: 2, allow: 1 };

function inspectPrompt(prompt, context = {}) {
  const findings = [];
  let sanitizedPrompt = prompt;
  let maxAction = 'allow';

  for (const threat of THREATS) {
    // Handle PII specially
    if (threat.id === 'PII.IN_PROMPT') {
      const result = detectPII(prompt, { types: ['email', 'ssn', 'credit-card', 'phone'] });
      const detected = result.matches || result || [];
      if (detected.length > 0) {
        sanitizedPrompt = redactText(prompt).redacted || redactText(prompt);
        findings.push({
          threat: threat.id,
          severity: threat.severity,
          action: 'redact',
          reason: `PII detected (${detected.map(d => d.type).join(', ')}) — redacted before sending`,
          fix: threat.fix,
        });
        if (ACTION_PRIORITY.redact > ACTION_PRIORITY[maxAction]) maxAction = 'redact';
      }
      continue;
    }

    if (threat.re && threat.re.test(prompt)) {
      findings.push({
        threat: threat.id,
        severity: threat.severity,
        action: threat.action,
        reason: threat.reason,
        fix: threat.fix,
      });
      if (ACTION_PRIORITY[threat.action] > ACTION_PRIORITY[maxAction]) {
        maxAction = threat.action;
      }
    }
  }

  // If blocked, don't sanitize — return as-is with block verdict
  if (maxAction === 'block') {
    return {
      action: 'block',
      findings,
      sanitizedPrompt: null,
      reason: findings.find(f => f.action === 'block')?.reason || 'Request blocked by VibeGuard Firewall',
      threatCount: findings.length,
    };
  }

  // If redact, return sanitized prompt
  if (maxAction === 'redact') {
    return {
      action: 'redact',
      findings,
      sanitizedPrompt,
      reason: 'PII redacted from prompt',
      threatCount: findings.length,
    };
  }

  // If warn, return prompt with warnings
  if (maxAction === 'warn') {
    return {
      action: 'warn',
      findings,
      sanitizedPrompt: prompt,
      reason: `${findings.length} warning(s) — review before proceeding`,
      threatCount: findings.length,
    };
  }

  return {
    action: 'allow',
    findings: [],
    sanitizedPrompt: prompt,
    reason: 'No threats detected',
    threatCount: 0,
  };
}

// Agent Guard — constrains what an AI agent can do
const AGENT_CONSTRAINTS = {
  // File access
  allowedPaths: ['src/', 'test/', 'public/', 'static/'],
  blockedPaths: ['.env', '.env.*', '*.pem', '*.key', 'secrets/', '.aws/', '.ssh/', 'node_modules/', '.git/'],
  // Command patterns
  blockedCommands: ['rm -rf', 'sudo', 'chmod 777', 'curl', 'wget', 'nc ', 'netcat', 'mkfs', 'dd if=', 'shutdown', 'reboot'],
  // Network access
  blockedDomains: ['169.254.169.254', 'localhost', '127.0.0.1', '0.0.0.0'],
  // Resource limits
  maxFileSize: 10 * 1024 * 1024, // 10MB
  maxExecTime: 30000, // 30s
};

function checkAgentAction(action) {
  const violations = [];

  // Check file access
  if (action.type === 'file_read' || action.type === 'file_write' || action.type === 'file_delete') {
    const filePath = action.path || '';
    for (const blocked of AGENT_CONSTRAINTS.blockedPaths) {
      const re = new RegExp(blocked.replace(/\./g, '\\.').replace(/\*/g, '.*'));
      if (re.test(filePath)) {
        violations.push({
          type: 'blocked_path',
          severity: 'critical',
          message: `Agent attempting to access blocked path: ${filePath} (matches: ${blocked})`,
          action: 'block',
        });
      }
    }
  }

  // Check command execution
  if (action.type === 'exec') {
    const cmd = action.command || '';
    for (const blocked of AGENT_CONSTRAINTS.blockedCommands) {
      if (cmd.includes(blocked)) {
        violations.push({
          type: 'blocked_command',
          severity: 'critical',
          message: `Agent attempting to run blocked command: ${cmd} (contains: ${blocked})`,
          action: 'block',
        });
      }
    }
  }

  // Check network access
  if (action.type === 'network') {
    const url = action.url || '';
    for (const blocked of AGENT_CONSTRAINTS.blockedDomains) {
      if (url.includes(blocked)) {
        violations.push({
          type: 'blocked_domain',
          severity: 'critical',
          message: `Agent attempting to access blocked domain: ${url} (contains: ${blocked})`,
          action: 'block',
        });
      }
    }
  }

  return {
    allowed: violations.filter(v => v.action === 'block').length === 0,
    violations,
    constraints: AGENT_CONSTRAINTS,
  };
}

// Exfiltration Firewall — checks if outbound data contains PII/secrets
function checkExfiltration(data, destination) {
  const risks = [];

  // Check for PII in the data
  const piiResult = detectPII(data, { types: ['email', 'ssn', 'credit-card', 'phone', 'aws-access-key', 'jwt', 'private-key'] });
  const pii = piiResult.matches || piiResult || [];
  if (pii.length > 0) {
    risks.push({
      type: 'pii_in_data',
      severity: 'critical',
      message: `Outbound data contains PII: ${pii.map(p => p.type).join(', ')}`,
      action: 'block',
    });
  }

  // Check for secrets in the data
  const secretPatterns = [
    { re: /sk-proj-[A-Za-z0-9_-]{20,}/, type: 'OpenAI key' },
    { re: /sk-ant-[A-Za-z0-9_-]{50,}/, type: 'Anthropic key' },
    { re: /sk_live_[A-Za-z0-9]{16,}/, type: 'Stripe key' },
    { re: /AKIA[A-Z0-9]{16}/, type: 'AWS key' },
    { re: /gh[pousr]_[A-Za-z0-9]{36}/, type: 'GitHub token' },
    { re: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/, type: 'Private key' },
  ];
  for (const { re, type } of secretPatterns) {
    if (re.test(data)) {
      risks.push({
        type: 'secret_in_data',
        severity: 'critical',
        message: `Outbound data contains ${type}`,
        action: 'block',
      });
    }
  }

  // Check destination
  if (destination) {
    const blockedDestinations = ['169.254.169.254', 'metadata.google.internal'];
    for (const blocked of blockedDestinations) {
      if (destination.includes(blocked)) {
        risks.push({
          type: 'blocked_destination',
          severity: 'critical',
          message: `Data being sent to cloud metadata service: ${destination}`,
          action: 'block',
        });
      }
    }
  }

  return {
    allowed: risks.filter(r => r.action === 'block').length === 0,
    risks,
    sanitizedData: risks.some(r => r.type === 'pii_in_data') ? (redactText(data).redacted || redactText(data)) : data,
  };
}

// Dependency Firewall — checks package names before npm install
const MALICIOUS_PACKAGE_PATTERNS = [
  { re: /(?:cryptominer|xmrig|coinhive|crypto-?loot)/i, reason: 'Known crypto miner package' },
  { re: /(?:stealer|exfil|backdoor|trojan|keylog|botnet|ratware)/i, reason: 'Malware package name' },
  { re: /(?:hack|crack|pirate|warez|serial|keygen)/i, reason: 'Piracy tool package' },
];

const TYPOSQUAT_MAP = {
  'reactt': 'react', 'reacct': 'react', 'lodahs': 'lodash', 'loadash': 'lodash',
  'expres': 'express', 'exress': 'express', 'axioss': 'axios',
  'mognoose': 'mongoose', 'mongose': 'mongoose', 'moongose': 'mongoose',
  'nextt': 'next', 'vuue': 'vue', 'angullar': 'angular',
  'sveltte': 'svelte', 'tailwindcsss': 'tailwindcss',
  'dottie': 'dotenv', 'envee': 'dotenv',
  'chalkk': 'chalk', 'momment': 'moment',
};

function checkPackage(name) {
  const risks = [];

  // Check for malicious package names
  for (const { re, reason } of MALICIOUS_PACKAGE_PATTERNS) {
    if (re.test(name)) {
      risks.push({ type: 'malicious', severity: 'critical', message: reason, action: 'block' });
    }
  }

  // Check for typosquats
  const lower = name.toLowerCase();
  if (TYPOSQUAT_MAP[lower]) {
    risks.push({
      type: 'typosquat',
      severity: 'high',
      message: `Possible typosquat of "${TYPOSQUAT_MAP[lower]}" — did you mean "${TYPOSQUAT_MAP[lower]}"?`,
      action: 'warn',
    });
  }

  // Check for suspicious patterns
  if (/^[a-z]{1,2}$/.test(lower)) {
    risks.push({ type: 'suspicious_short', severity: 'medium', message: 'Very short package name — common in typosquatting', action: 'warn' });
  }
  if (/[0-9]$/.test(lower) && !/(?:[a-z]2[a-z]|es[0-9]|v[0-9])/i.test(lower)) {
    risks.push({ type: 'suspicious_number_suffix', severity: 'low', message: 'Package name ends with number — verify legitimacy', action: 'warn' });
  }

  return {
    packageName: name,
    allowed: risks.filter(r => r.action === 'block').length === 0,
    risks,
  };
}

function renderFirewallReport(verdict) {
  const C = {
    red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
    cyan: '\x1b[36m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m',
  };
  const actionColor = { block: C.red, redact: C.yellow, warn: C.yellow, allow: C.green };
  const color = actionColor[verdict.action] || C.white;
  const lines = [
    `${C.bold}VibeGuard AI Firewall${C.reset}`,
    `${C.dim}${'─'.repeat(60)}${C.reset}`,
    '',
    `  Action:     ${color}${C.bold}${verdict.action.toUpperCase()}${C.reset}`,
    `  Threats:    ${verdict.threatCount}`,
    `  Reason:     ${verdict.reason}`,
    '',
  ];
  if (verdict.findings.length > 0) {
    lines.push(`${C.bold}Threats Detected${C.reset}`);
    for (const f of verdict.findings) {
      const sc = f.severity === 'critical' ? C.red : f.severity === 'high' ? C.yellow : C.dim;
      lines.push(`  ${sc}[${f.severity}]${C.reset} ${f.threat} — ${f.action}`);
      lines.push(`    ${f.reason}`);
      lines.push(`    ${C.green}fix:${C.reset} ${f.fix}`);
      lines.push('');
    }
  }
  if (verdict.sanitizedPrompt && verdict.action === 'redact') {
    lines.push(`${C.dim}Sanitized prompt:${C.reset}`);
    lines.push(`  ${verdict.sanitizedPrompt.slice(0, 200)}`);
    lines.push('');
  }
  return lines.join('\n');
}

module.exports = {
  inspectPrompt,
  checkAgentAction,
  checkExfiltration,
  checkPackage,
  renderFirewallReport,
  THREATS,
  AGENT_CONSTRAINTS,
  TYPOSQUAT_MAP,
  MALICIOUS_PACKAGE_PATTERNS,
};