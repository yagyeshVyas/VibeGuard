'use strict';

/*
 * src/shell-guard.js — Shell-level pre-execution guard with anti-evasion.
 *
 * Scans a command string BEFORE it runs. Normalizes obfuscation attempts,
 * then matches against danger patterns. If blocked, returns { blocked: true }.
 *
 * Anti-evasion layers (applied in order, all checked):
 *   1. Base64 decode: echo "cm0gLXJmIC8" | base64 -d | sh -> rm -rf /
 *   2. Env-var indirection: RM="rm -rf"; $RM / -> blocked
 *   3. Subshell expansion: $(echo rm) -rf / -> rm -rf /
 *   4. Backtick eval: `echo rm` -rf / -> rm -rf /
 *   5. Hex/unicode escapes: \x72\x6d -> rm
 *   6. rm obfuscation: rm -r -f, rm --recursive --force, /bin/rm, r""m
 *   7. Path splitting: /bin/r""m -rf /, /sbin/r''m
 *   8. Quoted command: "rm" -rf /, 'rm' -rf /
 *   9. Variable concatenation: r=m; ${r}m -rf / -> blocked
 *
 * IMPORTANT: This catches accidental/AI-mistake dangerous commands. A
 * determined adversary with knowledge of the patterns can still evade
 * (no static guard is unbreakable). This stops the agent from nuking
 * your machine — it is NOT sandbox escape prevention.
 *
 * 100% local. Zero network. Zero dependencies.
 */

const path = require('path');

// ─── Anti-evasion normalizer ──────────────────────────────────────────────

function normalizeCommand(cmd) {
  if (!cmd || typeof cmd !== 'string') return cmd || '';
  let normalized = cmd;

  // Layer 1: Base64 decode — catch "echo <base64> | base64 -d | sh"
  const b64Match = normalized.match(/echo\s+["']?([A-Za-z0-9+/=]{8,})["']?\s*\|\s*(?:base64|b64)\s+-d\s*\|/i);
  if (b64Match) {
    try {
      const decoded = Buffer.from(b64Match[1], 'base64').toString('utf8');
      normalized = normalized.replace(b64Match[0], decoded);
    } catch {}
  }

  // Layer 2: Env-var indirection — VAR="rm -rf"; $VAR /
  // Extract assignments and substitute $VAR references
  const assignMatch = normalized.match(/(\w+)=(["'])([^"']*)\2/);
  if (assignMatch) {
    const varName = assignMatch[1];
    const varValue = assignMatch[3];
    // If the variable contains a dangerous command fragment, substitute it
    if (/rm|sudo|chmod|mkfs|dd\s|shutdown|reboot|curl|wget/i.test(varValue)) {
      normalized = normalized.replace(new RegExp('\\$' + varName + '\\b', 'g'), varValue);
      normalized = normalized.replace(assignMatch[0], ''); // remove the assignment
    }
  }

  // Layer 3: Subshell expansion — $(echo rm) -> rm
  normalized = normalized.replace(/\$\(\s*echo\s+([^)]+)\s*\)/g, '$1');
  // $(printf "rm") -> rm
  normalized = normalized.replace(/\$\(\s*printf\s+["']([^"']+)["']\s*\)/g, '$1');

  // Layer 4: Backtick eval — `echo rm` -> rm
  normalized = normalized.replace(/`\s*echo\s+([^`]+)\s*`/g, '$1');
  normalized = normalized.replace(/`\s*printf\s+["']([^"']+)["']\s*`/g, '$1');

  // Layer 5: Hex/unicode escapes — \x72\x6d -> rm
  normalized = normalized.replace(/\\x([0-9a-f]{2})/gi, (m, hex) => {
    try { return String.fromCharCode(parseInt(hex, 16)); } catch { return m; }
  });
  // \u0072 -> r
  normalized = normalized.replace(/\\u([0-9a-f]{4})/gi, (m, hex) => {
    try { return String.fromCharCode(parseInt(hex, 16)); } catch { return m; }
  });

  // Layer 6: rm obfuscation — rm -r -f, rm --recursive --force, /bin/rm, /sbin/rm
  // Normalize rm flags: -r -f, -fr, -rf, -Rf, --recursive --force all -> -rf
  normalized = normalized.replace(/\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*|--recursive(?:\s+--force)?)\b/i, 'rm -rf');
  normalized = normalized.replace(/\brm\s+-r\s+-f\b/i, 'rm -rf');
  normalized = normalized.replace(/\brm\s+-f\s+-r\b/i, 'rm -rf');
  normalized = normalized.replace(/\brm\s+--recursive\s+--force\b/i, 'rm -rf');
  // /bin/rm, /sbin/rm -> rm
  normalized = normalized.replace(/(?:\/bin\/|\/sbin\/)rm\b/g, 'rm');

  // Layer 7: String concatenation — r""m, r''m, r\m -> rm
  // Remove quotes and backslashes between letters to detect split commands
  normalized = normalized.replace(/([a-zA-Z])["'\\]+([a-zA-Z])/g, '$1$2');

  // Layer 8: Quoted command — "rm", 'rm' -> rm
  normalized = normalized.replace(/["']([a-z]{2,})["']/gi, (m, inner) => inner);

  // Layer 9: Variable concatenation — ${r}m, ${RM} -> rm
  // If there's a var assignment followed by ${var}, substitute
  const varAssigns = {};
  const assignPattern = /(\w+)=(["']?)([^"'\s]*)\2/g;
  let am;
  while ((am = assignPattern.exec(cmd)) !== null) {
    varAssigns[am[1]] = am[3];
  }
  normalized = normalized.replace(/\$\{(\w+)\}/g, (m, name) => varAssigns[name] || m);

  return normalized.trim();
}

// ─── Danger patterns (matched against BOTH raw AND normalized) ───────────

const DANGEROUS_COMMANDS = [
  { re: /\brm\s+-rf\b/i, reason: 'rm -rf can delete entire directory trees', severity: 'critical' },
  { re: /\brm\s+-rf\s+\/(?:\s|$)/i, reason: 'rm -rf / — catastrophic deletion of root filesystem', severity: 'critical' },
  { re: /\brm\s+-rf\s+~(?:\s|$|\/)/i, reason: 'rm -rf ~ — deleting home directory', severity: 'critical' },
  { re: /\brm\s+-rf\s+\.(?:\s|$)/i, reason: 'rm -rf . — deleting current directory', severity: 'critical' },
  { re: /\brm\s+-rf\s+\.\.(?:\s|$)/i, reason: 'rm -rf .. — deleting parent directory', severity: 'critical' },
  { re: /\bsudo\b/i, reason: 'sudo escalates privileges — agents should not use sudo', severity: 'high' },
  { re: /\bchmod\s+777\b/i, reason: 'chmod 777 grants world write — insecure', severity: 'high' },
  { re: /\bmkfs\b/i, reason: 'mkfs formats filesystem — destructive', severity: 'critical' },
  { re: /\bdd\s+if=/i, reason: 'dd can overwrite disks — destructive', severity: 'critical' },
  { re: /\bdd\s+.*of=\/dev\//i, reason: 'dd writing directly to device — destructive', severity: 'critical' },
  { re: /\bshutdown\b/i, reason: 'shutdown stops the machine', severity: 'critical' },
  { re: /\breboot\b/i, reason: 'reboot restarts the machine', severity: 'critical' },
  { re: /\bhalt\b/i, reason: 'halt stops the machine', severity: 'critical' },
  { re: /\bpoweroff\b/i, reason: 'poweroff stops the machine', severity: 'critical' },
  { re: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;/i, reason: 'fork bomb detected', severity: 'critical' },
  { re: /\b(?:curl|wget)\b.*\|\s*(?:sh|bash|zsh)\b/i, reason: 'curl|sh — remote code execution via pipe to shell', severity: 'critical' },
  { re: /\b(?:curl|wget)\b.*(?:169\.254\.169\.254|metadata\.google\.internal)/i, reason: 'cloud metadata service access — credential theft', severity: 'critical' },
  { re: /\bnc\s+-l/i, reason: 'nc -l opens a listener — reverse shell risk', severity: 'high' },
  { re: /\b(?:python|python3|node|ruby|perl)\s+-c\s+['"]\s*(?:import|require)\s+(?:os|subprocess|child_process)/i, reason: 'inline script importing OS modules — potential injection', severity: 'high' },
  { re: /\bkill(?:\s+-9)?\s+-1\b/i, reason: 'kill -1 kills all processes — system-wide kill', severity: 'critical' },
  { re: /\bpkill\s+-9\b/i, reason: 'pkill -9 force kills processes — destructive', severity: 'high' },
  { re: /\biotop\s+--only\b/i, reason: 'iotop in batch mode can cause system instability', severity: 'low' },
  // Anti-evasion: base64 pipe to shell
  { re: /\|\s*(?:base64|b64)\s+-d\s*\|/i, reason: 'base64 decode piped to shell — obfuscated command execution', severity: 'critical' },
  { re: /\|\s*(?:sh|bash|zsh|python|python3|node|perl|ruby)\b/i, reason: 'piping to interpreter — potential remote code execution', severity: 'high' },
];

const SECRET_PATTERNS = [
  { re: /\bsk-proj-[A-Za-z0-9_-]{20,}\b/i, type: 'OpenAI API key' },
  { re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/i, type: 'Anthropic API key' },
  { re: /\bsk_live_[A-Za-z0-9]{16,}\b/i, type: 'Stripe secret key' },
  { re: /\bAKIA[A-Z0-9]{16}\b/, type: 'AWS access key' },
  { re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/i, type: 'GitHub token' },
  { re: /\bglpat-[A-Za-z0-9_-]{20,}\b/i, type: 'GitLab token' },
  { re: /\bxox[bpoa]-[A-Za-z0-9-]{10,}\b/i, type: 'Slack token' },
  { re: /-----BEGIN\s+(?:RSA\s+|EC\s+)?PRIVATE\s+KEY-----/i, type: 'Private key' },
];

const SENSITIVE_PATHS = [
  /\.env\b/i,
  /\.ssh\b/i,
  /\.aws\b/i,
  /\.gnupg\b/i,
  /\.npmrc\b/i,
  /\.gitconfig\b/i,
  /\/etc\/passwd/i,
  /\/etc\/shadow/i,
  /\/etc\/sudoers/i,
  /\/etc\/ssh\//i,
  /~\/\.ssh\//i,
];

const EXFIL_PATTERNS = [
  { re: /\b(?:curl|wget|nc|netcat)\b.*(?:\bapi\.|webhook|callback|exfil|upload|send)/i, reason: 'Potential data exfiltration via network tool to external endpoint' },
  { re: /\b(?:curl|wget)\b.*-d\s.*(?:token|key|password|secret|credential)/i, reason: 'Sending secrets via curl/wget POST data' },
  { re: /\b(?:curl|wget)\b.*--data\b.*(?:token|key|password|secret|credential)/i, reason: 'Sending secrets via curl/wget --data' },
  { re: /\b(?:scp|rsync)\b.*@(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i, reason: 'File transfer to raw IP — potential exfiltration' },
  { re: /\b(?:curl|wget)\b.*-F\s.*(?:token|key|password|secret)/i, reason: 'Sending secrets via curl/wget multipart form' },
];

// ─── Main check function ──────────────────────────────────────────────────

function checkCommand(cmd) {
  if (!cmd || typeof cmd !== 'string') return { blocked: false, allowed: true };
  const trimmed = cmd.trim();

  // Skip empty lines and comments
  if (!trimmed || trimmed.startsWith('#')) return { blocked: false, allowed: true };

  // Normalize for anti-evasion
  const normalized = normalizeCommand(trimmed);

  // Check BOTH the raw command AND the normalized version
  const inputs = [trimmed, normalized];
  const violations = [];
  const seen = new Set(); // dedupe violations across raw + normalized

  for (const input of inputs) {
    // 1. Dangerous commands
    for (const { re, reason, severity } of DANGEROUS_COMMANDS) {
      if (re.test(input)) {
        const key = reason;
        if (!seen.has(key)) {
          seen.add(key);
          violations.push({ type: 'dangerous_command', reason, severity, pattern: re.source });
        }
      }
    }

    // 2. Secret exfiltration
    for (const { re, reason } of EXFIL_PATTERNS) {
      if (re.test(input)) {
        const key = reason;
        if (!seen.has(key)) {
          seen.add(key);
          violations.push({ type: 'exfiltration', reason, severity: 'high', pattern: re.source });
        }
      }
    }

    // 3. Secrets in command
    for (const { re, type } of SECRET_PATTERNS) {
      if (re.test(input)) {
        const key = type;
        if (!seen.has(key)) {
          seen.add(key);
          violations.push({ type: 'secret_exposure', reason: `Secret detected in command: ${type}`, severity: 'critical', pattern: re.source });
        }
      }
    }

    // 4. Sensitive file access
    for (const re of SENSITIVE_PATHS) {
      if (re.test(input)) {
        const match = input.match(re)[0];
        const key = 'path:' + match;
        if (!seen.has(key)) {
          seen.add(key);
          violations.push({ type: 'sensitive_path', reason: `Access to sensitive path: ${match}`, severity: 'high', pattern: re.source });
        }
      }
    }
  }

  // 5. Prompt injection in shell (e.g., agent putting LLM output into eval)
  for (const input of inputs) {
    if (/\beval\s+["'].*(?:ignore|disregard|forget|system prompt)/i.test(input)) {
      violations.push({ type: 'prompt_injection', reason: 'eval with prompt injection pattern — agent may be compromised', severity: 'critical' });
      break;
    }
  }

  // 6. Obfuscation detection — flag suspicious patterns even if we can't decode them
  if (/[a-zA-Z]\[([0-9a-f]{1,2})\]/i.test(trimmed)) {
    violations.push({ type: 'obfuscation', reason: 'Bash escape sequence $\'\\xNN\' detected — possible command obfuscation', severity: 'high' });
  }
  if (trimmed.includes('eval ') && trimmed.includes('$((')) {
    violations.push({ type: 'obfuscation', reason: 'eval with arithmetic expansion — possible obfuscation', severity: 'high' });
  }

  if (violations.length === 0) return { blocked: false, allowed: true };

  return {
    blocked: true,
    allowed: false,
    violations,
    reason: violations[0].reason,
    severity: violations[0].severity,
    command: trimmed.slice(0, 200),
    normalized: normalized !== trimmed ? normalized.slice(0, 200) : undefined,
  };
}

// ─── Batch check (for scripts) ─────────────────────────────────────────────

function checkScript(content) {
  if (!content || typeof content !== 'string') return { blocked: false, findings: [] };
  const lines = content.split(/\r?\n/);
  const findings = [];
  for (let i = 0; i < lines.length; i++) {
    const result = checkCommand(lines[i]);
    if (result.blocked) {
      findings.push({ line: i + 1, ...result });
    }
  }
  return { blocked: findings.length > 0, findings };
}

module.exports = { checkCommand, checkScript, normalizeCommand, DANGEROUS_COMMANDS, SECRET_PATTERNS, SENSITIVE_PATHS, EXFIL_PATTERNS };