'use strict';

/*
 * VibeGuard AI Data Guard.
 *
 * Detects when user data (PII, secrets, personal information) is sent to
 * AI/LLM APIs without being redacted or anonymized first.
 *
 * This is the #1 privacy concern with AI agents: they send user data to
 * external AI providers (OpenAI, Anthropic, Google) as part of prompts.
 * VibeGuard catches this and warns before the data leaves your machine.
 *
 * 100% local. Zero network. Zero dependencies.
 */

const fs = require('fs');
const path = require('path');
const { detectPII } = require('./pii');

const AI_API_PATTERNS = [
  { re: /openai\.(?:chat\.completions|completions|embeddings|images|audio)/i, provider: 'OpenAI' },
  { re: /https?:\/\/api\.openai\.com\/v1\//i, provider: 'OpenAI' },
  { re: /anthropic\.(?:messages|completions)/i, provider: 'Anthropic' },
  { re: /https?:\/\/api\.anthropic\.com\/v1\//i, provider: 'Anthropic' },
  { re: /(?:google\.generativeai|genai|gemini)\.(?:generateContent|generate)/i, provider: 'Google Gemini' },
  { re: /https?:\/\/generativelanguage\.googleapis\.com/i, provider: 'Google Gemini' },
  { re: /https?:\/\/api\.cohere\.com/i, provider: 'Cohere' },
  { re: /https?:\/\/api\.mistral\.ai/i, provider: 'Mistral' },
  { re: /https?:\/\/api\.together\.xyz/i, provider: 'Together AI' },
  { re: /https?:\/\/api\.groq\.com/i, provider: 'Groq' },
  { re: /https?:\/\/api\.perplexity\.ai/i, provider: 'Perplexity' },
  { re: /https?:\/\/api\.x\.ai/i, provider: 'xAI (Grok)' },
  { re: /https?:\/\/api\.deepseek\.com/i, provider: 'DeepSeek' },
  { re: /https?:\/\/api\.replicate\.com/i, provider: 'Replicate' },
  { re: /fetch\s*\(\s*['"]https?:\/\/api\.(?:openai|anthropic|googleapis|cohere|mistral|together|groq|perplexity|x\.ai|deepseek|replicate)\./i, provider: 'AI API (fetch)' },
];

const USER_DATA_RE = /\b(?:req\.body|req\.query|req\.params|request\.body|request\.query|request\.data|userInput|userText|userMessage|userInput)\b/i;
const PII_IN_PROMPT_RE = /\b(?:email|phone|ssn|address|password|credit.?card|cvv|dob|name|ip.?address)\b/i;
const REDACTION_RE = /redact|anonym|mask|scrub|sanitize|detectPII|redactText/i;

function auditAIData(dir, files) {
  const findings = [];

  for (const file of files) {
    let content;
    try { content = fs.readFileSync(file, 'utf8'); } catch { continue; }
    const rel = path.relative(dir, file).split(path.sep).join('/');
    const lines = content.split(/\r?\n/);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Check for AI API calls
      for (const pattern of AI_API_PATTERNS) {
        if (!pattern.re.test(line)) continue;

        // Check nearby lines for user data and PII (within 5 lines)
        const start = Math.max(0, i - 5);
        const end = Math.min(lines.length, i + 6);
        const context = lines.slice(start, end).join('\n');

        const isUserDataPassed = USER_DATA_RE.test(line) || USER_DATA_RE.test(context);
        const hasPII = PII_IN_PROMPT_RE.test(context);
        const hasRedaction = REDACTION_RE.test(context);

        if (isUserDataPassed || hasPII) {
          findings.push({
            file: rel,
            line: i + 1,
            provider: pattern.provider,
            severity: hasRedaction ? 'low' : 'high',
            message: hasRedaction
              ? `Data sent to ${pattern.provider} — redaction detected nearby (verify it covers all PII)`
              : `User data sent to ${pattern.provider} without redaction — PII may leak to AI provider`,
            fix: hasRedaction
              ? 'Verify redaction covers all PII types (email, phone, SSN, credit cards).'
              : 'Redact PII before sending to AI: const { redactText } = require("vibeguard/pii"); const safe = redactText(userInput);',
            hasRedaction,
          });
        }
        break; // Only match one pattern per line
      }
    }
  }

  // Also check for raw PII in prompt strings going to AI APIs
  for (const file of files) {
    let content;
    try { content = fs.readFileSync(file, 'utf8'); } catch { continue; }
    const rel = path.relative(dir, file).split(path.sep).join('/');
    const lines = content.split(/\r?\n/);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Check for prompt/message strings with PII
      if (/(?:prompt|message|content|input)\s*[:=]\s*[`'"]/.test(line)) {
        const detected = detectPII(line, { types: ['email', 'ssn', 'credit-card', 'phone'] });
        if (detected.length > 0) {
          const context = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 4)).join('\n');
          if (/openai|anthropic|gemini|ai\.|llm|model|completion|chat/i.test(context)) {
            findings.push({
              file: rel,
              line: i + 1,
              provider: 'AI (inferred from context)',
              severity: 'critical',
              message: `PII (${detected.map(d => d.type).join(', ')}) detected in prompt/message string going to AI API`,
              fix: 'Redact PII before building the prompt: const { redactText } = require("vibeguard/pii"); prompt = redactText(prompt);',
              hasRedaction: false,
              piiTypes: detected.map(d => d.type),
            });
          }
        }
      }
    }
  }

  // Deduplicate by file+line
  const seen = new Set();
  const unique = findings.filter(f => {
    const key = `${f.file}:${f.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return {
    findings: unique,
    summary: {
      totalRisks: unique.length,
      highRisk: unique.filter(f => f.severity === 'high' || f.severity === 'critical').length,
      criticalRisk: unique.filter(f => f.severity === 'critical').length,
      providers: [...new Set(unique.map(f => f.provider))],
      redacted: unique.filter(f => f.hasRedaction).length,
      unredacted: unique.filter(f => !f.hasRedaction).length,
    },
  };
}

function renderAIGuardReport(result) {
  const C = {
    red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
    cyan: '\x1b[36m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m',
  };

  const lines = [];
  lines.push(`${C.bold}VibeGuard AI Data Guard${C.reset}`);
  lines.push(`${C.dim}${'─'.repeat(60)}${C.reset}`);
  lines.push('');

  lines.push(`${C.bold}Summary${C.reset}`);
  lines.push(`  Total risks:        ${result.summary.totalRisks}`);
  lines.push(`  Critical:           ${C.red}${result.summary.criticalRisk}${C.reset}`);
  lines.push(`  High:               ${C.yellow}${result.summary.highRisk - result.summary.criticalRisk}${C.reset}`);
  lines.push(`  Redacted (ok):      ${C.green}${result.summary.redacted}${C.reset}`);
  lines.push(`  Unredacted (risk):  ${C.red}${result.summary.unredacted}${C.reset}`);
  if (result.summary.providers.length > 0) {
    lines.push(`  AI providers:       ${result.summary.providers.join(', ')}`);
  }
  lines.push('');

  if (result.findings.length === 0) {
    lines.push(`  ${C.green}No user data sent to AI APIs without redaction${C.reset}`);
    lines.push('');
    return lines.join('\n');
  }

  const critical = result.findings.filter(f => f.severity === 'critical');
  const high = result.findings.filter(f => f.severity === 'high');
  const low = result.findings.filter(f => f.severity === 'low');

  if (critical.length > 0) {
    lines.push(`${C.red}${C.bold}Critical — PII in AI prompts${C.reset}`);
    for (const f of critical) {
      lines.push(`  ${C.red}[CRITICAL]${C.reset} ${f.provider} — ${f.file}:${f.line}`);
      lines.push(`    ${f.message}`);
      lines.push(`    ${C.green}fix:${C.reset} ${f.fix}`);
      lines.push('');
    }
  }

  if (high.length > 0) {
    lines.push(`${C.yellow}${C.bold}High — User data to AI without redaction${C.reset}`);
    for (const f of high) {
      lines.push(`  ${C.yellow}[HIGH]${C.reset} ${f.provider} — ${f.file}:${f.line}`);
      lines.push(`    ${f.message}`);
      lines.push(`    ${C.green}fix:${C.reset} ${f.fix}`);
      lines.push('');
    }
  }

  if (low.length > 0) {
    lines.push(`${C.dim}Redacted (verify coverage)${C.reset}`);
    for (const f of low.slice(0, 5)) {
      lines.push(`  ${C.dim}[LOW]${C.reset} ${f.provider} — ${f.file}:${f.line}`);
      lines.push(`    ${f.message}`);
      lines.push('');
    }
  }

  return lines.join('\n');
}

module.exports = { auditAIData, renderAIGuardReport, AI_API_PATTERNS };