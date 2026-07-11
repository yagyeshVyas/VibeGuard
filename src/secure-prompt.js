'use strict';

/*
 * secure_prompt — analyze an AI prompt BEFORE code is generated.
 *
 * This is VibeGuard's unique moat: catch security issues at the prompt level,
 * before any code is written. Scans for:
 *   - Prompt injection vectors (user input in system prompt)
 *   - Requested insecure patterns (eval, exec, innerHTML, SQL concatenation)
 *   - Missing security constraints (no auth, no input validation, no rate limiting)
 *   - Dangerous capability requests (shell access, file access, DB access)
 *   - Missing guardrails for AI-generated code
 */

const INJECTION_PATTERNS = [
  { re: /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions/i, risk: 'high', msg: 'Prompt contains instruction-override language — possible prompt injection' },
  { re: /you\s+are\s+(?:now|a)\s+(?:different|new)/i, risk: 'high', msg: 'Prompt contains role-reassignment language — possible prompt injection' },
  { re: /(?:disregard|forget)\s+(?:the\s+)?(?:above|previous|all)/i, risk: 'high', msg: 'Prompt contains context-discard language — possible prompt injection' },
  { re: /(?:system|developer)\s+(?:prompt|message)\s*:/i, risk: 'high', msg: 'Prompt references system/developer prompt — possible injection' },
  { re: /(?:jailbreak|DAN|developer\s+mode|unrestricted\s+mode)/i, risk: 'critical', msg: 'Prompt contains known jailbreak terminology' },
];

const INSECURE_REQUEST_PATTERNS = [
  { re: /\beval\b\s*\(?\s*(?:user|input|request|req|data|code)?/i, risk: 'high', msg: 'Prompt requests eval() — code injection risk' },
  { re: /new\s+Function\s*\(/i, risk: 'high', msg: 'Prompt requests new Function() — code injection risk' },
  { re: /\bexec(?:Sync|File)?\s*\(/i, risk: 'high', msg: 'Prompt requests exec() — command injection risk' },
  { re: /\bspawn\s*\(/i, risk: 'high', msg: 'Prompt requests spawn() — command injection risk' },
  { re: /innerHTML\s*=/i, risk: 'medium', msg: 'Prompt requests innerHTML assignment — XSS risk' },
  { re: /dangerouslySetInnerHTML/i, risk: 'medium', msg: 'Prompt requests dangerouslySetInnerHTML — XSS risk' },
  { re: /SQL.*?concatenat|string.*?SQL.*?query|SQL.*?\+/i, risk: 'high', msg: 'Prompt suggests SQL string concatenation — SQL injection risk' },
  { re: /(?:disable(?:s|d)?|skip|no|without|bypass|ignore)\s+(?:auth|authentication|authorization)/i, risk: 'high', msg: 'Prompt requests disabling authentication' },
  { re: /(?:disable|skip|no)\s+(?:input\s+)?validat/i, risk: 'medium', msg: 'Prompt requests skipping input validation' },
  { re: /(?:disable|skip|no)\s+(?:rate\s+limit|throttl)/i, risk: 'medium', msg: 'Prompt requests disabling rate limiting' },
  { re: /(?:allow|permit|enable)\s+(?:all\s+)?(?:CORS|origins|wildcard)/i, risk: 'medium', msg: 'Prompt requests wildcard CORS' },
  { re: /(?:store|save|put)\s+(?:password|secret|token|key|credential)\s+(?:in\s+)?(?:localStorage|client|browser)/i, risk: 'high', msg: 'Prompt suggests storing secrets client-side' },
  { re: /(?:skip|disable|no)\s+(?:TLS|SSL|HTTPS|encryption)/i, risk: 'high', msg: 'Prompt suggests disabling encryption' },
  { re: /(?:hardcode|hard-code|embed)\s+(?:password|secret|token|key|credential)/i, risk: 'high', msg: 'Prompt suggests hardcoding secrets' },
  { re: /(?:allow|permit)\s+(?:any|all)\s+(?:file|filesystem)\s+access/i, risk: 'high', msg: 'Prompt requests unrestricted filesystem access' },
  { re: /(?:allow|permit)\s+(?:arbitrary|any|all)\s+(?:command|shell)\s+(?:execution|access)/i, risk: 'critical', msg: 'Prompt requests arbitrary command execution' },
];

const MISSING_CONSTRAINT_PATTERNS = [
  { re: /(?:create|build|write|generate|implement)\s+(?:a\s+)?(?:REST|GraphQL|API|endpoint|route)/i, missing: 'auth', msg: 'API endpoint requested — ensure authentication is mentioned' },
  { re: /(?:create|build|write|generate|implement)\s+(?:a\s+)?(?:form|input|submission|upload)/i, missing: 'validation', msg: 'Form/input requested — ensure input validation is mentioned' },
  { re: /(?:create|build|write|generate|implement)\s+(?:a\s+)?(?:login|auth|register|signup)/i, missing: 'rate-limit', msg: 'Auth feature requested — ensure rate limiting is mentioned' },
  { re: /(?:create|build|write|generate|implement)\s+(?:a\s+)?(?:database|DB|query|migration)/i, missing: 'parameterization', msg: 'Database code requested — ensure parameterized queries are mentioned' },
  { re: /(?:create|build|write|generate|implement)\s+(?:a\s+)?(?:AI|LLM|agent|chat|assistant)/i, missing: 'prompt-injection-guard', msg: 'AI feature requested — ensure prompt injection protection is mentioned' },
  { re: /(?:create|build|write|generate|implement)\s+(?:a\s+)?(?:file\s+upload|download|attachment)/i, missing: 'file-validation', msg: 'File upload requested — ensure file type/size validation is mentioned' },
];

const DANGEROUS_CAPABILITY_PATTERNS = [
  { re: /(?:agent|tool|function)\s+(?:that|which|can)\s+(?:execute|run|eval)/i, risk: 'critical', msg: 'Prompt requests an agent that can execute code — RCE via prompt injection' },
  { re: /(?:agent|tool)\s+(?:that|which|can)\s+(?:access|read|write|modify)\s+(?:any|all)\s+(?:file|filesystem)/i, risk: 'high', msg: 'Prompt requests unrestricted filesystem access for an agent' },
  { re: /(?:agent|tool)\s+(?:that|which|can)\s+(?:access|read|query|modify)\s+(?:any|all)\s+(?:database|DB)/i, risk: 'high', msg: 'Prompt requests unrestricted database access for an agent' },
  { re: /(?:agent|tool)\s+(?:that|which|can)\s+(?:install|download|fetch|pip|npm)/i, risk: 'high', msg: 'Prompt requests package installation capability for an agent — supply chain risk' },
  { re: /(?:agent|tool)\s+(?:that|which|can)\s+(?:deploy|publish|release|ship)/i, risk: 'high', msg: 'Prompt requests deployment capability for an agent' },
  { re: /(?:agent|tool)\s+(?:that|which)\s+(?:has|with)\s+(?:full|unrestricted|admin|root)\s+(?:access|permissions?)/i, risk: 'critical', msg: 'Prompt requests unrestricted permissions for an agent' },
];

function analyzePrompt(promptText) {
  const findings = [];
  let score = 100;

  for (const p of INJECTION_PATTERNS) {
    if (p.re.test(promptText)) {
      findings.push({
        category: 'prompt-injection',
        risk: p.risk,
        message: p.msg,
        fix: 'Remove instruction-override language. Use system role for directives, user role for data.',
      });
      score -= p.risk === 'critical' ? 40 : 20;
    }
  }

  for (const p of INSECURE_REQUEST_PATTERNS) {
    if (p.re.test(promptText)) {
      findings.push({
        category: 'insecure-pattern-request',
        risk: p.risk,
        message: p.msg,
        fix: 'Add a security constraint: "Do not use eval/exec. Use parameterized queries. Validate all input."',
      });
      score -= p.risk === 'critical' ? 35 : p.risk === 'high' ? 15 : 8;
    }
  }

  for (const p of MISSING_CONSTRAINT_PATTERNS) {
    if (p.re.test(promptText)) {
      const hasConstraint = checkConstraintPresent(promptText, p.missing);
      if (!hasConstraint) {
        findings.push({
          category: 'missing-constraint',
          risk: 'medium',
          message: p.msg,
          fix: `Add to the prompt: "Ensure ${p.missing} is implemented."`,
        });
        score -= 5;
      }
    }
  }

  for (const p of DANGEROUS_CAPABILITY_PATTERNS) {
    if (p.re.test(promptText)) {
      findings.push({
        category: 'dangerous-capability',
        risk: p.risk,
        message: p.msg,
        fix: 'Add guardrails: sandbox, allowlist, human-in-the-loop, max-steps, and input validation.',
      });
      score -= p.risk === 'critical' ? 40 : 20;
    }
  }

  return {
    score: Math.max(0, score),
    grade: score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F',
    findings,
    recommendation:
      score >= 90
        ? 'Prompt looks safe to execute'
        : score >= 60
        ? 'Prompt has security concerns — add constraints before executing'
        : 'Prompt is unsafe — do NOT execute without adding security constraints',
  };
}

function checkConstraintPresent(text, type) {
  const checks = {
    auth: /(?:auth|authentication|authorization|login|session|token|middleware)/i,
    validation: /(?:validat|sanitize|schema|zod|joi|express-validator)/i,
    'rate-limit': /(?:rate\s*limit|throttl|cooldown|backoff)/i,
    parameterization: /(?:parameteriz|prepared|placeholder|bind|sql\`|\$\{)/i,
    'prompt-injection-guard': /(?:prompt\s*injection|sanitiz|guardrail|system\s*prompt|instruction)/i,
    'file-validation': /(?:file\s*type|mime|size\s*limit|extension|magic\s*number|fingerprint)/i,
  };
  return checks[type] ? checks[type].test(text) : false;
}

module.exports = { analyzePrompt, checkConstraintPresent };
