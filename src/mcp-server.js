#!/usr/bin/env node
'use strict';

/*
 * VibeGuard MCP server.
 *
 * Exposes the scanner to MCP clients (Claude Code, Cursor) over stdio.
 * Tools: scan_project, suggest_fixes, verify_fixes.
 *
 * Uses the low-level Server API from the official SDK so we don't pull in zod;
 * input schemas are plain JSON Schema.
 *
 * Install into Claude Code:
 *   claude mcp add vibeguard -- npx -y @yagyeshvyas/vibeguard mcp
 * or, from a checkout:
 *   claude mcp add vibeguard -- node /abs/path/src/mcp-server.js
 */

const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} = require('@modelcontextprotocol/sdk/types.js');

const { scan, computeGrade, sortFindings, walk } = require('./scanner');
const { verify, writeBaseline } = require('./verify');
const { renderFixPrompt } = require('./report');
const { scanUrl } = require('./urlscan');
const { generateComplianceReport } = require('./compliance');
const { analyzePrompt } = require('./secure-prompt');
const { scanSlopsquat } = require('./slopsquat');
const { trace } = require('./trace');
const { buildAuthCoverage, getChangedFiles, analyzePythonTaint } = require('./engine');
const { scanCVEs } = require('./cve-intel');
const { allRules } = require('./rules');
const fs = require('fs');
const path = require('path');

const DIR_SCHEMA = {
  type: 'object',
  properties: {
    dir: {
      type: 'string',
      description: 'Path to the project directory to analyze. Defaults to the current working directory.',
    },
  },
  required: [],
};

const TOOLS = [
  {
    name: 'scan_project',
    description: 'Scan a project for security issues. Returns findings with letter grade.',
    inputSchema: { type: 'object', properties: { dir: DIR_SCHEMA.properties.dir, saveBaseline: { type: 'boolean' } }, required: [] },
  },
  {
    name: 'suggest_fixes',
    description: 'Scan and return a concrete fix plan per finding plus a paste-ready prompt.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'verify_fixes',
    description: 'Re-scan and report resolved/remaining/new issues vs the baseline.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'review_hotspots',
    description: 'Deep semantic review: identifies security hotspot files + structured checklist for manual review.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'scan_url',
    description: 'Scan a live deployed URL for missing security headers, insecure cookies, server leakage.',
    inputSchema: { type: 'object', properties: { url: { type: 'string' } }, required: ['url'] },
  },
  {
    name: 'check_code',
    description: 'Scan a code snippet (string) for security issues without writing to disk.',
    inputSchema: { type: 'object', properties: { code: { type: 'string' }, language: { type: 'string' } }, required: ['code'] },
  },
  {
    name: 'scan_staged',
    description: 'Scan only staged git changes (pre-commit). Returns findings for files in the git diff.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'scan_dependencies',
    description: 'Query OSV.dev for known vulnerabilities in package.json dependencies.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'scan_secrets',
    description: 'Scan project for hardcoded secrets and API keys only (faster than full scan).',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'check_package_health',
    description: 'Check if npm packages referenced in the project are real (anti-slopsquat) and check typosquat risk.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'compliance_report',
    description: 'Map findings to compliance frameworks (SOC2, PCI-DSS, HIPAA, GDPR, ISO27001, EU AI Act).',
    inputSchema: { type: 'object', properties: { dir: DIR_SCHEMA.properties.dir, framework: { type: 'string', enum: ['SOC2', 'PCI-DSS', 'HIPAA', 'GDPR', 'ISO27001', 'EUAIAct'] } }, required: [] },
  },
  {
    name: 'export_sarif',
    description: 'Export scan results as SARIF 2.1.0 JSON with CWE/OWASP tags.',
    inputSchema: { type: 'object', properties: { dir: DIR_SCHEMA.properties.dir }, required: [] },
  },
  {
    name: 'fix_code',
    description: 'Return structured patch suggestions for findings (exactEdit or manualFix). Does not edit files.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'secure_this',
    description: 'Full pipeline: scan → suggest fixes → (after user applies) re-verify → rollback if new issues. Returns the plan only.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'guard_action',
    description: 'Agent action firewall — inspect an action BEFORE running it and block secret/PII exfiltration, dangerous commands, or sending sensitive data to an untrusted host. Call this before any shell command, network request, file write, LLM prompt, or MCP tool call. Returns allow | warn | block. Nothing leaves the machine that would leak an API key or personal data.',
    inputSchema: {
      type: 'object',
      properties: {
        type: { type: 'string', enum: ['shell', 'network', 'file-write', 'prompt', 'mcp', 'generic'], description: 'The kind of action.' },
        command: { type: 'string', description: 'For type=shell: the command line.' },
        url: { type: 'string', description: 'For type=network: the request URL.' },
        method: { type: 'string' },
        body: { description: 'For type=network: the request body (string or object).' },
        path: { type: 'string', description: 'For type=file-write: the destination path.' },
        content: { type: 'string', description: 'For file-write/prompt/generic: the content.' },
        provider: { type: 'string', description: 'For type=prompt: the LLM provider name.' },
        tool: { type: 'string', description: 'For type=mcp: the tool name.' },
        args: { description: 'For type=mcp: the tool arguments.' },
        trustedHosts: { type: 'array', items: { type: 'string' }, description: 'Hosts allowed to receive sensitive data.' },
      },
      required: ['type'],
    },
  },
  {
    name: 'agent_scan',
    description: 'AI Agent Security Posture — one graded verdict across every agent-era risk: MCP server trust, PII/secret leakage to LLM providers, LLM output reaching exec/eval/SQL/DOM, prompt injection, agent capability/loop safety, and hallucinated dependencies. Use this to answer "is my AI-agent setup safe?" Offline; aggregates VibeGuard\'s agent checks.',
    inputSchema: { type: 'object', properties: { dir: DIR_SCHEMA.properties.dir }, required: [] },
  },
  {
    name: 'mcp_audit',
    description: 'Audit the MCP servers this project trusts (.mcp.json / .cursor / .vscode) for tool poisoning (prompt injection), unpinned auto-install / rug-pull, remote-code commands, secrets in env, and definition drift since last approval. 100% offline — reads config only, never runs a server.',
    inputSchema: { type: 'object', properties: { dir: DIR_SCHEMA.properties.dir, pin: { type: 'boolean', description: 'Re-baseline server definition hashes after review.' } }, required: [] },
  },
  {
    name: 'audit_config',
    description: 'Cross-file config audit: checks .env, next.config, docker-compose, k8s, CI workflows for security misconfig.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'generate_policy',
    description: 'Generate security policy templates: CSP headers, CORS config, RLS policies, rate-limit middleware.',
    inputSchema: { type: 'object', properties: { type: { type: 'string', enum: ['csp', 'cors', 'rls', 'rate-limit'] }, dir: DIR_SCHEMA.properties.dir }, required: ['type'] },
  },
  {
    name: 'review_pr',
    description: 'Review a git diff (unstaged or branch diff) for security issues in changed lines.',
    inputSchema: { type: 'object', properties: { dir: DIR_SCHEMA.properties.dir, base: { type: 'string', description: 'Base branch (default: main)' } }, required: [] },
  },
  {
    name: 'scan_secrets_history',
    description: 'Scan git history for committed-then-removed secrets.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'analyze_dataflow',
    description: 'Run taint analysis on a single file to trace user input to dangerous sinks.',
    inputSchema: { type: 'object', properties: { file: { type: 'string', description: 'File path to analyze' } }, required: ['file'] },
  },
  {
    name: 'analyze_cross_file_dataflow',
    description: 'Run cross-file taint analysis across the project import/export graph.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'check_command',
    description: 'Analyze a shell command string for security risks (pipe-to-bash, rm -rf, chmod 777, sudo).',
    inputSchema: { type: 'object', properties: { command: { type: 'string' } }, required: ['command'] },
  },
  {
    name: 'scan_config_change',
    description: 'Detect if security-relevant config files were weakened since last scan (config downgrade detection).',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'repo_security_posture',
    description: 'Overall security posture: grade, coverage, auth map, dependency health, compliance gaps.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'explain_remediation',
    description: 'Get detailed remediation guidance for a specific rule ID.',
    inputSchema: { type: 'object', properties: { ruleId: { type: 'string' } }, required: ['ruleId'] },
  },
  {
    name: 'scan_file',
    description: 'Scan a single file for security issues (for real-time post-edit checks).',
    inputSchema: { type: 'object', properties: { file: { type: 'string' } }, required: ['file'] },
  },
  {
    name: 'scan_changed_files',
    description: 'Incremental scan: only re-scan files that changed since last scan (file-hash cache).',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'security_stats',
    description: 'Dashboard: finding counts by category, grade trend, top risky files, rule coverage.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'guardvibe_doctor',
    description: 'AI host security audit: check for hook injection, base URL hijack, MCP config abuse.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'auth_coverage',
    description: 'Enumerate routes → middleware → auth guards. Shows which API routes are unprotected.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'deep_scan',
    description: 'LLM-powered deep review: combines scan + hotspot analysis + auth coverage + behavior trace for comprehensive audit.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'full_audit',
    description: 'Run ALL checks: scan + CVE + slopsquat + compliance + auth coverage + history. Returns full verdict + hash.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'remediation_plan',
    description: 'Generate a prioritized fix checklist with effort estimates and dependencies.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'verify_remediation',
    description: 'Compare before/after scan results. Run scan, apply fixes, then run this to see what improved.',
    inputSchema: { type: 'object', properties: { dir: DIR_SCHEMA.properties.dir, baselineHash: { type: 'string' } }, required: [] },
  },
  {
    name: 'secure_prompt',
    description: 'Analyze an AI prompt for security risks BEFORE code is generated. Catches injection, insecure requests, missing constraints.',
    inputSchema: { type: 'object', properties: { prompt: { type: 'string' } }, required: ['prompt'] },
  },
  {
    name: 'scan_hallucinated_packages',
    description: 'Check if packages referenced in source code actually exist on npm (anti-slopsquat).',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'redact_pii',
    description: 'Redact personal/sensitive data (emails, SSNs, credit cards, phone numbers, AWS keys, JWTs, IPs, IBANs, private keys) from text. Call this BEFORE sending user text to another model, tool, log, or external service. Returns scrubbed text. 100% local, zero network.',
    inputSchema: { type: 'object', properties: { text: { type: 'string', description: 'The text to scrub.' }, types: { type: 'array', items: { type: 'string' }, description: 'Optional: only redact these entity types.' } }, required: ['text'] },
  },
  {
    name: 'detect_pii',
    description: 'Detect (without redacting) personal/sensitive data in text. Returns entity types, counts, and offsets so you can decide whether text is safe to send onward.',
    inputSchema: { type: 'object', properties: { text: { type: 'string', description: 'The text to inspect.' }, types: { type: 'array', items: { type: 'string' }, description: 'Optional: only look for these entity types.' } }, required: ['text'] },
  },
  {
    name: 'trace_prompt',
    description: 'Trace findings back to AI prompts that generated them. Reads Cursor/Claude session history.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'list_rules',
    description: 'List all VibeGuard rules with their ID, severity, category, and description.',
    inputSchema: { type: 'object', properties: { category: { type: 'string' } }, required: [] },
  },
  {
    name: 'cve_intel',
    description: 'Query OSV.dev for known vulnerabilities in dependencies. Returns CVE IDs and fix versions.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'generate_html_report',
    description: 'Generate a self-contained HTML security report with findings, grade, and charts.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'risk_score',
    description: 'Calculate a weighted risk score (0-100) with risk level and top 5 risks. Faster than full scan for quick posture checks.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'batch_fix',
    description: 'Auto-fix all fixable issues in one pass. Snapshots before applying. Returns list of applied fixes.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'ignore_rule',
    description: 'Add a rule to the ignore list in .vibeguardrc.json. Suppresses false positives.',
    inputSchema: {
      type: 'object',
      properties: {
        ruleId: { type: 'string', description: 'The rule ID to ignore (e.g. "secret.openai-key")' },
        dir: { type: 'string', description: 'Project directory. Defaults to cwd.' },
      },
      required: ['ruleId'],
    },
  },
  {
    name: 'baseline',
    description: 'Save current findings as a baseline (.vibeguard-baseline.json) for trend tracking. Compare future scans against this.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'rule_info',
    description: 'Get detailed info about a specific rule: severity, confidence, CWE, OWASP, auto-fixability, and remediation guidance.',
    inputSchema: {
      type: 'object',
      properties: {
        ruleId: { type: 'string', description: 'The rule ID to query (e.g. "secret.openai-key")' },
      },
      required: ['ruleId'],
    },
  },
  {
    name: 'severity_matrix',
    description: 'Show a severity-by-category matrix showing where risks cluster. Useful for prioritizing remediation.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'dependency_tree',
    description: 'Analyze package-lock.json: list all dependencies, integrity hash coverage, and dev vs prod split.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'config_dump',
    description: 'Dump all VibeGuard configuration: .vibeguardrc.json, MCP install status, hook status, baseline status.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'trend_report',
    description: 'Compare current scan against saved baseline. Shows resolved, new, and persisted findings. Tracks security posture over time.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'security_scorecard',
    description: 'Generate a comprehensive security scorecard with grade, risk score, compliance posture, top risks, and remediation priority. JSON output for CI/CD.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'pr_comment',
    description: 'Generate a GitHub PR comment in markdown format with security findings summary, grade emoji, and top findings table. Paste directly into PR reviews.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'slack_notify',
    description: 'Generate a Slack-formatted security alert message with color-coded attachment, grade, and critical findings. For Slack webhook integration.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'preset_apply',
    description: 'Apply a rule pack preset for your tech stack (nextjs, django, rails, spring, aws, gcp, azure, api, mobile, fullstack). Reduces noise by enabling only relevant rules.',
    inputSchema: {
      type: 'object',
      properties: {
        preset: { type: 'string', description: 'Preset name: nextjs, django, rails, spring, aws, gcp, azure, api, mobile, fullstack' },
        dir: { type: 'string', description: 'Project directory. Defaults to cwd.' },
      },
      required: ['preset'],
    },
  },
  {
    name: 'interactive_dashboard',
    description: 'Generate a beautiful terminal dashboard with ASCII art grade meter, severity bars, risk gauge, category matrix, and top findings. For CLI display.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'privacy_audit',
    description: 'Inventory all PII collection, storage, and transmission in the codebase. Shows what personal data is collected, where it is stored, where it is sent, and what consent/encryption/retention mechanisms exist. GDPR/CCPA compliance check.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'network_audit',
    description: 'Map every outbound HTTP/HTTPS call in the codebase. Shows all external endpoints, flags unknown/suspicious domains. Privacy: shows exactly where your data goes.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'ai_data_guard',
    description: 'Detect user data (PII, secrets) sent to AI/LLM APIs without redaction. Catches the #1 privacy risk with AI agents: user data leaking to OpenAI/Anthropic/Gemini as part of prompts.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'generate_privacy_policy',
    description: 'Auto-generate a privacy policy (markdown) from code analysis. Detects what PII is collected, where it is stored, what third-party services are used, and what consent/encryption/retention mechanisms exist. GDPR/CCPA ready. Must be reviewed by legal before publication.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'generate_csp',
    description: 'Auto-generate a Content-Security-Policy header from code analysis. Scans HTML/JS files for external script/style/image sources and builds a CSP with only the domains your code actually uses. Returns CSP header value and Helmet config.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'ai_firewall',
    description: 'AI Firewall — inspect a prompt BEFORE sending to an LLM. Blocks prompt injection, jailbreaks, secret access requests, data exfiltration, and redacts PII. Returns verdict (block/redact/warn/allow) with threat details.',
    inputSchema: {
      type: 'object',
      properties: {
        prompt: { type: 'string', description: 'The prompt to inspect before sending to the LLM.' },
      },
      required: ['prompt'],
    },
  },
  {
    name: 'agent_guard',
    description: 'Check if an AI agent action is safe. Validates file access (blocks .env, secrets, .ssh), command execution (blocks rm -rf, sudo), and network access (blocks metadata services, internal IPs). Returns allowed/blocked with violations.',
    inputSchema: {
      type: 'object',
      properties: {
        type: { type: 'string', description: 'Action type: file_read, file_write, file_delete, exec, network' },
        path: { type: 'string', description: 'File path (for file operations)' },
        command: { type: 'string', description: 'Command to execute (for exec)' },
        url: { type: 'string', description: 'URL to access (for network)' },
      },
      required: ['type'],
    },
  },
  {
    name: 'exfil_check',
    description: 'Exfiltration Firewall — check if data contains PII or secrets before sending it externally. Blocks if credit cards, API keys, SSNs, or private keys are detected. Returns sanitized data if PII found.',
    inputSchema: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'The data to check before sending externally.' },
        destination: { type: 'string', description: 'Where the data is being sent (URL or service).' },
      },
      required: ['data'],
    },
  },
  {
    name: 'dep_firewall',
    description: 'Dependency Firewall — check a package name before npm/pip install. Detects malicious package names, typosquats, and suspicious patterns. Run BEFORE installing any package.',
    inputSchema: {
      type: 'object',
      properties: {
        package: { type: 'string', description: 'Package name to check (e.g. "lodash", "reactt")' },
      },
      required: ['package'],
    },
  },
  {
    name: 'threat_model',
    description: 'Generate a threat model for the project. Identifies attack surfaces, threat actors, attack vectors, and mitigation recommendations based on code analysis.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'output_guard',
    description: 'Sanitize an AI response for PII and secrets BEFORE showing it to the user. Catches secrets, API keys, PII, env var dumps, and sensitive file paths that leak into AI output.',
    inputSchema: {
      type: 'object',
      properties: {
        response: { type: 'string', description: 'The AI response text to sanitize.' },
      },
      required: ['response'],
    },
  },
  {
    name: 'env_lock',
    description: 'Lock environment variables — hide all secrets (API keys, tokens, passwords) from the AI. Returns list of protected variables. Even if AI is jailbroken, it cannot read locked env vars.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'self_check',
    description: 'Check if VibeGuard itself has been tampered with. Verifies all modules are intact, rules are loaded, config is valid, and .env is in .gitignore. Run after any AI session.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'tamper_check',
    description: 'Check if a prompt contains attempts to disable, bypass, or uninstall VibeGuard itself. Detects tampering patterns even in obfuscated or encoded prompts.',
    inputSchema: {
      type: 'object',
      properties: {
        prompt: { type: 'string', description: 'The prompt to check for tampering attempts.' },
      },
      required: ['prompt'],
    },
  },
  {
    name: 'sandbox_exec',
    description: 'Execute AI-generated code in a zero-trust sandbox. No process.env, no fs, no child_process, no network. Time-limited and memory-limited. Full audit log of every operation attempted.',
    inputSchema: {
      type: 'object',
      properties: {
        code: { type: 'string', description: 'The code to execute in sandbox.' },
        timeout: { type: 'number', description: 'Execution timeout in ms (default: 5000).' },
      },
      required: ['code'],
    },
  },
  {
    name: 'behavior_analysis',
    description: 'Analyze AI agent behavior patterns over a session. Detects trust-building, data gathering, slow exfiltration, privilege escalation, repeated blocks, tamper attempts, off-hours access, and rapid-fire patterns.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'supply_chain_audit',
    description: 'Full supply chain audit: lockfile integrity, dangerous scripts, license risks, unpinned versions, non-registry sources. Run before npm install.',
    inputSchema: DIR_SCHEMA,
  },
  {
    name: 'vault_manage',
    description: 'Encrypted in-memory secret vault. Store secrets encrypted — AI cannot read them via process.env. Use vault instead of env vars for maximum security.',
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['list', 'store', 'get', 'clear'], description: 'Vault action' },
        key: { type: 'string', description: 'Secret key (for store/get)' },
        value: { type: 'string', description: 'Secret value (for store)' },
      },
      required: ['action'],
    },
  },
  {
    name: 'audit_log',
    description: 'Tamper-proof audit trail of every AI action, blocked attempt, and secret access. Uses chained SHA-256 hashes. Export, verify, or show the log.',
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['show', 'export', 'verify', 'log'], description: 'Audit action' },
        type: { type: 'string', description: 'Filter by entry type (blocked, tamper, etc.)' },
        limit: { type: 'number', description: 'Limit number of entries' },
      },
    },
  },
  {
    name: 'pre_deploy',
    description: 'Run ALL 13 security gates before deployment. If ANY gate fails, deployment is blocked. Gates: static scan, secrets, git history, dependencies, supply chain, privacy, network, AI data guard, compliance, config, self-check, tamper check, behavioral check. Returns deploy-ready verdict.',
    inputSchema: DIR_SCHEMA,
  },
];

function summarize(result) {
  const c = result.counts;
  let s = `Grade ${result.grade} — ${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low across ${result.scannedFiles} files.`;
  if (result.engine && result.engine.mode === 'regex-only') {
    s += ' ⚠ engine: regex-only (acorn not installed) — AST/taint precision disabled; do not treat as an all-clear.';
  }
  if (result.diagnostics && result.diagnostics.degradedFileCount > 0) {
    s += ` ⚠ ${result.diagnostics.degradedFileCount} file(s) only partially analyzed (degraded coverage).`;
  }
  return s;
}

function textResult(text, isError) {
  return { content: [{ type: 'text', text }], isError: !!isError };
}

async function handleScan(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);
  if (args.saveBaseline) writeBaseline(dir, result);
  const payload = {
    grade: result.grade,
    counts: result.counts,
    scannedFiles: result.scannedFiles,
    // Coverage transparency: tell the agent whether the scan ran at full
    // precision and whether any file was only partially analyzed. An agent
    // must not treat a degraded/regex-only scan as an all-clear.
    engine: result.engine,
    diagnostics: result.diagnostics && {
      degradedFileCount: result.diagnostics.degradedFileCount,
      parseFailedFiles: result.diagnostics.parseFailedFiles,
    },
    findings: result.findings.map((f) => ({
      severity: f.severity,
      ruleId: f.ruleId,
      file: f.file,
      line: f.line,
      message: f.message,
      fix: f.fix,
    })),
  };
  return textResult(
    summarize(result) + '\n\n' + JSON.stringify(payload, null, 2)
  );
}

async function handleSuggest(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);
  if (result.findings.length === 0) {
    return textResult('No issues found — nothing to fix.');
  }
  return textResult(
    summarize(result) +
      '\n\nApply these fixes under review (VibeGuard does not edit files):\n\n' +
      renderFixPrompt(result)
  );
}

async function handleVerify(args) {
  const dir = args.dir || process.cwd();
  const res = verify(dir);
  if (!res.hasBaseline) {
    return textResult(
      'No baseline found. Run scan_project with saveBaseline=true before fixing to enable a before/after diff.\n\n' +
        summarize(res.current)
    );
  }
  const lines = [];
  lines.push(
    `${res.resolved.length} resolved, ${res.remaining.length} remaining, ${res.introduced.length} new. Current ${summarize(res.current)}`
  );
  lines.push('');
  for (const f of res.resolved) lines.push(`RESOLVED  ${f.file}:${f.line} [${f.ruleId}]`);
  for (const f of res.remaining) lines.push(`REMAINING ${f.file}:${f.line} [${f.ruleId}]`);
  for (const f of res.introduced) lines.push(`NEW       ${f.file}:${f.line} [${f.ruleId}]`);
  return textResult(lines.join('\n'));
}

const HOTSPOT_RE = /(auth|login|signin|signup|register|password|session|token|jwt|payment|billing|checkout|charge|invoice|admin|role|permission|acl|account|user|profile|order|route|controller|api|middleware|upload|webhook)/i;

async function handleReviewHotspots(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);

  // Hotspot files: those with heuristic/auth findings, plus files named like a
  // security-sensitive area.
  const fromFindings = new Set(
    result.findings
      .filter((f) => /^(auth|idor|backdoor|upload|ratelimit|taint|web|supabase)\./.test(f.ruleId))
      .map((f) => f.file)
  );
  const hotspots = new Set(fromFindings);
  for (const f of result.findings) if (HOTSPOT_RE.test(f.file)) hotspots.add(f.file);

  const reviewList = result.findings
    .filter((f) => f.confidence !== 'high')
    .map((f) => `- ${f.file}:${f.line} [${f.ruleId}] ${f.message}`)
    .slice(0, 40);

  const checklist = [
    'For EACH mutating route/endpoint: is there an authentication AND an authorization check? Who can call it?',
    'For EACH data read/write using an id from the request: is ownership verified (record belongs to req.user)? (IDOR)',
    'Payments/amounts/quantities: can the client tamper with price, total, currency, or quantity? Is the amount re-derived server-side?',
    'Any hardcoded credential comparison, magic token, or `if (user === "admin")` style bypass? (backdoor)',
    'Is input validated (type, range, length) before use? Any mass-assignment (spreading req.body into a model)?',
    'Access control: are admin-only actions actually gated, or only hidden in the UI?',
    'Secrets/config: anything sensitive logged, returned in a response, or sent to the client?',
    'State-changing GETs / missing CSRF protection on cookie-authenticated mutations?',
  ];

  const text =
    summarize(result) +
    `\n\nHOTSPOT FILES to review manually (regex cannot judge logic/authz):\n` +
    (hotspots.size ? [...hotspots].map((f) => `- ${f}`).join('\n') : '- (none obvious; review routes and data-access code)') +
    `\n\nVibeGuard "review" findings (low/medium confidence — verify each):\n` +
    (reviewList.length ? reviewList.join('\n') : '- none') +
    `\n\nNOW DO A SEMANTIC REVIEW. Open the hotspot files and answer this checklist per file:\n` +
    checklist.map((c, i) => `${i + 1}. ${c}`).join('\n') +
    `\n\nReport concrete issues with file:line and a fix. Be honest about what you could not verify.`;

  return textResult(text);
}

async function handleGuardAction(args) {
  const { inspectAction } = require('./action-guard');
  const verdict = inspectAction(args, { trustedHosts: args.trustedHosts });
  const head = verdict.blocked
    ? `🛑 BLOCKED — ${verdict.reason}`
    : verdict.action === 'warn'
      ? `⚠ WARN — ${verdict.reason}`
      : '✓ ALLOW — no secret/PII exfiltration or dangerous action detected.';
  return textResult(head + '\n\n' + JSON.stringify(verdict, null, 2));
}

async function handleAgentScan(args) {
  const dir = args.dir || process.cwd();
  const { agentScan } = require('./agent-scan');
  const result = agentScan(dir);
  const cats = Object.entries(result.categories)
    .map(([k, v]) => `${k}=${v.length}`).join(', ');
  const summary = `Agent Risk Grade ${result.grade} — ${result.counts.critical} critical, ${result.counts.high} high, ${result.counts.medium} medium across ${result.mcpServers} MCP server(s) and ${result.scannedFiles} files.` +
    (cats ? ` [${cats}]` : '') +
    (result.mcpDrifted && result.mcpDrifted.length ? ` ⚠ MCP drift: ${result.mcpDrifted.join(', ')}.` : '');
  return textResult(summary + '\n\n' + JSON.stringify(result, null, 2));
}

async function handleMcpAudit(args) {
  const dir = args.dir || process.cwd();
  const { auditMcp } = require('./mcp-audit');
  const result = auditMcp(dir, { pin: !!args.pin });
  if (!result.configFound) {
    return textResult('No MCP config found (.mcp.json / .cursor/mcp.json / .vscode/mcp.json).');
  }
  const c = result.counts;
  const summary = `MCP audit: ${result.servers.length} server(s), ${c.critical} critical, ${c.high} high, ${c.medium} medium.` +
    (result.drifted.length ? ` ⚠ definition drift on: ${result.drifted.join(', ')} (rug-pull risk — re-review).` : '');
  return textResult(summary + '\n\n' + JSON.stringify(result, null, 2));
}

async function handleScanUrl(args) {
  if (!args.url) return textResult('scan_url requires a "url" argument.', true);
  let res;
  try {
    res = await scanUrl(args.url);
  } catch (err) {
    return textResult(`Could not scan URL: ${err && err.message ? err.message : err}`, true);
  }
  const findings = sortFindings(res.findings);
  const { grade, counts } = computeGrade(findings);
  const payload = {
    url: res.url,
    status: res.status,
    grade,
    counts,
    findings: findings.map((f) => ({
      severity: f.severity,
      ruleId: f.ruleId,
      message: f.message,
      fix: f.fix,
    })),
  };
  return textResult(
    `${res.url} (HTTP ${res.status}) — grade ${grade}, ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low.\n\n` +
      JSON.stringify(payload, null, 2)
  );
}

// ---------------------------------------------------------------------------
// NEW TOOL HANDLERS (34 tools)
// ---------------------------------------------------------------------------

const { execSync } = require('child_process');
const { renderSarif, renderHtml } = require('./report');
const { allRules: getAllRules } = require('./rules');
const { suggestFixes: autoFix } = require('./autofix');

async function handleCheckCode(args) {
  const code = args.code || '';
  const lang = args.language || 'js';
  const fakePath = `snippet.${lang}`;
  const { scanFileContent } = require('./scanner');
  const findings = scanFileContent(fakePath, fakePath, code, null);
  if (findings.length === 0) return textResult('No issues found in the code snippet.');
  return textResult(JSON.stringify(findings.map(f => ({ ruleId: f.ruleId, severity: f.severity, line: f.line, message: f.message, fix: f.fix })), null, 2));
}

async function handleScanStaged(args) {
  const dir = args.dir || process.cwd();
  let staged;
  try { staged = execSync('git diff --cached --name-only --diff-filter=ACM', { cwd: dir, encoding: 'utf8' }).trim().split('\n').filter(Boolean); }
  catch { return textResult('Not a git repo or no staged changes.'); }
  if (staged.length === 0) return textResult('No staged files to scan.');
  const { scan } = require('./scanner');
  const all = scan(dir);
  const stagedSet = new Set(staged);
  const stagedFindings = all.findings.filter(f => stagedSet.has(f.file));
  return textResult(`${stagedFindings.length} findings in ${staged.length} staged files.\n\n` + JSON.stringify(stagedFindings.map(f => ({ file: f.file, line: f.line, ruleId: f.ruleId, severity: f.severity, message: f.message, fix: f.fix })), null, 2));
}

async function handleScanDeps(args) {
  const dir = args.dir || process.cwd();
  const { scanCVEs } = require('./cve-intel');
  const result = await scanCVEs(dir);
  return textResult(`Checked ${result.checked} packages. ${result.findings.length} vulnerabilities found.\n\n` + JSON.stringify(result.findings, null, 2));
}

async function handleScanSecrets(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);
  const secrets = result.findings.filter(f => f.ruleId.startsWith('secret.') || f.ruleId.startsWith('keys.'));
  return textResult(`${secrets.length} secret findings.\n\n` + JSON.stringify(secrets.map(f => ({ file: f.file, line: f.line, ruleId: f.ruleId, severity: f.severity, message: f.message })), null, 2));
}

async function handleSlopsquat(args) {
  const dir = args.dir || process.cwd();
  const { walk } = require('./scanner');
  const files = walk(dir, []);
  const { scanSlopsquat } = require('./slopsquat');
  const result = await scanSlopsquat(dir, files);
  return textResult(`Checked ${result.checked} imports. ${result.findings.length} suspicious packages.\n\n` + JSON.stringify(result.findings.map(f => ({ ruleId: f.ruleId, title: f.title, message: f.message, fix: f.fix })), null, 2));
}

async function handleCompliance(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);
  const { generateComplianceReport } = require('./compliance');
  const report = generateComplianceReport(result.findings, args.framework);
  return textResult(JSON.stringify(report, null, 2));
}

async function handleSarif(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);
  const sarif = renderSarif(result);
  return textResult(JSON.stringify(sarif, null, 2));
}

async function handleFixCode(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);
  if (result.findings.length === 0) return textResult('No issues to fix.');
  const { computeAutoFixes } = require('./autofix');
  const autoChanges = computeAutoFixes(dir, result);
  const autoFileSet = new Set(autoChanges.map(c => c.file));
  const patches = result.findings.map(f => {
    const isAuto = autoFileSet.has(f.file) || (f.fix && /process\.env|console\.error|vibeguard:/.test(f.fix));
    return {
      file: f.file,
      line: f.line,
      ruleId: f.ruleId,
      severity: f.severity,
      type: isAuto ? 'exactEdit' : 'manualFix',
      fix: f.fix || 'No automated fix available — manual review required.',
      verify: `vibeguard verify --baseline ${f.fingerprint || ''}`,
    };
  });
  return textResult(JSON.stringify({
    agent: 'vibeguard.v1',
    summary: summarize(result),
    patches,
    verify: 'After applying, run: vibeguard verify',
  }, null, 2));
}

async function handleSecureThis(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);
  const plan = {
    step1_scan: summarize(result),
    step2_fixes: renderFixPrompt(result),
    step3_verify: 'After applying fixes, run: vibeguard verify — it will compare against the baseline and report resolved/remaining/new.',
    step4_rollback: 'If verify introduces new issues, run: vibeguard rollback to restore the pre-fix state.',
  };
  return textResult(JSON.stringify(plan, null, 2));
}

async function handleAuditConfig(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);
  const configFindings = result.findings.filter(f =>
    f.file && (f.file.includes('.env') || f.file.includes('next.config') || f.file.includes('docker-compose') || f.file.includes('Dockerfile') || f.file.includes('.github/workflows') || f.file.includes('vercel.json') || f.file.includes('netlify.toml') || f.file.includes('k8s') || f.file.includes('terraform'))
  );
  return textResult(`${configFindings.length} config issues.\n\n` + JSON.stringify(configFindings.map(f => ({ file: f.file, line: f.line, ruleId: f.ruleId, message: f.message, fix: f.fix })), null, 2));
}

async function handleGeneratePolicy(args) {
  const type = args.type || 'csp';
  const templates = {
    csp: "Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none';",
    cors: "const allowedOrigins = ['https://yourdomain.com'];\napp.use(cors({ origin: (origin, cb) => { if (!origin || allowedOrigins.includes(origin)) cb(null, true); else cb(new Error('Not allowed by CORS')); }, credentials: true }));",
    rls: "CREATE POLICY \"users_select_own\" ON users FOR SELECT USING (auth.uid() = id);\nCREATE POLICY \"users_update_own\" ON users FOR UPDATE USING (auth.uid() = id);\nCREATE POLICY \"users_delete_own\" ON users FOR DELETE USING (auth.uid() = id);",
    'rate-limit': "const rateLimit = require('express-rate-limit');\napp.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false }));",
  };
  return textResult(templates[type] || 'Unknown policy type.');
}

async function handleReviewPr(args) {
  const dir = args.dir || process.cwd();
  const base = args.base || 'main';
  let diffFiles;
  try { diffFiles = execSync(`git diff ${base} --name-only`, { cwd: dir, encoding: 'utf8' }).trim().split('\n').filter(Boolean); }
  catch { return textResult('Not a git repo or no diff available.'); }
  const result = scan(dir);
  const diffSet = new Set(diffFiles);
  const prFindings = result.findings.filter(f => diffSet.has(f.file));
  return textResult(`${prFindings.length} findings in ${diffFiles.length} changed files.\n\n` + JSON.stringify(prFindings.map(f => ({ file: f.file, line: f.line, ruleId: f.ruleId, severity: f.severity, message: f.message, fix: f.fix })), null, 2));
}

async function handleScanHistory(args) {
  const dir = args.dir || process.cwd();
  const { scanHistory } = require('./history');
  let findings;
  try { findings = scanHistory(dir); }
  catch { return textResult('Not a git repo or git history not available.'); }
  return textResult(`${findings.length} findings in git history.\n\n` + JSON.stringify(findings.map(f => ({ commit: f.commit, file: f.file, line: f.line, ruleId: f.ruleId, message: f.message })), null, 2));
}

async function handleAnalyzeDataflow(args) {
  const fs = require('fs');
  const path = require('path');
  const file = args.file;
  if (!file) return textResult('analyze_dataflow requires a "file" argument.', true);
  const abs = path.resolve(file);
  if (!fs.existsSync(abs)) return textResult(`File not found: ${abs}`, true);
  const content = fs.readFileSync(abs, 'utf8');
  const { scanFileContent } = require('./scanner');
  const findings = scanFileContent(abs, path.basename(abs), content, null);
  const taintFindings = findings.filter(f => f.ruleId.includes('taint') || f.ruleId.includes('injection') || f.ruleId.includes('eval') || f.ruleId.includes('exec'));
  return textResult(`${taintFindings.length} taint/dataflow findings.\n\n` + JSON.stringify(taintFindings.map(f => ({ line: f.line, ruleId: f.ruleId, message: f.message, fix: f.fix })), null, 2));
}

async function handleCrossFileTaint(args) {
  const dir = args.dir || process.cwd();
  const { analyzeCrossFileTaint } = require('./crosstaint');
  let findings;
  try { findings = analyzeCrossFileTaint(dir); }
  catch { return textResult('Cross-file taint analysis requires acorn (optional dependency).'); }
  return textResult(`${findings.length} cross-file taint findings.\n\n` + JSON.stringify(findings.map(f => ({ file: f.file, line: f.line, ruleId: f.ruleId, message: f.message })), null, 2));
}

async function handleCheckCommand(args) {
  const cmd = args.command || '';
  const risks = [];
  if (/\bcurl\b.*\|\s*(?:sh|bash)/i.test(cmd)) risks.push({ risk: 'critical', msg: 'Pipe to bash — arbitrary code execution' });
  if (/chmod\s+777/i.test(cmd)) risks.push({ risk: 'low', msg: 'chmod 777 — world-writable' });
  if (/rm\s+-rf?\s+(?:\/|~|\.\.\/\.\.)/i.test(cmd)) risks.push({ risk: 'high', msg: 'rm -rf on root/parent — filesystem destruction' });
  if (/sudo\s+--?password/i.test(cmd)) risks.push({ risk: 'high', msg: 'sudo with password on command line' });
  if (/\beval\b/i.test(cmd)) risks.push({ risk: 'high', msg: 'eval in command — code injection' });
  if (risks.length === 0) return textResult('No security risks detected in the command.');
  return textResult(JSON.stringify(risks, null, 2));
}

async function handleScanConfigChange(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);
  const configFindings = result.findings.filter(f => f.file && /\.(?:env|json|ya?ml|toml|ini|conf|config)$/i.test(f.file));
  return textResult(`${configFindings.length} config-related findings.\n\n` + JSON.stringify(configFindings.map(f => ({ file: f.file, line: f.line, ruleId: f.ruleId, message: f.message })), null, 2));
}

async function handlePosture(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);
  const { walk } = require('./scanner');
  const files = walk(dir, []);
  const { buildAuthCoverage } = require('./engine');
  const auth = buildAuthCoverage(dir, files);
  return textResult(JSON.stringify({
    grade: result.grade,
    counts: result.counts,
    scannedFiles: result.scannedFiles,
    authCoverage: auth.coverage + '% (' + auth.protectedRoutes + '/' + auth.totalRoutes + ' routes protected)',
    unprotectedRoutes: auth.unprotected.length,
    topRiskyFiles: [...new Set(result.findings.map(f => f.file))].slice(0, 10),
    ruleCoverage: allRules().length + ' rules active',
  }, null, 2));
}

async function handleExplainRemediation(args) {
  const ruleId = args.ruleId;
  if (!ruleId) return textResult('explain_remediation requires a "ruleId" argument.', true);
  const rule = allRules().find(r => r.id === ruleId);
  if (!rule) return textResult(`Unknown rule: ${ruleId}`, true);
  return textResult(JSON.stringify({
    id: rule.id,
    severity: rule.severity,
    confidence: rule.confidence,
    title: rule.title,
    message: rule.message,
    fix: rule.fix,
    owasp: rule.owasp,
    cwe: rule.cwe,
  }, null, 2));
}

async function handleScanFile(args) {
  const fs = require('fs');
  const path = require('path');
  const file = args.file;
  if (!file) return textResult('scan_file requires a "file" argument.', true);
  const abs = path.resolve(file);
  if (!fs.existsSync(abs)) return textResult(`File not found: ${abs}`, true);
  const content = fs.readFileSync(abs, 'utf8');
  const { scanFileContent } = require('./scanner');
  const findings = scanFileContent(abs, path.basename(abs), content, null);
  return textResult(`${findings.length} findings in ${path.basename(abs)}.\n\n` + JSON.stringify(findings.map(f => ({ line: f.line, ruleId: f.ruleId, severity: f.severity, message: f.message, fix: f.fix })), null, 2));
}

async function handleScanChanged(args) {
  const dir = args.dir || process.cwd();
  const { walk } = require('./scanner');
  const allFiles = walk(dir, []);
  const { getChangedFiles } = require('./engine');
  const { changed, total, cached } = getChangedFiles(dir, allFiles);
  if (changed.length === 0) return textResult(`No files changed since last scan. (${cached}/${total} cached)`);
  const result = scan(dir);
  const changedSet = new Set(changed.map(f => path.relative(dir, f)));
  const changedFindings = result.findings.filter(f => changedSet.has(f.file));
  return textResult(`${changedFindings.length} findings in ${changed.length} changed files (${cached}/${total} cached).\n\n` + JSON.stringify(changedFindings.map(f => ({ file: f.file, line: f.line, ruleId: f.ruleId, message: f.message })), null, 2));
}

async function handleStats(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);
  const byCategory = {};
  for (const f of result.findings) {
    const cat = f.ruleId.split('.')[0];
    byCategory[cat] = (byCategory[cat] || 0) + 1;
  }
  const byFile = {};
  for (const f of result.findings) {
    byFile[f.file] = (byFile[f.file] || 0) + 1;
  }
  const topFiles = Object.entries(byFile).sort((a, b) => b[1] - a[1]).slice(0, 10);
  return textResult(JSON.stringify({
    grade: result.grade,
    counts: result.counts,
    byCategory,
    topRiskyFiles: topFiles,
    totalRules: allRules().length,
    filesScanned: result.scannedFiles,
  }, null, 2));
}

async function handleDoctor(args) {
  const dir = args.dir || process.cwd();
  const { runDoctor } = require('./doctor');
  const report = runDoctor(dir);
  return textResult(JSON.stringify(report, null, 2));
}

async function handleAuthCoverage(args) {
  const dir = args.dir || process.cwd();
  const { walk } = require('./scanner');
  const files = walk(dir, []);
  const { buildAuthCoverage } = require('./engine');
  const coverage = buildAuthCoverage(dir, files);
  return textResult(JSON.stringify(coverage, null, 2));
}

async function handleDeepScan(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);
  const { walk } = require('./scanner');
  const files = walk(dir, []);
  const { buildAuthCoverage } = require('./engine');
  const auth = buildAuthCoverage(dir, files);
  const { trace } = require('./trace');
  const tr = trace(dir, result.findings);
  return textResult(JSON.stringify({
    scan: summarize(result),
    findings: result.findings.slice(0, 50).map(f => ({ file: f.file, line: f.line, ruleId: f.ruleId, severity: f.severity, message: f.message, fix: f.fix })),
    authCoverage: auth,
    behaviorTrace: tr.behavior,
    hotspots: [...new Set(result.findings.filter(f => /auth|payment|admin|upload|webhook/i.test(f.file)).map(f => f.file))].slice(0, 20),
  }, null, 2));
}

async function handleFullAudit(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);
  const { walk } = require('./scanner');
  const files = walk(dir, []);
  const { buildAuthCoverage } = require('./engine');
  const auth = buildAuthCoverage(dir, files);
  const { generateComplianceReport } = require('./compliance');
  const compliance = generateComplianceReport(result.findings);
  let cveFindings = [];
  try {
    const { scanCVEs } = require('./cve-intel');
    const cveRes = await scanCVEs(dir);
    cveFindings = cveRes.findings;
  } catch {}
  const crypto = require('crypto');
  const hash = crypto.createHash('sha256').update(JSON.stringify(result.findings)).digest('hex').slice(0, 16);
  return textResult(JSON.stringify({
    verdict: result.grade === 'A' ? 'PASS' : result.grade <= 'C' ? 'FAIL' : 'WARN',
    grade: result.grade,
    counts: result.counts,
    hash,
    authCoverage: auth.coverage + '%',
    compliance: Object.fromEntries(Object.entries(compliance).map(([k, v]) => [k, v.summary])),
    cveCount: cveFindings.length,
    totalFindings: result.findings.length,
    filesScanned: result.scannedFiles,
  }, null, 2));
}

async function handleRemediationPlan(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);
  const bySeverity = { critical: [], high: [], medium: [], low: [] };
  for (const f of result.findings) bySeverity[f.severity] = (bySeverity[f.severity] || []).concat(f);
  const plan = [];
  let priority = 1;
  for (const sev of ['critical', 'high', 'medium', 'low']) {
    for (const f of bySeverity[sev] || []) {
      plan.push({
        priority: priority++,
        severity: f.severity,
        file: f.file,
        line: f.line,
        ruleId: f.ruleId,
        fix: f.fix || 'Manual review required',
        effort: f.severity === 'critical' || f.severity === 'high' ? '30min' : '15min',
      });
    }
  }
  return textResult(JSON.stringify({ totalSteps: plan.length, plan }, null, 2));
}

async function handleVerifyRemediation(args) {
  const dir = args.dir || process.cwd();
  const result = verify(dir);
  if (!result.hasBaseline) {
    return textResult('No baseline found. Run scan_project with saveBaseline=true first.');
  }
  return textResult(JSON.stringify({
    resolved: result.resolved.length,
    remaining: result.remaining.length,
    introduced: result.introduced.length,
    resolvedList: result.resolved.map(f => ({ file: f.file, line: f.line, ruleId: f.ruleId })),
    remainingList: result.remaining.map(f => ({ file: f.file, line: f.line, ruleId: f.ruleId })),
    newList: result.introduced.map(f => ({ file: f.file, line: f.line, ruleId: f.ruleId })),
  }, null, 2));
}

async function handleRedactPII(args) {
  const text = typeof args.text === 'string' ? args.text : '';
  if (!text) return textResult('redact_pii requires a "text" argument.', true);
  const { redactText } = require('./pii');
  const res = redactText(text, { types: Array.isArray(args.types) ? args.types : undefined });
  return textResult(JSON.stringify(res, null, 2));
}

async function handleDetectPII(args) {
  const text = typeof args.text === 'string' ? args.text : '';
  if (!text) return textResult('detect_pii requires a "text" argument.', true);
  const { detectPII } = require('./pii');
  const res = detectPII(text, { types: Array.isArray(args.types) ? args.types : undefined });
  // Do not echo raw values back — return only type/severity/token/offsets.
  return textResult(JSON.stringify({
    total: res.total,
    counts: res.counts,
    types: res.types,
    matches: res.matches.map((m) => ({ type: m.type, severity: m.severity, token: m.token, start: m.start, end: m.end })),
  }, null, 2));
}

async function handleSecurePrompt(args) {
  const prompt = args.prompt || '';
  if (!prompt) return textResult('secure_prompt requires a "prompt" argument.', true);
  const { analyzePrompt } = require('./secure-prompt');
  const result = analyzePrompt(prompt);
  return textResult(JSON.stringify(result, null, 2));
}

async function handleTracePrompt(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);
  const { trace } = require('./trace');
  const tr = trace(dir, result.findings);
  return textResult(JSON.stringify({ sessions: tr.sessions, traces: tr.traces }, null, 2));
}

async function handleBehaviorAnalysis(args) {
  const dir = args.dir || process.cwd();
  const { findSessionFiles, parseSession, analyzeBehavior } = require('./trace');
  const sessionFiles = findSessionFiles(dir);
  if (sessionFiles.length === 0) return textResult('No AI session history found. Looked for: .cursor, .claude, .windsurf, .continue');
  const sessions = sessionFiles.map(parseSession);
  const allMessages = sessions.flatMap(s => s.messages);
  const analysis = analyzeBehavior(allMessages);
  return textResult(JSON.stringify({ sessions: sessions.length, ...analysis }, null, 2));
}

async function handleListRules(args) {
  let rules = allRules();
  if (args.category) rules = rules.filter(r => r.id.startsWith(args.category + '.'));
  return textResult(JSON.stringify(rules.map(r => ({ id: r.id, severity: r.severity, confidence: r.confidence, title: r.title, category: r.id.split('.')[0] })), null, 2));
}

async function handleHtmlReport(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);
  const { renderHtml } = require('./report');
  const html = renderHtml(result);
  return textResult(html);
}

async function handleRiskScore(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);
  const weights = { critical: 10, high: 5, medium: 2, low: 1 };
  let score = 0;
  for (const f of result.findings) score += weights[f.severity] || 1;
  const maxScore = result.scannedFiles * 10 || 1;
  const riskPercent = Math.min(100, Math.round((score / maxScore) * 100));
  const riskLevel = score === 0 ? 'NONE' : score < 10 ? 'LOW' : score < 30 ? 'MEDIUM' : score < 60 ? 'HIGH' : 'CRITICAL';
  const summary = {
    riskScore: score,
    riskLevel,
    riskPercent,
    filesScanned: result.scannedFiles,
    totalFindings: result.findings.length,
    grade: result.grade,
    topRisks: sortFindings(result.findings).slice(0, 5).map(f => ({
      ruleId: f.ruleId, severity: f.severity, file: f.file, line: f.line, message: f.message,
    })),
  };
  return textResult(JSON.stringify(summary, null, 2));
}

async function handleBatchFix(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);
  const { computeAutoFixes, snapshot, applyChanges } = require('./autofix');
  const changes = computeAutoFixes(dir, result);
  if (changes.length === 0) return textResult('No auto-fixable issues found.');
  snapshot(dir, changes);
  const applied = [];
  for (const c of changes) {
    try { applyChanges(dir, [c]); applied.push(`${c.file}: ${c.description}`); } catch {}
  }
  return textResult(`Auto-fixed ${applied.length} issues:\n` + applied.join('\n'));
}

async function handleIgnoreRule(args) {
  const ruleId = args.ruleId;
  if (!ruleId) return textResult('Error: ruleId required', true);
  const dir = args.dir || process.cwd();
  const configPath = path.join(dir, '.vibeguardrc.json');
  let config = {};
  try { config = JSON.parse(fs.readFileSync(configPath, 'utf8')); } catch {}
  if (!config.ignoreRules) config.ignoreRules = [];
  if (!config.ignoreRules.includes(ruleId)) config.ignoreRules.push(ruleId);
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');
  return textResult(`Rule '${ruleId}' added to ignore list in ${configPath}`);
}

async function handleBaseline(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);
  const baselinePath = path.join(dir, '.vibeguard-baseline.json');
  const baseline = {
    generatedAt: new Date().toISOString(),
    grade: result.grade,
    counts: result.counts,
    findings: result.findings.map(f => ({ ruleId: f.ruleId, file: f.file, line: f.line, fingerprint: f.fingerprint })),
  };
  fs.writeFileSync(baselinePath, JSON.stringify(baseline, null, 2) + '\n');
  return textResult(`Baseline saved to ${baselinePath} with ${baseline.findings.length} findings (grade: ${result.grade})`);
}

async function handleRuleInfo(args) {
  const ruleId = args.ruleId;
  if (!ruleId) return textResult('Error: ruleId required', true);
  const all = allRules();
  const rule = all.find(r => r.id === ruleId);
  if (!rule) return textResult(`Rule '${ruleId}' not found`, true);
  const info = {
    id: rule.id,
    severity: rule.severity,
    confidence: rule.confidence || 'high',
    message: rule.message,
    fix: rule.fix,
    cwe: rule.cwe || null,
    owasp: rule.owasp || null,
    fileFilter: rule.fileFilter ? String(rule.fileFilter) : null,
    autoFixable: require('./autofix').isAutoFixable(rule.id),
  };
  return textResult(JSON.stringify(info, null, 2));
}

async function handleSeverityMatrix(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);
  const matrix = {};
  for (const f of result.findings) {
    const cat = f.ruleId.split('.')[0];
    if (!matrix[cat]) matrix[cat] = { critical: 0, high: 0, medium: 0, low: 0 };
    matrix[cat][f.severity]++;
  }
  const sorted = Object.entries(matrix).sort((a, b) => {
    const sa = a[1].critical * 10 + a[1].high * 5 + a[1].medium * 2 + a[1].low;
    const sb = b[1].critical * 10 + b[1].high * 5 + b[1].medium * 2 + b[1].low;
    return sb - sa;
  });
  const lines = ['Category    Critical  High  Medium  Low', '──────────  ────────  ────  ──────  ───'];
  for (const [cat, counts] of sorted) {
    lines.push(`${cat.padEnd(10)}  ${String(counts.critical).padStart(8)}  ${String(counts.high).padStart(4)}  ${String(counts.medium).padStart(6)}  ${String(counts.low).padStart(3)}`);
  }
  return textResult(lines.join('\n'));
}

async function handleDependencyTree(args) {
  const dir = args.dir || process.cwd();
  const lockPath = path.join(dir, 'package-lock.json');
  try {
    const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
    const deps = lock.dependencies || {};
    const tree = {};
    for (const [name, info] of Object.entries(deps)) {
      tree[name] = {
        version: info.version,
        resolved: info.resolved ? info.resolved.split('/').pop() : null,
        integrity: info.integrity ? info.integrity.split('-')[0] : 'none',
        dev: info.dev || false,
      };
    }
    const total = Object.keys(tree).length;
    const withIntegrity = Object.values(tree).filter(d => d.integrity !== 'none').length;
    const devDeps = Object.values(tree).filter(d => d.dev).length;
    return textResult(`Dependency tree: ${total} packages (${withIntegrity} with integrity, ${devDeps} dev)\n\n` + JSON.stringify(tree, null, 2).slice(0, 4000));
  } catch {
    return textResult('No package-lock.json found or invalid. Run npm install first.');
  }
}

async function handleConfigDump(args) {
  const dir = args.dir || process.cwd();
  const configPaths = ['.vibeguardrc.json', 'vibeguard.config.json', '.vibeguard/config.json'];
  const result = {};
  for (const p of configPaths) {
    try { result[p] = JSON.parse(fs.readFileSync(path.join(dir, p), 'utf8')); } catch { result[p] = null; }
  }
  result.mcpInstalled = fs.existsSync(path.join(dir, '.mcp.json'));
  result.hookInstalled = fs.existsSync(path.join(dir, '.claude', 'settings.json'));
  result.baselineExists = fs.existsSync(path.join(dir, '.vibeguard-baseline.json'));
  return textResult(JSON.stringify(result, null, 2));
}

async function handleTrendReport(args) {
  const dir = args.dir || process.cwd();
  const baselinePath = path.join(dir, '.vibeguard-baseline.json');
  let baseline = null;
  try { baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf8')); } catch {
    return textResult('No baseline found. Run baseline tool first to start tracking trends.');
  }
  const current = scan(dir);
  const baselineFingerprints = new Set(baseline.findings.map(f => f.fingerprint));
  const currentFingerprints = new Set(current.findings.map(f => f.fingerprint));
  const resolved = [...baselineFingerprints].filter(f => !currentFingerprints.has(f));
  const newFindings = [...currentFingerprints].filter(f => !baselineFingerprints.has(f));
  const persisted = [...baselineFingerprints].filter(f => currentFingerprints.has(f));
  const trend = {
    baselineDate: baseline.generatedAt,
    currentDate: current.generatedAt,
    baselineGrade: baseline.grade,
    currentGrade: current.grade,
    baselineCount: baseline.findings.length,
    currentCount: current.findings.length,
    resolved: resolved.length,
    new: newFindings.length,
    persisted: persisted.length,
    improving: resolved.length > newFindings.length,
    newFindings: current.findings.filter(f => newFindings.has(f.fingerprint)).map(f => ({ ruleId: f.ruleId, file: f.file, line: f.line, severity: f.severity })).slice(0, 20),
  };
  return textResult(JSON.stringify(trend, null, 2));
}

async function handleScorecard(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);
  const weights = { critical: 10, high: 5, medium: 2, low: 1 };
  let score = 0;
  for (const f of result.findings) score += weights[f.severity] || 1;
  const maxScore = result.scannedFiles * 10 || 1;
  const riskPercent = Math.min(100, Math.round((score / maxScore) * 100));
  const riskLevel = score === 0 ? 'NONE' : score < 10 ? 'LOW' : score < 30 ? 'MEDIUM' : score < 60 ? 'HIGH' : 'CRITICAL';

  let compliance = {};
  try {
    const { generateComplianceReport } = require('./compliance');
    compliance = generateComplianceReport(result.findings);
  } catch {}

  const fixable = result.findings.filter(f => {
    try { return require('./autofix').isAutoFixable(f.ruleId); } catch { return false; }
  });

  const scorecard = {
    grade: result.grade,
    riskScore: score,
    riskLevel,
    riskPercent,
    filesScanned: result.scannedFiles,
    totalFindings: result.findings.length,
    counts: result.counts,
    autoFixable: fixable.length,
    compliance,
    topRisks: sortFindings(result.findings).slice(0, 10).map(f => ({
      ruleId: f.ruleId, severity: f.severity, file: f.file, line: f.line, message: f.message, cwe: f.cwe, fix: f.fix ? f.fix.slice(0, 100) : null,
    })),
    generatedAt: new Date().toISOString(),
  };
  return textResult(JSON.stringify(scorecard, null, 2));
}

async function handlePRComment(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);
  const { renderPRComment } = require('./dashboard');
  return textResult(renderPRComment(result));
}

async function handleSlackNotify(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);
  const c = result.counts;
  const color = c.critical > 0 ? '#FF0000' : c.high > 0 ? '#FFA500' : c.medium > 0 ? '#FFFF00' : '#00FF00';
  const emoji = result.grade === 'A' || result.grade === 'B' ? ':white_check_mark:' : result.grade === 'F' ? ':x:' : ':warning:';
  const attachment = {
    color,
    title: `${emoji} VibeGuard Security Scan`,
    fields: [
      { title: 'Grade', value: result.grade, short: true },
      { title: 'Risk Score', value: String(c.critical * 10 + c.high * 5 + c.medium * 2 + c.low), short: true },
      { title: 'Critical', value: String(c.critical), short: true },
      { title: 'High', value: String(c.high), short: true },
      { title: 'Medium', value: String(c.medium), short: true },
      { title: 'Low', value: String(c.low), short: true },
    ],
    footer: 'VibeGuard Security Scanner',
    ts: Math.floor(Date.now() / 1000),
  };
  if (c.critical > 0) {
    const top = sortFindings(result.findings).filter(f => f.severity === 'critical').slice(0, 3);
    attachment.fields.push({ title: 'Top Critical Findings', value: top.map(f => `• \`${f.ruleId}\` — ${f.file}:${f.line}`).join('\n'), short: false });
  }
  const payload = { text: `Security scan complete: Grade ${result.grade} (${result.findings.length} findings)`, attachments: [attachment] };
  return textResult(JSON.stringify(JSON.stringify(payload, null, 2)));
}

async function handlePresetApply(args) {
  const presetName = args.preset;
  const dir = args.dir || process.cwd();
  const { getPreset, listPresets } = require('./presets');
  if (!presetName) {
    const list = listPresets();
    return textResult('Available presets:\n' + list.map(p => `  ${p.key.padEnd(12)} ${p.name}`).join('\n'));
  }
  const preset = getPreset(presetName);
  if (!preset) return textResult(`Unknown preset: ${presetName}. Available: ${Object.keys(require('./presets').PRESETS).join(', ')}`, true);
  const configPath = path.join(dir, '.vibeguardrc.json');
  let config = {};
  try { config = JSON.parse(fs.readFileSync(configPath, 'utf8')); } catch {}
  config.preset = presetName;
  config.presetName = preset.name;
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');
  return textResult(`Applied preset: ${preset.name}\n${preset.description}\nConfig written to ${configPath}`);
}

async function handleDashboard(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);
  const { renderDashboard } = require('./dashboard');
  return textResult(renderDashboard(result));
}

async function handlePrivacyAudit(args) {
  const dir = args.dir || process.cwd();
  const { walk } = require('./scanner');
  const { auditPrivacy, renderPrivacyReport } = require('./privacy-audit');
  const files = walk(dir, []);
  const inventory = auditPrivacy(dir, files);
  return textResult(renderPrivacyReport(inventory));
}

async function handleNetworkAudit(args) {
  const dir = args.dir || process.cwd();
  const { walk } = require('./scanner');
  const { auditNetwork, renderNetworkReport } = require('./net-audit');
  const files = walk(dir, []);
  const result = auditNetwork(dir, files);
  return textResult(renderNetworkReport(result));
}

async function handleAIDataGuard(args) {
  const dir = args.dir || process.cwd();
  const { walk } = require('./scanner');
  const { auditAIData, renderAIGuardReport } = require('./ai-guard');
  const files = walk(dir, []);
  const result = auditAIData(dir, files);
  return textResult(renderAIGuardReport(result));
}

async function handlePrivacyPolicy(args) {
  const dir = args.dir || process.cwd();
  const { walk } = require('./scanner');
  const { generatePrivacyPolicy } = require('./policy-gen');
  const files = walk(dir, []);
  const policy = generatePrivacyPolicy(dir, files);
  return textResult(policy);
}

async function handleCSP(args) {
  const dir = args.dir || process.cwd();
  const { walk } = require('./scanner');
  const { generateCSP } = require('./policy-gen');
  const files = walk(dir, []);
  const result = generateCSP(dir, files);
  return textResult(JSON.stringify(result, null, 2));
}

async function handleAIFirewall(args) {
  const prompt = args.prompt;
  if (!prompt) return textResult('ai_firewall requires a "prompt" argument.', true);
  const { inspectPrompt, renderFirewallReport } = require('./firewall');
  const verdict = inspectPrompt(prompt);
  return textResult(renderFirewallReport(verdict));
}

async function handleAgentGuard(args) {
  const { checkAgentAction, AGENT_CONSTRAINTS } = require('./firewall');
  if (!args.type) return textResult(JSON.stringify({ constraints: AGENT_CONSTRAINTS }, null, 2));
  const result = checkAgentAction(args);
  return textResult(JSON.stringify(result, null, 2));
}

async function handleExfilCheck(args) {
  const data = args.data;
  if (!data) return textResult('exfil_check requires a "data" argument.', true);
  const { checkExfiltration } = require('./firewall');
  const result = checkExfiltration(data, args.destination);
  return textResult(JSON.stringify(result, null, 2));
}

async function handleDepFirewall(args) {
  const pkg = args.package;
  if (!pkg) return textResult('dep_firewall requires a "package" argument.', true);
  const { checkPackage } = require('./firewall');
  const result = checkPackage(pkg);
  return textResult(JSON.stringify(result, null, 2));
}

async function handleThreatModel(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);
  const { auditPrivacy } = require('./privacy-audit');
  const { auditNetwork } = require('./net-audit');
  const { walk } = require('./scanner');
  const files = walk(dir, []);
  const privacy = auditPrivacy(dir, files);
  const network = auditNetwork(dir, files);

  const attackSurfaces = [];
  const threats = [];
  const mitigations = [];

  if (result.findings.some(f => f.ruleId.startsWith('secret.'))) {
    attackSurfaces.push('Hardcoded secrets in source code');
    threats.push({ actor: 'Attacker with repo access', vector: 'Read secrets from code', severity: 'critical', impact: 'Credential theft' });
    mitigations.push('Move all secrets to environment variables. Run: vibeguard fix --apply');
  }
  if (result.findings.some(f => f.ruleId.includes('injection'))) {
    attackSurfaces.push('User input handlers (injection points)');
    threats.push({ actor: 'External attacker', vector: 'SQL/command injection', severity: 'high', impact: 'Data breach, RCE' });
    mitigations.push('Use parameterized queries. Validate all input.');
  }
  if (result.findings.some(f => f.ruleId.includes('auth'))) {
    attackSurfaces.push('Authentication endpoints');
    threats.push({ actor: 'External attacker', vector: 'Auth bypass, brute force', severity: 'high', impact: 'Account takeover' });
    mitigations.push('Add rate limiting. Verify JWT. Use bcrypt.');
  }
  if (network.summary.unknownDomains > 0) {
    attackSurfaces.push('Outbound HTTP calls to unknown domains');
    threats.push({ actor: 'Malicious third party', vector: 'Intercept outbound data', severity: 'medium', impact: 'Data exfiltration' });
    mitigations.push('Review all unknown endpoints. Use allowlist.');
  }
  if (privacy.summary.piiFieldCount > 0) {
    attackSurfaces.push('PII collection and storage');
    threats.push({ actor: 'Insider or data broker', vector: 'Access PII without consent', severity: 'high', impact: 'Privacy violation, GDPR fines' });
    mitigations.push('Implement consent. Encrypt PII. Define retention policy.');
  }

  const model = {
    generatedAt: new Date().toISOString(),
    grade: result.grade,
    attackSurfaces,
    threats,
    mitigations,
    riskScore: result.counts.critical * 10 + result.counts.high * 5 + result.counts.medium * 2 + result.counts.low,
    summary: {
      totalThreats: threats.length,
      criticalThreats: threats.filter(t => t.severity === 'critical').length,
      mitigations: mitigations.length,
    },
  };
  return textResult(JSON.stringify(model, null, 2));
}

async function handleOutputGuard(args) {
  const response = args.response;
  if (!response) return textResult('output_guard requires a "response" argument.', true);
  const { sanitizeAIResponse } = require('./interceptor');
  const result = sanitizeAIResponse(response);
  return textResult(JSON.stringify(result, null, 2));
}

async function handleEnvLock(args) {
  const { lockEnvironment } = require('./interceptor');
  const lock = lockEnvironment();
  return textResult(JSON.stringify({
    locked: true,
    hiddenCount: lock.hiddenCount,
    totalKeys: lock.totalKeys,
    hiddenKeys: lock.hiddenKeys,
  }, null, 2));
}

async function handleSelfCheck(args) {
  const dir = args.dir || process.cwd();
  const fs = require('fs');
  const path = require('path');
  const checks = [];
  let ok = true;
  const modules = ['firewall', 'interceptor', 'scanner', 'pii', 'mcp-server', 'autofix'];
  for (const mod of modules) {
    try { require('./' + mod); checks.push({ module: mod, status: 'intact' }); }
    catch { checks.push({ module: mod, status: 'corrupted' }); ok = false; }
  }
  try { const r = require('./rules'); checks.push({ module: 'rules', status: 'loaded', count: r.lineRules.length }); }
  catch { checks.push({ module: 'rules', status: 'corrupted' }); ok = false; }
  const gi = path.join(dir, '.gitignore');
  checks.push({ check: 'gitignore', hasEnv: fs.existsSync(gi) ? /\.env/.test(fs.readFileSync(gi, 'utf8')) : false });
  return textResult(JSON.stringify({ allPassed: ok, checks }, null, 2));
}

async function handleTamperCheck(args) {
  const prompt = args.prompt;
  if (!prompt) return textResult('tamper_check requires a "prompt" argument.', true);
  const { detectTamper } = require('./interceptor');
  const result = detectTamper(prompt);
  return textResult(JSON.stringify(result, null, 2));
}

async function handleSandboxExec(args) {
  const code = args.code;
  if (!code) return textResult('sandbox_exec requires a "code" argument.', true);
  const { runInSandbox, renderSandboxReport } = require('./sandbox');
  const result = runInSandbox(code, { timeout: args.timeout });
  return textResult(renderSandboxReport(result));
}

async function handleBehaviorAnalysis(args) {
  const dir = args.dir || process.cwd();
  const result = scan(dir);
  const { createSession, recordEvent, analyzeSession, renderBehaviorReport } = require('./behavior');
  const session = createSession();
  for (const f of result.findings.slice(0, 50)) {
    recordEvent(session, f.ruleId.startsWith('secret.') ? 'secret_access' : f.ruleId.includes('injection') ? 'exec' : 'file_read', { ruleId: f.ruleId });
  }
  recordEvent(session, 'network', { detail: 'scan complete' });
  const analysis = analyzeSession(session);
  return textResult(renderBehaviorReport(analysis));
}

async function handleSupplyAudit(args) {
  const dir = args.dir || process.cwd();
  const { auditLockfile, auditPackageJson } = require('./supply-firewall');
  const lockResult = auditLockfile(dir);
  const pkgResult = auditPackageJson(dir);
  return textResult(JSON.stringify({ lockfile: lockResult, packageJson: pkgResult }, null, 2));
}

async function handleVaultManage(args) {
  const vault = require('./vault');
  const action = args.action || 'list';
  if (action === 'list') return textResult(vault.renderVaultReport());
  if (action === 'store') {
    if (!args.key || !args.value) return textResult('store requires key and value', true);
    vault.store(args.key, args.value);
    return textResult(`Stored "${args.key}" in encrypted vault`);
  }
  if (action === 'get') {
    if (!args.key) return textResult('get requires key', true);
    const value = vault.get(args.key, { purpose: 'mcp' });
    return textResult(value ? `Decrypted: ${value.slice(0, 10)}...` : 'Key not found');
  }
  if (action === 'clear') { vault.clear(); return textResult('Vault cleared'); }
  return textResult('Unknown action: ' + action, true);
}

async function handleAuditLog(args) {
  const audit = require('./audit-trail');
  const action = args.action || 'show';
  if (action === 'show') return textResult(audit.renderAuditReport());
  if (action === 'export') return textResult(audit.exportLog());
  if (action === 'verify') {
    const v = audit.verifyChain();
    return textResult(JSON.stringify(v, null, 2));
  }
  if (action === 'log') {
    const entries = audit.getEntries({ type: args.type, limit: args.limit });
    return textResult(JSON.stringify(entries, null, 2));
  }
  return textResult('Unknown action: ' + action, true);
}

async function handlePreDeploy(args) {
  const dir = args.dir || process.cwd();
  const { runPreDeployGate, renderPreDeployReport } = require('./pre-deploy');
  const summary = runPreDeployGate(dir, { strict: args.strict });
  return textResult(renderPreDeployReport(summary));
}

async function main() {
  // ─── AUTO-ACTIVATE ALL PROTECTION LAYERS ON STARTUP ────────────────
  const audit = require('./audit-trail');
  const { lockEnvironment } = require('./interceptor');
  const { createSession, recordEvent, analyzeSession } = require('./behavior');

  // Layer 7: Lock environment variables
  const envLock = lockEnvironment();
  audit.log('system', { event: 'env_locked', hidden: envLock.hiddenCount });

  // Layer 13: Audit trail is active
  audit.log('system', { event: 'mcp_server_start', version: require('../package.json').version });

  // Layer 10: Behavioral analysis session
  const behaviorSession = createSession();

  // Layer 4: Runtime interceptor (activate silently, don't break existing code)
  let interceptorActive = false;
  try {
    const interceptor = require('./interceptor');
    // We don't call activate() here because it wraps global fetch which
    // could break MCP transport. Instead, we use check functions manually
    // in every tool handler below.
    interceptorActive = true;
    audit.log('system', { event: 'interceptor_loaded' });
  } catch (e) {
    audit.log('warning', { event: 'interceptor_load_failed', error: e.message });
  }

  process.stderr.write(`vibeguard MCP server: 13 layers active (env lock: ${envLock.hiddenCount} vars hidden, interceptor: ${interceptorActive ? 'ready' : 'off'}, audit: recording, behavior: monitoring)\n`);

  const server = new Server(
    { name: 'vibeguard', version: require('../package.json').version },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: args = {} } = req;
    const startTime = Date.now();

    // ─── LAYER 2: AI FIREWALL — auto-inspect any prompt argument ─────
    if (args.prompt && typeof args.prompt === 'string') {
      try {
        const { inspectPrompt } = require('./firewall');
        const verdict = inspectPrompt(args.prompt);
        recordEvent(behaviorSession, 'ai_api', { tool: name, action: verdict.action });
        audit.log('ai_firewall', { tool: name, action: verdict.action, threats: verdict.threatCount });
        if (verdict.action === 'block') {
          recordEvent(behaviorSession, 'blocked', { tool: name, reason: verdict.reason });
          return textResult(`VibeGuard AI Firewall BLOCKED this request:\n${verdict.reason}\n\nThreats: ${JSON.stringify(verdict.findings, null, 2)}`);
        }
        if (verdict.action === 'redact') {
          args.prompt = verdict.sanitizedPrompt;
        }
      } catch {}
    }

    // ─── LAYER 8: TAMPER DETECTION — check for VibeGuard bypass ──────
    if (args.prompt || args.code || args.response || args.data) {
      const checkText = [args.prompt, args.code, args.response, args.data].filter(Boolean).join(' ');
      try {
        const { detectTamper } = require('./interceptor');
        const tamper = detectTamper(checkText);
        if (tamper.detected) {
          recordEvent(behaviorSession, 'tamper', { tool: name, threat: tamper.threat });
          audit.log('tamper_blocked', { tool: name, threat: tamper.threat, severity: tamper.severity });
          return textResult(`VibeGuard SELF-PROTECTION blocked this request:\nTampering attempt detected: ${tamper.threat}\n\nThis request tried to disable, bypass, or uninstall VibeGuard security controls.`);
        }
      } catch {}
    }

    try {
      let result;

      if (name === 'scan_project') result = await handleScan(args);
      else if (name === 'suggest_fixes') result = await handleSuggest(args);
      else if (name === 'verify_fixes') result = await handleVerify(args);
      else if (name === 'scan_url') result = await handleScanUrl(args);
      else if (name === 'review_hotspots') result = await handleReviewHotspots(args);
      else if (name === 'check_code') result = await handleCheckCode(args);
      else if (name === 'scan_staged') result = await handleScanStaged(args);
      else if (name === 'scan_dependencies' || name === 'cve_intel') result = await handleScanDeps(args);
      else if (name === 'scan_secrets') result = await handleScanSecrets(args);
      else if (name === 'check_package_health' || name === 'scan_hallucinated_packages') result = await handleSlopsquat(args);
      else if (name === 'redact_pii') result = await handleRedactPII(args);
      else if (name === 'detect_pii') result = await handleDetectPII(args);
      else if (name === 'compliance_report') result = await handleCompliance(args);
      else if (name === 'export_sarif') result = await handleSarif(args);
      else if (name === 'fix_code') result = await handleFixCode(args);
      else if (name === 'secure_this') result = await handleSecureThis(args);
      else if (name === 'audit_config') result = await handleAuditConfig(args);
      else if (name === 'generate_policy') result = await handleGeneratePolicy(args);
      else if (name === 'review_pr') result = await handleReviewPr(args);
      else if (name === 'scan_secrets_history') result = await handleScanHistory(args);
      else if (name === 'analyze_dataflow') result = await handleAnalyzeDataflow(args);
      else if (name === 'analyze_cross_file_dataflow') result = await handleCrossFileTaint(args);
      else if (name === 'check_command') result = await handleCheckCommand(args);
      else if (name === 'scan_config_change') result = await handleScanConfigChange(args);
      else if (name === 'repo_security_posture') result = await handlePosture(args);
      else if (name === 'explain_remediation') result = await handleExplainRemediation(args);
      else if (name === 'scan_file') result = await handleScanFile(args);
      else if (name === 'scan_changed_files') result = await handleScanChanged(args);
      else if (name === 'security_stats') result = await handleStats(args);
      else if (name === 'guardvibe_doctor') result = await handleDoctor(args);
      else if (name === 'auth_coverage') result = await handleAuthCoverage(args);
      else if (name === 'deep_scan') result = await handleDeepScan(args);
      else if (name === 'full_audit') result = await handleFullAudit(args);
      else if (name === 'remediation_plan') result = await handleRemediationPlan(args);
      else if (name === 'verify_remediation') result = await handleVerifyRemediation(args);
      else if (name === 'secure_prompt') result = await handleSecurePrompt(args);
      else if (name === 'trace_prompt') result = await handleTracePrompt(args);
      else if (name === 'behavior_analysis') result = await handleBehaviorAnalysis(args);
      else if (name === 'list_rules') result = await handleListRules(args);
      else if (name === 'generate_html_report') result = await handleHtmlReport(args);
      else if (name === 'risk_score') result = await handleRiskScore(args);
      else if (name === 'batch_fix') result = await handleBatchFix(args);
      else if (name === 'ignore_rule') result = await handleIgnoreRule(args);
      else if (name === 'baseline') result = await handleBaseline(args);
      else if (name === 'rule_info') result = await handleRuleInfo(args);
      else if (name === 'severity_matrix') result = await handleSeverityMatrix(args);
      else if (name === 'dependency_tree') result = await handleDependencyTree(args);
      else if (name === 'config_dump') result = await handleConfigDump(args);
      else if (name === 'trend_report') result = await handleTrendReport(args);
      else if (name === 'security_scorecard') result = await handleScorecard(args);
      else if (name === 'pr_comment') result = await handlePRComment(args);
      else if (name === 'slack_notify') result = await handleSlackNotify(args);
      else if (name === 'preset_apply') result = await handlePresetApply(args);
      else if (name === 'interactive_dashboard') result = await handleDashboard(args);
      else if (name === 'privacy_audit') result = await handlePrivacyAudit(args);
      else if (name === 'network_audit') result = await handleNetworkAudit(args);
      else if (name === 'ai_data_guard') result = await handleAIDataGuard(args);
      else if (name === 'mcp_audit') result = await handleMcpAudit(args);
      else if (name === 'agent_scan') result = await handleAgentScan(args);
      else if (name === 'guard_action') result = await handleGuardAction(args);
      else if (name === 'generate_privacy_policy') result = await handlePrivacyPolicy(args);
      else if (name === 'generate_csp') result = await handleCSP(args);
      else if (name === 'ai_firewall') result = await handleAIFirewall(args);
      else if (name === 'agent_guard') result = await handleAgentGuard(args);
      else if (name === 'exfil_check') result = await handleExfilCheck(args);
      else if (name === 'dep_firewall') result = await handleDepFirewall(args);
      else if (name === 'threat_model') result = await handleThreatModel(args);
      else if (name === 'output_guard') result = await handleOutputGuard(args);
      else if (name === 'env_lock') result = await handleEnvLock(args);
      else if (name === 'self_check') result = await handleSelfCheck(args);
      else if (name === 'tamper_check') result = await handleTamperCheck(args);
      else if (name === 'sandbox_exec') result = await handleSandboxExec(args);
      else if (name === 'supply_chain_audit') result = await handleSupplyAudit(args);
      else if (name === 'vault_manage') result = await handleVaultManage(args);
      else if (name === 'audit_log') result = await handleAuditLog(args);
      else if (name === 'pre_deploy') result = await handlePreDeploy(args);
      else result = textResult(`Unknown tool: ${name}`, true);

      // ─── LAYER 5: OUTPUT GUARD — auto-sanitize any text result ────
      if (result && result.content && result.content[0] && result.content[0].text) {
        try {
          const { sanitizeAIResponse } = require('./interceptor');
          const sanitized = sanitizeAIResponse(result.content[0].text);
          if (!sanitized.safe && sanitized.blockedCount > 0) {
            result = textResult(sanitized.sanitized);
            audit.log('output_guard', { tool: name, blocked: sanitized.blockedCount });
          }
        } catch {}
      }

      // ─── LAYER 13: AUDIT TRAIL — log every tool call ───────────────
      const duration = Date.now() - startTime;
      recordEvent(behaviorSession, 'file_read', { tool: name, duration });
      audit.log('tool_call', { tool: name, duration, success: !result?.isError });

      // ─── LAYER 10: BEHAVIORAL ANALYSIS — check patterns every 20 calls ─
      if (behaviorSession.events.length % 20 === 0 && behaviorSession.events.length > 0) {
        const analysis = analyzeSession(behaviorSession);
        if (analysis.patternsCount > 0) {
          audit.log('behavior_alert', { patterns: analysis.patterns.map(p => p.pattern) });
          process.stderr.write(`VibeGuard Behavioral Alert: ${analysis.patternsCount} pattern(s) detected — ${analysis.patterns.map(p => p.message).join('; ')}\n`);
        }
      }

      return result;
    } catch (err) {
      audit.log('error', { tool: name, error: err.message });
      return textResult(`VibeGuard error: ${err && err.message ? err.message : err}`, true);
    }
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(`vibeguard MCP server running on stdio — all 13 layers active\n`);
}

main().catch((err) => {
  process.stderr.write(`fatal: ${err && err.stack ? err.stack : err}\n`);
  process.exit(1);
});
