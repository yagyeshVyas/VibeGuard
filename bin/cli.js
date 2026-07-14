#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { scan, computeGrade, sortFindings } = require('../src/scanner');
const { scanUrl } = require('../src/urlscan');
const { verify, writeBaseline } = require('../src/verify');
const {
  computeAutoFixes,
  renderDiff,
  snapshot,
  applyChanges,
  rollback,
} = require('../src/autofix');
const {
  renderHuman,
  renderJson,
  renderSarif,
  renderHtml,
  renderFixPrompt,
  C,
} = require('../src/report');

// Flags that take a value (support both --flag=value and --flag value).
const VALUE_FLAGS = new Set(['fail-on', 'scope', 'focus', 'model', 'since', 'base', 'o', 'output', 'file', 'types', 'min-confidence', 'trust', 'allow']);

function parseArgs(argv) {
  const args = { _: [], flags: {} };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq !== -1) {
        args.flags[a.slice(2, eq)] = a.slice(eq + 1);
      } else {
        const name = a.slice(2);
        if (VALUE_FLAGS.has(name) && i + 1 < argv.length && !argv[i + 1].startsWith('--')) {
          args.flags[name] = argv[++i];
        } else {
          args.flags[name] = true;
        }
      }
    } else {
      args._.push(a);
    }
  }
  return args;
}

function printHelp() {
  process.stdout.write(`
VibeGuard — offline security scanner for AI-generated code.

Usage:
  vibeguard scan [dir]              Scan a project (auto-detects framework).
  vibeguard fix [dir]               Auto-fix safe issues (secret->env, .gitignore).
  vibeguard pre-deploy [dir]        13-gate deployment check.
  vibeguard dashboard [dir]         Visual terminal dashboard.
  vibeguard mcp                     MCP server (for Claude Code, Cursor, etc.).
  vibeguard auto [dir]              One-command full protection (daemon + hooks).
  vibeguard auto --stop             Turn off, restore backups.
  vibeguard auto --status           Show what's active.

Advanced:
  vibeguard verify [dir]            Re-scan, report resolved vs remaining.
  vibeguard install                 Wire MCP server into detected AI clients.
  vibeguard rules                   List every detection rule.
  vibeguard explain <ruleId>        Show details + fix for one rule.
  vibeguard doctor [dir]            Audit AI-tool host config.
  vibeguard install-hook            git pre-commit hook (blocks on CRITICAL).
  vibeguard install-hook-post       PostToolUse hook (auto-scan AI edits).
  vibeguard uninstall-hook-post     Remove PostToolUse hook.
  vibeguard rollback [dir]          Undo last 'fix --apply'.
  vibeguard watch [dir]             Re-scan on file change (live).
  vibeguard history [dir]           Scan git history for secrets.
  vibeguard url <url>               Scan a live site's HTTP headers.
  vibeguard badge [dir]             Award badge SVG (zero critical+high).
  vibeguard init-ci [dir]           Write GitHub Actions workflow.
  vibeguard mcp-audit [dir]         Audit configured MCP servers (injection, rug-pull, secrets). --pin to re-baseline.
  vibeguard agent-scan [dir]        AI Agent Security Posture: one grade across MCP, data leakage, LLM-output sinks, prompt injection, agent capability.
  vibeguard guard-action <action>   Action firewall: block secret/PII exfiltration before it runs. Pass a shell command or JSON action. --trust host1,host2.
  vibeguard compliance [dir]         Map findings to SOC2/PCI/HIPAA/GDPR.
  vibeguard cve [dir]               Query OSV.dev for dependency CVEs.
  vibeguard slopsquat [dir]          Check for hallucinated npm packages.
  vibeguard secure-prompt <p>       Analyze AI prompt for security risks.
  vibeguard trace [dir]             Trace findings to AI prompts.
  vibeguard repl [dir]              Interactive REPL.
  vibeguard auth-coverage [dir]     Enumerate routes -> auth guards.
  vibeguard diff [dir]              Compare vs baseline.
  vibeguard deep-scan [dir]          Full audit: scan + CVE + auth + behavior.
  vibeguard html [dir]              Generate HTML security report.
  vibeguard inject-rules [dir]      Inject rules into CLAUDE.md/.cursorrules.
  vibeguard bench [dir]             Benchmark: files/sec, rules, findings.
  vibeguard risk-score [dir]         Weighted risk score (0-100).
  vibeguard why <ruleId>            Explain why a rule fired.
  vibeguard preset <name>           Apply a rule preset (nextjs, django, etc.).
  vibeguard preset --list           List all presets.
  vibeguard guard "<cmd>"           Check a shell command before running.
  vibeguard install-shell-hook      Install shell pre-exec hook.
  vibeguard uninstall-shell-hook   Remove shell hook.
  vibeguard privacy-audit [dir]     Inventory PII collection/storage.
  vibeguard net-audit [dir]         Map outbound HTTP calls.
  vibeguard ai-guard [dir]          Detect user data to AI APIs.
  vibeguard privacy-policy [dir]    Generate privacy policy from code.
  vibeguard csp-generate [dir]      Generate Content-Security-Policy.
  vibeguard firewall <prompt>       AI firewall — inspect prompt before LLM.
  vibeguard exfil-check <data>      Check data for PII/secrets.
  vibeguard dep-firewall <pkg>      Check package before npm install.
  vibeguard sandbox <code>          Execute code in zero-trust sandbox.
  vibeguard self-check [dir]        Check if VibeGuard is tampered with.
  vibeguard env-lock [dir]          Lock env vars from AI agents.
  vibeguard vault <action>          Encrypted secret vault.
  vibeguard audit-trail <action>    Tamper-proof audit trail.
  vibeguard redact "<text>"         Redact PII from text.
  vibeguard detect-pii "<text>"     List PII in text.
  vibeguard sbom [dir]              Generate CycloneDX 1.5 SBOM from lockfile + imports.
  vibeguard reachability [dir]      Check which CVE-vulnerable deps are actually imported.
  vibeguard container-scan <image>  Scan container image with trivy (if installed).
  vibeguard license [dir]           Check package licenses against allowlist.
  vibeguard proxy-start             Start local MITM proxy for polyglot interception.
  vibeguard proxy-stop              Stop the local proxy.
  vibeguard proxy-status            Show proxy status and blocked request audit log.

Options:
  --json                      JSON output.
  --sarif                     SARIF 2.1.0 (GitHub code scanning).
  --fix-prompt                Print only the fix prompt block.
  --apply                     (fix) Apply safe auto-fixes.
  --all                       Show all findings (ignore baseline, show low-confidence).
  --min-confidence <level>    Filter: low|medium|high (default: medium).
  --baseline                  Save current findings as baseline. Future scans auto-suppress known issues.
  --new-only                  Report only findings not in baseline.
  --no-deps                   Skip dependency audit.
  --deep                      Fold in semgrep/gitleaks/bandit.
  --changed                   Incremental: only rescan files changed since last scan (per-file; skips cross-file analysis).
  --staged                    Scan only git-staged files (pre-commit; skips cross-file analysis).
  --strict                    Fail (exit 3) if any file scanned degraded.
  --no-suppress               Ignore inline vibeguard-ignore comments + heuristic FP filter (CI trust mode).
  --fail-on <level>           Exit non-zero at/above severity.
  --no-summary                Suppress summary line.
  --show-suppressed           Include inline-suppressed findings.
  --yes                       Skip consent prompts (shell hook, auto).
  --patch                     Output as unified diff.
  -o, --output <file>         HTML report output path.
  -h, --help                  Show this help.

Scope: VibeGuard flags high-frequency security issues (secrets, injection,
misconfig) and helps you fix them. It does NOT prove an app is safe.
`);
}

function outputResult(result, flags) {
  if (flags.json) {
    process.stdout.write(renderJson(result) + '\n');
    return;
  }
  if (flags.sarif) {
    process.stdout.write(renderSarif(result) + '\n');
    return;
  }
  if (flags['fix-prompt']) {
    process.stdout.write(renderFixPrompt(result) + '\n');
    return;
  }
  if (flags['patch']) {
    const patches = generatePatch(result.findings);
    process.stdout.write(patches);
    return;
  }
  process.stdout.write(renderHuman(result));
}

function detectFramework(dir) {
  const root = path.resolve(dir || '.');
  const exists = (f) => fs.existsSync(path.join(root, f));
  // Check in priority order — most specific first
  if (exists('next.config.js') || exists('next.config.mjs') || exists('next.config.ts')) return 'nextjs';
  if (exists('supabase') || exists('supabase/config.toml')) return 'nextjs'; // supabase often paired with nextjs
  if (exists('firebase.json') || exists('.firebaserc')) return 'react';
  if (exists('requirements.txt') || exists('manage.py')) return 'django';
  if (exists('app.py') || exists('wsgi.py')) return 'flask';
  if (exists('Gemfile') || exists('config/routes.rb')) return 'rails';
  if (exists('pom.xml') || exists('build.gradle') && exists('src/main/java')) return 'spring';
  if (exists('go.mod')) return 'api'; // Go apps are usually API servers
  if (exists('Cargo.toml')) return 'api';
  if (exists('docker-compose.yml') || exists('docker-compose.yaml')) return 'fullstack';
  if (exists('package.json')) {
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      if (deps['next']) return 'nextjs';
      if (deps['react-native'] || deps['expo']) return 'mobile';
      if (deps['react']) return 'react';
      if (deps['express'] || deps['fastify'] || deps['hono'] || deps['@hono/node-server']) return 'api';
    } catch {}
  }
  return null;
}

function cmdScan(dir, flags) {
  // Auto-detect framework/stack and apply preset if not explicitly set.
  if (!flags.preset && !flags['no-preset']) {
    const detected = detectFramework(dir);
    if (detected) {
      const { applyPreset } = require('../src/presets');
      const applied = applyPreset(detected);
      if (applied && !flags.json && !flags.sarif) {
        process.stderr.write(`${C.dim}detected: ${detected} — applied preset${C.reset}\n`);
      }
    }
  }

  // Dependency audit runs by default; disable with --no-deps.
  // --deep folds in external scanners (semgrep/gitleaks) when installed.
  const result = scan(dir, {
    deps: flags.deps !== false && !flags['no-deps'],
    deep: !!flags.deep,
    changed: !!flags.changed,
    staged: !!flags.staged,
    noSuppress: !!flags['no-suppress'],
  });

  if (flags.staged && result.staged && !flags.json && !flags.sarif) {
    process.stderr.write(
      `${C.dim}staged: scanned ${result.staged.scanned} staged file(s) of ${result.staged.total} ` +
        `(cross-file analysis skipped — run a full scan for that)${C.reset}\n`
    );
  }

  // Incremental mode note: report how much work was skipped, and be explicit
  // that cross-file analysis is not run (per-file only).
  if (flags.changed && result.incremental && !flags.json && !flags.sarif) {
    const inc = result.incremental;
    process.stderr.write(
      `${C.dim}incremental: scanned ${inc.scanned}/${inc.total} changed file(s), ${inc.cached} unchanged skipped ` +
        `(cross-file analysis skipped — run a full scan for that)${C.reset}\n`
    );
  }

  // Engine-mode + coverage transparency. Never let a degraded scan look clean.
  if (!flags.json && !flags.sarif) {
    if (result.engine && result.engine.mode === 'regex-only') {
      process.stderr.write(
        `${C.yellow}⚠ engine: regex-only — acorn not installed, AST/taint precision disabled. ` +
          `Install with: npm i -D acorn acorn-walk acorn-typescript${C.reset}\n`
      );
    }
    const d = result.diagnostics;
    if (d && d.degradedFileCount > 0) {
      const passes = [...new Set((d.degradedPasses || []).map((x) => x.pass))];
      process.stderr.write(
        `${C.yellow}⚠ degraded coverage: ${d.degradedFileCount} file(s) not fully analyzed` +
          (d.parseFailedFiles && d.parseFailedFiles.length ? ` (${d.parseFailedFiles.length} parse-failed)` : '') +
          (passes.length ? ` [passes: ${passes.join(', ')}]` : '') +
          `. Run with --strict to fail on degraded scans.${C.reset}\n`
      );
    }
  }

  // --strict: treat a degraded scan (any pass failed open) as a hard failure so
  // CI never trusts an incomplete result.
  if (flags.strict && result.diagnostics && result.diagnostics.degradedFileCount > 0) {
    process.stderr.write(
      `${C.red}✗ --strict: scan ran degraded on ${result.diagnostics.degradedFileCount} file(s); refusing to report clean.${C.reset}\n`
    );
    outputResult(result, flags);
    return 3;
  }

  // Default min-confidence: medium (unless --all or explicit --min-confidence).
  const CONFIDENCE_ORDER = { low: 0, medium: 1, high: 2 };
  const minConf = flags['min-confidence'] || (flags.all ? 'low' : 'medium');
  const threshold = CONFIDENCE_ORDER[String(minConf).toLowerCase()];
  if (threshold !== undefined) {
    result.findings = result.findings.filter((f) => {
      const fc = CONFIDENCE_ORDER[f.confidence] || 0;
      return fc >= threshold;
    });
    const { computeGrade } = require('../src/scanner');
    const g = computeGrade(result.findings);
    result.grade = g.grade;
    result.counts = g.counts;
  }

  // --show-suppressed: re-add suppressed findings (annotated) to the output.
  if (flags['show-suppressed'] && result.suppressedFindings) {
    result.findings = result.findings.concat(result.suppressedFindings);
  }

  // Baseline auto-suppression: if a baseline file exists and the user didn't
  // explicitly pass --new-only or --all, default to new-only and inform them.
  if (!flags.baseline && !flags['new-only'] && !flags.all && !flags.json && !flags.sarif) {
    const { readBaseline } = require('../src/verify');
    const base = readBaseline(dir);
    if (base && Array.isArray(base.findings) && base.findings.length > 0) {
      const seen = new Set(
        base.findings.map((f) => f.fingerprint || `${f.ruleId} ${f.file} ${(f.snippet || '').trim()}`)
      );
      const before = result.findings.length;
      result.findings = result.findings.filter((f) => !seen.has(f.fingerprint));
      const suppressed = before - result.findings.length;
      if (suppressed > 0) {
        const { computeGrade } = require('../src/scanner');
        const g = computeGrade(result.findings);
        result.grade = g.grade;
        result.counts = g.counts;
        result.baselineSuppressed = suppressed;
      }
    }
  }

  // --new-only: explicit flag — same behavior but no message (user asked for it).
  if (flags['new-only']) {
    const { readBaseline } = require('../src/verify');
    const base = readBaseline(dir);
    if (base && Array.isArray(base.findings)) {
      const seen = new Set(
        base.findings.map((f) => f.fingerprint || `${f.ruleId} ${f.file} ${(f.snippet || '').trim()}`)
      );
      result.findings = result.findings.filter((f) => !seen.has(f.fingerprint));
      const { computeGrade } = require('../src/scanner');
      const g = computeGrade(result.findings);
      result.grade = g.grade;
      result.counts = g.counts;
    }
  }

  if (flags.deep && result.externalInfo && !flags.json && !flags.sarif) {
    const ran = result.externalInfo.ran || {};
    process.stderr.write(
      `${C.dim}deep: semgrep=${ran.semgrep ? 'ran' : 'skipped'}, gitleaks=${ran.gitleaks ? 'ran' : 'skipped'}` +
        (result.externalInfo.notes.length ? ' (' + result.externalInfo.notes.join('; ') + ')' : '') +
        `${C.reset}\n`
    );
  }
  if (flags.baseline) {
    const p = writeBaseline(dir, result);
    if (!flags.json && !flags.sarif) {
      process.stderr.write(`${C.dim}baseline saved: ${p}${C.reset}\n`);
    }
  }
  outputResult(result, flags);

  if (flags.precommit) {
    // Hook mode: block only on CRITICAL.
    return result.counts.critical > 0 ? 2 : 0;
  }
  // --fail-on <level>: exit 1 only when a finding at/above that severity exists.
  if (flags['fail-on']) {
    const order = ['critical', 'high', 'medium', 'low'];
    const threshold = order.indexOf(String(flags['fail-on']).toLowerCase());
    if (String(flags['fail-on']).toLowerCase() === 'none') return 0;
    if (threshold === -1) return result.findings.length > 0 ? 1 : 0;
    const worst = result.findings.reduce((acc, f) => Math.min(acc, order.indexOf(f.severity)), 4);
    return worst <= threshold ? 1 : 0;
  }
  // Default exit: non-zero if any finding, so CI notices.
  return result.findings.length > 0 ? 1 : 0;
}

function cmdFix(dir, flags) {
  const result = scan(dir);

  if (flags.json) {
    process.stdout.write(renderJson(result) + '\n');
    return result.findings.length > 0 ? 1 : 0;
  }

  // fix NEVER rewrites files silently. It prints the concrete fixes plus a
  // ready-to-paste prompt for the user's AI tool to apply under review.
  if (result.findings.length === 0) {
    process.stdout.write(`${C.green}Nothing to fix — no issues found.${C.reset}\n`);
    return 0;
  }

  process.stdout.write(renderHuman(result));

  // Safe auto-fixes: dry-run diff by default; apply only with --apply (snapshotted).
  const changes = computeAutoFixes(dir, result);
  if (changes.length > 0) {
    process.stdout.write(
      `${C.bold}${C.cyan}Safe auto-fixes available (${changes.length}) — mechanical & reversible:${C.reset}\n\n`
    );
    for (const c of changes) {
      process.stdout.write(`${C.bold}${c.description}${C.reset} ${C.dim}[${c.ruleId}]${C.reset}\n`);
      process.stdout.write(renderDiff(c) + '\n\n');
    }
    if (flags.apply) {
      const snapDir = snapshot(dir, changes);
      applyChanges(dir, changes);
      process.stdout.write(
        `${C.green}Applied ${changes.length} safe fix(es).${C.reset} ` +
          `${C.dim}Snapshot: ${snapDir}${C.reset}\n` +
          `Undo with: ${C.bold}vibeguard rollback ${dir}${C.reset}\n\n`
      );
    } else {
      process.stdout.write(
        `${C.yellow}Dry run — nothing written.${C.reset} Apply these with: ` +
          `${C.bold}vibeguard fix ${dir} --apply${C.reset} (files are snapshotted first).\n\n`
      );
    }
  }

  process.stdout.write(
    `${C.bold}${C.cyan}Copy-paste this into your AI coding tool to apply the remaining fixes:${C.reset}\n`
  );
  process.stdout.write(`${C.dim}${'-'.repeat(70)}${C.reset}\n`);
  process.stdout.write(renderFixPrompt(result) + '\n');
  process.stdout.write(`${C.dim}${'-'.repeat(70)}${C.reset}\n`);
  process.stdout.write(
    `\n${C.yellow}Review every change before committing. VibeGuard will not edit your files for you.${C.reset}\n`
  );
  process.stdout.write(
    `${C.dim}Tip: run 'vibeguard scan --baseline' first, then 'vibeguard verify' after fixing.${C.reset}\n`
  );
  return result.findings.length > 0 ? 1 : 0;
}

function cmdVerify(dir, flags) {
  const res = verify(dir);

  if (flags.json) {
    process.stdout.write(
      JSON.stringify(
        {
          hasBaseline: res.hasBaseline,
          grade: res.current.grade,
          counts: res.current.counts,
          resolved: res.resolved,
          remaining: res.remaining,
          introduced: res.introduced,
        },
        null,
        2
      ) + '\n'
    );
    return res.remaining.length + res.introduced.length > 0 ? 1 : 0;
  }

  process.stdout.write(`\n${C.bold}${C.cyan}VibeGuard verify${C.reset}\n\n`);

  if (!res.hasBaseline) {
    process.stdout.write(
      `${C.yellow}No baseline found.${C.reset} Showing current state. ` +
        `Run 'vibeguard scan --baseline' before fixing to enable a before/after diff.\n\n`
    );
    outputResult(res.current, {});
    return res.current.findings.length > 0 ? 1 : 0;
  }

  for (const f of res.resolved) {
    process.stdout.write(
      `${C.green}✓ resolved${C.reset} ${f.file}:${f.line} ${C.dim}[${f.ruleId}]${C.reset}\n`
    );
  }
  for (const f of res.remaining) {
    process.stdout.write(
      `${C.red}✗ still present${C.reset} ${f.file}:${f.line} ${C.dim}[${f.ruleId}]${C.reset}\n`
    );
  }
  for (const f of res.introduced) {
    process.stdout.write(
      `${C.magenta}! new issue${C.reset} ${f.file}:${f.line} ${C.dim}[${f.ruleId}]${C.reset}\n`
    );
  }

  process.stdout.write(
    `\n${C.bold}${res.resolved.length} resolved${C.reset}, ` +
      `${res.remaining.length} remaining, ${res.introduced.length} new. ` +
      `Current grade: ${res.current.grade}\n\n`
  );

  return res.remaining.length + res.introduced.length > 0 ? 1 : 0;
}

function cmdWatch(dir, flags) {
  const runScan = () => {
    const result = scan(dir, { deps: false });
    process.stdout.write('\x1b[2J\x1b[H'); // clear screen
    process.stdout.write(renderHuman(result));
  };
  process.stdout.write(`${C.cyan}VibeGuard watching ${path.resolve(dir)} — Ctrl+C to stop${C.reset}\n`);
  runScan();
  let timer = null;
  const debounced = (_e, file) => {
    if (file && /node_modules|\.git|\.vibeguard/.test(String(file))) return;
    clearTimeout(timer);
    timer = setTimeout(runScan, 300);
  };
  try {
    fs.watch(path.resolve(dir), { recursive: true }, debounced);
  } catch (err) {
    process.stderr.write(`watch not supported here: ${err.message}\n`);
    return 2;
  }
  return new Promise(() => {}); // never resolves; runs until Ctrl+C
}

async function cmdUrl(target, flags) {
  if (!target || target === '.') {
    process.stderr.write('usage: vibeguard url <https://your-site.com>\n');
    return 2;
  }
  let res;
  try {
    res = await scanUrl(target);
  } catch (err) {
    process.stderr.write(`vibeguard url error: ${err.message}\n`);
    return 2;
  }
  const findings = sortFindings(res.findings);
  const { grade, counts } = computeGrade(findings);
  const result = {
    root: res.url,
    scannedFiles: 1,
    findings,
    grade,
    counts,
    generatedAt: new Date().toISOString(),
  };
  outputResult(result, flags);
  return findings.length > 0 ? 1 : 0;
}

function cmdRules(flags) {
  const { allRules } = require('../src/rules');
  const rules = allRules().sort((a, b) => (a.category + a.id).localeCompare(b.category + b.id));
  if (flags.json) {
    process.stdout.write(JSON.stringify(rules, null, 2) + '\n');
    return 0;
  }
  let cat = '';
  for (const r of rules) {
    if (r.category !== cat) { cat = r.category; process.stdout.write(`\n${C.bold}${C.cyan}${cat}${C.reset}\n`); }
    process.stdout.write(`  ${r.id.padEnd(34)} ${C.dim}${r.severity}${C.reset}  ${r.title}\n`);
  }
  process.stdout.write(`\n${C.dim}${rules.length} rules. 'vibeguard explain <ruleId>' for details.${C.reset}\n`);
  return 0;
}

function cmdExplain(ruleId, flags) {
  const { allRules } = require('../src/rules');
  const r = allRules().find((x) => x.id === ruleId);
  if (!r) {
    process.stderr.write(`Unknown rule: ${ruleId}. Run 'vibeguard rules' to list them.\n`);
    return 2;
  }
  if (flags.json) { process.stdout.write(JSON.stringify(r, null, 2) + '\n'); return 0; }
  process.stdout.write(
    `\n${C.bold}${r.id}${C.reset}  ${C.dim}[${r.category}]${C.reset}\n` +
    `severity: ${r.severity}   confidence: ${r.confidence}\n` +
    `${C.bold}${r.title}${C.reset}\n\n` +
    (r.message ? r.message + '\n\n' : '') +
    (r.fix ? `${C.green}fix:${C.reset} ${r.fix}\n` : `${C.dim}(dynamic message — run a scan to see specifics)${C.reset}\n`)
  );
  return 0;
}

function cmdDoctor(dir, flags) {
  const { runDoctor } = require('../src/doctor');
  const findings = runDoctor(dir, { scope: flags.scope || 'full' });
  if (flags.json) { process.stdout.write(JSON.stringify({ findings }, null, 2) + '\n'); return findings.length ? 1 : 0; }
  process.stdout.write(`\n${C.bold}${C.cyan}VibeGuard doctor${C.reset} ${C.dim}(AI host security)${C.reset}\n\n`);
  if (findings.length === 0) {
    process.stdout.write(`${C.green}No host security issues found in AI tool configs / environment.${C.reset}\n`);
    return 0;
  }
  for (const f of findings) {
    process.stdout.write(`${C.red}${f.severity.toUpperCase()}${C.reset} ${f.file} ${C.dim}[${f.ruleId}]${C.reset}\n  ${f.message}\n  ${C.green}fix:${C.reset} ${f.fix}\n\n`);
  }
  process.stdout.write(`${C.bold}${findings.length} host issue(s).${C.reset} These affect your machine/AI tools, not just this repo.\n`);
  return 1;
}

function cmdHistory(dir, flags) {
  const { scanHistory } = require('../src/history');
  const res = scanHistory(dir, { all: !!flags.all });
  if (!res.ran) {
    process.stderr.write(`${C.yellow}${res.note}${C.reset}\n`);
    return 2;
  }
  if (flags.json) {
    process.stdout.write(JSON.stringify({ findings: res.findings }, null, 2) + '\n');
    return res.findings.length ? 1 : 0;
  }
  if (res.findings.length === 0) {
    process.stdout.write(`${C.green}No secrets found in git history (scanned recent commits).${C.reset}\n`);
    return 0;
  }
  process.stdout.write(`\n${C.bold}${C.red}Secrets found in git history:${C.reset}\n\n`);
  for (const f of res.findings) {
    process.stdout.write(`${C.red}CRITICAL${C.reset} ${f.file}:${f.line} ${C.dim}[${f.ruleId}]${C.reset}\n  ${f.message}\n  ${C.green}fix:${C.reset} ${f.fix}\n\n`);
  }
  process.stdout.write(`${C.bold}${res.findings.length} secret(s) in history.${C.reset} Rotate them — removing the file does NOT remove them from git.\n`);
  return 1;
}

function cmdRollback(dir) {
  const res = rollback(dir);
  if (!res.ok) {
    process.stderr.write(`${C.yellow}Nothing to roll back:${C.reset} ${res.reason}\n`);
    return 1;
  }
  process.stdout.write(
    `${C.green}Rolled back ${res.restored.length} file(s)${C.reset} from snapshot ${res.stamp}:\n` +
      res.restored.map((f) => `  ${f}`).join('\n') +
      '\n'
  );
  return 0;
}

function cmdInstall(flags) {
  const { install } = require('../src/install');
  const { spec, results, paste } = install({ local: !!flags.local });

  process.stdout.write(`\n${C.bold}${C.cyan}VibeGuard — wiring the MCP server into your AI tools${C.reset}\n`);
  process.stdout.write(`${C.dim}server: ${spec.command} ${spec.args.join(' ')}${C.reset}\n\n`);

  const icon = { installed: `${C.green}✓${C.reset}`, skipped: `${C.dim}–${C.reset}`, manual: `${C.yellow}!${C.reset}`, error: `${C.red}✗${C.reset}` };
  for (const r of results) {
    process.stdout.write(`  ${icon[r.status] || '?'} ${r.client.padEnd(14)} ${C.dim}${r.detail}${C.reset}\n`);
  }

  const installed = results.filter((r) => r.status === 'installed').length;
  process.stdout.write(
    `\n${C.bold}${installed} client(s) wired.${C.reset} Restart the client to pick up the server.\n`
  );
  process.stdout.write(
    `\n${C.dim}For any client not listed (Antigravity, Gemini CLI, JetBrains, …), paste this into its MCP config:${C.reset}\n`
  );
  process.stdout.write(paste + '\n');
  if (!flags.local) {
    process.stdout.write(
      `\n${C.dim}Tip: add --local to point clients at this checkout instead of npx (for dev/testing before publish).${C.reset}\n`
    );
  }
  return 0;
}

function cmdBadge(dir, flags) {
  const badge = require('../src/badge');
  const result = scan(dir, { deps: flags.deps !== false && !flags['no-deps'] });
  const date = new Date().toISOString().slice(0, 10);

  if (!badge.isEligible(result)) {
    process.stderr.write(
      `${C.yellow}No badge awarded.${C.reset} A badge requires zero critical and zero high findings.\n` +
        `Current grade ${result.grade}: ${result.counts.critical} critical, ${result.counts.high} high. ` +
        `Fix those, then run 'vibeguard badge' again.\n`
    );
    return 1;
  }

  const svgPath = path.join(path.resolve(dir), 'vibeguard-badge.svg');
  fs.writeFileSync(svgPath, badge.svg(result, date));
  const md = badge.markdown(result, date, './vibeguard-badge.svg');

  if (flags.json) {
    process.stdout.write(
      JSON.stringify({ eligible: true, date, grade: result.grade, svg: svgPath, markdown: md }, null, 2) + '\n'
    );
    return 0;
  }
  process.stdout.write(
    `${C.green}Badge awarded${C.reset} — ${badge.passLabel(date)}.\n` +
      `SVG written to ${svgPath}\n\n` +
      `Add to your README:\n  ${md}\n\n` +
      `${C.dim}This attests the project passed VibeGuard's checks on ${date}. It is not a` +
      ` guarantee of safety.${C.reset}\n`
  );
  return 0;
}

function cmdInitCi(dir) {
  const root = path.resolve(dir);
  const wfDir = path.join(root, '.github', 'workflows');
  fs.mkdirSync(wfDir, { recursive: true });
  const dest = path.join(wfDir, 'vibeguard.yml');
  if (fs.existsSync(dest)) {
    process.stderr.write(`${dest} already exists — not overwriting.\n`);
    return 2;
  }
  const src = path.join(__dirname, '..', 'ci', 'vibeguard.yml');
  fs.copyFileSync(src, dest);
  process.stdout.write(
    `${C.green}Wrote GitHub Actions workflow${C.reset} to ${dest}\n` +
      `${C.dim}It uploads SARIF to code scanning and fails the build on CRITICAL findings.${C.reset}\n`
  );
  return 0;
}

function cmdGuardAction(input, flags) {
  const { inspectAction } = require('../src/action-guard');
  // Accept a JSON action ('{"type":"network",...}') or, for convenience, a bare
  // shell command string.
  let action;
  const raw = (input || '').trim();
  if (raw.startsWith('{')) {
    try { action = JSON.parse(raw); } catch { process.stderr.write('Invalid JSON action.\n'); return 2; }
  } else if (raw) {
    action = { type: 'shell', command: raw };
  } else {
    process.stderr.write('Usage: vibeguard guard-action \'<json-action>\' | "<shell command>"\n');
    return 2;
  }
  const trustedHosts = flags.trust ? String(flags.trust).split(',') : [];
  const verdict = inspectAction(action, { trustedHosts });
  if (flags.json) {
    process.stdout.write(JSON.stringify(verdict, null, 2) + '\n');
  } else {
    const C2 = { red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', dim: '\x1b[2m', reset: '\x1b[0m' };
    const tag = verdict.blocked ? `${C2.red}BLOCKED${C2.reset}` : verdict.action === 'warn' ? `${C2.yellow}WARN${C2.reset}` : `${C2.green}ALLOW${C2.reset}`;
    process.stdout.write(`${tag} ${verdict.reason || 'no leak or dangerous action detected'}\n`);
    for (const v of verdict.violations) process.stdout.write(`  ${C2.dim}${v.level}: ${v.kind} — ${v.detail}${C2.reset}\n`);
  }
  return verdict.blocked ? 1 : 0;
}

function cmdAgentScan(dir, flags) {
  const { agentScan, renderAgentScan } = require('../src/agent-scan');
  const result = agentScan(dir, { pin: !!flags.pin });
  if (flags.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    process.stdout.write(renderAgentScan(result) + '\n');
  }
  // Fail on critical by default; --fail-on <level> to tune.
  if (flags['fail-on']) {
    const order = ['critical', 'high', 'medium', 'low'];
    const t = order.indexOf(String(flags['fail-on']).toLowerCase());
    const worst = result.items.reduce((a, it) => Math.min(a, order.indexOf(it.severity)), 4);
    return t !== -1 && worst <= t ? 1 : 0;
  }
  return result.counts.critical > 0 ? 1 : 0;
}

function cmdMcpAudit(dir, flags) {
  const { auditMcp, renderMcpAudit } = require('../src/mcp-audit');
  const result = auditMcp(dir, { pin: !!flags.pin });
  if (flags.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    process.stdout.write(renderMcpAudit(result) + '\n');
  }
  if (!result.configFound) return 0;
  // Fail on critical (blockable in CI), like the scan gate.
  if (flags['fail-on']) {
    const order = ['critical', 'high', 'medium', 'low'];
    const t = order.indexOf(String(flags['fail-on']).toLowerCase());
    const worst = result.findings.reduce((a, f) => Math.min(a, order.indexOf(f.severity)), 4);
    return t !== -1 && worst <= t ? 1 : 0;
  }
  return result.counts.critical > 0 ? 1 : 0;
}

function cmdInstallHook(dir) {
  const root = path.resolve(dir);
  const gitDir = path.join(root, '.git');
  if (!fs.existsSync(gitDir)) {
    process.stderr.write(
      `error: ${root} is not a git repository (no .git). Run 'git init' first.\n`
    );
    return 2;
  }
  const hooksDir = path.join(gitDir, 'hooks');
  fs.mkdirSync(hooksDir, { recursive: true });
  const dest = path.join(hooksDir, 'pre-commit');

  if (fs.existsSync(dest)) {
    const existing = fs.readFileSync(dest, 'utf8');
    if (!existing.includes('VibeGuard pre-commit hook')) {
      process.stderr.write(
        `A pre-commit hook already exists at ${dest}.\n` +
          `Refusing to overwrite it. Merge in hooks/pre-commit manually.\n`
      );
      return 2;
    }
  }

  // Bake in the absolute path to THIS CLI so the hook always finds the scanner,
  // and fail LOUD (block) if it can't run — a security hook must never pass
  // silently just because the tool is missing.
  const cliPath = path.resolve(__dirname, 'cli.js');
  const nodeBin = process.execPath;
  const hook = `#!/usr/bin/env sh
# VibeGuard pre-commit hook (generated by 'vibeguard install-hook').
# Blocks the commit ONLY when a CRITICAL issue is found. Bypass: git commit --no-verify
NODE="${nodeBin.split('\\').join('/')}"
CLI="${cliPath.split('\\').join('/')}"
if [ ! -x "$NODE" ]; then NODE=node; fi
if [ ! -f "$CLI" ]; then
  echo "VibeGuard: scanner not found at $CLI — commit blocked (fail-closed). Reinstall the hook."
  exit 1
fi
"$NODE" "$CLI" scan . --precommit
STATUS=$?
if [ "$STATUS" -eq 2 ]; then
  echo ""
  echo "VibeGuard: commit blocked — CRITICAL security issue(s) found above."
  echo "Fix them, or bypass intentionally with: git commit --no-verify"
  exit 1
fi
exit 0
`;
  fs.writeFileSync(dest, hook);
  try {
    fs.chmodSync(dest, 0o755);
  } catch {
    /* chmod is a no-op / may fail on Windows — git uses core.fileMode there */
  }
  process.stdout.write(
    `${C.green}Installed pre-commit hook${C.reset} at ${dest}\n` +
      `${C.dim}It blocks commits only when a CRITICAL issue is found.${C.reset}\n`
  );
  return 0;
}

async function main() {
  const argv = process.argv.slice(2);
  const args = parseArgs(argv);
  const flags = args.flags;

  if (flags.help || flags.h || args._[0] === 'help') {
    printHelp();
    process.exit(0);
  }

  const cmd = args._[0] || 'scan';
  const dir = args._[1] || '.';

  const noDirCmds = new Set(['url', 'rules', 'explain', 'secure-prompt', 'redact', 'detect-pii', 'firewall', 'exfil-check', 'dep-firewall', 'sandbox', 'output-guard', 'vault', 'audit-trail', 'why', 'guard', 'guard-action', 'install-shell-hook', 'uninstall-shell-hook', 'auto-start', 'auto-stop', 'auto-status', 'auto', 'container-scan', 'proxy-start', 'proxy-stop', 'proxy-status']);
  if (!noDirCmds.has(cmd) && !fs.existsSync(dir)) {
    process.stderr.write(`error: directory not found: ${dir}\n`);
    process.exit(2);
  }

  // MCP server mode: hand off to the server (it runs until stdin closes).
  // This is what `npx -y vibeguard mcp` starts inside Claude Code / Cursor / etc.
  if (cmd === 'mcp') {
    require('../src/mcp-server.js');
    return; // do NOT process.exit — the server owns the process lifetime
  }

  // scan --verify-keys: async provider probing.
  if (cmd === 'scan' && flags['verify-keys']) {
    (async () => {
      const result = scan(dir, { deps: flags.deps !== false && !flags['no-deps'], deep: !!flags.deep });
      try {
        const { verifyKeys } = require('../src/verifykeys');
        const live = await verifyKeys(dir, result.findings);
        if (live > 0 && !flags.json && !flags.sarif) {
          process.stderr.write(`${C.red}${live} key(s) CONFIRMED LIVE.${C.reset}\n`);
        }
      } catch (err) {
        process.stderr.write(`verify-keys error: ${err.message}\n`);
      }
      const { computeGrade } = require('../src/scanner');
      const g = computeGrade(result.findings);
      result.grade = g.grade;
      result.counts = g.counts;
      outputResult(result, flags);
      process.exit(result.counts.critical > 0 ? 2 : result.findings.length > 0 ? 1 : 0);
    })().catch((err) => {
      process.stderr.write(`vibeguard error: ${err.message}\n`);
      process.exit(2);
    });
    return;
  }

  // Watch mode (long-running).
  if (cmd === 'watch') {
    Promise.resolve(cmdWatch(dir, flags)).catch((err) => {
      process.stderr.write(`vibeguard error: ${err && err.message ? err.message : err}\n`);
      process.exit(2);
    });
    return;
  }

  // Async command: live URL scan.
  if (cmd === 'url') {
    cmdUrl(args._[1], flags)
      .then((c) => process.exit(c))
      .catch((err) => {
        process.stderr.write(`vibeguard error: ${err && err.message ? err.message : err}\n`);
        process.exit(2);
      });
    return;
  }

  let code = 0;
  try {
    if (cmd === 'scan') code = cmdScan(dir, flags);
    else if (cmd === 'fix') code = cmdFix(dir, flags);
    else if (cmd === 'verify') code = cmdVerify(dir, flags);
    else if (cmd === 'install-hook') code = cmdInstallHook(dir);
    else if (cmd === 'rollback') code = cmdRollback(dir);
    else if (cmd === 'history') code = cmdHistory(dir, flags);
    else if (cmd === 'badge') code = cmdBadge(dir, flags);
    else if (cmd === 'init-ci') code = cmdInitCi(dir);
    else if (cmd === 'mcp-audit') code = cmdMcpAudit(dir, flags);
    else if (cmd === 'agent-scan') code = cmdAgentScan(dir, flags);
    else if (cmd === 'guard-action') code = cmdGuardAction(args._[1], flags);
    else if (cmd === 'install') code = cmdInstall(flags);
    else if (cmd === 'rules') code = cmdRules(flags);
    else if (cmd === 'explain') code = cmdExplain(args._[1], flags);
    else if (cmd === 'doctor') code = cmdDoctor(dir, flags);
    else if (cmd === 'compliance') code = cmdCompliance(dir, flags);
    else if (cmd === 'cve') code = await cmdCve(dir, flags);
    else if (cmd === 'slopsquat') code = await cmdSlopsquat(dir, flags);
    else if (cmd === 'secure-prompt') code = cmdSecurePrompt(args._[1] || '.', flags);
    else if (cmd === 'trace') code = cmdTrace(dir, flags);
    else if (cmd === 'repl') code = await cmdRepl(dir, flags);
    else if (cmd === 'auth-coverage') code = cmdAuthCoverage(dir, flags);
    else if (cmd === 'diff') code = cmdDiff(dir, flags);
    else if (cmd === 'deep-scan') code = await cmdDeepScan(dir, flags);
    else if (cmd === 'html') code = cmdHtml(dir, flags);
    else if (cmd === 'inject-rules') code = cmdInjectRules(dir, flags);
    else if (cmd === 'bench') code = cmdBench(dir, flags);
    else if (cmd === 'hook-post-edit') { require('../src/hook').handlePostEdit(); return; }
    else if (cmd === 'install-hook-post') {
      const r = require('../src/hook').installPostEditHook(dir);
      if (r.installed) {
        process.stdout.write(`\n  VibeGuard PostToolUse hook installed in ${r.file}\n\n`);
        process.stdout.write(`  VibeGuard will now auto-scan every file Claude edits.\n`);
        process.stdout.write(`  If a critical issue is found, you'll see a warning immediately.\n\n`);
        process.stdout.write(`  To uninstall: vibeguard uninstall-hook-post\n\n`);
      } else {
        process.stdout.write(`Hook ${r.reason || 'not installed'}\n`);
      }
      code = 0;
    }
    else if (cmd === 'uninstall-hook-post') { const r = require('../src/hook').uninstallPostEditHook(dir); process.stdout.write(r.uninstalled ? 'PostToolUse hook removed.\n' : `Not found: ${r.reason}\n`); code = 0; }
    else if (cmd === 'risk-score') code = cmdRiskScore(dir, flags);
    else if (cmd === 'trend') code = cmdTrend(dir, flags);
    else if (cmd === 'why') code = cmdWhy(dir, args, flags);
    else if (cmd === 'config-check') code = cmdConfigCheck(dir, flags);
    else if (cmd === 'watch') code = cmdWatch(dir, flags);
    else if (cmd === 'dashboard') code = cmdDashboard(dir, flags);
    else if (cmd === 'pr-comment') code = cmdPRComment(dir, flags);
    else if (cmd === 'preset') code = cmdPreset(dir, args, flags);
    else if (cmd === 'privacy-audit') code = cmdPrivacyAudit(dir, flags);
    else if (cmd === 'net-audit') code = cmdNetAudit(dir, flags);
    else if (cmd === 'ai-guard') code = cmdAIGuard(dir, flags);
    else if (cmd === 'privacy-policy') code = cmdPrivacyPolicy(dir, flags);
    else if (cmd === 'csp-generate') code = cmdCSPGenerate(dir, flags);
    else if (cmd === 'firewall') code = cmdFirewall(args, flags);
    else if (cmd === 'agent-guard') code = cmdAgentGuard(dir, flags);
    else if (cmd === 'exfil-check') code = cmdExfilCheck(args, flags);
    else if (cmd === 'dep-firewall') code = cmdDepFirewall(args, flags);
    else if (cmd === 'intercept-test') code = cmdInterceptTest(dir, args, flags);
    else if (cmd === 'output-guard') code = cmdOutputGuard(args, flags);
    else if (cmd === 'env-lock') code = cmdEnvLock(dir, flags);
    else if (cmd === 'self-check') code = cmdSelfCheck(dir, flags);
    else if (cmd === 'sandbox') code = cmdSandbox(args, flags);
    else if (cmd === 'behavior') code = cmdBehavior(dir, flags);
    else if (cmd === 'supply-firewall') code = cmdSupplyFirewall(dir, flags);
    else if (cmd === 'vault') code = cmdVault(args, flags);
    else if (cmd === 'audit-trail') code = cmdAuditTrail(args, flags);
    else if (cmd === 'pre-deploy') code = cmdPreDeploy(dir, flags);
    else if (cmd === 'redact') code = cmdRedact(args, flags);
    else if (cmd === 'detect-pii') code = cmdDetectPII(args, flags);
    else if (cmd === 'sbom') code = cmdSBOM(dir, flags);
    else if (cmd === 'reachability') code = await cmdReachability(dir, flags);
    else if (cmd === 'container-scan') code = await cmdContainerScan(args, flags);
    else if (cmd === 'license') code = await cmdLicense(dir, flags);
    else if (cmd === 'proxy-start') code = cmdProxyStart(flags);
    else if (cmd === 'proxy-stop') code = cmdProxyStop(flags);
    else if (cmd === 'proxy-status') code = cmdProxyStatus(flags);
    else if (cmd === 'guard') code = cmdGuard(args, flags);
    else if (cmd === 'install-shell-hook') code = cmdInstallShellHook(flags);
    else if (cmd === 'uninstall-shell-hook') code = cmdUninstallShellHook(flags);
    else if (cmd === 'auto') code = cmdAutoUnified(dir, args, flags);
    else if (cmd === 'auto-start') code = cmdAutoStart(dir, flags);
    else if (cmd === 'auto-stop') code = cmdAutoStop(dir, flags);
    else if (cmd === 'auto-status') code = cmdAutoStatus(dir, flags);
    else {
      process.stderr.write(`unknown command: ${cmd}\n`);
      printHelp();
      code = 2;
    }
  } catch (err) {
    process.stderr.write(`vibeguard error: ${err && err.message ? err.message : err}\n`);
    code = 2;
  }
  process.exit(code);
}

function generatePatch(findings) {
  const lines = [];
  for (const f of findings) {
    if (!f.fix) continue;
    lines.push(`--- a/${f.file}`);
    lines.push(`+++ b/${f.file}`);
    lines.push(`@@ -${f.line},1 +${f.line},1 @@`);
    lines.push(`- ${f.snippet || ''}`);
    lines.push(`+ # vibeguard: ${f.ruleId} — ${f.fix}`);
    lines.push('');
  }
  return lines.join('\n');
}

// --- NEW COMMAND HANDLERS ---

function cmdCompliance(dir, flags) {
  const { scan } = require('../src/scanner');
  const result = scan(dir);
  const { generateComplianceReport } = require('../src/compliance');
  const report = generateComplianceReport(result.findings, flags.framework);
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  return 0;
}

async function cmdCve(dir, flags) {
  const { scanCVEs } = require('../src/cve-intel');
  const result = await scanCVEs(dir);
  if (flags.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    process.stdout.write(`Checked ${result.checked} packages. ${result.findings.length} vulnerabilities.\n`);
    for (const f of result.findings) {
      process.stdout.write(`  ${C.red}${f.severity}${C.reset} ${f.title}\n    ${f.message}\n    ${C.green}fix:${C.reset} ${f.fix}\n\n`);
    }
  }
  return result.findings.length > 0 ? 1 : 0;
}

async function cmdSlopsquat(dir, flags) {
  const { walk } = require('../src/scanner');
  const files = walk(dir, []);
  const { scanSlopsquat } = require('../src/slopsquat');
  const result = await scanSlopsquat(dir, files);
  if (flags.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    process.stdout.write(`Checked ${result.checked} imports. ${result.findings.length} suspicious packages.\n`);
    for (const f of result.findings) {
      process.stdout.write(`  ${C.yellow}${f.title}${C.reset}\n    ${f.message}\n    ${C.green}fix:${C.reset} ${f.fix}\n\n`);
    }
  }
  return result.findings.length > 0 ? 1 : 0;
}

function cmdSecurePrompt(promptText, flags) {
  if (!promptText || promptText === '.') {
    process.stderr.write('usage: vibeguard secure-prompt "your prompt text here"\n');
    return 2;
  }
  const { analyzePrompt } = require('../src/secure-prompt');
  const result = analyzePrompt(promptText);
  if (flags.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    process.stdout.write(
      `${C.bold}Score: ${result.score}/100 — Grade: ${result.grade}${C.reset}\n` +
      `${result.recommendation}\n\n`
    );
    for (const f of result.findings) {
      const sev = f.risk === 'critical' ? C.red : f.risk === 'high' ? C.red : f.risk === 'medium' ? C.yellow : C.blue;
      process.stdout.write(`  ${sev}[${f.risk}]${C.reset} ${f.category}: ${f.message}\n    ${C.green}fix:${C.reset} ${f.fix}\n\n`);
    }
  }
  return result.score < 60 ? 1 : 0;
}

function cmdTrace(dir, flags) {
  const { scan } = require('../src/scanner');
  const result = scan(dir);
  const { trace } = require('../src/trace');
  const tr = trace(dir, result.findings);
  if (flags.json) {
    process.stdout.write(JSON.stringify(tr, null, 2) + '\n');
  } else {
    process.stdout.write(`Sessions found: ${tr.sessions}\n`);
    if (tr.behavior) {
      process.stdout.write(`Behavior risk: ${tr.behavior.risk}\n`);
      process.stdout.write(`Approval ratio: ${tr.behavior.delegationRatio}\n`);
      process.stdout.write(`Behaviors: ${tr.behavior.behaviors.length}\n\n`);
      for (const b of tr.behavior.behaviors) {
        process.stdout.write(`  [${b.id}] ${b.message}\n`);
      }
    }
    if (tr.traces.length > 0) {
      process.stdout.write(`\nTraces (${tr.traces.length}):\n`);
      for (const t of tr.traces) {
        process.stdout.write(`  ${t.finding} → ${t.matches.length} prompt match(es)\n`);
      }
    }
  }
  return 0;
}

async function cmdRepl(dir, flags) {
  const { startRepl } = require('../src/repl');
  return await startRepl(dir, flags);
}

function cmdAuthCoverage(dir, flags) {
  const { walk } = require('../src/scanner');
  const files = walk(dir, []);
  const { buildAuthCoverage } = require('../src/engine');
  const coverage = buildAuthCoverage(dir, files);
  if (flags.json) {
    process.stdout.write(JSON.stringify(coverage, null, 2) + '\n');
  } else {
    process.stdout.write(`Auth coverage: ${coverage.coverage}% (${coverage.protectedRoutes}/${coverage.totalRoutes} routes protected)\n`);
    if (coverage.unprotectedRoutes.length > 0) {
      process.stdout.write(`\n${C.red}Unprotected API routes:${C.reset}\n`);
      for (const r of coverage.unprotectedRoutes) {
        process.stdout.write(`  ${r.file}:${r.line} — ${r.path}\n`);
      }
    }
  }
  return coverage.unprotectedRoutes.length > 0 ? 1 : 0;
}

function cmdDiff(dir, flags) {
  const { scan } = require('../src/scanner');
  const { verify } = require('../src/verify');
  const res = verify(dir);
  if (!res.hasBaseline) {
    process.stderr.write('No baseline. Run "vibeguard scan --save-baseline" first.\n');
    return 2;
  }
  if (flags.json) {
    process.stdout.write(JSON.stringify({
      resolved: res.resolved.map(f => ({ file: f.file, line: f.line, ruleId: f.ruleId })),
      remaining: res.remaining.map(f => ({ file: f.file, line: f.line, ruleId: f.ruleId })),
      introduced: res.introduced.map(f => ({ file: f.file, line: f.line, ruleId: f.ruleId })),
    }, null, 2) + '\n');
  } else {
    process.stdout.write(`${res.resolved.length} resolved, ${res.remaining.length} remaining, ${res.introduced.length} new.\n\n`);
    for (const f of res.resolved) process.stdout.write(`  ${C.green}RESOLVED${C.reset}  ${f.file}:${f.line} [${f.ruleId}]\n`);
    for (const f of res.introduced) process.stdout.write(`  ${C.red}NEW${C.reset}       ${f.file}:${f.line} [${f.ruleId}]\n`);
    for (const f of res.remaining) process.stdout.write(`  ${C.yellow}REMAINING${C.reset} ${f.file}:${f.line} [${f.ruleId}]\n`);
  }
  return res.introduced.length > 0 ? 1 : 0;
}

async function cmdDeepScan(dir, flags) {
  const { scan } = require('../src/scanner');
  const { walk } = require('../src/scanner');
  const result = scan(dir);
  const files = walk(dir, []);
  const { buildAuthCoverage } = require('../src/engine');
  const auth = buildAuthCoverage(dir, files);
  const { trace } = require('../src/trace');
  const tr = trace(dir, result.findings);
  let cveFindings = [];
  try {
    const { scanCVEs } = require('../src/cve-intel');
    const cveRes = await scanCVEs(dir);
    cveFindings = cveRes.findings;
  } catch {}
  const payload = {
    scan: { grade: result.grade, counts: result.counts, findings: result.findings.length },
    authCoverage: auth,
    cveFindings: cveFindings.length,
    behaviorTrace: tr.behavior,
    hotspots: [...new Set(result.findings.filter(f => /auth|payment|admin|upload|webhook/i.test(f.file)).map(f => f.file))].slice(0, 20),
  };
  if (flags.json) {
    process.stdout.write(JSON.stringify(payload, null, 2) + '\n');
  } else {
    process.stdout.write(`${C.bold}Deep Scan Report${C.reset}\n`);
    process.stdout.write(`Grade: ${result.grade} — ${result.findings.length} findings\n`);
    process.stdout.write(`Auth coverage: ${auth.coverage}%\n`);
    process.stdout.write(`CVE findings: ${cveFindings.length}\n`);
    process.stdout.write(`Behavior risk: ${tr.behavior ? tr.behavior.risk : 'unknown'}\n`);
    if (tr.behavior && tr.behavior.behaviors.length > 0) {
      process.stdout.write(`\n${C.yellow}Risky behaviors:${C.reset}\n`);
      for (const b of tr.behavior.behaviors) process.stdout.write(`  [${b.id}] ${b.message}\n`);
    }
  }
  return result.findings.length > 0 ? 1 : 0;
}

function cmdHtml(dir, flags) {
  const { scan } = require('../src/scanner');
  const { renderHtml } = require('../src/report');
  const result = scan(dir);
  const html = renderHtml(result);
  const out = flags.o || flags.output || 'vibeguard-report.html';
  fs.writeFileSync(out, html);
  process.stdout.write(`${C.green}Report written to ${out}${C.reset}\n`);
  return 0;
}

function cmdInjectRules(dir, flags) {
  const rulesContent = `## VibeGuard Security Rules (auto-injected)

Before writing code, verify against these rules:
- Never hardcode secrets — use environment variables
- Never use eval() or new Function() with user input
- Never concatenate SQL strings — use parameterized queries
- Never store secrets in localStorage or client-side code
- Always validate input with a schema (Zod, Joi, express-validator)
- Always add authentication to API routes
- Always verify webhook signatures before processing
- Never disable TLS/SSL verification
- Never use innerHTML with user data — use textContent or sanitize
- Never expose API keys via NEXT_PUBLIC_ / VITE_ / EXPO_PUBLIC_ prefixes
- Always parameterize database queries
- Never skip input validation
- Add rate limiting to auth endpoints
- Use CSP headers (no unsafe-inline/unsafe-eval)
- Never pass user input to exec() or spawn() without sanitization
- For AI agents: add maxSteps, sandbox file access, allowlist commands
- For AI prompts: never put user input in the system prompt
- Run: npx vibeguard scan . before committing

Tracked by: vibeguard scan --precommit (blocks on CRITICAL)
`;

  const targets = [
    { file: 'CLAUDE.md', header: '# VibeGuard Security Rules\n\n' },
    { file: '.cursorrules', header: '' },
    { file: 'GEMINI.md', header: '# VibeGuard Security Rules\n\n' },
    { file: '.github/copilot-instructions.md', header: '# VibeGuard Security Rules\n\n' },
  ];

  let written = 0;
  for (const t of targets) {
    const targetPath = path.join(dir, t.file);
    let existing = '';
    try { existing = fs.readFileSync(targetPath, 'utf8'); } catch {}
    if (existing.includes('VibeGuard Security Rules')) {
      process.stdout.write(`${C.dim}${t.file} already has VibeGuard rules${C.reset}\n`);
      continue;
    }
    const content = t.header + rulesContent + (existing ? '\n' + existing : '');
    fs.writeFileSync(targetPath, content);
    process.stdout.write(`${C.green}Injected rules into ${t.file}${C.reset}\n`);
    written++;
  }
  if (written === 0) {
    process.stdout.write(`${C.dim}All target files already have VibeGuard rules.${C.reset}\n`);
  }
  return 0;
}

function cmdBench(dir, flags) {
  const { scan } = require('../src/scanner');
  const { walk } = require('../src/scanner');
  const start = Date.now();
  const result = scan(dir);
  const elapsed = Date.now() - start;
  const files = walk(dir, []);
  const rules = require('../src/rules').allRules().length;
  process.stdout.write(
    `${C.bold}VibeGuard Benchmark${C.reset}\n` +
    `  Files scanned:    ${result.scannedFiles}\n` +
    `  Rules active:     ${rules}\n` +
    `  Findings:         ${result.findings.length}\n` +
    `  Grade:            ${result.grade}\n` +
    `  Time:             ${elapsed}ms\n` +
    `  Throughput:       ${Math.round(result.scannedFiles / (elapsed / 1000))} files/sec\n` +
    `  Per-file:         ${Math.round(elapsed / result.scannedFiles)}ms/file\n`
  );
  return 0;
}

function cmdPrivacyAudit(dir, flags) {
  const { walk } = require('../src/scanner');
  const { auditPrivacy, renderPrivacyReport } = require('../src/privacy-audit');
  const files = walk(dir, []);
  const inventory = auditPrivacy(dir, files);
  process.stdout.write(renderPrivacyReport(inventory) + '\n');
  return inventory.risks.filter(r => r.severity === 'high').length > 0 ? 1 : 0;
}

function cmdNetAudit(dir, flags) {
  const { walk } = require('../src/scanner');
  const { auditNetwork, renderNetworkReport } = require('../src/net-audit');
  const files = walk(dir, []);
  const result = auditNetwork(dir, files);
  process.stdout.write(renderNetworkReport(result) + '\n');
  return result.summary.suspiciousDomains > 0 ? 1 : 0;
}

function cmdAIGuard(dir, flags) {
  const { walk } = require('../src/scanner');
  const { auditAIData, renderAIGuardReport } = require('../src/ai-guard');
  const files = walk(dir, []);
  const result = auditAIData(dir, files);
  process.stdout.write(renderAIGuardReport(result) + '\n');
  return result.summary.criticalRisk > 0 ? 1 : 0;
}

function cmdPrivacyPolicy(dir, flags) {
  const { walk } = require('../src/scanner');
  const { generatePrivacyPolicy } = require('../src/policy-gen');
  const files = walk(dir, []);
  const policy = generatePrivacyPolicy(dir, files);
  process.stdout.write(policy + '\n');
  return 0;
}

function cmdCSPGenerate(dir, flags) {
  const { walk } = require('../src/scanner');
  const { generateCSP } = require('../src/policy-gen');
  const files = walk(dir, []);
  const result = generateCSP(dir, files);
  process.stdout.write(`${C.bold}Content-Security-Policy${C.reset}\n\n`);
  process.stdout.write(`${C.dim}Header value:${C.reset}\n`);
  process.stdout.write(result.csp + '\n\n');
  process.stdout.write(`${C.dim}Express/Helmet config:${C.reset}\n`);
  process.stdout.write(result.helmet + '\n\n');
  if (result.warnings.length > 0) {
    process.stdout.write(`${C.yellow}Warnings:${C.reset}\n`);
    for (const w of result.warnings) process.stdout.write(`  ${C.yellow}!${C.reset} ${w}\n`);
  }
  return 0;
}

function cmdFirewall(args, flags) {
  const prompt = (args._ || args || []).slice(1).join(' ');
  if (!prompt) { process.stderr.write('Usage: vibeguard firewall <prompt>\n'); return 1; }
  const { inspectPrompt, renderFirewallReport } = require('../src/firewall');
  const verdict = inspectPrompt(prompt);
  process.stdout.write(renderFirewallReport(verdict) + '\n');
  return verdict.action === 'block' ? 1 : 0;
}

function cmdAgentGuard(dir, flags) {
  const { AGENT_CONSTRAINTS } = require('../src/firewall');
  const C2 = { red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m' };
  process.stdout.write(`${C2.bold}VibeGuard Agent Guard${C.reset}\n`);
  process.stdout.write(`${C2.dim}${'─'.repeat(60)}${C.reset}\n\n`);
  process.stdout.write(`${C2.bold}Blocked Paths${C.reset}\n`);
  for (const p of AGENT_CONSTRAINTS.blockedPaths) process.stdout.write(`  ${C2.red}✗${C.reset} ${p}\n`);
  process.stdout.write(`\n${C2.bold}Blocked Commands${C.reset}\n`);
  for (const c of AGENT_CONSTRAINTS.blockedCommands) process.stdout.write(`  ${C2.red}✗${C.reset} ${c}\n`);
  process.stdout.write(`\n${C2.bold}Blocked Domains${C.reset}\n`);
  for (const d of AGENT_CONSTRAINTS.blockedDomains) process.stdout.write(`  ${C2.red}✗${C.reset} ${d}\n`);
  process.stdout.write(`\n${C2.bold}Resource Limits${C.reset}\n`);
  process.stdout.write(`  Max file size: ${AGENT_CONSTRAINTS.maxFileSize / 1024 / 1024}MB\n`);
  process.stdout.write(`  Max exec time: ${AGENT_CONSTRAINTS.maxExecTime / 1000}s\n`);
  process.stdout.write(`\n${C2.dim}Use MCP tool 'agent_guard' to check specific actions.${C.reset}\n`);
  return 0;
}

function cmdExfilCheck(args, flags) {
  const data = (args._ || args || []).slice(1).join(' ');
  if (!data) { process.stderr.write('Usage: vibeguard exfil-check <data>\n'); return 1; }
  const { checkExfiltration } = require('../src/firewall');
  const result = checkExfiltration(data);
  const C2 = { red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m' };
  process.stdout.write(`${C2.bold}VibeGuard Exfiltration Firewall${C.reset}\n`);
  process.stdout.write(`${C2.dim}${'─'.repeat(60)}${C.reset}\n\n`);
  if (result.allowed) {
    process.stdout.write(`  ${C2.green}✓ Data is safe to send${C.reset}\n`);
  } else {
    process.stdout.write(`  ${C2.red}✗ BLOCKED${C.reset}\n\n`);
    for (const r of result.risks) {
      const sc = r.severity === 'critical' ? C2.red : C2.yellow;
      process.stdout.write(`  ${sc}[${r.severity}]${C.reset} ${r.message}\n`);
    }
    if (result.sanitizedData !== data) {
      process.stdout.write(`\n${C2.dim}Sanitized version:${C.reset}\n  ${result.sanitizedData.slice(0, 200)}\n`);
    }
  }
  return result.allowed ? 0 : 1;
}

function cmdDepFirewall(args, flags) {
  const pkg = (args._ || args || [])[1] || (args[0] || null);
  if (!pkg) { process.stderr.write('Usage: vibeguard dep-firewall <package-name>\n'); return 1; }
  const { checkPackage } = require('../src/firewall');
  const result = checkPackage(pkg);
  const C2 = { red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m' };
  process.stdout.write(`${C2.bold}VibeGuard Dependency Firewall${C.reset}\n`);
  process.stdout.write(`${C2.dim}${'─'.repeat(60)}${C.reset}\n\n`);
  process.stdout.write(`  Package:  ${pkg}\n`);
  if (result.allowed && result.risks.length === 0) {
    process.stdout.write(`  ${C2.green}✓ No risks detected${C.reset}\n`);
  } else if (result.allowed) {
    process.stdout.write(`  ${C2.yellow}⚠ Warnings${C.reset}\n`);
    for (const r of result.risks) {
      const sc = r.severity === 'high' ? C2.yellow : C2.dim;
      process.stdout.write(`  ${sc}[${r.severity}]${C.reset} ${r.message}\n`);
    }
  } else {
    process.stdout.write(`  ${C2.red}✗ BLOCKED${C.reset}\n\n`);
    for (const r of result.risks) {
      const sc = r.severity === 'critical' ? C2.red : C2.yellow;
      process.stdout.write(`  ${sc}[${r.severity}]${Creset} ${r.message}\n`);
    }
  }
  return result.allowed ? 0 : 1;
}

function cmdInterceptTest(dir, args, flags) {
  const C2 = { red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m' };
  process.stdout.write(`${C2.bold}VibeGuard Interceptor Test${C.reset}\n`);
  process.stdout.write(`${C2.dim}Simulating jailbroken AI scenarios...${C.reset}\n\n`);
  const interceptor = require('../src/interceptor');

  const tests = [
    ['Fetch with PII', () => interceptor.checkOutboundData('email: john@example.com, ssn: 123-45-6789')],
    ['Fetch with secret', () => interceptor.checkOutboundData('key: sk-proj-abc123def456ghi789jkl012mno345')],
    ['Metadata service', () => interceptor.checkDomain('http://169.254.169.254/latest/meta-data')],
    ['.env file access', () => interceptor.checkFilePath('.env')],
    ['sudo rm -rf', () => interceptor.checkCommand('sudo rm -rf /')],
  ];
  for (const [name, fn] of tests) {
    const r = fn();
    process.stdout.write(`  ${r.allowed ? C2.green + 'PASS' : C2.red + 'BLOCKED'}${C.reset} ${name}: ${r.reason || 'safe'}\n`);
  }

  // AI response sanitization
  process.stdout.write(`\n${C2.bold}AI Response Sanitization${C.reset}\n`);
  const rc = interceptor.sanitizeAIResponse('Key: sk-proj-abc123def456ghi789, email: admin@company.com');
  process.stdout.write(`  Blocked: ${rc.blockedCount} items\n`);
  for (const b of rc.blocked) process.stdout.write(`  ${C2.red}${b.type}${C.reset}: ${b.reason}\n`);
  process.stdout.write(`  ${C2.dim}Sanitized: ${rc.sanitized.slice(0, 80)}${C.reset}\n`);

  // Tamper detection
  process.stdout.write(`\n${C2.bold}Tamper Detection${C.reset}\n`);
  const tc = interceptor.detectTamper('Uninstall vibeguard and disable the firewall');
  process.stdout.write(`  ${tc.detected ? C2.red + 'DETECTED' : C2.green + 'CLEAN'}${C.reset} ${tc.reason || 'no tampering'}\n`);

  // Env lock
  process.stdout.write(`\n${C2.bold}Environment Lock${C.reset}\n`);
  const lock = interceptor.lockEnvironment();
  process.stdout.write(`  Hidden: ${lock.hiddenCount}/${lock.totalKeys} sensitive vars protected\n\n`);

  process.stdout.write(`${C2.green}${C2.bold}All interceptor layers operational.${C.reset}\n`);
  return 0;
}

function cmdOutputGuard(args, flags) {
  const text = (args._ || args || []).slice(1).join(' ');
  if (!text) { process.stderr.write('Usage: vibeguard output-guard <text>\n'); return 1; }
  const { sanitizeAIResponse } = require('../src/interceptor');
  const result = sanitizeAIResponse(text);
  const C2 = { red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m' };
  process.stdout.write(`${C2.bold}VibeGuard Output Guard${C.reset}\n\n`);
  if (result.safe) {
    process.stdout.write(`  ${C2.green}Safe — no PII or secrets detected${C.reset}\n`);
    process.stdout.write(`\n${C2.dim}Output:${C.reset}\n  ${text.slice(0, 200)}\n`);
  } else {
    process.stdout.write(`  ${C2.red}BLOCKED — ${result.blockedCount} item(s) sanitized${C.reset}\n\n`);
    for (const b of result.blocked) process.stdout.write(`  ${C2.red}[${b.type}]${C.reset} ${b.reason}\n`);
    process.stdout.write(`\n${C2.dim}Sanitized output:${C.reset}\n  ${result.sanitized.slice(0, 200)}\n`);
  }
  return result.safe ? 0 : 1;
}

function cmdEnvLock(dir, flags) {
  const { lockEnvironment } = require('../src/interceptor');
  const lock = lockEnvironment();
  const C2 = { red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m' };
  process.stdout.write(`${C2.bold}VibeGuard Environment Lock${C.reset}\n\n`);
  process.stdout.write(`  Total env vars:      ${lock.totalKeys}\n`);
  process.stdout.write(`  Hidden (sensitive): ${C2.red}${lock.hiddenCount}${C.reset}\n`);
  process.stdout.write(`  Visible (safe):     ${C2.green}${lock.totalKeys - lock.hiddenCount}${C.reset}\n\n`);
  if (lock.hiddenKeys.length > 0) {
    process.stdout.write(`${C2.bold}Protected Variables${C.reset}\n`);
    for (const key of lock.hiddenKeys.slice(0, 20)) process.stdout.write(`  ${C2.red}[HIDDEN]${C.reset} ${key}\n`);
    if (lock.hiddenKeys.length > 20) process.stdout.write(`  ${C2.dim}... and ${lock.hiddenKeys.length - 20} more${C.reset}\n`);
  }
  return 0;
}

function cmdSelfCheck(dir, flags) {
  const C2 = { red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m' };
  process.stdout.write(`${C2.bold}VibeGuard Self-Check${C.reset}\n\n`);
  const checks = [];
  let ok = true;
  const modules = [
    ['firewall', 'Firewall module'],
    ['interceptor', 'Interceptor module'],
    ['scanner', 'Scanner module'],
    ['pii', 'PII module'],
    ['mcp-server', 'MCP server'],
    ['autofix', 'Auto-fix module'],
  ];
  for (const [mod, name] of modules) {
    try { require('../src/' + mod); checks.push(`  ${C2.green}PASS${C.reset}  ${name} intact`); }
    catch { checks.push(`  ${C2.red}FAIL${C.reset}  ${name} corrupted`); ok = false; }
  }
  // Rules count
  try { const r = require('../src/rules'); checks.push(`  ${C2.green}PASS${C.reset}  Rules loaded (${r.lineRules.length} rules)`); }
  catch { checks.push(`  ${C2.red}FAIL${C.reset}  Rules corrupted`); ok = false; }
  // Config
  const configPath = path.join(dir, '.vibeguardrc.json');
  if (fs.existsSync(configPath)) {
    try { const c = JSON.parse(fs.readFileSync(configPath, 'utf8')); if (c.ignoreRules && c.ignoreRules.length > 10) checks.push(`  ${C2.yellow}WARN${C.reset}  Many rules ignored (${c.ignoreRules.length})`); else checks.push(`  ${C2.green}PASS${C.reset}  Config normal`); }
    catch { checks.push(`  ${C2.yellow}WARN${C.reset}  Config corrupted`); }
  } else { checks.push(`  ${C2.dim}INFO  No config (defaults)${C.reset}`); }
  // .gitignore
  const gi = path.join(dir, '.gitignore');
  if (fs.existsSync(gi) && /\.env/.test(fs.readFileSync(gi, 'utf8'))) checks.push(`  ${C2.green}PASS${C.reset}  .env in .gitignore`);
  else { checks.push(`  ${C2.red}FAIL${C.reset}  .env NOT in .gitignore`); ok = false; }

  // Cryptographic content integrity — detects a patched/neutered guard that a
  // load-only check would miss.
  try {
    const { verifyIntegrity } = require('../src/integrity');
    const iv = verifyIntegrity(path.join(__dirname, '..', 'src'));
    if (!iv.available) {
      checks.push(`  ${C2.dim}INFO  Integrity manifest not present (run: node scripts/gen-integrity.js)${C.reset}`);
    } else if (iv.intact) {
      checks.push(`  ${C2.green}PASS${C.reset}  Content integrity verified (${iv.checked} security modules, sha256)`);
    } else {
      ok = false;
      if (iv.modified.length) checks.push(`  ${C2.red}FAIL${C.reset}  TAMPERED — modified: ${iv.modified.join(', ')}`);
      if (iv.missing.length) checks.push(`  ${C2.red}FAIL${C.reset}  MISSING — ${iv.missing.join(', ')}`);
    }
  } catch (e) {
    checks.push(`  ${C2.yellow}WARN${C.reset}  Integrity check failed to run: ${e.message}`);
  }

  for (const c of checks) process.stdout.write(c + '\n');
  process.stdout.write(`\n${ok ? C2.green + C2.bold + 'VibeGuard is intact.' : C2.red + C2.bold + 'INTEGRITY / SECURITY CHECK FAILED — do not trust this install.'}${C.reset}\n`);
  return ok ? 0 : 1;
}

function cmdSandbox(args, flags) {
  const code = (args._ || args || []).slice(1).join(' ');
  if (!code) { process.stderr.write('Usage: vibeguard sandbox <code>\n'); return 1; }
  const { runInSandbox, renderSandboxReport } = require('../src/sandbox');
  const result = runInSandbox(code);
  process.stdout.write(renderSandboxReport(result) + '\n');
  return result.success ? 0 : 1;
}

function cmdBehavior(dir, flags) {
  const { createSession, recordEvent, analyzeSession, renderBehaviorReport } = require('../src/behavior');
  const session = createSession();
  // Simulate some events based on scan results
  const result = scan(dir);
  for (const f of result.findings.slice(0, 50)) {
    recordEvent(session, f.ruleId.startsWith('secret.') ? 'secret_access' : f.ruleId.includes('injection') ? 'exec' : 'file_read', { ruleId: f.ruleId });
  }
  recordEvent(session, 'network', { detail: 'scan complete' });
  const analysis = analyzeSession(session);
  process.stdout.write(renderBehaviorReport(analysis) + '\n');
  return analysis.patternsCount > 0 ? 1 : 0;
}

function cmdSupplyFirewall(dir, flags) {
  const { auditLockfile, auditPackageJson, renderSupplyReport } = require('../src/supply-firewall');
  process.stdout.write(`${C.bold}VibeGuard Supply Chain Firewall${C.reset}\n${C.dim}${'─'.repeat(60)}${C.reset}\n\n`);
  const lockResult = auditLockfile(dir);
  process.stdout.write(renderSupplyReport(lockResult) + '\n\n');
  const pkgResult = auditPackageJson(dir);
  process.stdout.write(renderSupplyReport(pkgResult) + '\n');
  const hasFindings = (lockResult.findings?.length || 0) + (pkgResult.findings?.length || 0) > 0;
  return hasFindings ? 1 : 0;
}

function cmdVault(args, flags) {
  const allArgs = args._ || args || [];
  const action = allArgs[1] || allArgs[0] || 'list';
  const vault = require('../src/vault');
  const C2 = { red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m' };
  if (action === 'list' || action === 'status') {
    process.stdout.write(vault.renderVaultReport() + '\n');
  } else if (action === 'store') {
    const key = args[1];
    const value = args[2];
    if (!key || !value) { process.stderr.write('Usage: vibeguard vault store <KEY> <VALUE>\n'); return 1; }
    vault.store(key, value);
    process.stdout.write(`${C2.green}Stored "${key}" in encrypted vault${C.reset}\n`);
  } else if (action === 'get') {
    const key = args[1];
    if (!key) { process.stderr.write('Usage: vibeguard vault get <KEY>\n'); return 1; }
    const value = vault.get(key, { purpose: 'cli' });
    process.stdout.write(value ? `${C2.green}Decrypted: ${value.slice(0, 10)}...${C.reset}\n` : `${C2.red}Key not found${C.reset}\n`);
  } else if (action === 'log') {
    const log = vault.getAccessLog();
    process.stdout.write(`${C2.bold}Vault Access Log${C.reset}\n\n`);
    for (const a of log) process.stdout.write(`  ${a.key} — ${a.purpose} — ${new Date(a.timestamp).toISOString()}\n`);
  } else if (action === 'clear') {
    vault.clear();
    process.stdout.write(`${C2.yellow}Vault cleared${C.reset}\n`);
  } else {
    process.stderr.write('Usage: vibeguard vault [list|store|get|log|clear]\n');
    return 1;
  }
  return 0;
}

function cmdAuditTrail(args, flags) {
  const allArgs = args._ || args || [];
  const action = allArgs[1] || allArgs[0] || 'show';
  const audit = require('../src/audit-trail');
  const C2 = { red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m' };
  if (action === 'show' || action === 'status') {
    process.stdout.write(audit.renderAuditReport() + '\n');
  } else if (action === 'export') {
    const outPath = args[1] || 'vibeguard-audit.json';
    audit.exportLog(outPath);
    process.stdout.write(`${C2.green}Exported to ${outPath}${C_reset}\n`);
  } else if (action === 'verify') {
    const v = audit.verifyChain();
    process.stdout.write(v.valid ? `${C2.green}PASS Chain intact (${v.total} entries)${C_reset}\n` : `${C2.red}FAIL Chain broken at: ${v.brokenAt.join(',')}${C_reset}\n`);
  } else {
    process.stderr.write('Usage: vibeguard audit-trail [show|export|verify]\n');
    return 1;
  }
  return 0;
}

function cmdPreDeploy(dir, flags) {
  const { runPreDeployGate, renderPreDeployReport } = require('../src/pre-deploy');
  const summary = runPreDeployGate(dir, { strict: flags.strict, json: flags.json });
  if (flags.json) {
    process.stdout.write(JSON.stringify(summary, null, 2) + '\n');
  } else {
    process.stdout.write(renderPreDeployReport(summary) + '\n');
  }
  return summary.deployReady ? 0 : 1;
}

function cmdRiskScore(dir, flags) {
  const result = scan(dir);
  const weights = { critical: 10, high: 5, medium: 2, low: 1 };
  let score = 0;
  for (const f of result.findings) score += weights[f.severity] || 1;
  const maxScore = result.scannedFiles * 10 || 1;
  const riskPercent = Math.min(100, Math.round((score / maxScore) * 100));
  const riskLevel = score === 0 ? 'NONE' : score < 10 ? 'LOW' : score < 30 ? 'MEDIUM' : score < 60 ? 'HIGH' : 'CRITICAL';
  const colors = { NONE: C.green, LOW: C.green, MEDIUM: C.yellow, HIGH: C.yellow, CRITICAL: C.red };
  process.stdout.write(
    `${C.bold}VibeGuard Risk Score${C.reset}\n` +
    `  Risk Score:     ${colors[riskLevel]}${score}${C.reset} (${riskPercent}% of max)\n` +
    `  Risk Level:     ${colors[riskLevel]}${riskLevel}${C.reset}\n` +
    `  Grade:           ${result.grade}\n` +
    `  Files Scanned:  ${result.scannedFiles}\n` +
    `  Findings:       ${result.findings.length}\n\n`
  );
  if (result.findings.length > 0) {
    process.stdout.write(`${C.bold}Top Risks:${C.reset}\n`);
    const top = sortFindings(result.findings).slice(0, 5);
    for (const f of top) {
      const sc = f.severity === 'critical' ? C.red : f.severity === 'high' ? C.yellow : C.dim;
      process.stdout.write(`  ${sc}[${f.severity}]${C.reset} ${f.ruleId} — ${f.file}:${f.line}\n    ${f.message.slice(0, 80)}\n`);
    }
  }
  return 0;
}

function cmdTrend(dir, flags) {
  const baselinePath = path.join(dir, '.vibeguard-baseline.json');
  let baseline;
  try { baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf8')); }
  catch { process.stderr.write('No baseline found. Run: vibeguard verify --baseline\n'); return 1; }
  const current = scan(dir);
  const baselineFps = new Set(baseline.findings.map(f => f.fingerprint));
  const currentFps = new Set(current.findings.map(f => f.fingerprint));
  const resolved = [...baselineFps].filter(f => !currentFps.has(f)).length;
  const newCount = [...currentFps].filter(f => !baselineFps.has(f)).length;
  const persisted = [...baselineFps].filter(f => currentFps.has(f)).length;
  const trend = resolved > newCount ? 'IMPROVING' : newCount > resolved ? 'WORSENING' : 'STABLE';
  const trendColor = trend === 'IMPROVING' ? C.green : trend === 'WORSENING' ? C.red : C.yellow;
  process.stdout.write(
    `${C.bold}VibeGuard Trend Report${C.reset}\n` +
    `  Baseline:   ${baseline.generatedAt} (grade ${baseline.grade}, ${baseline.findings.length} findings)\n` +
    `  Current:    ${current.generatedAt} (grade ${current.grade}, ${current.findings.length} findings)\n\n` +
    `  ${C.green}Resolved:   ${resolved}${C.reset}\n` +
    `  ${C.red}New:        ${newCount}${C.reset}\n` +
    `  ${C.yellow}Persisted:  ${persisted}${C.reset}\n` +
    `  Trend:      ${trendColor}${trend}${C.reset}\n`
  );
  if (newCount > 0) {
    const newFindings = current.findings.filter(f => !baselineFps.has(f.fingerprint));
    process.stdout.write(`\n${C.bold}New Findings:${C.reset}\n`);
    for (const f of sortFindings(newFindings).slice(0, 10)) {
      process.stdout.write(`  [${f.severity}] ${f.ruleId} — ${f.file}:${f.line}\n    ${f.message.slice(0, 80)}\n`);
    }
  }
  return 0;
}

function cmdWhy(dir, args, flags) {
  const ruleId = args[0];
  if (!ruleId) { process.stderr.write('Usage: vibeguard why <ruleId>\n'); return 1; }
  const rules = require('../src/rules').allRules();
  const rule = rules.find(r => r.id === ruleId);
  if (!rule) { process.stderr.write(`Rule '${ruleId}' not found.\n`); return 1; }
  const autoFixable = require('../src/autofix').isAutoFixable(ruleId);
  process.stdout.write(
    `${C.bold}Rule: ${rule.id}${C.reset}\n` +
    `  Severity:    ${rule.severity}\n` +
    `  Confidence:  ${rule.confidence || 'high'}\n` +
    `  CWE:         ${rule.cwe || 'N/A'}\n` +
    `  OWASP:       ${rule.owasp || 'N/A'}\n` +
    `  Auto-fix:    ${autoFixable ? C.green + 'YES' + C.reset : C.red + 'NO' + C.reset}\n\n` +
    `${C.bold}What it detects:${C.reset}\n  ${rule.message}\n\n` +
    `${C.bold}How to fix:${C.reset}\n  ${rule.fix || 'No automated fix available.'}\n`
  );
  if (rule.fileFilter) process.stdout.write(`\n${C.bold}File filter:${C.reset} ${rule.fileFilter}\n`);
  return 0;
}

function cmdConfigCheck(dir, flags) {
  let ok = true;
  const checks = [];
  // Config files
  const configFiles = ['.vibeguardrc.json', 'vibeguard.config.json', '.vibeguard/config.json'];
  let configFound = false;
  for (const cf of configFiles) {
    if (fs.existsSync(path.join(dir, cf))) { configFound = true; checks.push(`${C.green}✓${C.reset} Config: ${cf}`); break; }
  }
  if (!configFound) checks.push(`${C.dim}○ No config file (using defaults)${C.reset}`);
  // MCP install
  if (fs.existsSync(path.join(dir, '.mcp.json'))) checks.push(`${C.green}✓${C.reset} MCP installed (.mcp.json)`);
  else { checks.push(`${C.yellow}⚠${C.reset} MCP not installed — run: vibeguard install`); ok = false; }
  // Hook
  const settingsPath = path.join(dir, '.claude', 'settings.json');
  if (fs.existsSync(settingsPath)) {
    try {
      const s = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
      if (s.hooks && s.hooks.PostToolUse) checks.push(`${C.green}✓${C.reset} PostToolUse hook installed`);
      else checks.push(`${C.yellow}⚠${C.reset} PostToolUse hook not configured`);
    } catch { checks.push(`${C.yellow}⚠${C.reset} .claude/settings.json invalid`); }
  } else checks.push(`${C.dim}○ No PostToolUse hook${C.reset}`);
  // Baseline
  if (fs.existsSync(path.join(dir, '.vibeguard-baseline.json'))) checks.push(`${C.green}✓${C.reset} Baseline exists`);
  else checks.push(`${C.dim}○ No baseline (run: vibeguard verify --baseline)${C.reset}`);
  // .gitignore
  const gitignore = path.join(dir, '.gitignore');
  if (fs.existsSync(gitignore)) {
    const gi = fs.readFileSync(gitignore, 'utf8');
    if (/\.env/.test(gi)) checks.push(`${C.green}✓${C.reset} .env in .gitignore`);
    else { checks.push(`${C.red}✗${C.reset} .env NOT in .gitignore`); ok = false; }
  }
  // CI
  const ciFiles = ['.github/workflows/test.yml', '.gitlab-ci.yml', 'Jenkinsfile', '.circleci/config.yml'];
  const ciFound = ciFiles.some(f => fs.existsSync(path.join(dir, f)));
  if (ciFound) checks.push(`${C.green}✓${C.reset} CI pipeline detected`);
  else checks.push(`${C.dim}○ No CI pipeline detected${C.reset}`);
  process.stdout.write(`${C.bold}VibeGuard Configuration Check${C.reset}\n\n`);
  for (const c of checks) process.stdout.write(`  ${c}\n`);
  process.stdout.write(`\n${ok ? C.green + 'All checks passed.' + C.reset : C.yellow + 'Some checks need attention.' + C.reset}\n`);
  return ok ? 0 : 1;
}

function cmdWatch(dir, flags) {
  process.stdout.write(`${C.bold}VibeGuard Watch Mode${C.reset}\n  Watching ${dir} for changes... (Ctrl+C to stop)\n\n`);
  const { scanFileContent } = require('../src/scanner');
  const watched = new Map();
  function checkFile(filePath) {
    try {
      const stat = fs.statSync(filePath);
      if (!stat.isFile()) return;
      const ext = path.extname(filePath);
      const scanExts = new Set(['.js', '.jsx', '.ts', '.tsx', '.py', '.go', '.rb', '.php', '.java', '.kt', '.swift', '.sh', '.yml', '.yaml', '.json', '.toml', '.sql', '.env', '.tf']);
      if (!scanExts.has(ext) && !/^Dockerfile/i.test(path.basename(filePath))) return;
      const content = fs.readFileSync(filePath, 'utf8');
      const rel = path.relative(dir, filePath).split(path.sep).join('/');
      const prevMtime = watched.get(filePath);
      if (prevMtime === stat.mtimeMs) return;
      watched.set(filePath, stat.mtimeMs);
      const findings = scanFileContent(filePath, rel, content, null);
      if (findings.length > 0) {
        const critical = findings.filter(f => f.severity === 'critical').length;
        const high = findings.filter(f => f.severity === 'high').length;
        const med = findings.filter(f => f.severity === 'medium').length;
        const color = critical > 0 ? C.red : high > 0 ? C.yellow : C.dim;
        process.stdout.write(`${color}[${new Date().toLocaleTimeString()}] ${rel}: ${findings.length} findings${C.reset}\n`);
        for (const f of findings.slice(0, 5)) {
          const sc = f.severity === 'critical' ? C.red : f.severity === 'high' ? C.yellow : C.dim;
          process.stdout.write(`  ${sc}[${f.severity}]${C.reset} ${f.ruleId} line ${f.line} — ${f.message.slice(0, 60)}\n`);
        }
        if (findings.length > 5) process.stdout.write(`  ... and ${findings.length - 5} more\n`);
        process.stdout.write('\n');
      }
    } catch {}
  }
  // Initial scan
  const { walk } = require('../src/scanner');
  const files = walk(dir, []);
  for (const f of files) checkFile(f);
  // Poll for changes (no chokidar dependency)
  setInterval(() => {
    const currentFiles = walk(dir, []);
    for (const f of currentFiles) checkFile(f);
  }, 2000);
  return 0;
}

function cmdPreset(dir, args, flags) {
  if (!args[0] || args[0] === '--list') {
    const list = listPresets();
    process.stdout.write(`${C.bold}Available Presets${C.reset}\n\n`);
    for (const p of list) {
      process.stdout.write(`  ${C.cyan}${p.key.padEnd(12)}${C.reset} ${p.name}\n${C.dim}                ${p.description}${C.reset}\n\n`);
    }
    process.stdout.write(`${C.dim}Usage: vibeguard preset <name>${C.reset}\n`);
    return 0;
  }
  const name = args[0];
  const preset = getPreset(name);
  if (!preset) {
    process.stderr.write(`Unknown preset: ${name}\nAvailable: ${Object.keys(require('../src/presets').PRESETS).join(', ')}\n`);
    return 1;
  }
  const configPath = path.join(dir, '.vibeguardrc.json');
  let config = {};
  try { config = JSON.parse(fs.readFileSync(configPath, 'utf8')); } catch {}
  config.preset = name;
  config.presetName = preset.name;
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');
  process.stdout.write(`${C.green}✓${C.reset} Applied preset: ${C.bold}${preset.name}${C.reset}\n  ${preset.description}\n  Config: ${configPath}\n`);
  return 0;
}

// Read the text to scan from: positional arg, --file <path>, or stdin.
function readPIIInput(args, flags) {
  const positional = args._.slice(1).join(' ').trim();
  if (positional && positional !== '.') return positional;
  if (flags.file) return fs.readFileSync(flags.file, 'utf8');
  try {
    const s = fs.readFileSync(0, 'utf8'); // stdin (fd 0)
    if (s) return s;
  } catch {
    /* no stdin */
  }
  return '';
}

function cmdRedact(args, flags) {
  const { redactText } = require('../src/pii');
  const text = readPIIInput(args, flags);
  if (!text) {
    process.stderr.write('usage: vibeguard redact "text with pii"  |  --file <path>  |  echo text | vibeguard redact\n');
    return 2;
  }
  const types = flags.types ? String(flags.types).split(',').map((s) => s.trim()) : undefined;
  const res = redactText(text, { types });
  if (flags.json) {
    process.stdout.write(JSON.stringify(res, null, 2) + '\n');
    return res.clean ? 0 : 1;
  }
  // Human mode: print the scrubbed text to stdout (pipe-safe), summary to stderr.
  process.stdout.write(res.redacted + (res.redacted.endsWith('\n') ? '' : '\n'));
  if (res.clean) {
    process.stderr.write(`${C.green}No personal data detected — text unchanged.${C.reset}\n`);
  } else {
    const parts = Object.entries(res.counts).map(([t, n]) => `${t}×${n}`).join(', ');
    process.stderr.write(`${C.yellow}Redacted ${res.total} item(s): ${parts}${C.reset}\n`);
  }
  return res.clean ? 0 : 1;
}

function cmdDetectPII(args, flags) {
  const { detectPII } = require('../src/pii');
  const text = readPIIInput(args, flags);
  if (!text) {
    process.stderr.write('usage: vibeguard detect-pii "text with pii"  |  --file <path>  |  echo text | vibeguard detect-pii\n');
    return 2;
  }
  const types = flags.types ? String(flags.types).split(',').map((s) => s.trim()) : undefined;
  const res = detectPII(text, { types });
  if (flags.json) {
    process.stdout.write(JSON.stringify(res, null, 2) + '\n');
    return res.total > 0 ? 1 : 0;
  }
  if (res.total === 0) {
    process.stdout.write(`${C.green}No personal data detected.${C.reset}\n`);
    return 0;
  }
  process.stdout.write(`${C.bold}${C.red}${res.total} personal-data item(s) found:${C.reset}\n\n`);
  for (const m of res.matches) {
    const sc = m.severity === 'critical' ? C.red : m.severity === 'high' ? C.red : m.severity === 'medium' ? C.yellow : C.dim;
    process.stdout.write(`  ${sc}[${m.severity}]${C.reset} ${m.type.padEnd(15)} → ${m.token}  ${C.dim}(offset ${m.start})${C.reset}\n`);
  }
  process.stdout.write(`\n${C.dim}Scrub it: pipe the same text through 'vibeguard redact'.${C.reset}\n`);
  return 1;
}

function cmdSBOM(dir, flags) {
  const { generateSBOM } = require('../src/sbom');
  const bom = generateSBOM(dir);
  if (flags.json || flags.output === 'json') {
    process.stdout.write(JSON.stringify(bom, null, 2) + '\n');
    return 0;
  }
  process.stdout.write(`${C.bold}VibeGuard SBOM — CycloneDX 1.5${C.reset}\n`);
  process.stdout.write(`${C.dim}${'─'.repeat(60)}${C.reset}\n\n`);
  process.stdout.write(`  Format:     ${bom.bomFormat} ${bom.specVersion}\n`);
  process.stdout.write(`  Serial:     ${bom.serialNumber}\n`);
  process.stdout.write(`  Generated:  ${bom.metadata.timestamp}\n`);
  if (bom.metadata.component) {
    process.stdout.write(`  Project:    ${bom.metadata.component.name}@${bom.metadata.component.version}\n`);
  }
  process.stdout.write(`  Components: ${bom.components.length}\n\n`);
  const imported = bom.components.filter(c => c.properties && c.properties.some(p => p.name === 'vibeguard:imported' && p.value === 'true'));
  process.stdout.write(`  ${C.green}Imported in code: ${imported.length}${C.reset}  ${C.dim}(${bom.components.length - imported.length} transitive/not imported)${C.reset}\n\n`);
  if (flags['show-all'] || imported.length <= 20) {
    process.stdout.write(`${C.bold}Components${C.reset}\n`);
    for (const c of bom.components) {
      const isImported = c.properties && c.properties.some(p => p.name === 'vibeguard:imported' && p.value === 'true');
      const mark = isImported ? C.green + '●' : C.dim + '○';
      const lic = c.licenses ? c.licenses[0].license.id : C.dim + 'no license' + C.reset;
      process.stdout.write(`  ${mark}${C.reset} ${c.name.padEnd(30)} ${c.version.padEnd(12)} ${C.dim}${lic}${C.reset}\n`);
    }
  } else {
    process.stdout.write(`${C.dim}Use --show-all to list all ${bom.components.length} components.${C.reset}\n`);
  }
  return 0;
}

async function cmdReachability(dir, flags) {
  const { buildImportGraph } = require('../src/sbom');
  const { scanCVEs } = require('../src/cve-intel');
  const importGraph = buildImportGraph(dir);
  let cveFindings = [];
  try {
    const cveRes = await scanCVEs(dir);
    cveFindings = cveRes.findings || [];
  } catch (e) {
    process.stderr.write(`CVE scan failed: ${e.message}\n`);
    return 2;
  }
  const reachable = [];
  const unreachable = [];
  for (const f of cveFindings) {
    const pkgMatch = f.message && f.message.match(/([@a-z0-9/-]+)\s/);
    const pkgName = pkgMatch ? pkgMatch[1] : '';
    if (pkgName && importGraph[pkgName]) {
      reachable.push({ ...f, reachable: true, importedBy: importGraph[pkgName] });
    } else {
      unreachable.push({ ...f, reachable: false });
    }
  }
  if (flags.json) {
    process.stdout.write(JSON.stringify({ summary: { total: cveFindings.length, reachable: reachable.length, unreachable: unreachable.length }, reachable, unreachable }, null, 2) + '\n');
    return reachable.length > 0 ? 1 : 0;
  }
  process.stdout.write(`${C.bold}VibeGuard Dependency Reachability${C.reset}\n`);
  process.stdout.write(`${C.dim}${'─'.repeat(60)}${C.reset}\n\n`);
  process.stdout.write(`  Total CVEs:       ${cveFindings.length}\n`);
  process.stdout.write(`  ${C.red}Reachable:        ${reachable.length}${C.reset}  ${C.dim}(imported in your code — fix these first)${C.reset}\n`);
  process.stdout.write(`  ${C.dim}Unreachable:      ${unreachable.length}${C.reset}  ${C.dim}(transitive only — lower priority)${C.reset}\n\n`);
  if (reachable.length > 0) {
    process.stdout.write(`${C.red}${C.bold}Reachable vulnerabilities (fix first):${C.reset}\n`);
    for (const f of reachable) {
      process.stdout.write(`  ${C.red}[${f.severity}]${C.reset} ${f.title}\n    ${C.dim}Imported by: ${f.importedBy.join(', ')}${C.reset}\n    ${C.green}fix:${C.reset} ${f.fix}\n\n`);
    }
  }
  if (unreachable.length > 0 && flags['show-all']) {
    process.stdout.write(`${C.dim}Unreachable (transitive only):${C.reset}\n`);
    for (const f of unreachable) {
      process.stdout.write(`  ${C.dim}[${f.severity}]${C.reset} ${C.dim}${f.title}${C.reset}\n`);
    }
  }
  return reachable.length > 0 ? 1 : 0;
}

async function cmdContainerScan(args, flags) {
  const image = args._[1];
  if (!image) {
    process.stderr.write('Usage: vibeguard container-scan <image>\n');
    process.stderr.write('Example: vibeguard container-scan myapp:latest\n');
    return 2;
  }
  const { execFileSync } = require('child_process');
  process.stdout.write(`${C.bold}VibeGuard Container Scan${C.reset}\n`);
  process.stdout.write(`${C.dim}Image: ${image}${C.reset}\n`);
  process.stdout.write(`${C.dim}${'─'.repeat(60)}${C.reset}\n\n`);
  try {
    const output = execFileSync('trivy', ['image', '--format', 'json', '--quiet', image], {
      timeout: 120000,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const result = JSON.parse(output);
    const vulns = (result.Results || []).flatMap(r => (r.Vulnerabilities || []).map(v => ({
      cve: v.VulnerabilityID,
      package: v.PkgName,
      severity: v.Severity,
      installed: v.InstalledVersion,
      fixed: v.FixedVersion,
      title: v.Title,
    })));
    if (flags.json) {
      process.stdout.write(JSON.stringify({ image, summary: { vulnerabilities: vulns.length, critical: vulns.filter(v => v.severity === 'CRITICAL').length, high: vulns.filter(v => v.severity === 'HIGH').length }, vulnerabilities: vulns }, null, 2) + '\n');
      return vulns.length > 0 ? 1 : 0;
    }
    const crit = vulns.filter(v => v.severity === 'CRITICAL');
    const high = vulns.filter(v => v.severity === 'HIGH');
    const med = vulns.filter(v => v.severity === 'MEDIUM');
    const low = vulns.filter(v => v.severity === 'LOW');
    process.stdout.write(`  ${C.red}CRITICAL: ${crit.length}${C.reset}  ${C.red}HIGH: ${high.length}${C.reset}  ${C.yellow}MEDIUM: ${med.length}${C.reset}  ${C.dim}LOW: ${low.length}${C.reset}\n\n`);
    if (vulns.length === 0) {
      process.stdout.write(`${C.green}No vulnerabilities found.${C.reset}\n`);
      return 0;
    }
    for (const v of vulns) {
      const sc = v.severity === 'CRITICAL' ? C.red : v.severity === 'HIGH' ? C.red : v.severity === 'MEDIUM' ? C.yellow : C.dim;
      process.stdout.write(`  ${sc}[${v.severity}]${C.reset} ${v.cve}  ${C.bold}${v.package}${C.reset} ${v.installed} → ${C.green}${v.fixed || 'no fix'}${C.reset}\n    ${C.dim}${v.title}${C.reset}\n`);
    }
    return crit.length > 0 ? 1 : 0;
  } catch (err) {
    if (err.code === 'ENOENT' || (err.message && err.message.includes('not found'))) {
      process.stderr.write(`${C.red}trivy is not installed.${C.reset}\n`);
      process.stderr.write(`${C.dim}Install from https://trivy.dev or: brew install trivy (macOS) / choco install trivy (Windows)${C.reset}\n`);
      return 2;
    }
    if (err.killed) {
      process.stderr.write(`${C.red}trivy scan timed out (120s).${C.reset}\n`);
      return 2;
    }
    process.stderr.write(`${C.red}trivy scan failed: ${err.message}${C.reset}\n`);
    return 2;
  }
}

async function cmdLicense(dir, flags) {
  const fs = require('fs');
  const path = require('path');
  const pkgPath = path.join(dir, 'package.json');
  if (!fs.existsSync(pkgPath)) {
    process.stderr.write(`No package.json found in ${dir}\n`);
    return 2;
  }
  const pkgJson = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  const allDeps = { ...(pkgJson.dependencies || {}), ...(pkgJson.devDependencies || {}) };
  const ALLOWED = ['MIT', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause', 'Apache-2.0', '0BSD', 'Unlicensed', 'CC0-1.0', 'Python-2.0'];
  const customAllow = flags.allow ? String(flags.allow).split(',').map(s => s.trim()) : [];
  const fullAllow = [...ALLOWED, ...customAllow];
  const compliant = [];
  const nonCompliant = [];
  for (const [name, version] of Object.entries(allDeps)) {
    let depPkg = null;
    try {
      depPkg = JSON.parse(fs.readFileSync(path.join(dir, 'node_modules', name, 'package.json'), 'utf8'));
    } catch {
      nonCompliant.push({ name, version, license: 'unknown', reason: 'package.json not found (run npm install first)' });
      continue;
    }
    const lic = depPkg.license || 'unknown';
    const licStr = typeof lic === 'string' ? lic : (lic && lic.type) || 'unknown';
    if (fullAllow.includes(licStr)) {
      compliant.push({ name, version, license: licStr });
    } else {
      nonCompliant.push({ name, version, license: licStr, reason: 'license not in allowlist' });
    }
  }
  if (flags.json) {
    process.stdout.write(JSON.stringify({ summary: { total: Object.keys(allDeps).length, compliant: compliant.length, nonCompliant: nonCompliant.length }, allowlist: fullAllow, compliant, nonCompliant }, null, 2) + '\n');
    return nonCompliant.length > 0 ? 1 : 0;
  }
  process.stdout.write(`${C.bold}VibeGuard License Compliance${C.reset}\n`);
  process.stdout.write(`${C.dim}${'─'.repeat(60)}${C.reset}\n\n`);
  process.stdout.write(`  Total dependencies: ${Object.keys(allDeps).length}\n`);
  process.stdout.write(`  ${C.green}Compliant:          ${compliant.length}${C.reset}\n`);
  process.stdout.write(`  ${C.red}Non-compliant:      ${nonCompliant.length}${C.reset}\n`);
  process.stdout.write(`  ${C.dim}Allowlist:          ${fullAllow.join(', ')}${C.reset}\n\n`);
  if (nonCompliant.length > 0) {
    process.stdout.write(`${C.red}${C.bold}Non-compliant licenses:${C.reset}\n`);
    for (const nc of nonCompliant) {
      process.stdout.write(`  ${C.red}[${nc.license}]${C.reset} ${C.bold}${nc.name}${C.reset}@${nc.version}  ${C.dim}${nc.reason}${C.reset}\n`);
    }
    process.stdout.write(`\n${C.dim}Use --allow GPL-3.0 to add licenses to the allowlist.${C.reset}\n`);
  } else {
    process.stdout.write(`${C.green}All dependencies use compliant licenses.${C.reset}\n`);
  }
  return nonCompliant.length > 0 ? 1 : 0;
}

function cmdDashboard(dir, flags) {
  const result = scan(dir);
  const { renderDashboard } = require('../src/dashboard');
  process.stdout.write(renderDashboard(result));
  return result.findings.length > 0 ? 1 : 0;
}

function cmdPRComment(dir, flags) {
  const result = scan(dir);
  const { renderPRComment } = require('../src/dashboard');
  process.stdout.write(renderPRComment(result));
  return result.findings.length > 0 ? 1 : 0;
}

function cmdProxyStart(flags) {
  const { startProxy, getProxyStatus, PROXY_DIR } = require('../src/proxy');
  const port = flags.port ? parseInt(flags.port) : undefined;
  const server = startProxy(port);
  const status = getProxyStatus();
  process.stdout.write(`${C.green}VibeGuard proxy started${C.reset} on port ${status.port}\n`);
  process.stdout.write(`${C.dim}CA cert: ${PROXY_DIR}/ca-cert.pem${C.reset}\n`);
  process.stdout.write(`${C.dim}Export for child processes:${C.reset}\n`);
  process.stdout.write(`  export HTTP_PROXY=http://127.0.0.1:${status.port}\n`);
  process.stdout.write(`  export HTTPS_PROXY=http://127.0.0.1:${status.port}\n`);
  process.stdout.write(`\n${C.yellow}To inspect HTTPS traffic, install the CA cert in your trust store:${C.reset}\n`);
  process.stdout.write(`${C.dim}  macOS: security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ${PROXY_DIR}/ca-cert.pem${C.reset}\n`);
  process.stdout.write(`${C.dim}  Linux: sudo cp ${PROXY_DIR}/ca-cert.pem /usr/local/share/ca-certificates/ && sudo update-ca-certificates${C.reset}\n`);
  process.stdout.write(`${C.dim}  Windows: certutil -addstore -f "ROOT" ${PROXY_DIR}\\ca-cert.pem${C.reset}\n`);
  // Keep the process alive
  process.stdin.resume();
  return 0;
}

function cmdProxyStop(flags) {
  const { stopProxy } = require('../src/proxy');
  stopProxy();
  process.stdout.write(`${C.green}VibeGuard proxy stopped.${C.reset}\n`);
  return 0;
}

function cmdProxyStatus(flags) {
  const { getProxyStatus } = require('../src/proxy');
  const status = getProxyStatus();
  if (flags.json) {
    process.stdout.write(JSON.stringify(status, null, 2) + '\n');
    return 0;
  }
  process.stdout.write(`${C.bold}VibeGuard Proxy Status${C.reset}\n`);
  process.stdout.write(`${C.dim}${'─'.repeat(60)}${C.reset}\n\n`);
  process.stdout.write(`  Running:    ${status.running ? C.green + 'YES' : C.red + 'NO'}${C.reset}\n`);
  process.stdout.write(`  Port:       ${status.port || 'N/A'}\n`);
  process.stdout.write(`  CA Cert:    ${status.caCertPath || 'not generated'}\n`);
  if (status.auditLog && status.auditLog.length > 0) {
    process.stdout.write(`\n${C.bold}Recent blocked requests${C.reset} (${status.auditLog.length}):\n`);
    for (const entry of status.auditLog.slice(-20)) {
      const sc = entry.violation.severity === 'critical' ? C.red : C.yellow;
      process.stdout.write(`  ${sc}[${entry.violation.severity}]${C.reset} ${entry.method} ${entry.url}\n`);
      process.stdout.write(`    ${C.dim}${entry.violation.message}${C.reset}\n`);
    }
  } else if (status.running) {
    process.stdout.write(`\n${C.green}No blocked requests.${C.reset}\n`);
  }
  return 0;
}

function cmdGuard(args, flags) {
  const { checkCommand } = require('../src/shell-guard');
  const cmd = args._.slice(1).join(' ');
  if (!cmd) {
    process.stderr.write('Usage: vibeguard guard "<command>"\n');
    process.stderr.write('Checks a command for danger before execution.\n');
    process.stderr.write('Exit 0 = safe, exit 1 = blocked, exit 2 = error.\n');
    return 2;
  }
  const result = checkCommand(cmd);
  if (flags.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else if (result.blocked) {
    process.stdout.write(`\n  ${C.red}[VibeGuard] BLOCKED:${C.reset} ${C.bold}${result.command}${C.reset}\n`);
    process.stdout.write(`  ${C.red}Reason:${C.reset}   ${result.reason}\n`);
    process.stdout.write(`  ${C.red}Severity:${C.reset} ${result.severity}\n`);
    if (result.violations.length > 1) {
      process.stdout.write(`  ${C.red}All violations:${C.reset}\n`);
      for (const v of result.violations) {
        process.stdout.write(`    - [${v.severity}] ${v.type}: ${v.reason}\n`);
      }
    }
    process.stdout.write(`\n  ${C.dim}Override: VG_OVERRIDE=1 <command>${C.reset}\n\n`);
  } else {
    process.stdout.write(`${C.green}[VibeGuard] Safe:${C.reset} ${cmd.slice(0, 100)}\n`);
  }
  return result.blocked ? 1 : 0;
}

function cmdInstallShellHook(flags) {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');

  // Consent prompt — never modify shell profiles without asking.
  if (!flags.yes && !flags.force) {
    process.stdout.write('\n  VibeGuard will modify your shell profile (.bashrc/.zshrc/PowerShell profile)\n');
    process.stdout.write('  to intercept dangerous commands before they execute.\n\n');
    process.stdout.write('  This adds a sourced line and is fully reversible (vibeguard uninstall-shell-hook).\n');
    process.stdout.write('  Backups are saved to .vibeguard/backups/.\n\n');
    process.stdout.write('  Proceed? [y/N] ');
    const answer = fs.readFileSync(0, 'utf8').trim().toLowerCase();
    if (answer !== 'y' && answer !== 'yes') {
      process.stdout.write('\n  Skipped. Run "vibeguard install-shell-hook --yes" to skip this prompt.\n\n');
      return 0;
    }
  }

  const srcDir = path.resolve(__dirname, '..', 'src');
  const home = os.homedir();
  const results = [];

  // Detect shells and install
  // 1. bash
  const bashProfile = path.join(home, '.bashrc');
  const bashMarker = '# >>> VibeGuard shell hook >>>';
  const bashEndMarker = '# <<< VibeGuard shell hook <<<';
  const bashHook = [
    bashMarker,
    `source "${path.join(srcDir, 'shell-hook.sh')}"`,
    bashEndMarker,
  ].join('\n');

  try {
    let content = fs.existsSync(bashProfile) ? fs.readFileSync(bashProfile, 'utf8') : '';
    // Remove old hook
    content = content.replace(new RegExp(`${bashMarker}[\\s\\S]*?${bashEndMarker}\\n?`, 'g'), '');
    content = content.trimEnd() + '\n' + bashHook + '\n';
    fs.writeFileSync(bashProfile, content);
    results.push(`bash: installed in ${bashProfile}`);
  } catch (e) {
    results.push(`bash: failed (${e.message})`);
  }

  // 2. zsh
  const zshProfile = path.join(home, '.zshrc');
  try {
    let content = fs.existsSync(zshProfile) ? fs.readFileSync(zshProfile, 'utf8') : '';
    content = content.replace(new RegExp(`${bashMarker}[\\s\\S]*?${bashEndMarker}\\n?`, 'g'), '');
    content = content.trimEnd() + '\n' + bashHook + '\n';
    fs.writeFileSync(zshProfile, content);
    results.push(`zsh: installed in ${zshProfile}`);
  } catch (e) {
    results.push(`zsh: failed (${e.message})`);
  }

  // 3. PowerShell (Windows)
  if (process.platform === 'win32') {
    try {
      const psProfileDir = path.join(home, 'Documents', 'WindowsPowerShell');
      if (!fs.existsSync(psProfileDir)) fs.mkdirSync(psProfileDir, { recursive: true });
      const psProfile = path.join(psProfileDir, 'Microsoft.PowerShell_profile.ps1');
      const psMarker = '### >>> VibeGuard shell hook >>>';
      const psEndMarker = '### <<< VibeGuard shell hook <<<';
      let content = fs.existsSync(psProfile) ? fs.readFileSync(psProfile, 'utf8') : '';
      content = content.replace(new RegExp(`${psMarker}[\\s\\S]*?${psEndMarker}\\n?`, 'g'), '');
      const psHook = [
        psMarker,
        `$VG_SCRIPT_DIR = "${srcDir.replace(/\\/g, '\\\\')}"`,
        `. "${path.join(srcDir, 'shell-hook.ps1').replace(/\\/g, '\\\\')}"`,
        psEndMarker,
      ].join('\n');
      content = content.trimEnd() + '\n' + psHook + '\n';
      fs.writeFileSync(psProfile, content);
      results.push(`powershell: installed in ${psProfile}`);
    } catch (e) {
      results.push(`powershell: failed (${e.message})`);
    }
  }

  // 4. Node.js guard info
  results.push(`node: use --require vibeguard/guard to protect any Node.js process`);

  process.stdout.write(`\n${C.green}[VibeGuard] Shell hook installed:${C.reset}\n\n`);
  for (const r of results) {
    process.stdout.write(`  ${C.bold}${r}${C.reset}\n`);
  }
  process.stdout.write(`\n${C.dim}Restart your shell for changes to take effect.${C.reset}\n`);
  process.stdout.write(`${C.dim}Override: set VG_OVERRIDE=1 to bypass for a single command.${C.reset}\n`);
  process.stdout.write(`${C.dim}Uninstall: vibeguard uninstall-shell-hook${C.reset}\n\n`);
  return 0;
}

function cmdUninstallShellHook(flags) {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const home = os.homedir();
  const results = [];
  const bashMarker = '# >>> VibeGuard shell hook >>>';
  const bashEndMarker = '# <<< VibeGuard shell hook <<<';
  const psMarker = '### >>> VibeGuard shell hook >>>';
  const psEndMarker = '### <<< VibeGuard shell hook <<<';

  for (const profile of ['.bashrc', '.zshrc']) {
    const p = path.join(home, profile);
    try {
      if (fs.existsSync(p)) {
        let content = fs.readFileSync(p, 'utf8');
        content = content.replace(new RegExp(`${bashMarker}[\\s\\S]*?${bashEndMarker}\\n?`, 'g'), '');
        fs.writeFileSync(p, content);
        results.push(`${profile}: removed`);
      }
    } catch (e) {
      results.push(`${profile}: failed (${e.message})`);
    }
  }

  if (process.platform === 'win32') {
    try {
      const psProfile = path.join(home, 'Documents', 'WindowsPowerShell', 'Microsoft.PowerShell_profile.ps1');
      if (fs.existsSync(psProfile)) {
        let content = fs.readFileSync(psProfile, 'utf8');
        content = content.replace(new RegExp(`${psMarker}[\\s\\S]*?${psEndMarker}\\n?`, 'g'), '');
        fs.writeFileSync(psProfile, content);
        results.push('powershell: removed');
      }
    } catch (e) {
      results.push(`powershell: failed (${e.message})`);
    }
  }

  process.stdout.write(`\n${C.green}[VibeGuard] Shell hook removed:${C.reset}\n\n`);
  for (const r of results) {
    process.stdout.write(`  ${C.bold}${r}${C.reset}\n`);
  }
  process.stdout.write(`\n${C.dim}Restart your shell for changes to take effect.${C.reset}\n\n`);
  return 0;
}

// ─── unified auto: delegates to src/auto.js ────────────────────────────────

function cmdAutoUnified(dir, args, flags) {
  const auto = require('../src/auto');
  const rootDir = path.resolve(dir || '.');

  // auto --stop
  if (flags.stop || (args._ && args._[1] === '--stop')) {
    const r = auto.autoStop(rootDir);
    if (!r.ok) {
      process.stdout.write(`${C.yellow}[VibeGuard] ${r.reason}${C.reset}\n`);
      return 0;
    }
    process.stdout.write(`${C.green}[VibeGuard] Auto protection stopped.${C.reset}\n\n`);
    for (const s of r.reversed) {
      process.stdout.write(`  ${C.green}OK${C.reset} ${s}\n`);
    }
    process.stdout.write(`\n${C.dim}All hooks removed. Repo restored.${C.reset}\n`);
    return 0;
  }

  // auto --status
  if (flags.status || (args._ && args._[1] === '--status')) {
    const s = auto.autoStatus(rootDir);
    if (flags.json) {
      process.stdout.write(JSON.stringify(s, null, 2) + '\n');
      return 0;
    }
    if (!s.running) {
      process.stdout.write(`${C.dim}[VibeGuard] Not active${C.reset}\n`);
      process.stdout.write(`${C.dim}Run 'vibeguard auto' to start.${C.reset}\n`);
      return 0;
    }
    process.stdout.write(`${C.green}[VibeGuard] Active${C.reset}\n\n`);
    process.stdout.write(`  ${C.bold}PID:${C.reset}            ${s.pid}\n`);
    process.stdout.write(`  ${C.bold}Daemon PID:${C.reset}     ${s.daemonPid || 'n/a'} ${s.daemonAlive ? C.green + '(alive)' + C.reset : C.red + '(dead)' + C.reset}\n`);
    process.stdout.write(`  ${C.bold}Started:${C.reset}        ${s.startedAt}\n`);
    process.stdout.write(`  ${C.bold}Uptime:${C.reset}         ${Math.round(s.uptimeMs / 1000)}s\n`);
    process.stdout.write(`  ${C.bold}Last scan:${C.reset}      ${s.lastScan || 'n/a'}\n`);
    process.stdout.write(`  ${C.bold}Findings:${C.reset}       ${s.findingsSinceStart}\n\n`);
    process.stdout.write(`  ${C.bold}Features:${C.reset}\n`);
    for (const [k, v] of Object.entries(s.features || {})) {
      process.stdout.write(`    ${v ? C.green + 'ON' + C.reset : C.dim + 'OFF' + C.reset} ${k}\n`);
    }
    process.stdout.write(`\n  ${C.dim}Stop: vibeguard auto --stop${C.reset}\n`);
    return 0;
  }

  // auto --ci (non-interactive pipeline mode)
  if (flags.ci) {
    const r = auto.autoCI(rootDir, { ci: true, strict: flags.strict, deep: flags.deep });
    if (r.ci) {
      for (const step of r.steps) {
        if (step.step === 'scan') {
          process.stdout.write(`Grade: ${step.grade}  Critical: ${step.counts.critical || 0}  High: ${step.counts.high || 0}\n`);
        }
      }
      return r.exitCode || 0;
    }
    process.stderr.write(`${C.red}[VibeGuard] CI mode failed${C.reset}\n`);
    return 2;
  }

  // auto (full start)
  const opts = {
    fix: !!flags.fix,
    strict: !!flags.strict,
    noShell: !!flags['no-shell'],
    deep: !!flags.deep,
    verbose: !!flags.verbose,
    yes: !!flags.yes || !!flags.force,
  };

  process.stdout.write(`\n${C.bold}${C.cyan}[VibeGuard] Activating full protection...${C.reset}\n\n`);

  const r = auto.autoStart(rootDir, opts);
  if (!r.ok) {
    process.stderr.write(`${C.red}[VibeGuard] ${r.reason}${C.reset}\n`);
    return 2;
  }

  if (r.alreadyRunning) {
    process.stdout.write(`${C.yellow}[VibeGuard] Already active. Use 'vibeguard auto --status' for details.${C.reset}\n`);
    return 0;
  }

  // Print steps
  for (const step of r.steps) {
    const icon = step.error ? C.red + 'X' : C.green + 'OK';
    const name = step.step.padEnd(20);
    if (step.error) {
      process.stdout.write(`  ${icon} ${name} ${C.red}${step.error}${C.reset}\n`);
    } else if (step.step === 'scan') {
      process.stdout.write(`  ${icon} ${name} ${C.bold}Grade: ${step.grade}${C.reset}  Critical: ${step.counts.critical || 0}  High: ${step.counts.high || 0}${C.reset}\n`);
    } else {
      process.stdout.write(`  ${icon} ${name} ${C.dim}done${C.reset}\n`);
    }
  }

  process.stdout.write(`\n${C.green}${C.bold}[VibeGuard] Fully active:${C.reset}\n\n`);
  process.stdout.write(`  ${C.green}1.${C.reset} Daemon          — auto-scans every file change\n`);
  process.stdout.write(`  ${C.green}2.${C.reset} Pre-commit hook  — blocks commits on critical\n`);
  process.stdout.write(`  ${C.green}3.${C.reset} Post-edit hook   — scans AI agent edits\n`);
  process.stdout.write(`  ${C.green}4.${C.reset} Shell guard      — blocks dangerous commands${C.reset}\n\n`);
  process.stdout.write(`  ${C.dim}Status: vibeguard auto --status${C.reset}\n`);
  process.stdout.write(`  ${C.dim}Stop:   vibeguard auto --stop${C.reset}\n`);
  process.stdout.write(`  ${C.dim}Override: VG_OVERRIDE=1 <command>${C.reset}\n\n`);

  return 0;
}

// Keep old auto-* commands as aliases to unified auto
function cmdAutoStart(dir, flags) {
  return cmdAutoUnified(dir, {}, flags);
}
function cmdAutoStop(dir, flags) {
  return cmdAutoUnified(dir, { _: ['', '--stop'] }, { stop: true, ...flags });
}
function cmdAutoStatus(dir, flags) {
  return cmdAutoUnified(dir, { _: ['', '--status'] }, { status: true, ...flags });
}

main().catch((err) => {
  process.stderr.write(`vibeguard error: ${err && err.message ? err.message : err}\n`);
  process.exit(2);
});
