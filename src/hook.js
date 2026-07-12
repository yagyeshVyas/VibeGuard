'use strict';

/*
 * VibeGuard Real-Time Hook — PostToolUse auto-scan.
 *
 * This module provides two integration modes:
 *
 * 1. Claude Code hook (settings.json):
 *    Add to .claude/settings.json:
 *    {
 *      "hooks": {
 *        "PostToolUse": [{
 *          "matcher": "Edit|Write|MultiEdit",
 *          "hooks": [{ "type": "command", "command": "npx -y @yagyeshvyas/vibeguard hook-post-edit" }]
 *        }]
 *      }
 *    }
 *    After every file edit/write by Claude Code, VibeGuard scans the changed file
 *    and prints warnings if security issues are found.
 *
 * 2. Generic file watcher (any AI tool):
 *    vibeguard watch-post-edit
 *    Watches the current directory for file changes and auto-scans them.
 *
 * 3. Git pre-commit hook (already exists via `vibeguard install-hook`).
 *
 * All modes are ZERO-COST — no API calls, no network, pure local scanning.
 */

const fs = require('fs');
const path = require('path');
const { scanFileContent } = require('./scanner');
const { computeGrade } = require('./scanner');

const C = {
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
  blue: '\x1b[34m', cyan: '\x1b[36m', dim: '\x1b[2m',
  bold: '\x1b[1m', reset: '\x1b[0m',
};

// Called by Claude Code PostToolUse hook — reads the tool input from stdin
// (Claude Code pipes the tool result as JSON on stdin).
function handlePostEdit() {
  let input = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => (input += chunk));
  process.stdin.on('end', () => {
    let toolInput;
    try { toolInput = JSON.parse(input); } catch { return; }

    // Claude Code PostToolUse sends { tool_name, tool_input, tool_result }
    const toolName = toolInput.tool_name || toolInput.toolName || '';
    const toolInputData = toolInput.tool_input || toolInput.toolInput || {};
    const filePath = toolInputData.file_path || toolInputData.filePath || toolInputData.path || '';

    if (!filePath || !fs.existsSync(filePath)) {
      return; // no file to scan
    }

    // Only scan code files
    const ext = path.extname(filePath).toLowerCase();
    const scanExts = new Set(['.js', '.jsx', '.ts', '.tsx', '.py', '.go', '.rb', '.php', '.java', '.kt', '.swift', '.m', '.sh', '.yml', '.yaml', '.json', '.toml', '.sql', '.env', '.dockerfile', '.tf']);
    if (!scanExts.has(ext) && !/^Dockerfile/i.test(path.basename(filePath))) return;

    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const relPath = path.relative(process.cwd(), filePath);
      const findings = scanFileContent(filePath, relPath, content, null);

      if (findings.length === 0) return;

      // Print warnings to stderr (Claude Code captures stderr and shows it)
      const critical = findings.filter(f => f.severity === 'critical');
      const high = findings.filter(f => f.severity === 'high');
      const medium = findings.filter(f => f.severity === 'medium');

      if (critical.length > 0 || high.length > 0) {
        process.stderr.write(`\n${C.red}${C.bold}VibeGuard: ${critical.length} critical, ${high.length} high in ${relPath}${C.reset}\n`);
        for (const f of [...critical, ...high].slice(0, 10)) {
          process.stderr.write(`  ${C.red}[${f.severity}]${C.reset} ${f.ruleId} ${C.dim}line ${f.line}${C.reset} — ${f.message}\n`);
          if (f.fix) process.stderr.write(`  ${C.green}fix:${C.reset} ${f.fix}\n`);
        }
        process.stderr.write(`${C.dim}Run 'vibeguard scan' for full report.${C.reset}\n\n`);
      } else if (medium.length > 0) {
        process.stderr.write(`\n${C.yellow}VibeGuard: ${medium.length} medium findings in ${relPath}${C.reset}\n`);
        for (const f of medium.slice(0, 5)) {
          process.stderr.write(`  ${C.yellow}[medium]${C.reset} ${f.ruleId} ${C.dim}line ${f.line}${C.reset}\n`);
        }
        process.stderr.write(`\n`);
      }
    } catch {
      // silent fail — never block the AI from working
    }
  });
}

// Install the PostToolUse hook into Claude Code's settings.json
function installPostEditHook(dir) {
  const settingsDir = path.join(dir, '.claude');
  const settingsFile = path.join(settingsDir, 'settings.json');

  let settings = {};
  try {
    settings = JSON.parse(fs.readFileSync(settingsFile, 'utf8'));
  } catch {}

  if (!settings.hooks) settings.hooks = {};
  if (!settings.hooks.PostToolUse) settings.hooks.PostToolUse = [];

  // Check if already installed
  const exists = settings.hooks.PostToolUse.some(
    h => h.hooks && h.hooks.some(hh => hh.command && (hh.command.includes('vibeguard') || hh.command.includes('hook-post-edit')))
  );
  if (exists) return { installed: false, reason: 'already present' };

  const cliPath = path.resolve(__dirname, '..', 'bin', 'cli.js');
  const nodeBin = process.execPath;
  const cmd = process.platform === 'win32'
    ? `"${nodeBin}" "${cliPath}" hook-post-edit`
    : `node "${cliPath}" hook-post-edit`;

  settings.hooks.PostToolUse.push({
    matcher: 'Edit|Write|MultiEdit',
    hooks: [{ type: 'command', command: cmd }],
  });

  fs.mkdirSync(settingsDir, { recursive: true });
  fs.writeFileSync(settingsFile, JSON.stringify(settings, null, 2) + '\n');
  return { installed: true, file: settingsFile };
}

// Remove the PostToolUse hook
function uninstallPostEditHook(dir) {
  const settingsFile = path.join(dir, '.claude', 'settings.json');
  let settings;
  try { settings = JSON.parse(fs.readFileSync(settingsFile, 'utf8')); } catch { return { uninstalled: false, reason: 'no settings.json' }; }
  if (!settings.hooks || !settings.hooks.PostToolUse) return { uninstalled: false, reason: 'no PostToolUse hooks' };

  const before = settings.hooks.PostToolUse.length;
  settings.hooks.PostToolUse = settings.hooks.PostToolUse.filter(
    h => !h.hooks || !h.hooks.some(hh => hh.command && (hh.command.includes('vibeguard') || hh.command.includes('hook-post-edit')))
  );
  const afterLen = settings.hooks.PostToolUse ? settings.hooks.PostToolUse.length : 0;
  if (settings.hooks.PostToolUse && settings.hooks.PostToolUse.length === 0) delete settings.hooks.PostToolUse;
  if (settings.hooks && Object.keys(settings.hooks).length === 0) delete settings.hooks;

  fs.writeFileSync(settingsFile, JSON.stringify(settings, null, 2) + '\n');
  return { uninstalled: before > afterLen };
}

module.exports = { handlePostEdit, installPostEditHook, uninstallPostEditHook };
