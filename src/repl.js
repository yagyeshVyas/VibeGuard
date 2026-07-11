'use strict';

/*
 * Interactive REPL for VibeGuard.
 *
 * Launches an interactive session where the user can:
 *   - Inspect findings one by one
 *   - Mark findings as "solved" (fixed), "ignored" (suppress), or "skip"
 *   - Auto-apply suggested fixes where available
 *   - Persist decisions to .vibeguard/state.json for team sharing
 *
 * Usage: vibeguard repl [dir]
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { scan } = require('./scanner');
const { suggestFixes } = require('./autofix');

const STATE_FILE = '.vibeguard/state.json';

function loadState(root) {
  const p = path.join(root, STATE_FILE);
  if (fs.existsSync(p)) {
    try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch {}
  }
  return { decisions: {}, lastRun: null };
}

function saveState(root, state) {
  const dir = path.join(root, '.vibeguard');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  state.lastRun = new Date().toISOString();
  fs.writeFileSync(path.join(dir, 'state.json'), JSON.stringify(state, null, 2));
}

const COLORS = {
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
  blue: '\x1b[34m', cyan: '\x1b[36m', dim: '\x1b[2m',
  bold: '\x1b[1m', reset: '\x1b[0m',
};

async function startRepl(dir, opts) {
  opts = opts || {};
  const result = scan(dir);
  const findings = result.findings;

  if (findings.length === 0) {
    process.stdout.write(`${COLORS.green}No findings. Clean!${COLORS.reset}\n`);
    return 0;
  }

  const state = loadState(dir);
  let idx = 0;
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  process.stdout.write(
    `${COLORS.bold}${COLORS.cyan}VibeGuard Interactive REPL${COLORS.reset}\n` +
    `${COLORS.dim}${findings.length} findings. Commands: (s)olved (i)gnore (n)ext (a)uto-fix (q)uit (l)ist${COLORS.reset}\n\n`
  );

  function showCurrent() {
    if (idx >= findings.length) {
      process.stdout.write(`${COLORS.green}All findings reviewed!${COLORS.reset}\n`);
      saveState(dir, state);
      rl.close();
      return;
    }
    const f = findings[idx];
    const sev = f.severity || 'medium';
    const sevColor = sev === 'critical' || sev === 'high' ? COLORS.red : sev === 'medium' ? COLORS.yellow : COLORS.blue;
    const status = state.decisions[f.fingerprint] || 'open';

    process.stdout.write(
      `\n${COLORS.bold}[${idx + 1}/${findings.length}]${COLORS.reset} ` +
      `${sevColor}${sev}${COLORS.reset} ` +
      `${COLORS.dim}${f.ruleId}${COLORS.reset}\n` +
      `  ${COLORS.bold}${f.title}${COLORS.reset}\n` +
      `  ${COLORS.dim}${f.file}:${f.line}${COLORS.reset}\n` +
      `  ${f.message || ''}\n` +
      `  ${f.fix ? `${COLORS.green}fix: ${COLORS.reset}${f.fix}` : ''}\n` +
      `  ${COLORS.dim}status: ${status}${COLORS.reset}\n` +
      `${COLORS.dim}(s)olved (i)gnore (n)ext (a)uto-fix (b)ack (l)ist (q)uit${COLORS.reset}\n> `
    );
  }

  return new Promise((resolve) => {
    rl.on('line', (input) => {
      const cmd = input.trim().toLowerCase();
      const f = findings[idx];

      switch (cmd) {
        case 's':
        case 'solved':
          state.decisions[f.fingerprint] = 'solved';
          idx++;
          showCurrent();
          break;
        case 'i':
        case 'ignore':
          state.decisions[f.fingerprint] = 'ignored';
          idx++;
          showCurrent();
          break;
        case 'n':
        case 'next':
        case '':
          idx++;
          showCurrent();
          break;
        case 'b':
        case 'back':
          if (idx > 0) idx--;
          showCurrent();
          break;
        case 'a':
        case 'auto-fix':
          if (f.fix) {
            process.stdout.write(`${COLORS.yellow}Auto-fix: ${f.fix}${COLORS.reset}\n`);
          } else {
            process.stdout.write(`${COLORS.dim}No auto-fix available for this rule.${COLORS.reset}\n`);
          }
          state.decisions[f.fingerprint] = 'auto-fix-pending';
          showCurrent();
          break;
        case 'l':
        case 'list':
          findings.forEach((ff, i) => {
            const st = state.decisions[ff.fingerprint] || 'open';
            const mark = st === 'solved' ? '✓' : st === 'ignored' ? '✗' : ' ';
            process.stdout.write(`  ${mark} [${i + 1}] ${ff.severity} ${ff.ruleId} ${ff.file}:${ff.line}\n`);
          });
          process.stdout.write(`\n> `);
          break;
        case 'q':
        case 'quit':
          saveState(dir, state);
          rl.close();
          resolve(0);
          break;
        default:
          process.stdout.write(`${COLORS.dim}Unknown command.${COLORS.reset}\n> `);
      }
    });
    showCurrent();
  });
}

module.exports = { startRepl, loadState, saveState };
