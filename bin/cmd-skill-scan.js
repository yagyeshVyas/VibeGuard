'use strict';

/*
 * bin/cmd-skill-scan.js — scan agent skills / plugins / instruction files.
 *
 * Exit codes: 0 clean, 1 medium/high, 2 critical.
 */

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { scanSkills, renderSkillReport, collectSkillFiles } = require('../src/skill-scan');

// Skill pinning (rug-pull protection): an agent skill is an executable
// instruction set. Pin its content hash after review; a later change to a pinned
// file is reported as critical drift, and a pinned file that disappears is
// medium. Pins live next to the other VibeGuard runtime state.
function pinsPath(root) {
  return path.join(root, '.vibeguard', 'skill-pins.json');
}

function hashSkillFiles(root, files) {
  const pins = {};
  for (const abs of files) {
    try {
      const rel = path.relative(root, abs).split(path.sep).join('/');
      pins[rel] = crypto.createHash('sha256').update(fs.readFileSync(abs)).digest('hex');
    } catch { /* unreadable file: leave it unpinned rather than guessing */ }
  }
  return pins;
}

function loadPins(root) {
  try {
    const data = JSON.parse(fs.readFileSync(pinsPath(root), 'utf8'));
    return data && typeof data.pins === 'object' ? data.pins : null;
  } catch {
    return null;
  }
}

function applyPins(root, files, result, opts) {
  const current = hashSkillFiles(root, files);
  if (opts.pin) {
    const target = pinsPath(root);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, JSON.stringify({ schema: 'vibeguard/skill-pins@1', pinnedAt: new Date().toISOString(), pins: current }, null, 2) + '\n');
    return { written: target, count: Object.keys(current).length, drift: [] };
  }
  const pins = loadPins(root);
  if (!pins) return { written: null, count: 0, drift: [] };
  const drift = [];
  for (const [rel, want] of Object.entries(pins)) {
    if (!(rel in current)) {
      drift.push({
        ruleId: 'skill.pinned-file-missing', severity: 'medium', confidence: 'high',
        title: 'Pinned skill file disappeared', message: `${rel} was pinned after review and is now gone — the skill's behavior can no longer be verified.`,
        fix: 'Restore the file, or remove it from pins with `vibeguard skill-scan --pin` after re-reviewing the skill.',
        file: rel, line: 1, column: 1, snippet: 'missing',
      });
    } else if (current[rel] !== want) {
      drift.push({
        ruleId: 'skill.rug-pull', severity: 'critical', confidence: 'high',
        title: 'Pinned skill changed after review (rug-pull)',
        message: `${rel} changed since it was pinned. A reviewed skill that silently changes is the exact rug-pull pattern agents are vulnerable to.`,
        fix: 'Diff the skill before running it; re-pin with `vibeguard skill-scan --pin` only after reviewing the change.',
        file: rel, line: 1, column: 1, snippet: `${want.slice(0, 12)}… -> ${current[rel].slice(0, 12)}…`,
      });
    }
  }
  for (const f of drift) {
    result.findings.push(f);
    result.counts[f.severity] = (result.counts[f.severity] || 0) + 1;
  }
  return { written: null, count: Object.keys(pins).length, drift };
}

function cmdSkillScan(args, flags) {
  const root = path.resolve(flags.dir || args._[1] || '.');
  const extraPaths = args._.slice(2);
  if (flags.path) extraPaths.push(String(flags.path));
  if (extraPaths.length && !fs.existsSync(root)) {
    process.stderr.write(`error: directory not found: ${root}\n`);
    return 2;
  }
  const result = scanSkills(root, { paths: extraPaths.length ? extraPaths : undefined, all: !!flags.all });
  const files = collectSkillFiles(root, { paths: extraPaths.length ? extraPaths : undefined, all: !!flags.all });
  const pinState = applyPins(root, files, result, { pin: !!flags.pin });
  if (pinState.written) {
    process.stdout.write(`pinned ${pinState.count} skill file(s) -> ${pinState.written}\n`);
  } else if (pinState.count && pinState.drift.length === 0) {
    process.stderr.write(`skill-scan: ${pinState.count} pinned skill file(s) unchanged.\n`);
  }
  if (flags.json) {
    process.stdout.write(JSON.stringify(Object.assign({}, result, { pins: { count: pinState.count, drift: pinState.drift.map((d) => d.ruleId + ':' + d.file) } }), null, 2) + '\n');
  } else if (flags.list) {
    process.stdout.write(files.map((f) => path.relative(root, f)).join('\n') + '\n');
  } else {
    process.stdout.write(renderSkillReport(result) + '\n');
  }
  if (result.counts.critical > 0) return 2;
  if (result.counts.high > 0 || result.counts.medium > 0) return 1;
  return 0;
}

module.exports = { cmdSkillScan };
