'use strict';

/*
 * bin/cmd-skill-scan.js — scan agent skills / plugins / instruction files.
 *
 * Exit codes: 0 clean, 1 medium/high, 2 critical.
 */

const path = require('path');
const fs = require('fs');
const { scanSkills, renderSkillReport, collectSkillFiles } = require('../src/skill-scan');

function cmdSkillScan(args, flags) {
  const root = path.resolve(flags.dir || args._[1] || '.');
  const extraPaths = args._.slice(2);
  if (flags.path) extraPaths.push(String(flags.path));
  if (extraPaths.length && !fs.existsSync(root)) {
    process.stderr.write(`error: directory not found: ${root}\n`);
    return 2;
  }
  const result = scanSkills(root, { paths: extraPaths.length ? extraPaths : undefined, all: !!flags.all });
  if (flags.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else if (flags.list) {
    const files = collectSkillFiles(root, { paths: extraPaths.length ? extraPaths : undefined, all: !!flags.all });
    process.stdout.write(files.map((f) => path.relative(root, f)).join('\n') + '\n');
  } else {
    process.stdout.write(renderSkillReport(result) + '\n');
  }
  if (result.counts.critical > 0) return 2;
  if (result.counts.high > 0 || result.counts.medium > 0) return 1;
  return 0;
}

module.exports = { cmdSkillScan };
