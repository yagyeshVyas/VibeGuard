'use strict';

// cmdGif — `vibeguard gif <query>`: print (or download) a keyless open GIF.
//
//   vibeguard gif cat                     # print a validated GIF URL
//   vibeguard gif "all tests passed"      # cat GIF with text overlay
//   vibeguard gif yes                     # yes/no reaction GIF
//   vibeguard gif cat --save out.gif      # download to a file
//   vibeguard gif yes --json              # machine-readable result
//
// 100% keyless. No account, no tracking, no paid tier. Byte-verified before
// being printed as valid. See src/gif.js for the backend list + known dead
// backends (Tenor/GIPHY/Klipy all need keys — tested).

const path = require('path');

const C = {
  bold: '\x1b[1m', dim: '\x1b[2m', green: '\x1b[32m', cyan: '\x1b[36m',
  yellow: '\x1b[33m', magenta: '\x1b[35m', reset: '\x1b[0m',
};

async function cmdGif(args, flags) {
  const { searchGifs, downloadGif } = require('../src/gif');
  const query = args._.slice(1).join(' ').trim();
  if (!query) {
    process.stderr.write('usage: vibeguard gif <query> [--save out.gif] [--json]\n');
    process.stderr.write('examples: vibeguard gif cat | vibeguard gif "all tests passed" | vibeguard gif yes\n');
    return 2;
  }

  let result;
  try {
    result = await searchGifs(query);
  } catch (e) {
    process.stderr.write(`gif: ${e.message}\n`);
    return 1;
  }

  const saveTarget = flags.save || flags.output;
  if (saveTarget) {
    const outPath = path.resolve(String(saveTarget));
    const d = await downloadGif(query, outPath);
    if (flags.json) {
      process.stdout.write(JSON.stringify({ title: result.title, url: result.url, source: result.source, license: result.license, path: d.path, bytes: d.bytes, valid: d.valid }, null, 2) + '\n');
    } else {
      process.stdout.write(`${C.green}✓${C.reset} saved ${C.bold}${d.bytes}${C.reset} bytes to ${C.cyan}${d.path}${C.reset} ${C.dim}(${result.source}, ${result.license})${C.reset}\n`);
    }
    return 0;
  }

  if (flags.json) {
    process.stdout.write(JSON.stringify({ title: result.title, url: result.url, source: result.source, license: result.license, bytes: result.bytes, valid: result.valid }, null, 2) + '\n');
    return 0;
  }

  process.stdout.write(`${C.magenta}${C.bold}🎞 ${result.title}${C.reset}\n`);
  process.stdout.write(`  ${C.cyan}${result.url}${C.reset}\n`);
  process.stdout.write(`  ${C.dim}${result.source} · ${result.license} · ${result.bytes} bytes${result.valid ? ' · byte-verified GIF' : ''}${C.reset}\n`);
  return 0;
}

module.exports = { cmdGif };
