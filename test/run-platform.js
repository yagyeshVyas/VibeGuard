'use strict';

// Standalone runner for the v2 platform security suite (used by Windows/macOS
// CI and local verification). No process.exit before output flushes.
const suite = require('./platform-security-tests');

(async () => {
  let pass = 0;
  let fail = 0;
  for (const t of suite.tests) {
    try {
      const result = t.fn();
      if (result && typeof result.then === 'function') await result;
      pass++;
      console.log('  ok  ' + t.name);
    } catch (err) {
      fail++;
      console.log('  FAIL ' + t.name + '\n       ' + String((err && err.stack) || err).split('\n').slice(0, 5).join('\n       '));
    }
  }
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exitCode = fail === 0 ? 0 : 1;
})();
