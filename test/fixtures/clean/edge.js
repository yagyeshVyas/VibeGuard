'use strict';
// Edge cases that naive scanners false-positive on. All must stay clean.

// "FROM" / "WHERE" as plain English in concatenated strings — NOT SQL.
const emailHeader = 'FROM: ' + 'noreply@example.com';
const label = 'Delete from list: ' + 'item';
const msg = 'Where to go? ' + destination;
const note = 'Update available: ' + version;

// SVG / XML namespace URLs — not network requests.
const svg = '<svg xmlns="http://www.w3.org/2000/svg"></svg>';
const schema = 'http://www.w3.org/2001/XMLSchema';

// TypeScript type/interface fields named like secrets — declarations, not values.
// (kept as strings to survive .js parsing)
const iface = 'interface User { password: string; apiKey: string }';

// A logger line mentioning eval in a string literal.
const help = 'Do not call eval() on user input';

// Function named "evaluate" must not trip the eval rule.
function evaluateScore(x) {
  return x * 2;
}

// exec mentioned as a property/word, not a call from variables.
const runner = { execLabel: 'runs a command' };

module.exports = { emailHeader, label, msg, note, svg, schema, iface, help, evaluateScore, runner };
