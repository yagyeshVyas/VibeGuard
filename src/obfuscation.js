'use strict';

/*
 * Obfuscation / backdoor analysis.
 *
 * Regex rule packs detect visible sinks (`eval(`…). They do not decode a payload,
 * correlate behaviour, or notice that a "minified helper" contains a network
 * client, the environment, and a shell. This pass does the reverse: it looks for
 * hidden code and for capability combinations that no honest file needs.
 *
 * Everything is local, deterministic and bounded (decode at most 3 layers, cap
 * payload size). It runs per file and returns ordinary findings.
 */

const MAX_DECODE = 3;
const MAX_BLOB = 64 * 1024;

// Dangerous capabilities inside a decoded payload.
const DANGER = [
  { re: /require\(\s*['"]child_process['"]\s*\)|from\s+['"]child_process['"]|execSync|exec\(|spawn\(/, label: 'process execution', weight: 3 },
  { re: /\brequire\(\s*['"](?:http|https|net|tls|dgram)['"]\s*\)|from\s+['"](?:http|https|net|dgram)['"]|fetch\(|axios\./, label: 'network access', weight: 2 },
  { re: /process\.env|os\.environ|getenv/, label: 'environment access', weight: 2 },
  { re: /fs\.(?:readFile|writeFile|appendFile|unlink|readdir)|os\.remove|shutil\.rmtree/, label: 'filesystem access', weight: 2 },
  { re: /\beval\b|\bFunction\s*\(|vm\.runIn|new\s+Function/, label: 'dynamic code', weight: 3 },
  { re: /\.ssh|id_rsa|authorized_keys|ssh-rsa/, label: 'SSH credential access', weight: 4 },
  { re: /\/etc\/passwd|\/etc\/shadow|crontab|launchctl|schtasks|reg\s+add|systemd/, label: 'persistence', weight: 4 },
  { re: /wallet|mnemonic|bitcoin|ethereum|privateKey|keystore/, label: 'wallet/credential theft', weight: 4 },
  { re: /powershell|cmd\.exe|\bwscript\b|\bcscript\b|mshta/, label: 'Windows execution', weight: 3 },
  { re: /base64|atob\(|btoa\(/, label: 'second-layer encoding', weight: 1 },
];

// Names that look like obfuscator.io output.
const OBFUSCATOR_MARKERS = [
  { re: /\b_0x[0-9a-f]{4,}\b/g, label: '_0x identifiers', min: 12 },
  { re: /while\s*\(\s*!!\s*\[\s*\]\s*\)/, label: 'string-array rotation', min: 1 },
  { re: /\b(?:var|let|const)\s+\w+\s*=\s*\[\s*(?:'\\x[0-9a-f]{2}'|"\\x[0-9a-f]{2}")(?:\s*,\s*(?:'\\x[0-9a-f]{2}'|"\\x[0-9a-f]{2}")){4,}\s*\]/i, label: 'hex string array', min: 1 },
  { re: /\}\s*\(\s*\d{3,}\s*\)\s*\)\s*\)?\s*;?\s*$/, label: 'decoder IIFE', min: 1 },
  { re: /\[\s*!!\s*\[\s*\]\s*\]\s*\+/, label: 'JSFuck coercion', min: 1 },
];

const SKIP_FILE = /(?:\.min\.(?:js|css)|\.map|(?:^|\/)node_modules\/|(?:^|\/)dist\/|(?:^|\/)vendor\/|(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock))$/i;

function isSkippable(relPath) {
  return SKIP_FILE.test(String(relPath || ''));
}

function lineOf(content, index) {
  return content.slice(0, index).split('\n').length;
}

function colOf(content, index) {
  const before = content.slice(0, index);
  return index - before.lastIndexOf('\n');
}

function snippetOf(content, index, match) {
  const start = content.lastIndexOf('\n', index) + 1;
  const end = content.indexOf('\n', index);
  const line = content.slice(start, end === -1 ? undefined : end).trim();
  return (match ? line.split(match).join(match.slice(0, 6) + '…') : line).slice(0, 160);
}

// --- decoding ---------------------------------------------------------------

function tryBase64(s) {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(s) || s.length < 40 || s.length % 4 !== 0) return null;
  try {
    const out = Buffer.from(s, 'base64').toString('utf8');
    let printable = 0;
    for (let i = 0; i < out.length; i++) {
      const c = out.charCodeAt(i);
      if (c >= 32 || c === 10 || c === 9 || c === 13) printable++;
    }
    // Binary decoded base64 is not a payload we can judge.
    if (out.length < 12 || printable / out.length < 0.85) return null;
    return out;
  } catch {
    return null;
  }
}

function tryHexEscapes(s) {
  if (!/(?:\\x[0-9a-fA-F]{2}){6,}/.test(s)) return null;
  try {
    const unescaped = s.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    return unescaped;
  } catch {
    return null;
  }
}

function tryUnicodeEscapes(s) {
  if (!/(?:\\u[0-9a-fA-F]{4}){6,}/.test(s)) return null;
  try {
    return s.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
  } catch {
    return null;
  }
}

function tryFromCharCode(s) {
  const m = /String\.fromCharCode\(\s*((?:\d{1,3}\s*,\s*){5,})\d{1,3}\s*\)/.exec(s);
  if (!m) return null;
  const codes = (m[0].match(/\d{1,3}/g) || []).map(Number).filter((n) => n > 8 && n < 0x10ffff);
  if (codes.length < 6) return null;
  try {
    return String.fromCharCode(...codes);
  } catch {
    return null;
  }
}

function tryRot13(s) {
  if (!/rot13|rot-13/i.test(s)) return null;
  return s.replace(/[a-zA-Z]/g, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

function dangerousTokens(text) {
  const hits = [];
  for (const d of DANGER) if (d.re.test(text)) hits.push({ label: d.label, weight: d.weight });
  return hits;
}

function decodeLayers(text) {
  let cur = text;
  const techniques = [];
  for (let i = 0; i < MAX_DECODE; i++) {
    const blob = (cur.match(/[A-Za-z0-9+/=]{40,}/) || [''])[0];
    const candidates = [
      ['hex escapes', tryHexEscapes(cur)],
      ['unicode escapes', tryUnicodeEscapes(cur)],
      ['String.fromCharCode', tryFromCharCode(cur)],
      ['base64', tryBase64(blob)],
      ['rot13', tryRot13(cur)],
    ];
    const hit = candidates.find(([, v]) => v && v !== cur);
    if (!hit) break;
    cur = hit[1];
    techniques.push(hit[0]);
  }
  return { decoded: cur, techniques: [...new Set(techniques)] };
}

// --- main analysis ----------------------------------------------------------

function makeFinding(relPath, content, index, ruleId, severity, confidence, title, message, fix, snippet) {
  return {
    ruleId,
    severity,
    confidence,
    title,
    message,
    fix,
    file: relPath,
    line: lineOf(content, index),
    column: colOf(content, index),
    snippet: snippet || snippetOf(content, index),
  };
}

function analyzeObfuscation(content, relPath) {
  if (!content || isSkippable(relPath)) return [];
  const findings = [];
  const safePush = (f) => {
    if (findings.length >= 40) return;
    findings.push(f);
  };

  // 1. Executable-position encoded payloads ---------------------------------
  // eval(atob(...)) / Function(Buffer.from(...,'base64')) / import(decodedUrl)
  const execEncoded = [
    /\beval\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent|unescape)\s*\(/,
    /new\s+Function\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent)\s*\(/,
    /(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent)\s*\(/,
    /\bimport\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent)\s*\(/,
  ];
  for (const re of execEncoded) {
    const m = re.exec(content);
    if (!m) continue;
    // Decode the literal if we can find one in the call.
    const around = content.slice(m.index, m.index + 400);
    const blob = /(?:['"`])([A-Za-z0-9+/=\\x0-9a-f]{20,})(?:['"`])/.exec(around);
    const decoded = blob ? decodeLayers(blob[1]).decoded : '';
    const tokens = decoded ? dangerousTokens(decoded) : [];
    if (tokens.length === 0) continue; // encoded but harmless-looking: not worth a finding
    safePush(
      makeFinding(relPath, content, m.index, 'obf.exec-encoded-payload', 'critical', 'high',
        'Encoded payload executed at runtime',
        `Executable code is decoded and run here. The decoded payload contains: ${tokens.map((t) => t.label).join(', ')}. Payloads hidden this way bypass code review and text scanners.`,
        'Remove the loader. If the library is legitimate, vendor it as readable source and update by version; never execute remote/encoded strings.',
        undefined)
    );
    break;
  }

  // 2. Dangerous decode cascade anywhere ------------------------------------
  // Long base64/hex blobs whose decoded form carries dangerous capability.
  const blobRe = /(?:['"`])([A-Za-z0-9+/]{60,}={0,2})(?:['"`])/g;
  let bm;
  let blobCount = 0;
  while ((bm = blobRe.exec(content)) !== null && blobCount < 6) {
    const decoded = tryBase64(bm[1]);
    if (!decoded) continue;
    const tokens = dangerousTokens(decoded);
    if (tokens.length === 0) continue;
    const weight = tokens.reduce((s, t) => s + t.weight, 0);
    if (weight < 3) continue;
    blobCount++;
    safePush(
      makeFinding(relPath, content, bm.index, 'obf.encoded-dangerous-payload', weight >= 6 ? 'critical' : 'high',
        'medium', 'Encoded payload with dangerous capability',
        `A base64 blob decodes to text that can ${tokens.map((t) => t.label).join(', ')}. Legitimate code rarely ships executable capability as an encoded string.`,
        'Decode and review the payload. Replace with readable source or remove; pin the dependency that introduced it.',
        undefined)
    );
  }

  // 3. Obfuscator fingerprints ----------------------------------------------
  const marks = OBFUSCATOR_MARKERS.filter((m) => {
    const count = (content.match(m.re) || []).length;
    return count >= m.min;
  });
  if (marks.length >= 2) {
    const idx = Math.max(0, content.search(/_0x[0-9a-f]{4,}/));
    safePush(
      makeFinding(relPath, content, idx, 'obf.javascript-obfuscator', 'high', 'medium',
        'Heavily obfuscated JavaScript',
        `This file carries ${marks.map((m) => m.label).join(', ')} — the signature of javascript-obfuscator/obfuscator.io. Obfuscation in application code hides behaviour from review; it is normal only in third-party minified bundles.`,
        'Replace the obfuscated file with the original package (installed from the registry, pinned) or vendor readable source. Never ship hand-obfuscated first-party code.',
        undefined)
    );
  }

  // 4. Behavioural co-occurrence (dropper / exfiltration) --------------------
  const has = (re) => re.test(content);
  const net = has(/\b(?:fetch\s*\(|axios\.|https?\.request\s*\(|net\.connect\s*\(|new\s+WebSocket\s*\()/);
  const exec = has(/\b(?:child_process|execSync\s*\(|exec\s*\(|spawn\s*\(|os\.system\s*\()/);
  const env = has(/process\.env|os\.environ|os\.getenv/);
  const fsx = has(/\bfs\.(?:readFile|writeFile|readdir|unlink|appendFile)/);
  const cryptoBlob = has(/crypto\.createCipheriv|createDecipheriv|subtle\.encrypt/);

  if (net && exec && env) {
    safePush(
      makeFinding(relPath, content, Math.max(0, content.search(/fetch\s*\(|https?\.request/)), 'obf.dropper-behavior', 'high', 'medium',
        'File combines process execution, environment access and outbound network',
        'This file can spawn processes, read the environment (tokens, cloud credentials) and talk to the network. That combination is a loader/exfiltration primitive — legitimate build tooling isolates these behind explicit APIs.',
        'Split the responsibilities: a tool that runs commands must not also fetch arbitrary URLs. Review who introduced this file and pin its origin.',
        undefined)
    );
  }
  if (net && env && !exec && (fsx || cryptoBlob)) {
    const idx = Math.max(0, content.search(/fetch\s*\(|https?\.request/));
    safePush(
      makeFinding(relPath, content, idx, 'obf.env-exfil-behavior', 'medium', 'medium',
        'Credential-exfiltration pattern (env + filesystem/crypto + network)',
        'The file reads the environment (and files/keys) and sends data over the network. If this is not the payment/auth integration itself, it is an exfiltration path for tokens and PII.',
        'Move secret handling to the server process that needs it; log/egress only through an allowlisted client. Audit the reviewer who added the network call.',
        undefined)
    );
  }

  // 5. Encoded/remote execution primitives ----------------------------------
  const primitives = [
    { re: /\bimport\s*\(\s*['"`]https?:\/\//, id: 'obf.remote-module-import', sev: 'high', title: 'Remote module loaded at runtime', msg: 'A module is imported from a URL. The remote server — not this repository — decides what code runs, and the reviewed version is not the executed version.', fix: 'Bundle/pin the dependency locally. Remote imports bypass review, SRI and lockfiles.' },
    { re: /\brequire\s*\(\s*['"`]https?:\/\//, id: 'obf.remote-require', sev: 'high', title: 'Remote module required at runtime', msg: 'require() from a URL loads unreviewed remote code into the process.', fix: 'Install and pin the package; never require over HTTP(S).' },
    { re: /powershell(?:\.exe)?\s+[^;\n]*(?:-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{20,}/i, id: 'obf.powershell-encoded-command', sev: 'critical', title: 'PowerShell encoded command', msg: 'A base64 -EncodedCommand blob executes a hidden PowerShell script — the standard payload-delivery form.', fix: 'Remove it. Legitimate installers use signed MSI/exe or readable scripts checked into the repo.' },
    { re: /(?:curl|wget)[^;\n|]{0,160}\|\s*(?:sh|bash|zsh|python|node)\b/i, id: 'obf.curl-pipe-shell', sev: 'critical', title: 'Downloaded code piped into a shell', msg: 'A network response is executed directly. The downloaded content can change after review and is not pinned by any hash.', fix: 'Download, verify a published checksum/signature, then run a pinned file. Prefer a package registry.' },
    { re: /fetch\s*\([^)]*\)\s*\.then\s*\([^)]*\)\s*\.then\s*\(\s*(?:eval|Function|window\.eval)/, id: 'obf.fetch-then-eval', sev: 'critical', title: 'Fetched content passed to eval', msg: 'A network response is evaluated as code. Whoever controls the endpoint (or the DNS) controls this process.', fix: 'Parse data (JSON.parse) and switch on validated fields; never eval a response.' },
    { re: /\.toString\(\s*['"]base64['"]\s*\)[^;\n]{0,80}(?:exec|spawn|Function|eval)\b/, id: 'obf.base64-to-exec', sev: 'critical', title: 'Base64 payload piped into execution', msg: 'A base64-decoded string is executed — classic encoded dropper.', fix: 'Remove; replace with explicit, reviewable logic.' },
  ];
  for (const p of primitives) {
    const m = p.re.exec(content);
    if (!m) continue;
    safePush(makeFinding(relPath, content, m.index, p.id, p.sev, 'high', p.title, p.msg, p.fix, undefined));
  }

  // 6. Anti-analysis in application code ------------------------------------
  const anti = [
    { re: /Error\.prepareStackTrace\s*=/, id: 'obf.stack-sanity-off', sev: 'medium', title: 'Stack-trace formatting overridden', msg: 'prepareStackTrace is replaced, hiding the call path from logs and debuggers.', fix: 'Remove it; use a logging library with redaction instead.' },
    { re: /Function\.prototype\.toString\s*=/, id: 'obf.function-tostring-override', sev: 'high', title: 'Function.prototype.toString overridden', msg: 'Overriding function source text defeats "show me the code" inspection and some integrity checks.', fix: 'Remove the override.' },
    { re: /\bdebugger\s*;/, id: 'obf.debugger-statement', sev: 'low', title: 'debugger statement left in code', msg: 'A debugger statement pauses execution when devtools is open — noise in production, and used to frustrate analysis.', fix: 'Remove debugger statements before shipping (lint rule no-debugger).' },
  ];
  for (const a of anti) {
    const m = a.re.exec(content);
    if (!m) continue;
    // Skip tests/dev fixtures; debugger in a test helper is harmless.
    if (/(?:^|\/)(?:test|tests|__tests__|fixtures)\//.test(relPath)) continue;
    safePush(makeFinding(relPath, content, m.index, a.id, a.sev, 'medium', a.title, a.msg, a.fix, undefined));
  }

  // 7. Unicode concealment ---------------------------------------------------
  const zw = (content.match(/[\u200b-\u200f\u2060-\u2064\u2066-\u2069\u202a-\u202e]/g) || []).length;
  if (zw >= 6) {
    const idx = content.search(/[\u200b-\u200f\u2060-\u2064\u2066-\u2069\u202a-\u202e]/);
    safePush(
      makeFinding(relPath, content, idx, 'obf.unicode-concealment', 'medium', 'high',
        'Zero-width / bidi characters in source',
        `${zw} invisible or direction-override characters are present. They render as nothing to a reviewer but reach tokens, prompts and logs — the Trojan-Source class (CVE-2021-42574) used to hide instructions from AI review.`,
        'Strip all format-control characters (U+200B–U+200F, U+202A–U+202E, U+2066–U+2069) from source and prompt files; add a pre-commit check.',
        undefined)
    );
  }

  return findings;
}

module.exports = {
  analyzeObfuscation,
  decodeLayers,
  dangerousTokens,
  isSkippable,
};
