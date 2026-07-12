'use strict';

/*
 * Intra-file taint analysis — AST-based when acorn is available, regex fallback.
 *
 * The primary path is the scope-aware AST analysis in taint-ast.js, which
 * handles variable declarations, assignments, template literals, binary
 * string concat, function parameters, object property reads/writes, block/
 * function scope with shadowing, reassignment clearing, and sanitizer
 * recognition. Sinks are matched on CallExpression nodes, not text.
 *
 * When acorn is unavailable or a file doesn't parse, this module falls back
 * to the original regex-based taint pass (below) so behavior never regresses
 * on unparseable files.
 *
 * Public export analyzeTaint(content, lines, relPath) is unchanged; an
 * optional tree argument is accepted to reuse a preparsed AST (one parse
 * per file, threaded through scanFileContent).
 *
 * Scope: JS/TS-family files. Best-effort, not a substitute for a real taint tool.
 */

const path = require('path');

const TAINT_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte']);

// Something that introduces attacker-controlled data.
const SOURCE_RE =
  /\breq\.(?:body|query|params|headers|cookies|url|originalUrl|hostname)\b|\brequest\.(?:body|query|params|headers)\b|\bctx\.request\.(?:body|query|params)\b|\bevent\.(?:body|queryStringParameters|pathParameters|headers)\b|\.searchParams\b|\bprocess\.argv\b/;

// Sinks: dangerous call -> what kind of bug if it receives tainted data.
const SINKS = [
  {
    re: /\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(/,
    ruleId: 'taint.command-injection',
    severity: 'high',
    title: 'User input reaches a shell command (dataflow-confirmed)',
    message: 'A value derived from user input flows into a shell command — command injection.',
    fix: 'Pass arguments as an array (execFile("cmd",[arg])) and never build a shell string from input; validate/allowlist.',
  },
  {
    re: /\.(?:query|raw|execute)\s*\(|\bsequelize\.query\s*\(/,
    ruleId: 'taint.sql-injection',
    severity: 'high',
    title: 'User input reaches a SQL query (dataflow-confirmed)',
    message: 'A value derived from user input flows into a SQL query call — SQL injection.',
    fix: 'Use parameterized queries / prepared statements; pass input as bound parameters, not concatenated SQL.',
  },
  {
    re: /\beval\s*\(|\bnew\s+Function\s*\(/,
    ruleId: 'taint.code-injection',
    severity: 'critical',
    title: 'User input reaches eval()/Function() (dataflow-confirmed)',
    message: 'A value derived from user input flows into eval()/new Function() — remote code execution.',
    fix: 'Remove eval/Function on dynamic input. Use JSON.parse or an explicit dispatch table.',
  },
  {
    re: /\b(?:fs|fsp|fse)\.(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|unlink|unlinkSync|appendFile)\s*\(|\bres\.sendFile\s*\(|\bpath\.(?:join|resolve)\s*\(/,
    ruleId: 'taint.path-traversal',
    severity: 'high',
    title: 'User input reaches a filesystem path (dataflow-confirmed)',
    message: 'A value derived from user input is used to build a filesystem path — path traversal.',
    fix: 'Sanitize with path.basename(), resolve against a fixed base, and reject paths that escape it.',
  },
  {
    re: /\b(?:fetch|axios|got|superagent)\s*\(|\baxios\.(?:get|post|put|delete)\s*\(|\bhttps?\.(?:get|request)\s*\(/,
    ruleId: 'taint.ssrf',
    severity: 'high',
    title: 'User input reaches an outbound request URL (dataflow-confirmed)',
    message: 'A value derived from user input is used as an outbound request target — server-side request forgery (SSRF).',
    fix: 'Allowlist permitted hosts/schemes; never fetch a URL built from raw user input; block internal/metadata addresses.',
  },
  {
    re: /\bres\.redirect\s*\(|\bres\.location\s*\(/,
    ruleId: 'taint.open-redirect',
    severity: 'medium',
    title: 'User input reaches a redirect target (dataflow-confirmed)',
    message: 'A value derived from user input is used as a redirect target — open redirect (phishing).',
    fix: 'Redirect only to an allowlist of internal paths; reject absolute/off-site URLs from input.',
  },
];

// Extract identifier names that become tainted on this line, given the current
// tainted set. Returns array of new tainted names.
function newlyTainted(line, tainted) {
  const names = [];
  const rhsIsTainted = (rhs) => {
    if (SOURCE_RE.test(rhs)) return true;
    // references an already-tainted variable as a whole word
    for (const t of tainted) {
      if (new RegExp(`\\b${t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`).test(rhs)) return true;
    }
    return false;
  };

  // Destructuring: const { a, b } = <src>
  let m = /(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(.+)$/.exec(line);
  if (m && rhsIsTainted(m[2])) {
    for (const raw of m[1].split(',')) {
      const id = raw.split(':').pop().trim().replace(/\s.*$/, '');
      if (/^[A-Za-z_$][\w$]*$/.test(id)) names.push(id);
    }
    return names;
  }

  // Simple assignment: [const|let|var] NAME = <rhs>   or   NAME = <rhs>
  m = /(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*(.+)$/.exec(line);
  if (m && !/[=!<>]=/.test(m[0].slice(0, m.index + m[1].length + 3))) {
    const name = m[1];
    const rhs = m[2];
    if (rhsIsTainted(rhs)) names.push(name);
  }
  return names;
}

function referencesTainted(line, tainted) {
  // Strip string literals so we don't match variable names inside SQL strings.
  const stripped = line.replace(/(["'`])(?:[^\\]|\\.)*?\1/g, '""');
  for (const t of tainted) {
    if (new RegExp(`\\b${t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`).test(stripped)) return t;
  }
  return null;
}

function analyzeTaintRegex(content, lines, relPath) {
  const ext = path.extname(relPath || '').toLowerCase();
  if (!TAINT_EXT.has(ext)) return [];

  const tainted = new Set();
  const findings = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 4000) continue;
    const trimmed = line.trim();
    const isComment = trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*');

    // 1) Check sinks first (a line can both use and reassign).
    if (!isComment) {
      for (const sink of SINKS) {
        if (!sink.re.test(line)) continue;
        // Skip the inline source case — the regex rules already report it; taint
        // exists to catch the *multi-step* case where the source is elsewhere.
        if (SOURCE_RE.test(line)) continue;
        // Skip parameterized queries: if the tainted var is inside an array
        // literal (second arg), it's a bound parameter, not SQL injection.
        // Heuristic: if the line has "query(" or "execute(" or "raw(" and the
        // tainted var appears after a comma followed by [, skip it.
        if (sink.ruleId === 'taint.sql-injection' && /,\s*\[/.test(line)) {
          // Check if the tainted var is ONLY in the array, not in the SQL string.
          const beforeArray = line.split(/,\s*\[/)[0];
          const afterArray = ',' + line.split(/,\s*\[/).slice(1).join(',[');
          const viaSql = referencesTainted(beforeArray, tainted);
          if (!viaSql) continue; // tainted var only in params array — safe
        }
        const via = referencesTainted(line, tainted);
        if (via) {
          findings.push({
            ruleId: sink.ruleId,
            severity: sink.severity,
            confidence: 'high',
            title: sink.title,
            message: `${sink.message} (tainted via \`${via}\`)`,
            fix: sink.fix,
            file: relPath,
            line: i + 1,
            column: 1,
            snippet: trimmed.slice(0, 120),
          });
        }
      }
    }

    // 2) Propagate taint from assignments.
    if (!isComment) {
      for (const n of newlyTainted(line, tainted)) tainted.add(n);
    }
  }

  return findings;
}

// Primary entry point: tries AST-based taint first, falls back to regex.
// Accepts an optional pre-parsed tree to avoid re-parsing (one parse per file).
function analyzeTaint(content, lines, relPath, tree) {
  const ext = path.extname(relPath || '').toLowerCase();
  if (!TAINT_EXT.has(ext)) return [];

  // Try AST-based analysis (scope-aware, sanitizer-aware, cross-function).
  try {
    const ast = require('./ast');
    if (ast.isAvailable()) {
      const t = tree || ast.parseSource(content, relPath);
      if (t) {
        const { analyzeTaintAst } = require('./taint-ast');
        return analyzeTaintAst(content, lines, relPath, t);
      }
    }
  } catch {
    // fall through to regex
  }

  // Fallback: regex-based taint (no scopes, no AST).
  return analyzeTaintRegex(content, lines, relPath);
}

module.exports = { analyzeTaint, analyzeTaintRegex, SOURCE_RE, SINKS };
