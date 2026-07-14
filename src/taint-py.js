'use strict';

/*
 * VibeGuard Python Taint Analysis Engine.
 *
 * A multi-pass, scope-aware Python taint tracker — no external parser needed
 * (pure JS, zero dependencies, 100% offline).
 *
 * Improvements over the legacy engine.js analyzePythonTaint:
 * - Multi-hop propagation through f-strings: q = f"SELECT * FROM {name}"
 * - Format string propagation: q = "SELECT * FROM %s" % name
 * - .format() propagation: q = "SELECT * FROM {}".format(name)
 * - String concatenation propagation: q = "prefix" + name
 * - Dedent-aware: Python indentation tracks scope (function/if/for/while)
 *   — variables that go out of scope are cleared
 * - Sanitizer recognition: int(), float(), bool(), shlex.quote(), etc.
 * - Parameterized query detection (placeholder + second arg to execute)
 * - Confidence: 'high' when source→sink is confirmed (multi-hop), 'medium' for single-hop
 *
 * Sources: request.form/args/data/json/values/cookies/headers, request.get(),
 *          input(), os.environ, sys.argv, flask.request.args, django request.GET/POST
 *
 * Sinks: cursor.execute, os.system, subprocess.run/call/Popen, eval, exec,
 *        open, pickle.loads, os.popen, shell=True
 */

const PY_TAINT_SOURCES = [
  { re: /request\.(?:form|args|data|json|values|cookies|headers)(?:\.\w+)?(?:\s*\(|\s*\[)/, name: 'request' },
  { re: /request\.get\s*\(/, name: 'request.get' },
  { re: /request\.POST(?:\[|\.get)/, name: 'request.POST' },
  { re: /request\.GET(?:\[|\.get)/, name: 'request.GET' },
  { re: /flask\.request\.(?:form|args|data|json|cookies|headers)/, name: 'flask.request' },
  { re: /\binput\s*\(/, name: 'input()' },
  { re: /os\.environ\.get\s*\(/, name: 'os.environ' },
  { re: /\bos\.environ\s*\[/, name: 'os.environ' },
  { re: /\bsys\.argv\b/, name: 'sys.argv' },
  { re: /event\[(?:['"])?(?:body|queryStringParameters|headers|pathParameters)/, name: 'event' },
];

const PY_TAINT_SINKS = [
  { re: /cursor\.execute\s*\(/, name: 'cursor.execute', type: 'sql', ruleId: 'py.taint.sql-injection', cwe: 'CWE-89' },
  { re: /\.execute\s*\(/, name: 'execute()', type: 'sql', ruleId: 'py.taint.sql-injection', cwe: 'CWE-89' },
  { re: /os\.system\s*\(/, name: 'os.system', type: 'cmd', ruleId: 'py.taint.command-injection', cwe: 'CWE-77' },
  { re: /os\.popen\s*\(/, name: 'os.popen', type: 'cmd', ruleId: 'py.taint.command-injection', cwe: 'CWE-77' },
  { re: /subprocess\.(?:run|call|Popen)\s*\(/, name: 'subprocess', type: 'cmd', ruleId: 'py.taint.command-injection', cwe: 'CWE-77' },
  { re: /subprocess\.(?:run|call|Popen)\s*\([^)]*shell\s*=\s*True/, name: 'subprocess(shell=True)', type: 'cmd', ruleId: 'py.taint.command-injection', cwe: 'CWE-77' },
  { re: /\beval\s*\(/, name: 'eval()', type: 'code', ruleId: 'py.taint.code-injection', cwe: 'CWE-94' },
  { re: /\bexec\s*\(/, name: 'exec()', type: 'code', ruleId: 'py.taint.code-injection', cwe: 'CWE-94' },
  { re: /\bopen\s*\(/, name: 'open()', type: 'file', ruleId: 'py.taint.path-traversal', cwe: 'CWE-22' },
  { re: /pickle\.loads?\s*\(/, name: 'pickle', type: 'deserialization', ruleId: 'py.taint.deserialization', cwe: 'CWE-502' },
  { re: /yaml\.load\s*\(/, name: 'yaml.load', type: 'deserialization', ruleId: 'py.taint.deserialization', cwe: 'CWE-502' },
];

const PY_SANITIZERS = [
  'int', 'float', 'bool', 'decimal.Decimal',
  'shlex.quote', 'pipes.quote', 'shlex.split',
  'html.escape', 'markupsafe.escape', 'escape', 'bleach.clean',
  'urllib.parse.quote', 'urllib.parse.quote_plus', 're.escape',
  'str', 'len',
];

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function extractVarName(line) {
  const m = /^\s*([A-Za-z_]\w*)\s*=\s*(.+)$/.exec(line);
  return m ? { name: m[1], rhs: m[2] } : null;
}

function isSanitized(rhs, varName) {
  for (const san of PY_SANITIZERS) {
    const sanRe = new RegExp('\\b' + escapeRe(san) + '\\s*\\([^)]*' + escapeRe(varName) + '\\b');
    if (sanRe.test(rhs)) return true;
  }
  return false;
}

function isParameterizedSql(line) {
  if (!/\.execute\s*\(/.test(line)) return false;
  const hasPlaceholder = /%s|%\(|%d|\?|:\w+/.test(line);
  const hasSecondArg = /\.execute\s*\([^)]*?,\s*[([{\w'"]/.test(line);
  return hasPlaceholder && hasSecondArg;
}

function rhsReferencesTainted(rhs, tainted) {
  for (const [varName, info] of tainted) {
    const re = new RegExp('\\b' + escapeRe(varName) + '\\b');
    if (re.test(rhs) && !isSanitized(rhs, varName)) return { varName, info };
  }
  return null;
}

// Detect f-string, format, and concat propagation
function detectPropagation(line, lhs, rhs, tainted) {
  // f"SELECT ... {var}" — f-string
  if (/f["']/.test(line) || /f""".*{.*}/s.test(line)) {
    return rhsReferencesTainted(rhs, tainted);
  }
  // "SELECT ... %s" % var — format string
  if (/%s/.test(rhs) && /%\s*\(?([\w.]+)\)?/.test(rhs)) {
    return rhsReferencesTainted(rhs, tainted);
  }
  // "SELECT ... {}".format(var)
  if (/\.format\s*\(/.test(rhs)) {
    return rhsReferencesTainted(rhs, tainted);
  }
  // "prefix" + var — concatenation
  if (/\+/.test(rhs)) {
    return rhsReferencesTainted(rhs, tainted);
  }
  // Direct reference: q = var
  return rhsReferencesTainted(rhs, tainted);
}

function getIndent(line) {
  const m = /^(\s*)/.exec(line);
  return m ? m[1].length : 0;
}

function analyzePythonTaintAdvanced(content, lines, relPath) {
  const findings = [];
  const tainted = new Map(); // varName -> { name (source), line, hops }
  const seen = new Set(); // dedupe sink:line
  const scopeStack = [{ indent: 0, vars: new Set() }]; // scope tracking

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNo = i + 1;
    if (line.length > 4000) continue;
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const indent = getIndent(line);

    // Pop scopes when indentation decreases
    while (scopeStack.length > 1 && indent < scopeStack[scopeStack.length - 1].indent) {
      const popped = scopeStack.pop();
      for (const v of popped.vars) {
        tainted.delete(v);
      }
    }

    // Detect function/class/def/for/while/if/try — push new scope
    if (/^\s*(def |class |for |while |if |elif |else:|try:|except |with )/.test(line)) {
      scopeStack.push({ indent: indent + 1, vars: new Set() });
    }

    // 1. Source assignment.
    let matchedSource = null;
    for (const src of PY_TAINT_SOURCES) {
      if (src.re.test(line)) { matchedSource = src.name; break; }
    }
    if (matchedSource) {
      const extracted = extractVarName(line);
      if (extracted) {
        tainted.set(extracted.name, { name: matchedSource, line: lineNo, hops: 0 });
        scopeStack[scopeStack.length - 1].vars.add(extracted.name);
      }
    }

    // 2. Propagation via assignment.
    if (!matchedSource) {
      const extracted = extractVarName(line);
      if (extracted) {
        const lhs = extracted.name;
        const rhs = extracted.rhs;
        const ref = detectPropagation(line, lhs, rhs, tainted);
        if (ref) {
          tainted.set(lhs, { name: ref.info.name, line: ref.info.line, hops: ref.info.hops + 1 });
          scopeStack[scopeStack.length - 1].vars.add(lhs);
        } else if (tainted.has(lhs)) {
          // Reassigned to clean value — clear taint
          tainted.delete(lhs);
        }
      }
    }

    // 3. Sinks.
    for (const sink of PY_TAINT_SINKS) {
      if (!sink.re.test(line)) continue;
      for (const [tv, info] of tainted) {
        const re = new RegExp('\\b' + escapeRe(tv) + '\\b');
        if (!re.test(line)) continue;
        if (sink.type === 'sql' && isParameterizedSql(line)) continue;
        if (isSanitized(line, tv)) continue;
        const key = sink.ruleId + ':' + lineNo;
        if (seen.has(key)) break;
        seen.add(key);
        findings.push({
          ruleId: sink.ruleId,
          file: relPath,
          line: lineNo,
          column: 1,
          severity: sink.type === 'code' || sink.type === 'cmd' ? 'critical' : 'high',
          confidence: info.hops > 0 ? 'high' : 'medium',
          title: `Python taint: ${info.name} → ${sink.name}`,
          snippet: trimmed.slice(0, 120),
          message: `User input (${info.name} at line ${info.line}) flows to ${sink.name} (line ${lineNo}) via ${info.hops + 1} hop(s) without sanitization.`,
          fix: sink.type === 'sql' ? 'Use parameterized queries with bound parameters.' :
               sink.type === 'cmd' ? 'Use shlex.quote() or pass args as a list (shell=False).' :
               sink.type === 'code' ? 'Remove eval/exec on dynamic input. Use ast.literal_eval or explicit dispatch.' :
               sink.type === 'file' ? 'Sanitize with os.path.basename(), resolve against a fixed base, reject escapes.' :
               sink.type === 'deserialization' ? 'Use json.loads instead of pickle/yaml.load, or validate input first.' :
               'Sanitize or validate the input before use.',
          owasp: 'A03:2025 Injection',
          cwe: sink.cwe,
        });
        break;
      }
    }
  }

  return findings;
}

module.exports = {
  analyzePythonTaintAdvanced,
  PY_TAINT_SOURCES,
  PY_TAINT_SINKS,
  PY_SANITIZERS,
};