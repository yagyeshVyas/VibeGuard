'use strict';

/*
 * Engine gaps:
 *   1. Sanitizer recognition — stop taint propagation when a sanitizer is applied
 *   2. Incremental/diff-aware scanning — only scan changed files
 *   3. Auth coverage map — enumerate routes → middleware → guards
 *   4. Python taint — basic Python source-to-sink taint detection
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ---------------------------------------------------------------------------
// 1. SANITIZER RECOGNITION
// ---------------------------------------------------------------------------

const SANITIZERS = {
  xss: [
    'DOMPurify', 'sanitize', 'sanitizeHtml', 'escape', 'escapeHtml',
    'encodeURIComponent', 'encodeURI', 'textEncode', 'he.encode',
    'React.createElement', 'textContent',
  ],
  sql: [
    'parameterize', 'prepare', 'placeholder', 'bind', 'sql`', 'sql.query',
    'prisma.$queryRaw', 'pool.query', 'client.query',
  ],
  cmd: [
    'execFile', 'spawn', 'shell-quote', 'shellescape', 'sanitizeShell',
  ],
  path: [
    'path.resolve', 'path.join', 'path.normalize', 'sanitize',
  ],
};

function isSanitized(expr, type) {
  if (!expr || typeof expr !== 'string') return false;
  const sanitizers = SANITIZERS[type] || [];
  return sanitizers.some((s) => expr.includes(s));
}

// ---------------------------------------------------------------------------
// 2. INCREMENTAL / DIFF-AWARE SCANNING
// ---------------------------------------------------------------------------

const HASH_CACHE_DIR = '.vibeguard/cache';

function loadHashCache(root) {
  const p = path.join(root, HASH_CACHE_DIR, 'file-hashes.json');
  if (fs.existsSync(p)) {
    try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch {}
  }
  return {};
}

function saveHashCache(root, cache) {
  const dir = path.join(root, HASH_CACHE_DIR);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'file-hashes.json'), JSON.stringify(cache, null, 2));
}

function hashContent(content) {
  return crypto.createHash('sha256').update(content).digest('hex');
}

function getChangedFiles(root, allFiles) {
  const cache = loadHashCache(root);
  const changed = [];
  const newCache = {};

  for (const file of allFiles) {
    try {
      const content = fs.readFileSync(file, 'utf8');
      const hash = hashContent(content);
      newCache[file] = hash;
      if (cache[file] !== hash) changed.push(file);
    } catch {
      // can't read, skip
    }
  }

  saveHashCache(root, newCache);
  return { changed, total: allFiles.length, cached: allFiles.length - changed.length };
}

// ---------------------------------------------------------------------------
// 3. AUTH COVERAGE MAP
// ---------------------------------------------------------------------------

const ROUTE_RE = /(?:app|router|server)\.(?:get|post|put|delete|patch|all|use)\s*\(\s*['"`]([^'"`]+)['"`]/gi;
const MIDDLEWARE_RE = /(?:app|router)\.use\s*\(\s*['"`]([^'"`]+)['"`]/gi;
const AUTH_GUARD_RE = /(?:requireAuth|withAuth|protect|guard|authMiddleware|isAuthenticated|verifyToken|authenticate|clerkMiddleware|auth\(\)|getServerSession|getSession)/i;

function buildAuthCoverage(root, files) {
  const routes = [];
  const middlewares = [];

  for (const file of files) {
    try {
      const content = fs.readFileSync(file, 'utf8');
      const relPath = path.relative(root, file);

      let m;
      while ((m = ROUTE_RE.exec(content)) !== null) {
        const routePath = m[1];
        const beforeLines = content.slice(0, m.index).split('\n');
        const lineNum = beforeLines.length;
        const currentLine = content.slice(m.index, m.index + 300).split('\n')[0];
        const hasAuth = AUTH_GUARD_RE.test(currentLine);
        routes.push({
          path: routePath,
          file: relPath,
          line: lineNum,
          protected: hasAuth,
        });
      }

      while ((m = MIDDLEWARE_RE.exec(content)) !== null) {
        const mwPath = m[1];
        const lines = content.slice(0, m.index).split('\n');
        const lineNum = lines.length;
        const surrounding = content.slice(m.index, m.index + 300);
        const isAuth = AUTH_GUARD_RE.test(surrounding);
        if (isAuth) {
          middlewares.push({ path: mwPath, file: relPath, line: lineNum });
        }
      }
    } catch {}
  }

  const unprotected = routes.filter((r) => !r.protected && r.path.startsWith('/api/'));
  const protectedRoutes = routes.filter((r) => r.protected);

  return {
    totalRoutes: routes.length,
    protectedRoutes: protectedRoutes.length,
    unprotectedRoutes: unprotected.length,
    unprotected,
    middlewares,
    coverage: routes.length > 0 ? Math.round((protectedRoutes.length / routes.length) * 100) : 100,
  };
}

// ---------------------------------------------------------------------------
// 4. PYTHON TAINT (basic — regex-based, no AST)
// ---------------------------------------------------------------------------

const PY_SOURCES = [
  { re: /request\.(?:form|args|data|json|values|cookies|headers)(?:\.\w+)?\s*\(/g, name: 'request' },
  { re: /request\.get\s*\(/g, name: 'request' },
  { re: /\binput\s*\(/g, name: 'input()' },
  { re: /os\.environ\.get\s*\(/g, name: 'os.environ' },
  { re: /sys\.argv/g, name: 'sys.argv' },
];

const PY_SINKS = [
  { re: /cursor\.execute\s*\(/g, name: 'cursor.execute', type: 'sql' },
  { re: /os\.system\s*\(/g, name: 'os.system', type: 'cmd' },
  { re: /subprocess\.(?:run|call|Popen)\s*\(/g, name: 'subprocess', type: 'cmd' },
  { re: /eval\s*\(/g, name: 'eval()', type: 'code' },
  { re: /exec\s*\(/g, name: 'exec()', type: 'code' },
  { re: /open\s*\(/g, name: 'open()', type: 'file' },
  { re: /pickle\.loads?\s*\(/g, name: 'pickle', type: 'deserialization' },
];

function analyzePythonTaint(content, lines, relPath) {
  const findings = [];
  const sources = [];
  const sinks = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const src of PY_SOURCES) {
      src.re.lastIndex = 0;
      if (src.re.test(line)) {
        sources.push({ line: i + 1, name: src.name, var: extractVarName(line) });
      }
    }
    for (const sink of PY_SINKS) {
      sink.re.lastIndex = 0;
      if (sink.re.test(line)) {
        sinks.push({ line: i + 1, name: sink.name, type: sink.type });
      }
    }
  }

  for (const src of sources) {
    for (const sink of sinks) {
      if (sink.line >= src.line) {
        const varName = src.var;
        if (!varName) continue;
        const linesBetween = lines.slice(src.line - 1, sink.line).join('\n');
        if (linesBetween.includes(varName)) {
          findings.push({
            ruleId: 'py.taint-flow',
            file: relPath,
            line: sink.line,
            column: 1,
            severity: 'high',
            confidence: 'medium',
            title: `Python taint: ${src.name} → ${sink.name}`,
            snippet: lines[sink.line - 1]?.trim().slice(0, 120) || '',
            message: `User input (${src.name} at line ${src.line}) flows to ${sink.name} (line ${sink.line}) without sanitization.`,
            fix: `Sanitize or validate the input before passing it to ${sink.name}.`,
            owasp: 'A03:2025 Injection',
            cwe: sink.type === 'sql' ? 'CWE-89' : sink.type === 'cmd' ? 'CWE-77' : 'CWE-20',
          });
        }
      }
    }
  }

  return findings;
}

function extractVarName(line) {
  const m = /\b(\w+)\s*=\s*(?:request\.|input\(|os\.environ|sys\.argv)/.exec(line);
  if (m) return m[1];
  const m2 = /\b(?:for\s+)?(\w+)\s+in\s+request\./.exec(line);
  if (m2) return m2[1];
  return null;
}

module.exports = {
  isSanitized,
  SANITIZERS,
  getChangedFiles,
  loadHashCache,
  saveHashCache,
  hashContent,
  buildAuthCoverage,
  analyzePythonTaint,
};
