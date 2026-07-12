'use strict';

/*
 * Optional AST mode (acorn, + acorn-typescript for .ts/.tsx).
 *
 * When installed, VibeGuard parses files and does a precise pass regex can't:
 *   - eval()/new Function()/child_process.exec with a DYNAMIC (non-literal) arg
 *   - mass assignment: new Model(req.body) / Model.create(req.body) / Object.assign(x, req.body)
 *   - NoSQL injection: Model.find(req.body) / a query object containing $where
 *
 * AST findings are precise (no comment/string false positives). When a file is
 * successfully parsed, the scanner drops the *regex* versions of the same rules
 * for that file (see `parsed`), so precision replaces the heuristic.
 *
 * Fully optional: if acorn isn't installed or a file doesn't parse, returns
 * { findings: [], parsed: false } and the regex rules keep running.
 */

const path = require('path');

let acorn = null;
let walk = null;
let tsParser = null;
let loaded = false;

function load() {
  if (loaded) return acorn && walk;
  loaded = true;
  try {
    acorn = require('acorn');
    walk = require('acorn-walk');
  } catch {
    acorn = walk = null;
    return false;
  }
  try {
    const ts = require('acorn-typescript');
    const tsPlugin = ts.tsPlugin || ts.default || ts;
    tsParser = acorn.Parser.extend(tsPlugin());
  } catch {
    tsParser = null; // TS support optional-on-top-of-optional
  }
  return true;
}

function isAvailable() {
  return !!load();
}

const JS_EXT = new Set(['.js', '.jsx', '.mjs', '.cjs']);
const TS_EXT = new Set(['.ts', '.tsx', '.mts', '.cts']);

function parse(content, ext) {
  const opts = { ecmaVersion: 'latest', sourceType: 'module', locations: true, allowReturnOutsideFunction: true };
  const isTs = TS_EXT.has(ext);
  const parser = isTs ? tsParser : acorn.Parser;
  if (isTs && !tsParser) return null; // no TS plugin -> let regex handle it
  try {
    return parser.parse(content, opts);
  } catch {
    try {
      return parser.parse(content, Object.assign({}, opts, { sourceType: 'script' }));
    } catch {
      return null;
    }
  }
}

function isDynamic(node) {
  if (!node) return false;
  if (node.type === 'Literal') return false;
  if (node.type === 'TemplateLiteral') return node.expressions.length > 0;
  return true;
}

// Root identifier of a member chain, e.g. req.body.x -> "req".
function rootName(node) {
  let n = node;
  while (n && n.type === 'MemberExpression') n = n.object;
  return n && n.type === 'Identifier' ? n.name : null;
}

// Is this argument derived straight from the request?
function isReqDerived(node) {
  if (!node) return false;
  if (node.type === 'MemberExpression') return rootName(node) === 'req';
  if (node.type === 'Identifier') return /^req$/.test(node.name);
  return false;
}

function calleeName(node) {
  const c = node.callee;
  if (!c) return '';
  if (c.type === 'Identifier') return c.name;
  if (c.type === 'MemberExpression' && c.property && c.property.name) {
    const obj = (c.object && (c.object.name || (c.object.property && c.object.property.name))) || '';
    return `${obj}.${c.property.name}`;
  }
  return '';
}

function propName(c) {
  return (c.callee && c.callee.property && c.callee.property.name) || '';
}

const MUTATION_METHODS = new Set(['create', 'save', 'build', 'insert', 'insertOne', 'insertMany', 'update', 'updateOne', 'updateMany', 'findOneAndUpdate']);
const QUERY_METHODS = new Set(['find', 'findOne', 'findOneAndUpdate', 'findOneAndDelete', 'updateOne', 'updateMany', 'deleteOne', 'deleteMany', 'count', 'countDocuments']);

function objectHasWhere(node) {
  return (
    node &&
    node.type === 'ObjectExpression' &&
    node.properties.some((p) => {
      const k = p.key && (p.key.name || p.key.value);
      return k === '$where';
    })
  );
}

function analyzeAst(content, relPath, preparsed) {
  const result = { findings: [], parsed: false };
  if (!load()) return result;
  const ext = path.extname(relPath || '').toLowerCase();
  if (!JS_EXT.has(ext) && !TS_EXT.has(ext)) return result;

  // Reuse a cached tree when the scanner provides one (one parse per file).
  const tree = preparsed || parse(content, ext);
  if (!tree) return result;
  result.parsed = true;
  result._rel = relPath;

  const push = (node, f) =>
    result.findings.push({
      file: relPath,
      line: (node.loc && node.loc.start.line) || 1,
      column: (node.loc && node.loc.start.column + 1) || 1,
      confidence: 'high',
      ...f,
    });

  walk.simple(tree, {
    CallExpression(node) {
      const name = calleeName(node);
      const prop = propName(node);
      const args = node.arguments || [];
      const a0 = args[0];

      if (name === 'eval' && isDynamic(a0)) {
        push(node, { ruleId: 'ast.eval-dynamic', severity: 'critical', title: 'eval() with a non-literal argument (AST-confirmed)', message: 'eval() is called with a dynamic argument — arbitrary code execution.', fix: 'Remove eval(). Use JSON.parse or an explicit dispatch table.', snippet: 'eval(...)' });
      }
      if (/(?:^|\.)(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)$/.test(name) && isDynamic(a0)) {
        push(node, { ruleId: 'ast.command-injection', severity: 'high', title: 'Shell exec with a non-literal command (AST-confirmed)', message: `${name.split('.').pop()}() runs a dynamically built command — command injection.`, fix: 'Use execFile with an argument array; validate/allowlist inputs.', snippet: `${name}(...)` });
      }
      // Path traversal: fs.* / path.join|resolve / res.sendFile with request data.
      if (
        (['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'createReadStream', 'createWriteStream', 'unlink', 'unlinkSync', 'appendFile', 'sendFile'].includes(prop) ||
          name === 'path.join' || name === 'path.resolve') &&
        args.some(isReqDerived)
      ) {
        push(node, { ruleId: 'ast.path-traversal', severity: 'high', title: 'Filesystem path from request (AST-confirmed)', message: 'A request value is used to build a filesystem path — path traversal.', fix: 'Sanitize with path.basename(); resolve against a fixed base and reject escapes.', snippet: `${name || prop}(req.*)` });
      }
      // SSRF: fetch/axios/got/http(s).get|request with a request-derived URL.
      if (
        (/(?:^|\.)(?:fetch|got)$/.test(name) ||
          (['get', 'post', 'put', 'delete', 'request'].includes(prop) && /axios|http|https|got/.test(name))) &&
        isReqDerived(a0)
      ) {
        push(node, { ruleId: 'ast.ssrf', severity: 'high', title: 'Outbound request to a request-derived URL (AST-confirmed)', message: 'A request value is used as an outbound request target — SSRF.', fix: 'Allowlist hosts/schemes; block internal/metadata addresses.', snippet: `${name || prop}(req.*)` });
      }

      // Object.assign(target, req.body)
      if (name === 'Object.assign' && args.slice(1).some(isReqDerived)) {
        push(node, { ruleId: 'ast.mass-assignment', severity: 'high', title: 'Mass assignment from request (AST-confirmed)', message: 'Object.assign merges the request straight into a target object — attacker-set fields (role/isAdmin) get through.', fix: 'Merge only an explicit allowlist of fields.', snippet: 'Object.assign(_, req.*)' });
      }
      // Model.create(req.body) / .save(req.body) / ...
      if (MUTATION_METHODS.has(prop) && isReqDerived(a0)) {
        push(node, { ruleId: 'ast.mass-assignment', severity: 'high', title: 'Mass assignment from request (AST-confirmed)', message: `${prop}() writes the whole request body to a record — mass assignment.`, fix: 'Pick an explicit allowlist of fields from req.body.', snippet: `${prop}(req.*)` });
      }
      // Model.find(req.body) — query object from the request
      if (QUERY_METHODS.has(prop) && isReqDerived(a0)) {
        push(node, { ruleId: 'ast.nosql-injection', severity: 'high', title: 'NoSQL query from request (AST-confirmed)', message: `${prop}() uses the request as a query object — operator injection ({"$gt":""}).`, fix: 'Build the query from validated scalar fields only.', snippet: `${prop}(req.*)` });
      }
      // Model.find({ name: req.body.name }) — request data nested in query object
      if (QUERY_METHODS.has(prop) && a0 && a0.type === 'ObjectExpression' && a0.properties.some(p => p.value && isReqDerived(p.value))) {
        push(node, { ruleId: 'ast.nosql-injection', severity: 'high', title: 'NoSQL query with request data (AST-confirmed)', message: `${prop}() builds a query from request fields — operator injection if attacker sends {"$gt":""}.`, fix: 'Validate each field type before building the query; reject objects with $ operators.', snippet: `${prop}({...req.*})` });
      }
      // any call whose object arg contains $where
      if (args.some(objectHasWhere)) {
        push(node, { ruleId: 'ast.nosql-injection', severity: 'high', title: 'NoSQL $where operator (AST-confirmed)', message: 'A query uses the $where operator, which executes JavaScript on the DB server — injection risk.', fix: 'Avoid $where; use structured query operators on validated fields.', snippet: '$where' });
      }
    },
    NewExpression(node) {
      const args = node.arguments || [];
      if (node.callee && node.callee.name === 'Function' && args.some(isDynamic)) {
        push(node, { ruleId: 'ast.function-constructor', severity: 'critical', title: 'new Function() with a dynamic argument (AST-confirmed)', message: 'new Function() builds code from a dynamic argument — arbitrary code execution.', fix: 'Avoid new Function on dynamic input.', snippet: 'new Function(...)' });
      }
      // new Model(req.body)
      if (node.callee && node.callee.type === 'Identifier' && /^[A-Z]/.test(node.callee.name) && isReqDerived(args[0])) {
        push(node, { ruleId: 'ast.mass-assignment', severity: 'high', title: 'Mass assignment from request (AST-confirmed)', message: `new ${node.callee.name}(req.*) constructs a record from the whole request — mass assignment.`, fix: 'Construct from an explicit allowlist of fields.', snippet: `new ${node.callee.name}(req.*)` });
      }
    },
  });

  // -- Interprocedural taint (within-file): a local function whose first param
  // reaches a dangerous sink, then called with request-derived data. --
  interprocedural(tree, walk, result);

  return result;
}

// Does a node reference the identifier `name` (as itself or a member root)?
function refsName(node, name) {
  if (!node) return false;
  if (node.type === 'Identifier') return node.name === name;
  if (node.type === 'MemberExpression') return rootName(node) === name || refsName(node.object, name);
  if (node.type === 'BinaryExpression') return refsName(node.left, name) || refsName(node.right, name);
  if (node.type === 'TemplateLiteral') return node.expressions.some((e) => refsName(e, name));
  if (node.type === 'CallExpression') return (node.arguments || []).some((a) => refsName(a, name));
  return false;
}

// Classify any call as a dangerous sink (regardless of arguments).
function sinkKindOfCall(node) {
  const name = calleeName(node);
  const prop = (node.callee && node.callee.property && node.callee.property.name) || '';
  if (name === 'eval') return { ruleId: 'eval', label: 'eval()' };
  if (/(?:^|\.)(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)$/.test(name)) return { ruleId: 'command', label: 'a shell command' };
  if (['query', 'raw', 'execute'].includes(prop)) return { ruleId: 'sql', label: 'a SQL query' };
  if (/(?:^|\.)(?:fetch|get|request)$/.test(name) || (['get', 'post'].includes(prop) && /axios|http|got/.test(name))) return { ruleId: 'ssrf', label: 'an outbound request' };
  if (prop === 'join' || prop === 'resolve' || /readFile|writeFile|sendFile/.test(prop)) return { ruleId: 'path', label: 'a filesystem path' };
  return null;
}

// Is a call a dangerous sink whose argument list references `param`?
function sinkForParam(node, param) {
  const kind = sinkKindOfCall(node);
  if (!kind) return null;
  return (node.arguments || []).some((a) => refsName(a, param)) ? kind : null;
}

function interprocedural(tree, walk, result) {
  const funcs = new Map(); // funcName -> { param, sinkLabel }

  const recordFn = (name, fnNode) => {
    if (!name || !fnNode || !fnNode.params || !fnNode.params[0] || fnNode.params[0].type !== 'Identifier') return;
    const param = fnNode.params[0].name;
    let sink = null;
    walk.simple(fnNode, { CallExpression(n) { sink = sink || sinkForParam(n, param); } });
    if (sink) funcs.set(name, { param, sinkLabel: sink.label, kind: sink.ruleId });
  };

  walk.simple(tree, {
    FunctionDeclaration(n) { if (n.id) recordFn(n.id.name, n); },
    VariableDeclarator(n) {
      if (n.id && n.id.type === 'Identifier' && n.init && (n.init.type === 'ArrowFunctionExpression' || n.init.type === 'FunctionExpression')) {
        recordFn(n.id.name, n.init);
      }
    },
  });
  if (funcs.size === 0) return;

  const isReq = (node) => node && ((node.type === 'MemberExpression' && rootName(node) === 'req') || (node.type === 'Identifier' && node.name === 'req'));

  walk.simple(tree, {
    CallExpression(node) {
      const fname = node.callee && node.callee.type === 'Identifier' ? node.callee.name : '';
      const info = funcs.get(fname);
      if (!info) return;
      if ((node.arguments || []).some(isReq)) {
        result.findings.push({
          ruleId: 'taint.interprocedural',
          severity: 'high',
          confidence: 'medium',
          title: 'Request data flows through a function into a sink (AST-confirmed)',
          message: `Request data is passed to ${fname}(), which routes its argument into ${info.sinkLabel} — injection across a function boundary.`,
          fix: `Validate/sanitize inside ${fname}(), or pass only safe, structured values; parameterize the sink.`,
          file: result._rel,
          line: (node.loc && node.loc.start.line) || 1,
          column: (node.loc && node.loc.start.column + 1) || 1,
        });
      }
    },
  });
}

// Regex rule ids that AST supersedes once a file is parsed (avoids double-report
// and kills the regex heuristic's false positives for that file).
const AST_SUPERSEDES = new Set([
  'validation.mass-assignment',
  'injection.nosql',
  'code.eval',
  'code.command-injection',
  'upload.path-traversal',
  'web.ssrf',
]);

// Parse cache keyed by content hash — memoizes parses ACROSS scans (so `watch`
// re-scans and repeated runs don't re-parse unchanged files). Bounded size.
const crypto = require('crypto');
const PARSE_CACHE = new Map();
const PARSE_CACHE_MAX = 4000;

// Shared parse for other analyzers (e.g. cross-file taint). Returns a tree or null.
function parseSource(content, relPath) {
  if (!load()) return null;
  const ext = path.extname(relPath || '').toLowerCase();
  if (!JS_EXT.has(ext) && !TS_EXT.has(ext)) return null;
  const key = ext + ':' + crypto.createHash('sha1').update(content).digest('hex');
  if (PARSE_CACHE.has(key)) return PARSE_CACHE.get(key);
  const tree = parse(content, ext);
  if (PARSE_CACHE.size >= PARSE_CACHE_MAX) PARSE_CACHE.clear(); // simple bound
  PARSE_CACHE.set(key, tree);
  return tree;
}
function getWalk() {
  return load() ? walk : null;
}

module.exports = {
  analyzeAst, isAvailable, AST_SUPERSEDES,
  calleeName, rootName, refsName, sinkForParam, sinkKindOfCall, isDynamic,
  parseSource, getWalk,
};
