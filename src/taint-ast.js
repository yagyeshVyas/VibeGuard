'use strict';

/*
 * Scope-aware, AST-based intra-file taint analysis (requires acorn).
 *
 * Replaces the regex taint pass when a file parses successfully.
 * Handles: variable declarations, assignments, template literals, binary
 * string concat, function parameters, object property reads/writes, array
 * element access, block/function scope with shadowing, reassignment clearing,
 * and sanitizer recognition.
 *
 * Falls back to regex taint (in taint.js) when acorn is unavailable or the
 * file doesn't parse.
 */

const ast = require('./ast');

// ---------------------------------------------------------------------------
// Sources — matched on AST MemberExpression nodes, not text.
// ---------------------------------------------------------------------------

// Roots whose properties indicate attacker-controlled data.
const SOURCE_ROOTS = new Set(['req', 'request', 'ctx', 'event', 'process', 'location', 'window', 'document']);
const SOURCE_PROPS = new Set([
  'body', 'query', 'params', 'headers', 'cookies', 'url', 'originalUrl',
  'hostname', 'searchParams', 'argv', 'search', 'hash', 'href',
  'queryStringParameters', 'pathParameters',
]);

function isSourceNode(node) {
  if (!node) return false;
  // process.argv, location.search, location.hash, document.URL
  if (node.type === 'MemberExpression') {
    const root = ast.rootName(node);
    const prop = node.property && node.property.name;
    if (SOURCE_ROOTS.has(root) && SOURCE_PROPS.has(prop)) return true;
    // .searchParams on any object
    if (prop === 'searchParams') return true;
    // location.search, location.hash, document.URL
    if ((root === 'location' || root === 'window' || root === 'document') && SOURCE_PROPS.has(prop)) return true;
    // request.body, req.body etc. — also match deeper: req.body.x
    if (SOURCE_ROOTS.has(root)) return true;
    return false;
  }
  // bare `req` / `request` identifier
  if (node.type === 'Identifier' && SOURCE_ROOTS.has(node.name)) return true;
  // new URLSearchParams(...) — the constructor call is a source
  if (node.type === 'NewExpression' && node.callee && node.callee.name === 'URLSearchParams') return true;
  return false;
}

// ---------------------------------------------------------------------------
// Sinks — matched on CallExpression nodes.
// Kept identical ruleId/severity/title/message/fix to the regex SINKS in taint.js.
// ---------------------------------------------------------------------------

const SINKS_AST = [
  {
    match: (call) => {
      const name = ast.calleeName(call);
      return /(?:^|\.)(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)$/.test(name);
    },
    ruleId: 'taint.command-injection',
    severity: 'high',
    title: 'User input reaches a shell command (dataflow-confirmed)',
    message: 'A value derived from user input flows into a shell command — command injection.',
    fix: 'Pass arguments as an array (execFile("cmd",[arg])) and never build a shell string from input; validate/allowlist.',
  },
  {
    match: (call) => {
      const prop = (call.callee && call.callee.property && call.callee.property.name) || '';
      const name = ast.calleeName(call);
      if (prop === 'query' || prop === 'raw' || prop === 'execute') return true;
      if (name === 'sequelize.query') return true;
      return false;
    },
    ruleId: 'taint.sql-injection',
    severity: 'high',
    title: 'User input reaches a SQL query (dataflow-confirmed)',
    message: 'A value derived from user input flows into a SQL query call — SQL injection.',
    fix: 'Use parameterized queries / prepared statements; pass input as bound parameters, not concatenated SQL.',
  },
  {
    match: (call) => {
      const name = ast.calleeName(call);
      return name === 'eval' || /^new\s/.test('') && call.callee && call.callee.name === 'Function';
    },
    ruleId: 'taint.code-injection',
    severity: 'critical',
    title: 'User input reaches eval()/Function() (dataflow-confirmed)',
    message: 'A value derived from user input flows into eval()/new Function() — remote code execution.',
    fix: 'Remove eval/Function on dynamic input. Use JSON.parse or an explicit dispatch table.',
  },
  {
    match: (call) => {
      const prop = (call.callee && call.callee.property && call.callee.property.name) || '';
      const name = ast.calleeName(call);
      if (['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'createReadStream', 'createWriteStream', 'unlink', 'unlinkSync', 'appendFile', 'sendFile'].includes(prop)) return true;
      if (name === 'path.join' || name === 'path.resolve') return true;
      return false;
    },
    ruleId: 'taint.path-traversal',
    severity: 'high',
    title: 'User input reaches a filesystem path (dataflow-confirmed)',
    message: 'A value derived from user input is used to build a filesystem path — path traversal.',
    fix: 'Sanitize with path.basename(), resolve against a fixed base, and reject paths that escape it.',
  },
  {
    match: (call) => {
      const name = ast.calleeName(call);
      const prop = (call.callee && call.callee.property && call.callee.property.name) || '';
      if (/(?:^|\.)(?:fetch|got)$/.test(name)) return true;
      if (['get', 'post', 'put', 'delete', 'request'].includes(prop) && /axios|http|https|got/.test(name)) return true;
      return false;
    },
    ruleId: 'taint.ssrf',
    severity: 'high',
    title: 'User input reaches an outbound request URL (dataflow-confirmed)',
    message: 'A value derived from user input is used as an outbound request target — server-side request forgery (SSRF).',
    fix: 'Allowlist permitted hosts/schemes; never fetch a URL built from raw user input; block internal/metadata addresses.',
  },
  {
    match: (call) => {
      const prop = (call.callee && call.callee.property && call.callee.property.name) || '';
      return prop === 'redirect' || prop === 'location';
    },
    ruleId: 'taint.open-redirect',
    severity: 'medium',
    title: 'User input reaches a redirect target (dataflow-confirmed)',
    message: 'A value derived from user input is used as a redirect target — open redirect (phishing).',
    fix: 'Redirect only to an allowlist of internal paths; reject absolute/off-site URLs from input.',
  },
  {
    match: (call) => {
      const prop = (call.callee && call.callee.property && call.callee.property.name) || '';
      return prop === 'send' || prop === 'write' || prop === 'end';
    },
    ruleId: 'taint.xss-reflected',
    severity: 'high',
    title: 'User input reaches an HTML response (dataflow-confirmed)',
    message: 'A value derived from user input flows into res.send/write/end — reflected XSS.',
    fix: 'Escape/encode the value for HTML context, or return JSON (res.json) and render safely on the client.',
  },
  {
    match: (call) => {
      // fetch() to a known AI API host with tainted data in any argument.
      const name = ast.calleeName(call);
      if (name !== 'fetch' && name !== 'axios.post' && name !== 'axios.put' && name !== 'axios') return false;
      // Check if any argument or nested property contains a known AI host URL.
      const AI_HOSTS = ['api.openai.com', 'api.anthropic.com', 'generativelanguage.googleapis.com', 'api.groq.com', 'api.together.xyz', 'api.mistral.ai', 'api.cohere.ai', 'api.perplexity.ai'];
      const args = call.arguments || [];
      for (const arg of args) {
        // Check if the first arg is a string literal or template with an AI host.
        if (arg.type === 'Literal' && typeof arg.value === 'string' && AI_HOSTS.some(h => arg.value.includes(h))) return true;
        if (arg.type === 'TemplateLiteral') {
          for (const q of arg.quasi || []) {
            if (q && q.value && AI_HOSTS.some(h => q.value.includes(h))) return true;
          }
          // Also check cooked template
          if (arg.quasis) {
            for (const q of arg.quasis) {
              if (q && q.value && q.value.cooked && AI_HOSTS.some(h => q.value.cooked.includes(h))) return true;
            }
          }
        }
      }
      return false;
    },
    ruleId: 'taint.pii-to-llm',
    severity: 'high',
    title: 'User data sent to AI API without redaction (dataflow-confirmed)',
    message: 'A value derived from user input flows into a request to an AI API — potential PII leak.',
    fix: 'Redact PII before sending to any AI API. Send only the fields the LLM needs, not raw user data.',
  },
  {
    match: (call) => {
      // SDK calls: openai.chat.completions.create, anthropic.messages.create, genAI.generateContent
      const name = ast.calleeName(call);
      const prop = (call.callee && call.callee.property && call.callee.property.name) || '';
      if (prop === 'create' && name && (name.includes('completions') || name.includes('messages') || name.includes('generate'))) return true;
      if (prop === 'generateContent' || prop === 'generate') return true;
      return false;
    },
    ruleId: 'taint.pii-to-llm',
    severity: 'high',
    title: 'User data sent to AI SDK without redaction (dataflow-confirmed)',
    message: 'A value derived from user input flows into an AI SDK call — potential PII leak.',
    fix: 'Redact PII before sending to any AI API. Send only the fields the LLM needs, not raw user data.',
  },
];

// ---------------------------------------------------------------------------
// Sanitizers — configurable array of function names that clear taint.
// ---------------------------------------------------------------------------

const DEFAULT_SANITIZERS = [
  'parseInt', 'parseFloat', 'Number', 'String', 'Boolean',
  'escape', 'escapeHtml', 'encodeURI', 'encodeURIComponent',
  'basename',
];

function isSanitizerCall(call, sanitizers) {
  const name = ast.calleeName(call);
  const prop = (call.callee && call.callee.property && call.callee.property.name) || '';
  for (const s of sanitizers) {
    if (name === s || prop === s) return true;
    // validator.escape, DOMPurify.sanitize etc.
    if (name.endsWith('.' + s) || prop === s) return true;
  }
  // DOMPurify.sanitize — always recognized
  if (prop === 'sanitize') return true;
  // path.basename — always recognized
  if (name === 'path.basename') return true;
  return false;
}

// ---------------------------------------------------------------------------
// Scope tree: build a scope hierarchy from the AST.
// ---------------------------------------------------------------------------

// We walk the tree manually (not acorn-walk) so we can track enter/exit of
// scopes precisely and maintain a scope stack.

function isScopeNode(node) {
  return node && (
    node.type === 'Program' ||
    node.type === 'FunctionDeclaration' ||
    node.type === 'FunctionExpression' ||
    node.type === 'ArrowFunctionExpression' ||
    node.type === 'BlockStatement'
  );
}

function getScopeDeclarations(node) {
  // Returns names declared in this scope (var/let/const/function).
  const names = new Set();
  if (!node) return names;
  if (node.type === 'Program' || node.type === 'BlockStatement') {
    if (node.body && Array.isArray(node.body)) {
      for (const stmt of node.body) {
        collectDeclarations(stmt, names);
      }
    }
  }
  // Function params are declared in the function scope (not the block).
  if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression') {
    if (node.params) {
      for (const p of node.params) {
        bindingNames(p, names);
      }
    }
    // Function name (for FunctionDeclaration)
    if (node.type === 'FunctionDeclaration' && node.id) names.add(node.id.name);
  }
  return names;
}

function bindingNames(param, out) {
  out = out || new Set();
  if (!param) return out;
  if (param.type === 'Identifier') out.add(param.name);
  else if (param.type === 'AssignmentPattern') bindingNames(param.left, out);
  else if (param.type === 'RestElement') bindingNames(param.argument, out);
  else if (param.type === 'ObjectPattern') {
    for (const p of param.properties) {
      bindingNames(p.type === 'RestElement' ? p.argument : p.value, out);
    }
  }
  else if (param.type === 'ArrayPattern') {
    for (const e of param.elements) if (e) bindingNames(e, out);
  }
  return out;
}

function collectDeclarations(stmt, names) {
  if (!stmt) return;
  switch (stmt.type) {
    case 'VariableDeclaration':
      for (const d of stmt.declarations) {
        if (d.id) bindingNames(d.id, names);
      }
      break;
    case 'FunctionDeclaration':
      if (stmt.id) names.add(stmt.id.name);
      break;
    case 'ExportNamedDeclaration':
      if (stmt.declaration) collectDeclarations(stmt.declaration, names);
      break;
    case 'ExportDefaultDeclaration':
      if (stmt.declaration && stmt.declaration.type === 'FunctionDeclaration' && stmt.declaration.id) {
        names.add(stmt.declaration.id.name);
      }
      break;
    default:
      break;
  }
}

// ---------------------------------------------------------------------------
// Taint analysis engine
// ---------------------------------------------------------------------------

// A TaintScope tracks tainted variables within a lexical scope.
// Shadowing: if an inner scope declares a name that's tainted in an outer
// scope, the inner declaration starts clean (it's a different variable).

class TaintScope {
  constructor(parent, decls) {
    this.parent = parent;
    this.decls = decls; // Set of names declared in this scope
    this.tainted = new Map(); // name -> { via: string, sanitized: boolean }
  }

  // Look up a name: return taint info if found in this or any parent scope.
  // Returns { via, sanitized } or null. Respects shadowing: if this scope
  // declares the name but it's not tainted here, return null (shadowed).
  lookup(name) {
    if (this.decls.has(name)) {
      // Declared in this scope — only this scope's taint matters.
      return this.tainted.get(name) || null;
    }
    if (this.parent) return this.parent.lookup(name);
    // No parent and not declared: check our own taint map (covers isolated
    // function-analysis scopes where decls is empty but taint was set manually).
    return this.tainted.get(name) || null;
  }

  // Set taint for a name that's declared in this or an ancestor scope.
  // If the name is declared in an ancestor, set it there. Otherwise set it
  // here (e.g., it was assigned without a var — implicit global, or we
  // just track it locally).
  setTaint(name, info) {
    if (this.decls.has(name)) {
      this.tainted.set(name, info);
      return;
    }
    if (this.parent && this.parent.hasDecl(name)) {
      this.parent.setTaint(name, info);
      return;
    }
    // Not declared anywhere we can see — track in the nearest function/program scope.
    this.tainted.set(name, info);
  }

  hasDecl(name) {
    if (this.decls.has(name)) return true;
    if (this.parent) return this.parent.hasDecl(name);
    return false;
  }

  clearTaint(name) {
    if (this.decls.has(name)) {
      this.tainted.delete(name);
      return;
    }
    if (this.parent && this.parent.hasDecl(name)) {
      this.parent.clearTaint(name);
      return;
    }
    this.tainted.delete(name);
  }
}

// Check if an expression node references a tainted variable (considering scope).
function exprTaintInfo(node, scope) {
  if (!node) return null;
  switch (node.type) {
    case 'Identifier': {
      return scope.lookup(node.name);
    }
    case 'MemberExpression': {
      // For member expressions like req.body.name, the root identifier matters.
      // If the root is tainted (e.g., `const x = req; x.body.name`), the whole
      // member is tainted. Also check the object chain.
      const root = ast.rootName(node);
      if (root && scope.lookup(root)) {
        const info = scope.lookup(root);
        return info;
      }
      // Check if this is a direct source (req.body, location.search, etc.)
      if (isSourceNode(node)) return { via: 'source', sanitized: false };
      // Check if the object part is tainted.
      return exprTaintInfo(node.object, scope);
    }
    case 'BinaryExpression': {
      const l = exprTaintInfo(node.left, scope);
      if (l) return l;
      const r = exprTaintInfo(node.right, scope);
      return r;
    }
    case 'TemplateLiteral': {
      for (const expr of node.expressions) {
        const info = exprTaintInfo(expr, scope);
        if (info) return info;
      }
      return null;
    }
    case 'CallExpression': {
      // If this is a sanitizer call, the result is NOT tainted.
      // (We handle this at the assignment site too, but check here for safety.)
      const sanitizers = scope._sanitizers || DEFAULT_SANITIZERS;
      if (isSanitizerCall(node, sanitizers)) return null;
      // Check if any argument is tainted (taint through function call, best-effort).
      for (const arg of node.arguments || []) {
        const info = exprTaintInfo(arg, scope);
        if (info) return info;
      }
      // Check if the callee is a tainted variable holding a function
      const calleeInfo = exprTaintInfo(node.callee, scope);
      if (calleeInfo) return calleeInfo;
      return null;
    }
    case 'ConditionalExpression': {
      const c = exprTaintInfo(node.consequent, scope);
      if (c) return c;
      return exprTaintInfo(node.alternate, scope);
    }
    case 'LogicalExpression': {
      const l = exprTaintInfo(node.left, scope);
      if (l) return l;
      return exprTaintInfo(node.right, scope);
    }
    case 'ArrayExpression': {
      for (const el of node.elements || []) {
        const info = exprTaintInfo(el, scope);
        if (info) return info;
      }
      return null;
    }
    case 'ObjectExpression': {
      for (const prop of node.properties || []) {
        if (prop.value) {
          const info = exprTaintInfo(prop.value, scope);
          if (info) return info;
        }
      }
      return null;
    }
    case 'AssignmentExpression': {
      return exprTaintInfo(node.right, scope);
    }
    case 'UnaryExpression': {
      // typeof, void, !, etc. — these don't propagate taint meaningfully
      // except for + which is string concat, but that's BinaryExpression.
      return null;
    }
    case 'ChainExpression': {
      return exprTaintInfo(node.expression, scope);
    }
    case 'AwaitExpression': {
      return exprTaintInfo(node.argument, scope);
    }
    case 'SpreadElement': {
      return exprTaintInfo(node.argument, scope);
    }
    case 'NewExpression': {
      // new URLSearchParams(location.search) — if any arg is a source/tainted,
      // the result is tainted.
      if (isSourceNode(node)) return { via: 'source', sanitized: false };
      for (const arg of node.arguments || []) {
        const info = exprTaintInfo(arg, scope);
        if (info) return info;
      }
      return null;
    }
    default:
      return null;
  }
}

// Does the expression directly contain a source?
function exprIsSource(node) {
  if (!node) return false;
  if (isSourceNode(node)) return true;
  switch (node.type) {
    case 'MemberExpression':
      return exprIsSource(node.object);
    case 'BinaryExpression':
      return exprIsSource(node.left) || exprIsSource(node.right);
    case 'TemplateLiteral':
      return node.expressions.some((e) => exprIsSource(e));
    case 'CallExpression':
      return (node.arguments || []).some(exprIsSource);
    case 'ConditionalExpression':
      return exprIsSource(node.consequent) || exprIsSource(node.alternate);
    case 'LogicalExpression':
      return exprIsSource(node.left) || exprIsSource(node.right);
    case 'ArrayExpression':
      return (node.elements || []).some(exprIsSource);
    case 'ObjectExpression':
      return (node.properties || []).some((p) => p.value && exprIsSource(p.value));
    case 'AssignmentExpression':
      return exprIsSource(node.right);
    case 'ChainExpression':
      return exprIsSource(node.expression);
    case 'AwaitExpression':
      return exprIsSource(node.argument);
    default:
      return false;
  }
}

// ---------------------------------------------------------------------------
// Main analysis: walk the AST, maintain scope stack, track taint.
// ---------------------------------------------------------------------------

function analyzeTaintAst(content, lines, relPath, tree, sanitizers) {
  const walk = ast.getWalk();
  if (!walk || !tree) return [];
  const ext = require('path').extname(relPath || '').toLowerCase();
  const sanList = sanitizers || DEFAULT_SANITIZERS;

  const findings = [];
  const rootScope = new TaintScope(null, getScopeDeclarations(tree));
  rootScope._sanitizers = sanList;

  // Scope stack: maintain current scope as we traverse.
  let currentScope = rootScope;

  // We need to traverse manually to control scope entry/exit.
  // But acorn-walk's `walk.recursive` gives us enter/exit callbacks.
  // Since acorn-walk doesn't expose enter/exit in `walk.simple`, we'll
  // use a custom recursive walker.

  // First pass: collect all function definitions to support cross-function taint.
  // Map: funcName -> { node, paramTaintSlots: Map(paramName -> Set(argIndex)), sinkCalls: [{call, paramRefs}] }
  const functions = new Map();

  // Collect function declarations and expressions.
  function collectFunctions(node) {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'FunctionDeclaration' && node.id) {
      functions.set(node.id.name, { node, params: node.params || [] });
    }
    if (node.type === 'VariableDeclarator' && node.id && node.id.type === 'Identifier' && node.init) {
      if (node.init.type === 'ArrowFunctionExpression' || node.init.type === 'FunctionExpression') {
        functions.set(node.id.name, { node: node.init, params: node.init.params || [] });
      }
    }
    // Recurse into children
    for (const key in node) {
      if (key === 'type' || key === 'loc' || key === 'start' || key === 'end' || key === 'range') continue;
      const child = node[key];
      if (Array.isArray(child)) {
        child.forEach(collectFunctions);
      } else if (child && typeof child === 'object' && child.type) {
        collectFunctions(child);
      }
    }
  }
  collectFunctions(tree);

  // Analyze each function: does any param reach a sink?
  // We run proper intra-function taint tracking: params are tainted, then we
  // propagate through local assignments (fixpoint), then check sink call args.
  const funcSinkInfo = new Map(); // funcName -> [{ paramIndex, sinkDef }]

  for (const [name, info] of functions) {
    const paramNames = [];
    (info.params || []).forEach((p, i) => {
      for (const n of bindingNames(p)) paramNames.push({ name: n, index: i });
    });
    // Build a function-local scope with params tainted at their slot.
    const fnScope = new TaintScope(null, new Set());
    fnScope._sanitizers = sanList;
    for (const { name: pn, index } of paramNames) {
      fnScope.setTaint(pn, { via: `param:${index}`, sanitized: false });
    }

    // Collect all assignments in the function body (fixpoint for local propagation).
    const assigns = [];
    function collectAssigns(node) {
      if (!node || typeof node !== 'object') return;
      // Don't recurse into nested functions (their params shadow).
      if (node !== info.node && isScopeNode(node) && node.type !== 'BlockStatement') return;
      if (node.type === 'VariableDeclarator' && node.id && node.id.type === 'Identifier' && node.init) {
        assigns.push({ name: node.id.name, expr: node.init });
      }
      if (node.type === 'AssignmentExpression' && node.left && node.left.type === 'Identifier') {
        assigns.push({ name: node.left.name, expr: node.right });
      }
      for (const key in node) {
        if (key === 'type' || key === 'loc' || key === 'start' || key === 'end' || key === 'range') continue;
        const child = node[key];
        if (Array.isArray(child)) {
          child.forEach(collectAssigns);
        } else if (child && typeof child === 'object' && child.type) {
          collectAssigns(child);
        }
      }
    }
    collectAssigns(info.node);

    // Fixpoint: propagate taint through local assignments.
    for (let pass = 0; pass < 5; pass++) {
      let changed = false;
      for (const a of assigns) {
        // Sanitizer check first.
        if (a.expr.type === 'CallExpression' && isSanitizerCall(a.expr, sanList)) {
          if (fnScope.lookup(a.name)) fnScope.clearTaint(a.name);
          continue;
        }
        if (exprTaintInfo(a.expr, fnScope)) {
          const info2 = exprTaintInfo(a.expr, fnScope);
          fnScope.setTaint(a.name, { via: info2.via, sanitized: info2.sanitized });
          changed = true;
        }
      }
      if (!changed) break;
    }

    // Walk the function body for sink calls and check if args are tainted.
    const sinks = [];
    function walkForSinks(node) {
      if (!node || typeof node !== 'object') return;
      // Don't recurse into nested function bodies (they have their own scope).
      if (node !== info.node && isScopeNode(node) && node.type !== 'BlockStatement') return;
      if (node.type === 'CallExpression') {
        for (const sinkDef of SINKS_AST) {
          if (!sinkDef.match(node)) continue;
          for (let ai = 0; ai < (node.arguments || []).length; ai++) {
            const arg = node.arguments[ai];
            // Check if the arg is tainted (through local propagation).
            const taintInfo = exprTaintInfo(arg, fnScope);
            if (taintInfo && !taintInfo.sanitized) {
              // Find which param slot this taint originated from.
              const viaMatch = /param:(\d+)/.exec(taintInfo.via);
              if (viaMatch) {
                const paramIndex = parseInt(viaMatch[1], 10);
                sinks.push({ paramIndex, sinkDef, node });
              } else {
                // Taint from a source directly inside the function —
                // this is a source->sink inside the helper, not cross-function.
                // Skip it; the main visit pass handles source->sink.
              }
            }
          }
        }
      }
      for (const key in node) {
        if (key === 'type' || key === 'loc' || key === 'start' || key === 'end' || key === 'range') continue;
        const child = node[key];
        if (Array.isArray(child)) {
          child.forEach(walkForSinks);
        } else if (child && typeof child === 'object' && child.type) {
          walkForSinks(child);
        }
      }
    }
    walkForSinks(info.node);
    if (sinks.length > 0) {
      funcSinkInfo.set(name, sinks);
    }
  }

  // Now walk the full tree, maintaining scopes and tracking taint.
  // We detect sinks at call sites and check if arguments are tainted.

  function pushScope(node) {
    const decls = getScopeDeclarations(node);
    const scope = new TaintScope(currentScope, decls);
    scope._sanitizers = sanList;
    currentScope = scope;
  }

  function popScope() {
    currentScope = currentScope.parent || rootScope;
  }

  // Process a node: check for sinks, propagate taint through assignments.
  function visit(node) {
    if (!node || typeof node !== 'object') return;

    // Enter scope nodes.
    const isScope = isScopeNode(node);
    if (isScope) pushScope(node);

    // Handle VariableDeclarator: propagate taint from init to declared names.
    if (node.type === 'VariableDeclarator' && node.id && node.init) {
      handleDeclarator(node);
    }

    // Handle AssignmentExpression: propagate or clear taint.
    if (node.type === 'AssignmentExpression') {
      handleAssignment(node);
    }

    // Handle CallExpression: check sinks and cross-function taint.
    if (node.type === 'CallExpression') {
      handleCall(node);
    }

    // Recurse into children.
    for (const key in node) {
      if (key === 'type' || key === 'loc' || key === 'start' || key === 'end' || key === 'range') continue;
      const child = node[key];
      if (Array.isArray(child)) {
        child.forEach(visit);
      } else if (child && typeof child === 'object' && child.type) {
        visit(child);
      }
    }

    if (isScope) popScope();
  }

  function handleDeclarator(node) {
    const init = node.init;
    // Check sanitizer FIRST — parseInt(req.query.id) contains a source in its
    // arg, but the sanitizer result is clean.
    if (init.type === 'CallExpression' && isSanitizerCall(init, sanList)) {
      const names = bindingNames(node.id);
      for (const name of names) {
        currentScope.clearTaint(name);
      }
      return;
    }
    // Check if the init is a source directly.
    if (exprIsSource(init)) {
      const names = bindingNames(node.id);
      for (const name of names) {
        currentScope.setTaint(name, { via: 'source', sanitized: false });
      }
      return;
    }
    // Check if the init expression references a tainted variable.
    const taintInfo = exprTaintInfo(init, currentScope);
    if (taintInfo) {
      const names = bindingNames(node.id);
      for (const name of names) {
        currentScope.setTaint(name, { via: taintInfo.via, sanitized: taintInfo.sanitized });
      }
      return;
    }
    // Init is clean: clear taint for declared names (reassignment to clean).
    const names = bindingNames(node.id);
    for (const name of names) {
      currentScope.clearTaint(name);
    }
  }

  function handleAssignment(node) {
    const left = node.left;
    const right = node.right;

    // Only handle identifier and member-expression targets.
    if (left.type === 'Identifier') {
      // Sanitizer check first — see handleDeclarator for rationale.
      if (right.type === 'CallExpression' && isSanitizerCall(right, sanList)) {
        currentScope.clearTaint(left.name);
        return;
      }
      if (exprIsSource(right)) {
        currentScope.setTaint(left.name, { via: 'source', sanitized: false });
        return;
      }
      const taintInfo = exprTaintInfo(right, currentScope);
      if (taintInfo) {
        currentScope.setTaint(left.name, { via: taintInfo.via, sanitized: taintInfo.sanitized });
      } else {
        // Clean reassignment clears taint.
        currentScope.clearTaint(left.name);
      }
    }
    // Member expression assignment: obj.prop = tainted => obj becomes tainted.
    if (left.type === 'MemberExpression') {
      // Check for DOM XSS sinks: .innerHTML = tainted, .outerHTML = tainted
      const leftProp = left.property && left.property.name;
      if (leftProp === 'innerHTML' || leftProp === 'outerHTML') {
        if (right.type === 'CallExpression' && isSanitizerCall(right, sanList)) return;
        const ti = exprTaintInfo(right, currentScope);
        if (ti && !ti.sanitized) {
          const loc = left.loc && left.loc.start;
          const line = loc ? loc.line : 1;
          const col = loc ? loc.column + 1 : 1;
          const snippet = lines[line - 1] ? lines[line - 1].trim().slice(0, 120) : '';
          findings.push({
            ruleId: 'taint.xss-dom',
            severity: 'high',
            confidence: 'high',
            dataflow: true,
            title: 'User input reaches DOM sink (dataflow-confirmed)',
            message: `A value derived from user input (${ti.via}) is assigned to .${leftProp} — DOM XSS.`,
            fix: 'Use textContent instead of innerHTML/outerHTML. If HTML is needed, sanitize with DOMPurify.',
            file: relPath,
            line,
            column: col,
            snippet,
          });
          return;
        }
      }
      const root = ast.rootName(left);
      if (root) {
        if (right.type === 'CallExpression' && isSanitizerCall(right, sanList)) {
          currentScope.clearTaint(root);
          return;
        }
        if (exprIsSource(right)) {
          currentScope.setTaint(root, { via: 'source', sanitized: false });
          return;
        }
        const taintInfo = exprTaintInfo(right, currentScope);
        if (taintInfo) {
          currentScope.setTaint(root, { via: taintInfo.via, sanitized: taintInfo.sanitized });
        }
      }
    }
  }

  function handleCall(call) {

    // Check if an expression tree contains a PII-specific source.
    // Only fires for req.body.<pii_field> or whole-object sources like
    // JSON.stringify(req.body) or JSON.stringify(userProfile).
    function containsPiiSource(node, piiFields) {
      if (!node || typeof node !== 'object') return false;
      // Direct source: req.body (whole object), JSON.stringify(req.body)
      if (isSourceNode(node)) {
        // Check if it's a whole-object source (req.body, not req.body.q)
        if (node.type === 'MemberExpression') {
          const prop = node.property && node.property.name;
          if (prop === 'body' || prop === 'query' || prop === 'params') return true;
          // Check if the property name is a PII field
          if (piiFields.includes(prop)) return true;
        }
        // NewExpression (new URLSearchParams) — not PII
        if (node.type === 'NewExpression') return false;
        return false;
      }
      // Recurse into children
      for (const key in node) {
        if (key === 'type' || key === 'loc' || key === 'start' || key === 'end' || key === 'range') continue;
        const child = node[key];
        if (Array.isArray(child)) {
          for (const c of child) {
            if (containsPiiSource(c, piiFields)) return true;
          }
        } else if (child && typeof child === 'object' && child.type) {
          if (containsPiiSource(child, piiFields)) return true;
        }
      }
      return false;
    }

    // Check each sink.
    for (const sinkDef of SINKS_AST) {
      if (!sinkDef.match(call)) continue;
      // Determine which arguments to check.
      // For execFile/spawn: only arg[0] (command) — args array (arg[1]) is safe.
      // For query/execute/raw: only arg[0] (SQL string) — params array (arg[1]) is safe.
      const name = ast.calleeName(call);
      const isFirstArgOnly = /(?:^|\.)(?:execFile|execFileSync|spawn|spawnSync)$/.test(name) ||
        (sinkDef.ruleId === 'taint.sql-injection');
      const argsToCheck = isFirstArgOnly ? (call.arguments || []).slice(0, 1) : (call.arguments || []);

      for (const arg of argsToCheck) {
        // Skip if the argument itself is a source — regex rules handle that.
        // BUT: for PII-to-LLM and XSS-reflected sinks, the source may be nested
        // deep inside an object (e.g. { messages: [{ content: req.body.x }] })
        // and regex rules don't catch that — so don't skip for those sinks.
        if (sinkDef.ruleId !== 'taint.pii-to-llm' && sinkDef.ruleId !== 'taint.xss-reflected' && exprIsSource(arg)) continue;

        // For PII-to-LLM: only fire if the tainted value is a whole-object source
        // (req.body, JSON.stringify(userProfile)) or a PII-specific field.
        // Generic fields like req.body.q (user's question) are NOT PII.
        if (sinkDef.ruleId === 'taint.pii-to-llm') {
          const PII_FIELDS = ['email', 'phone', 'ssn', 'address', 'dob', 'name', 'password', 'creditCard', 'medicalHistory', 'healthData', 'patient', 'medical', 'biometric', 'profile', 'userProfile', 'userData'];
          // Check if the arg contains a PII-specific source
          if (!containsPiiSource(arg, PII_FIELDS)) continue;
        }

        let taintInfo = exprTaintInfo(arg, currentScope);
        if (!taintInfo) {
          // Also check: is the arg a call to a function whose param reaches a sink,
          // and is the call's argument tainted? (cross-function, return-value taint)
          // This is handled by the call-site cross-function check below.
          continue;
        }

        // If the tainted value was sanitized, skip.
        if (taintInfo.sanitized) continue;

        const loc = call.loc && call.loc.start;
        const line = loc ? loc.line : 1;
        const col = loc ? loc.column + 1 : 1;
        const snippet = lines[line - 1] ? lines[line - 1].trim().slice(0, 120) : '';

        findings.push({
          ruleId: sinkDef.ruleId,
          severity: sinkDef.severity,
          confidence: 'high',
          dataflow: true,
          title: sinkDef.title,
          message: `${sinkDef.message} (tainted via \`${taintInfo.via}\`)`,
          fix: sinkDef.fix,
          file: relPath,
          line,
          column: col,
          snippet,
        });
        break; // one finding per sink call
      }
    }

    // Cross-function taint: if we call a function whose param reaches a sink,
    // and the argument we pass is tainted, emit a finding.
    const calleeName = call.callee && call.callee.type === 'Identifier' ? call.callee.name : '';
    const sinkInfo = funcSinkInfo.get(calleeName);
    if (sinkInfo) {
      for (const { paramIndex, sinkDef, node: sinkNode } of sinkInfo) {
        const arg = (call.arguments || [])[paramIndex];
        if (!arg) continue;
        if (exprIsSource(arg)) {
          // Direct source -> function -> sink. This is already caught by interprocedural in ast.js,
          // but we also catch it here for the taint.* rule IDs.
          const loc = call.loc && call.loc.start;
          const line = loc ? loc.line : 1;
          const col = loc ? loc.column + 1 : 1;
          const snippet = lines[line - 1] ? lines[line - 1].trim().slice(0, 120) : '';
          findings.push({
            ruleId: sinkDef.ruleId,
            severity: sinkDef.severity,
            confidence: 'high',
            dataflow: true,
            title: sinkDef.title,
            message: `${sinkDef.message} (tainted via \`${calleeName}() param ${paramIndex + 1}\`)`,
            fix: sinkDef.fix,
            file: relPath,
            line,
            column: col,
            snippet,
          });
          continue;
        }
        const taintInfo = exprTaintInfo(arg, currentScope);
        if (taintInfo && !taintInfo.sanitized) {
          const loc = call.loc && call.loc.start;
          const line = loc ? loc.line : 1;
          const col = loc ? loc.column + 1 : 1;
          const snippet = lines[line - 1] ? lines[line - 1].trim().slice(0, 120) : '';
          findings.push({
            ruleId: sinkDef.ruleId,
            severity: sinkDef.severity,
            confidence: 'high',
            dataflow: true,
            title: sinkDef.title,
            message: `${sinkDef.message} (tainted via \`${taintInfo.via}\` -> \`${calleeName}()\`)`,
            fix: sinkDef.fix,
            file: relPath,
            line,
            column: col,
            snippet,
          });
        }
      }
    }

    // Sanitizer awareness: if a tainted value is passed through a sanitizer,
    // and the result is assigned to a variable, the variable is clean.
    // This is handled in handleDeclarator/handleAssignment, but we also need
    // to handle the case where the sanitizer result is used inline.
    // (No action needed here — exprTaintInfo already checks for sanitizer calls.)
  }

  // Collect all identifier names referenced in a subtree.
  function collectAllRefs(node, out) {
    out = out || new Set();
    if (!node || typeof node !== 'object') return out;
    if (node.type === 'Identifier') {
      out.add(node.name);
      return out;
    }
    if (node.type === 'MemberExpression') {
      const r = ast.rootName(node);
      if (r) out.add(r);
      return out;
    }
    for (const key in node) {
      if (key === 'type' || key === 'loc' || key === 'start' || key === 'end' || key === 'range') continue;
      const child = node[key];
      if (Array.isArray(child)) {
        child.forEach((c) => collectAllRefs(c, out));
      } else if (child && typeof child === 'object' && child.type) {
        collectAllRefs(child, out);
      }
    }
    return out;
  }

  // Start the walk.
  visit(tree);

  // Deduplicate findings (same ruleId+file+line+column).
  const seen = new Set();
  return findings.filter((f) => {
    const key = `${f.ruleId}:${f.file}:${f.line}:${f.column}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

module.exports = { analyzeTaintAst, DEFAULT_SANITIZERS, SINKS_AST, isSourceNode, isSanitizerCall, TaintScope, bindingNames, exprTaintInfo, exprIsSource, isScopeNode };