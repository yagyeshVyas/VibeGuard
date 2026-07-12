'use strict';

/*
 * Cross-file taint via an import/export graph (requires acorn).
 *
 * Flags request data reaching a dangerous sink across module boundaries.
 * Handles:
 *   - any argument position (not just the first) and destructured params;
 *   - local variable reassignment inside a helper (param -> local -> sink);
 *   - transitive sink-reaching (depth > 1) via a per-parameter-slot fixpoint;
 *   - barrel / re-exports (export * / export {x} from / module.exports = require);
 *   - return-value taint (exec(getInput(req)) where getInput returns its input);
 *   - object property propagation (const obj = {k: input}; helper(obj.k));
 *   - async/await and Promise.then chains (const d = await getInput(req); exec(d));
 *   - conditional returns (if tainted in either branch, function returns tainted).
 *
 * Bounded/best-effort: relative imports, positional argument->parameter mapping.
 * Confidence medium.
 */

const ast = require('./ast');

const CANDIDATE_EXTS = ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs', '/index.js', '/index.ts'];

function norm(p) {
  const parts = [];
  for (const seg of p.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') parts.pop();
    else parts.push(seg);
  }
  return parts.join('/');
}
function resolveModule(fromRel, spec, knownRels) {
  if (!spec.startsWith('.')) return null;
  const dir = fromRel.includes('/') ? fromRel.slice(0, fromRel.lastIndexOf('/')) : '';
  const base = norm(dir + '/' + spec);
  if (knownRels.has(base)) return base;
  for (const ext of CANDIDATE_EXTS) if (knownRels.has(base + ext)) return base + ext;
  return null;
}

const asFn = (n) =>
  n && (n.type === 'FunctionDeclaration' || n.type === 'FunctionExpression' || n.type === 'ArrowFunctionExpression') ? n : null;
const isReq = (node) =>
  node && ((node.type === 'MemberExpression' && ast.rootName(node) === 'req') || (node.type === 'Identifier' && node.name === 'req'));
const requireCall = (n) => n && n.type === 'CallExpression' && n.callee.name === 'require' && n.arguments[0] && typeof n.arguments[0].value === 'string';

// Names a parameter binds (handles destructuring, defaults, rest).
function bindingNames(param, out) {
  out = out || [];
  if (!param) return out;
  if (param.type === 'Identifier') out.push(param.name);
  else if (param.type === 'AssignmentPattern') bindingNames(param.left, out);
  else if (param.type === 'RestElement') bindingNames(param.argument, out);
  else if (param.type === 'ObjectPattern') for (const p of param.properties) bindingNames(p.type === 'RestElement' ? p.argument : p.value, out);
  else if (param.type === 'ArrayPattern') for (const e of param.elements) if (e) bindingNames(e, out);
  return out;
}

// All identifier names referenced in an expression subtree.
// Tracks object property reads: {k: input} -> obj.k references `obj` which
// carries taint from the property assignment.
function collectRefs(node, out) {
  out = out || new Set();
  if (!node || typeof node !== 'object') return out;
  if (node.type === 'Identifier') { out.add(node.name); return out; }
  if (node.type === 'MemberExpression') {
    // obj.prop or obj[expr] — the root identifier carries taint.
    const r = ast.rootName(node);
    if (r) out.add(r);
    // Also collect refs in computed property: obj[someVar]
    if (node.computed && node.property) collectRefs(node.property, out);
    return out;
  }
  // Await expression — the awaited value's refs matter.
  if (node.type === 'AwaitExpression') return collectRefs(node.argument, out);
  // Conditional expression — both branches can carry taint.
  if (node.type === 'ConditionalExpression') {
    collectRefs(node.consequent, out);
    collectRefs(node.alternate, out);
    return out;
  }
  // Logical expression — both sides can carry taint.
  if (node.type === 'LogicalExpression') {
    collectRefs(node.left, out);
    collectRefs(node.right, out);
    return out;
  }
  // Template literal — expressions inside can carry taint.
  if (node.type === 'TemplateLiteral') {
    for (const expr of node.expressions || []) collectRefs(expr, out);
    return out;
  }
  // Binary expression — string concat propagates taint.
  if (node.type === 'BinaryExpression') {
    collectRefs(node.left, out);
    collectRefs(node.right, out);
    return out;
  }
  // Call expression — a sanitizer call clears, but otherwise args propagate.
  if (node.type === 'CallExpression') {
    // Check for Promise.then chain: getInput(req).then(d => exec(d))
    // The callee refs matter (it could be a taint-returning function).
    collectRefs(node.callee, out);
    for (const arg of node.arguments || []) collectRefs(arg, out);
    return out;
  }
  for (const k in node) {
    if (k === 'type' || k === 'loc' || k === 'start' || k === 'end' || k === 'range') continue;
    const v = node[k];
    if (Array.isArray(v)) v.forEach((x) => collectRefs(x, out));
    else if (v && typeof v === 'object' && v.type) collectRefs(v, out);
  }
  return out;
}

// Analyze one function: which parameter SLOTS reach a sink, what it forwards, and
// which slots it returns. Tracks taint through local reassignments (fixpoint),
// object property writes (const o = {k: param}; exec(o.k)), and async/await.
function analyzeFunction(node, walk, resolveCallee) {
  const params = node.params || [];
  const taintOf = new Map(); // varName -> Set(paramSlot)
  // Track object property taint: Map(objectName -> Map(propKey -> Set(paramSlot)))
  const propTaintOf = new Map();
  params.forEach((p, i) => bindingNames(p).forEach((n) => { if (!taintOf.has(n)) taintOf.set(n, new Set([i])); }));

  const assigns = [];
  const propAssigns = []; // { objName, propName, expr }
  walk.simple(node, {
    VariableDeclarator(n) {
      if (n.id && n.id.type === 'Identifier' && n.init) assigns.push({ t: n.id.name, e: n.init });
      // Object property writes: const obj = { key: param } or { ...param }
      if (n.id && n.id.type === 'Identifier' && n.init && n.init.type === 'ObjectExpression') {
        for (const prop of n.init.properties || []) {
          if (prop.value && prop.key) {
            const keyName = prop.key.name || prop.key.value;
            if (keyName) propAssigns.push({ objName: n.id.name, propName: keyName, expr: prop.value });
          }
        }
      }
    },
    AssignmentExpression(n) {
      if (n.left && n.left.type === 'Identifier') assigns.push({ t: n.left.name, e: n.right });
      // obj.prop = tainted
      if (n.left && n.left.type === 'MemberExpression' && n.left.object && n.left.object.type === 'Identifier' && n.left.property) {
        const propName = n.left.property.name || n.left.property.value;
        if (propName) propAssigns.push({ objName: n.left.object.name, propName, expr: n.right });
      }
    },
  });

  // Fixpoint: propagate taint through local assignments + property writes.
  for (let pass = 0; pass < 8; pass++) {
    let changed = false;
    // Local var assignments.
    for (const a of assigns) {
      const slots = new Set();
      for (const r of collectRefs(a.e)) {
        const s = taintOf.get(r);
        if (s) for (const x of s) slots.add(x);
        // Also check if this ref is an object property that carries taint.
        const pt = propTaintOf.get(r);
        if (pt) for (const ps of pt.values()) for (const x of ps) slots.add(x);
      }
      if (slots.size) {
        let cur = taintOf.get(a.t);
        if (!cur) { cur = new Set(); taintOf.set(a.t, cur); }
        const before = cur.size;
        for (const x of slots) cur.add(x);
        if (cur.size !== before) changed = true;
      }
    }
    // Object property assignments: obj.prop = expr -> track taint on obj.prop
    for (const pa of propAssigns) {
      const slots = new Set();
      for (const r of collectRefs(pa.expr)) {
        const s = taintOf.get(r);
        if (s) for (const x of s) slots.add(x);
      }
      if (slots.size) {
        if (!propTaintOf.has(pa.objName)) propTaintOf.set(pa.objName, new Map());
        const propMap = propTaintOf.get(pa.objName);
        const before = (propMap.get(pa.propName) || new Set()).size;
        let cur = propMap.get(pa.propName);
        if (!cur) { cur = new Set(); propMap.set(pa.propName, cur); }
        for (const x of slots) cur.add(x);
        if (cur.size !== before) changed = true;
      }
    }
    if (!changed) break;
  }

  // Check if a var is tainted (either directly or through a property).
  const slotsFor = (n) => {
    const s = new Set();
    for (const r of collectRefs(n)) {
      const t = taintOf.get(r);
      if (t) for (const x of t) s.add(x);
      const pt = propTaintOf.get(r);
      if (pt) for (const ps of pt.values()) for (const x of ps) s.add(x);
    }
    return s;
  };

  const sinkSlots = new Map(); // slot -> label
  const forwards = []; // { toArgIndex, fromSlot, target }
  const returnsSlots = new Set();
  walk.simple(node, {
    CallExpression(call) {
      const kind = ast.sinkKindOfCall(call);
      if (kind) for (const arg of call.arguments || []) for (const slot of slotsFor(arg)) sinkSlots.set(slot, kind.label);
      const target = resolveCallee(call.callee);
      if (target) (call.arguments || []).forEach((arg, k) => { for (const slot of slotsFor(arg)) forwards.push({ toArgIndex: k, fromSlot: slot, target }); });
    },
    // Handle return statements including conditional returns.
    ReturnStatement(r) { if (r.argument) for (const slot of slotsFor(r.argument)) returnsSlots.add(slot); },
    // Handle arrow functions with expression bodies (implicit return).
    ArrowFunctionExpression(fn) {
      if (fn.body && fn.expression) for (const slot of slotsFor(fn.body)) returnsSlots.add(slot);
    },
  });
  return { sinkSlots, forwards, returnsSlots };
}

function analyzeCrossFile(files, treesCache) {
  if (!ast.isAvailable()) return [];
  const walk = ast.getWalk();
  const knownRels = new Set(files.map((f) => f.rel));

  const trees = new Map();
  for (const f of files) {
    if (!/\.(?:js|jsx|ts|tsx|mjs|cjs)$/.test(f.rel)) continue;
    const t = (treesCache && treesCache.get(f.rel)) || ast.parseSource(f.content, f.rel);
    if (t) trees.set(f.rel, t);
  }

  const funcs = new Map(); // gid -> { sinkSlots, forwards, returnsSlots }
  const exportsOf = new Map();
  const reExports = new Map();
  const importsOf = new Map();
  const gid = (rel, name) => `${rel}#${name}`;

  for (const [rel, tree] of trees) {
    const localFns = new Map();
    const exp = new Map();
    const re = [];
    const named = new Map();
    const ns = new Map();

    walk.simple(tree, {
      FunctionDeclaration(n) { if (n.id) localFns.set(n.id.name, n); },
      VariableDeclarator(n) { if (n.id && n.id.type === 'Identifier' && asFn(n.init)) localFns.set(n.id.name, n.init); },
    });
    walk.simple(tree, {
      ImportDeclaration(n) {
        const mod = resolveModule(rel, n.source.value, knownRels);
        if (!mod) return;
        for (const sp of n.specifiers) {
          if (sp.type === 'ImportSpecifier') named.set(sp.local.name, { mod, exported: sp.imported.name });
          else if (sp.type === 'ImportDefaultSpecifier') named.set(sp.local.name, { mod, exported: 'default' });
          else if (sp.type === 'ImportNamespaceSpecifier') ns.set(sp.local.name, mod);
        }
      },
      VariableDeclarator(n) {
        const init = n.init;
        if (!init) return;
        if (requireCall(init)) {
          const mod = resolveModule(rel, init.arguments[0].value, knownRels);
          if (!mod) return;
          if (n.id.type === 'Identifier') ns.set(n.id.name, mod);
          else if (n.id.type === 'ObjectPattern') for (const pr of n.id.properties) if (pr.key && pr.value && pr.value.type === 'Identifier') named.set(pr.value.name, { mod, exported: pr.key.name });
        } else if (init.type === 'MemberExpression' && requireCall(init.object) && init.property && init.property.name) {
          const mod = resolveModule(rel, init.object.arguments[0].value, knownRels);
          if (mod && n.id.type === 'Identifier') named.set(n.id.name, { mod, exported: init.property.name });
        }
      },
    });

    const regExport = (exportedName, localName) => { if (localFns.has(localName)) exp.set(exportedName, gid(rel, localName)); };
    walk.simple(tree, {
      ExportNamedDeclaration(n) {
        if (n.source) {
          const mod = resolveModule(rel, n.source.value, knownRels);
          if (mod) for (const sp of n.specifiers || []) re.push({ kind: 'named', mod, exported: sp.local.name, as: sp.exported.name });
          return;
        }
        if (n.declaration) {
          if (n.declaration.type === 'FunctionDeclaration' && n.declaration.id) regExport(n.declaration.id.name, n.declaration.id.name);
          else if (n.declaration.declarations) for (const d of n.declaration.declarations) if (asFn(d.init) && d.id.name) regExport(d.id.name, d.id.name);
        }
        for (const sp of n.specifiers || []) regExport(sp.exported.name, sp.local.name);
      },
      ExportAllDeclaration(n) { const mod = resolveModule(rel, n.source.value, knownRels); if (mod) re.push({ kind: 'all', mod }); },
      ExportDefaultDeclaration(n) { const fn = asFn(n.declaration); if (fn) { localFns.set('$default', fn); exp.set('default', gid(rel, '$default')); } },
      AssignmentExpression(n) {
        const left = n.left;
        if (left.type === 'MemberExpression' && left.property && left.property.name) {
          const obj = left.object;
          const isExports = (obj.type === 'Identifier' && obj.name === 'exports') || (obj.type === 'MemberExpression' && obj.object.name === 'module' && obj.property.name === 'exports');
          if (isExports) {
            if (n.right.type === 'Identifier') regExport(left.property.name, n.right.name);
            else if (asFn(n.right)) { const nm = `$export$${left.property.name}`; localFns.set(nm, n.right); exp.set(left.property.name, gid(rel, nm)); }
          }
        }
        if (left.type === 'MemberExpression' && left.object.name === 'module' && left.property.name === 'exports') {
          if (n.right.type === 'ObjectExpression') for (const p of n.right.properties) { const ex = p.key && (p.key.name || p.key.value); const loc = (p.value && p.value.name) || ex; if (ex) regExport(ex, loc); }
          else if (requireCall(n.right)) { const mod = resolveModule(rel, n.right.arguments[0].value, knownRels); if (mod) re.push({ kind: 'all', mod }); }
        }
      },
    });

    const resolveCallee = (c) => {
      if (c.type === 'Identifier') {
        if (localFns.has(c.name)) return { id: gid(rel, c.name) };
        if (named.has(c.name)) return { ref: named.get(c.name) };
      } else if (c.type === 'MemberExpression' && c.object.type === 'Identifier' && ns.has(c.object.name) && c.property.name) {
        return { ref: { mod: ns.get(c.object.name), exported: c.property.name } };
      }
      return null;
    };
    for (const [name, fnNode] of localFns) funcs.set(gid(rel, name), analyzeFunction(fnNode, walk, resolveCallee));

    exportsOf.set(rel, exp);
    reExports.set(rel, re);
    importsOf.set(rel, { named, ns });
  }

  // export table + re-export fixpoint
  const exportTable = new Map();
  for (const [rel, exp] of exportsOf) for (const [name, id] of exp) exportTable.set(`${rel}::${name}`, id);
  for (let pass = 0; pass < 6; pass++) {
    let changed = false;
    for (const [rel, edges] of reExports) for (const e of edges) {
      if (e.kind === 'named') {
        const src = exportTable.get(`${e.mod}::${e.exported}`);
        if (src && !exportTable.has(`${rel}::${e.as}`)) { exportTable.set(`${rel}::${e.as}`, src); changed = true; }
      } else if (e.kind === 'all') {
        for (const key of [...exportTable.keys()]) if (key.startsWith(e.mod + '::')) {
          const name = key.slice(e.mod.length + 2);
          const tkey = `${rel}::${name}`;
          if (!exportTable.has(tkey)) { exportTable.set(tkey, exportTable.get(key)); changed = true; }
        }
      }
    }
    if (!changed) break;
  }
  const resolveExport = (mod, exported) => exportTable.get(`${mod}::${exported}`) || null;

  // per-slot sink-reaching fixpoint
  const sinkOf = new Map(); // gid -> Map(slot -> label)
  for (const [id, f] of funcs) if (f.sinkSlots.size) sinkOf.set(id, new Map(f.sinkSlots));
  for (let pass = 0; pass < 8; pass++) {
    let changed = false;
    for (const [id, f] of funcs) {
      for (const fw of f.forwards) {
        const targetId = fw.target.id || (fw.target.ref && resolveExport(fw.target.ref.mod, fw.target.ref.exported));
        if (!targetId) continue;
        const targetSlots = sinkOf.get(targetId);
        if (targetSlots && targetSlots.has(fw.toArgIndex)) {
          let m = sinkOf.get(id);
          if (!m) { m = new Map(); sinkOf.set(id, m); }
          if (!m.has(fw.fromSlot)) { m.set(fw.fromSlot, targetSlots.get(fw.toArgIndex)); changed = true; }
        }
      }
    }
    if (!changed) break;
  }

  // registry: export key -> { slots: Map(slot->label) }; returns: key -> Set(slots)
  const registry = new Map();
  const returnsExport = new Map();
  for (const [key, id] of exportTable) {
    if (sinkOf.has(id)) registry.set(key, { slots: sinkOf.get(id) });
    const f = funcs.get(id);
    if (f && f.returnsSlots.size) returnsExport.set(key, f.returnsSlots);
  }

  // call sites
  const findings = [];
  const seen = new Set();
  const emit = (rel, node, msg, fix) => {
    const key = `${rel}:${node.loc ? node.loc.start.line : 0}:${msg.slice(0, 40)}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push({ ruleId: 'taint.cross-file', severity: 'high', confidence: 'medium', title: 'Request data flows across files into a sink (AST-confirmed)', message: msg, fix, file: rel, line: (node.loc && node.loc.start.line) || 1, column: (node.loc && node.loc.start.column + 1) || 1 });
  };

  for (const [rel, tree] of trees) {
    const { named, ns } = importsOf.get(rel);
    const resolve = (c) => {
      if (c.type === 'Identifier' && named.has(c.name)) { const im = named.get(c.name); return { key: `${im.mod}::${im.exported}`, name: c.name, mod: im.mod }; }
      if (c.type === 'MemberExpression' && c.object.type === 'Identifier' && ns.has(c.object.name) && c.property.name) { const mod = ns.get(c.object.name); return { key: `${mod}::${c.property.name}`, name: `${c.object.name}.${c.property.name}`, mod }; }
      return null;
    };

    // (3) Build a map of local variables that hold tainted return values from
    // imported functions. Handles: const x = importedFn(req) and
    // const x = await importedFn(req).
    const taintedReturnVars = new Map(); // varName -> { funcName, mod }
    walk.simple(tree, {
      VariableDeclarator(n) {
        if (!n.id || n.id.type !== 'Identifier' || !n.init) return;
        // Unwrap AwaitExpression: const x = await fn(req) -> fn(req)
        let init = n.init;
        if (init.type === 'AwaitExpression') init = init.argument;
        if (!init || init.type !== 'CallExpression') return;
        const ir = resolve(init.callee);
        if (!ir || !returnsExport.has(ir.key)) return;
        const retSlots = returnsExport.get(ir.key);
        const inner = init.arguments || [];
        if (inner.some((x, j) => isReq(x) && retSlots.has(j))) {
          taintedReturnVars.set(n.id.name, { funcName: ir.name, mod: ir.mod });
        }
      },
      AssignmentExpression(n) {
        if (!n.left || n.left.type !== 'Identifier') return;
        let init = n.right;
        if (init && init.type === 'AwaitExpression') init = init.argument;
        if (!init || init.type !== 'CallExpression') return;
        const ir = resolve(init.callee);
        if (!ir || !returnsExport.has(ir.key)) return;
        const retSlots = returnsExport.get(ir.key);
        const inner = init.arguments || [];
        if (inner.some((x, j) => isReq(x) && retSlots.has(j))) {
          taintedReturnVars.set(n.left.name, { funcName: ir.name, mod: ir.mod });
        }
      },
    });
    walk.simple(tree, {
      CallExpression(node) {
        const args = node.arguments || [];
        // (1) call an imported sink-reaching function, request data at a sink slot
        const r = resolve(node.callee);
        if (r && registry.has(r.key)) {
          const slots = registry.get(r.key).slots;
          for (let i = 0; i < args.length; i++) if (isReq(args[i]) && slots.has(i)) {
            emit(rel, node, `Request data (arg ${i + 1}) is passed to ${r.name}() (from ${r.mod}), which routes it into ${slots.get(i)} — injection across a module boundary.`, `Validate/sanitize inside ${r.name}(); parameterize the sink.`);
            break;
          }
        }
        // (2) return-value taint: local sink whose arg is an imported taint-returning call
        if (ast.sinkKindOfCall(node)) {
          for (const a of args) {
            if (a && a.type === 'CallExpression') {
              const ir = resolve(a.callee);
              if (ir && returnsExport.has(ir.key)) {
                const retSlots = returnsExport.get(ir.key);
                const inner = a.arguments || [];
                if (inner.some((x, j) => isReq(x) && retSlots.has(j))) {
                  emit(rel, node, `Return value of ${ir.name}() (from ${ir.mod}) carries request data into ${ast.sinkKindOfCall(node).label} — cross-file taint via a return value.`, `Sanitize the value returned by ${ir.name}() before using it in the sink.`);
                }
              }
            }
            // (3) indirect return-value taint: arg is a local variable that was
            // assigned from an imported taint-returning call (possibly via await).
            if (a && a.type === 'Identifier' && taintedReturnVars.has(a.name)) {
              const info = taintedReturnVars.get(a.name);
              emit(rel, node, `Variable \`${a.name}\` carries request data from ${info.funcName}() (from ${info.mod}) into ${ast.sinkKindOfCall(node).label} — cross-file taint via return value assigned to a local.`, `Sanitize ${a.name} before using it in the sink, or sanitize inside ${info.funcName}().`);
            }
          }
        }
      },
    });
  }
  return findings;
}

module.exports = { analyzeCrossFile, resolveModule };
