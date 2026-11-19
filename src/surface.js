'use strict';

/*
 * Attack-surface merge: entrypoints × findings × reachability.
 *
 * Every other scanner reports a flat list of "issues". The question a developer
 * or an AI agent actually needs answered is narrower: which of these can be hit
 * from outside, on which endpoint, with what access, and is the data flow real?
 *
 * This module joins three facts that normally live apart:
 *   1. entrypoints (src/routes.js): route/action/RPC + guards + handler scope
 *   2. findings: what the analyzers fired
 *   3. import reachability: is the flagged file even loaded by that entrypoint
 *
 * Output: per-endpoint risk with direct (in-handler) vs inherited (imported)
 * findings, plus an `exposed` list of endpoints that are reachable today.
 */

const path = require('path');

const SEV_WEIGHT = { critical: 40, high: 20, medium: 8, low: 2 };
const CONF_FACTOR = { high: 1, medium: 0.7, low: 0.4 };

// Which analyzer findings count as "the flow is real" (not a regex hint).
const DATAFLOW_PREFIXES = ['taint.', 'ast.', 'crosstaint', 'authz2026.', 'llm2026.', 'api2026.', 'obf.'];

// ---------------------------------------------------------------------------
// Import graph
// ---------------------------------------------------------------------------

const EXTS = ['', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '/index.js', '/index.ts', '/index.tsx'];

function resolveSpec(fromRel, spec, known) {
  if (!spec || !/^\.{1,2}\//.test(spec)) return null;
  const dir = fromRel.includes('/') ? fromRel.slice(0, fromRel.lastIndexOf('/')) : '';
  const base = path.posix.normalize(`${dir}/${spec}`).replace(/^\/+/, '');
  for (const ext of EXTS) {
    const cand = `${base}${ext}`;
    if (known.has(cand)) return cand;
  }
  return null;
}

function buildImportGraph(files) {
  const known = new Set(files.map((f) => f.rel));
  const graph = new Map(); // rel -> [rel]
  const specs = new Map(); // rel -> [raw specifiers]
  for (const f of files) {
    const deps = [];
    const raw = [];
    const patterns = [
      /\bimport\s+[^;'"]*from\s*['"]([^'"]+)['"]/g,
      /\bimport\s*['"]([^'"]+)['"]/g,
      /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
      /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    ];
    for (const re of patterns) {
      let m;
      while ((m = re.exec(f.content)) !== null) {
        raw.push(m[1]);
        const resolved = resolveSpec(f.rel, m[1], known);
        if (resolved && !deps.includes(resolved)) deps.push(resolved);
      }
    }
    graph.set(f.rel, deps);
    specs.set(f.rel, raw);
  }
  return { graph, specs };
}

// BFS: every file a given entrypoint file (transitively) loads.
function reachableFrom(startRel, graph) {
  const seen = new Set([startRel]);
  const queue = [startRel];
  while (queue.length) {
    const cur = queue.shift();
    for (const dep of graph.get(cur) || []) {
      if (seen.has(dep)) continue;
      seen.add(dep);
      queue.push(dep);
    }
  }
  return seen;
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

function findingReach(finding, entrypoints, reachSets) {
  // Direct: the finding sits inside a handler body. For Express-style routes the
  // handler may live in another file (resolved body), so check bodyFile first.
  for (const e of entrypoints) {
    if (e.bodyFile === finding.file && finding.line >= e.startLine && finding.line <= e.endLine) {
      return { kind: 'direct', entrypoint: e };
    }
    if (e.file === finding.file && e.bodyFile !== e.file && finding.line >= e.line && finding.line <= e.line + 20) {
      // Findings on the registration line itself (e.g. secrets in middleware args).
      return { kind: 'direct', entrypoint: e };
    }
    if (e.file === finding.file && e.bodyFile === e.file && finding.line >= e.startLine && finding.line <= e.endLine) {
      return { kind: 'direct', entrypoint: e };
    }
  }
  // Loaded-by: the finding's file is imported (transitively) by an entrypoint.
  for (const e of entrypoints) {
    const set = reachSets.get(e.file);
    if (set && set.has(finding.file)) return { kind: 'imported', entrypoint: e };
    if (e.bodyFile && e.bodyFile !== e.file) {
      const bodySet = reachSets.get(e.bodyFile);
      if (bodySet && bodySet.has(finding.file)) return { kind: 'imported', entrypoint: e };
    }
  }
  return { kind: 'dead', entrypoint: null };
}

function exposureMultiplier(entry, reachKind) {
  if (reachKind === 'dead') return 0.25;
  const open = entry && entry.auth === 'none';
  if (reachKind === 'direct') {
    if (open && entry.stateChanging) return 3;
    if (open) return 2;
    return 1.3;
  }
  return open ? 1.1 : 0.8;
}

function riskScore(finding, entry, reachKind) {
  const base = SEV_WEIGHT[finding.severity] || 1;
  const conf = CONF_FACTOR[finding.confidence] ?? 0.5;
  const dataflow = DATAFLOW_PREFIXES.some((p) => String(finding.ruleId || '').startsWith(p));
  const df = dataflow ? 1.25 : 1;
  return Math.round(base * conf * exposureMultiplier(entry, reachKind) * df);
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

function buildSurface({ files, findings }) {
  const { extractEntrypoints } = require('./routes');
  const { entrypoints, authCoverage, middleware } = extractEntrypoints(files);
  const { graph } = buildImportGraph(files);

  const reachSets = new Map();
  for (const e of entrypoints) {
    if (!reachSets.has(e.file)) reachSets.set(e.file, reachableFrom(e.file, graph));
  }

  // Attach findings to endpoints.
  const endpointById = new Map();
  for (const e of entrypoints) {
    endpointById.set(e.id, {
      id: e.id,
      kind: e.kind,
      framework: e.framework,
      method: e.method,
      path: e.path,
      file: e.file,
      line: e.line,
      bodyFile: e.bodyFile,
      startLine: e.startLine,
      endLine: e.endLine,
      auth: e.auth,
      guards: e.guards,
      ownership: e.ownership,
      stateChanging: e.stateChanging,
      writes: e.writes,
      readsObjectId: e.readsObjectId,
      sensitive: e.sensitive,
      rateLimited: e.rateLimited,
      score: 0,
      verdict: 'review',
      risks: [],
    });
    if (e.ownership === 'missing') endpointById.get(e.id).score += 25; // IDOR base weight
  }

  // Reachability index per finding (memoized by file for non-direct lookups).
  const fileEntryMap = new Map();
  for (const e of entrypoints) {
    if (!fileEntryMap.has(e.file)) fileEntryMap.set(e.file, []);
    fileEntryMap.get(e.file).push(e);
  }

  for (const f of findings) {
    const reach = findingReach(f, entrypoints, reachSets);
    f.surface = { reach: reach.kind };
    if (reach.kind === 'dead') continue;
    const ep = endpointById.get(reach.entrypoint.id);
    if (!ep) continue;
    const score = riskScore(f, reach.entrypoint, reach.kind);
    ep.score += score;
    ep.risks.push({
      ruleId: f.ruleId,
      severity: f.severity,
      confidence: f.confidence,
      title: f.title,
      file: f.file,
      line: f.line,
      reach: reach.kind,
      score,
    });
  }

  // Verdicts: open write/IDOR first, then anything with critical/high risk.
  const endpoints = [...endpointById.values()].map((ep) => {
    const directCritical = ep.risks.some((r) => r.severity === 'critical' && r.reach === 'direct');
    const directHigh = ep.risks.some((r) => r.severity === 'high' && r.reach === 'direct');
    const importedOnly = ep.risks.length > 0 && ep.risks.every((r) => r.reach === 'imported');
    let verdict = 'clean';
    if (ep.ownership === 'missing') verdict = 'critical'; // IDOR needs no finding to be a bug
    else if (ep.risks.length === 0) verdict = ep.auth === 'none' && ep.stateChanging ? 'unguarded' : 'clean';
    else if (directCritical || (ep.auth === 'none' && ep.stateChanging)) verdict = 'critical';
    else if (directHigh) verdict = 'high';
    else if (importedOnly && ep.auth === 'unknown') verdict = 'review';
    else verdict = 'review';
    return { ...ep, verdict, risks: ep.risks.sort((a, b) => b.score - a.score) };
  });
  endpoints.sort((a, b) => b.score - a.score || a.file.localeCompare(b.file));

  const exposed = endpoints.filter(
    (e) => e.verdict !== 'clean' && (e.auth === 'none' || e.ownership === 'missing' || e.risks.length > 0)
  );

  // Category rollup helps the CLI and an agent decide where to start.
  const byRule = {};
  for (const ep of endpoints) {
    for (const r of ep.risks) {
      byRule[r.ruleId] = byRule[r.ruleId] || { count: 0, endpoints: 0, maxScore: 0, severity: r.severity };
      byRule[r.ruleId].count++;
      byRule[r.ruleId].maxScore = Math.max(byRule[r.ruleId].maxScore, r.score);
    }
  }
  for (const ruleId of Object.keys(byRule)) {
    byRule[ruleId].endpoints = endpoints.filter((ep) => ep.risks.some((r) => r.ruleId === ruleId)).length;
  }

  const stats = {
    entrypoints: endpoints.length,
    byFramework: endpoints.reduce((acc, e) => ((acc[e.framework] = (acc[e.framework] || 0) + 1), acc), {}),
    unguarded: endpoints.filter((e) => e.auth === 'none').length,
    unknownAuth: endpoints.filter((e) => e.auth === 'unknown').length,
    unguardedStateChanging: endpoints.filter((e) => e.auth === 'none' && e.stateChanging).length,
    idorCandidates: endpoints.filter((e) => e.ownership === 'missing').length,
    endpointsWithDirectRisk: endpoints.filter((e) => e.risks.some((r) => r.reach === 'direct')).length,
    exposed: exposed.length,
    deadFindings: findings.filter((f) => f.surface && f.surface.reach === 'dead').length,
    reachableFindings: findings.filter((f) => f.surface && f.surface.reach !== 'dead').length,
  };

  const recommendations = buildRecommendations(stats, endpoints, middleware, authCoverage);
  const chains = buildChains(endpoints);

  return {
    entrypoints: endpoints,
    exposed,
    chains,
    authCoverage,
    middleware: middleware || null,
    stats,
    byRule,
    recommendations,
    diag: { importEdges: [...graph.values()].reduce((s, v) => s + v.length, 0) },
  };
}

function buildRecommendations(stats, endpoints, middleware, authCoverage) {
  const out = [];
  if (middleware && middleware.apiExcluded) {
    out.push({
      severity: 'high',
      text: 'middleware.ts matcher excludes /api. Guard each route handler itself; middleware-only auth is bypassable (x-middleware-subrequest).',
      file: middleware.file,
    });
  }
  const unguardedWrites = endpoints.filter((e) => e.auth === 'none' && e.stateChanging);
  for (const e of unguardedWrites.slice(0, 6)) {
    out.push({
      severity: 'critical',
      text: `${e.method} ${e.path} mutates state with no auth guard. Add the session check at the top of the handler.`,
      file: e.file,
      line: e.line,
    });
  }
  const idor = endpoints.filter((e) => e.ownership === 'missing');
  for (const e of idor.slice(0, 6)) {
    out.push({
      severity: 'high',
      text: `${e.method} ${e.path} fetches by request id without an owner/tenant predicate. Add the ownership constraint to the same query.`,
      file: e.file,
      line: e.line,
    });
  }
  if (authCoverage.unthrottledSensitive > 0) {
    out.push({
      severity: 'medium',
      text: `${authCoverage.unthrottledSensitive} credential-shaped endpoint(s) have no rate limiting. Add a limiter and lockout.`,
    });
  }
  if (stats.deadFindings > 0 && stats.deadFindings >= stats.reachableFindings) {
    out.push({
      severity: 'low',
      text: `${stats.deadFindings} finding(s) sit outside every entrypoint's import graph (dead/tooling code). Fix the reachable ones first; do not chase noise.`,
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Deterministic exploit chains
// ---------------------------------------------------------------------------

// Impact classification per rule family. Static analysis cannot "prove" an
// exploit, but for these families the consequence is fixed by the sink type.
function impactOf(ruleId) {
  const id = String(ruleId || '');
  if (/^(?:taint\.(?:command|code)-injection|code\.eval|ast\.function-constructor|ast\.eval-dynamic|deser\.|deser2026\.|obf\.)/.test(id)) {
    return { impact: 'remote code execution', cwe: 'CWE-94' };
  }
  if (/sql|orm|injection\.nosql|injection\.prototype|injection\.ssti|deser2026\.template/.test(id)) {
    return { impact: 'database compromise / auth bypass', cwe: 'CWE-89' };
  }
  if (/authz2026\.|auth\.idor|authz\.idor|idor/i.test(id)) {
    return { impact: 'cross-user data access (IDOR)', cwe: 'CWE-639' };
  }
  if (/ssrf/i.test(id)) return { impact: 'internal network / cloud metadata access', cwe: 'CWE-918' };
  if (/path-traversal/i.test(id)) return { impact: 'arbitrary file read/write', cwe: 'CWE-22' };
  if (/xss/i.test(id)) return { impact: 'session compromise via script injection', cwe: 'CWE-79' };
  if (/llm2026\.|^ai\./.test(id)) return { impact: 'model-driven exploitation (prompt injection → action)', cwe: 'CWE-1427' };
  if (/secret/i.test(id)) return { impact: 'credential exposure', cwe: 'CWE-798' };
  if (/csrf|jwt2026\.|cookie/.test(id)) return { impact: 'account takeover / request forgery', cwe: 'CWE-352' };
  if (/supply|npmrc|postinstall/.test(id)) return { impact: 'build/install-time code execution', cwe: 'CWE-829' };
  return { impact: 'security impact', cwe: '' };
}

const DATAFLOW_PREFERENCE = ['taint.', 'ast.', 'authz2026.', 'llm2026.', 'api2026.'];

function buildChains(endpoints, limit = 25) {
  const chains = [];
  for (const ep of endpoints) {
    if (ep.auth === 'unknown') continue; // cannot state the precondition
    const unauthenticated = ep.auth === 'none';

    // 1) A real sink reachable from this endpoint (direct preferred).
    const sinks = ep.risks
      .filter((r) => r.reach === 'direct' && (r.severity === 'critical' || r.severity === 'high'))
      .sort((a, b) => {
        const da = DATAFLOW_PREFERENCE.some((p) => a.ruleId.startsWith(p)) ? 1 : 0;
        const db = DATAFLOW_PREFERENCE.some((p) => b.ruleId.startsWith(p)) ? 1 : 0;
        return db - da || b.score - a.score;
      });
    if (sinks.length > 0) {
      const sink = sinks[0];
      const { impact, cwe } = impactOf(sink.ruleId);
      chains.push({
        kind: 'sink',
        entrypoint: { method: ep.method, path: ep.path, file: ep.file, line: ep.line, auth: ep.auth },
        sink: { ruleId: sink.ruleId, file: sink.file, line: sink.line, severity: sink.severity },
        precondition: unauthenticated ? 'no authentication' : 'authenticated user',
        impact,
        cwe,
        score: Math.round(ep.score + (unauthenticated ? 25 : 0) + (sink.severity === 'critical' ? 20 : 0)),
        narrative:
          `${unauthenticated ? 'Unauthenticated' : 'Authenticated'} ${ep.method} ${ep.path} reaches ${sink.ruleId} ` +
          `(${sink.file}:${sink.line}) → ${impact}.`,
      });
      continue;
    }

    // 2) Object-level authorization absent: the endpoint is the vulnerability.
    if (ep.ownership === 'missing') {
      chains.push({
        kind: 'idor',
        entrypoint: { method: ep.method, path: ep.path, file: ep.file, line: ep.line, auth: ep.auth },
        sink: null,
        precondition: unauthenticated ? 'no authentication' : 'authenticated user',
        impact: 'cross-user data access (IDOR): any caller can address another user\'s record by id',
        cwe: 'CWE-639',
        score: Math.round(ep.score + (unauthenticated ? 25 : 0)),
        narrative:
          `${ep.method} ${ep.path} reads an object id from the request with no owner/tenant filter ` +
          `→ any authenticated user can access other users' records.`,
      });
    }
  }
  return chains.sort((a, b) => b.score - a.score).slice(0, limit);
}

function summarizeSurface(surface) {
  const s = surface.stats;
  return (
    `attack surface: ${s.entrypoints} entrypoints (${Object.entries(s.byFramework)
      .map(([k, v]) => `${k} ${v}`)
      .join(', ')}) · ${s.unguarded} unguarded · ${s.unknownAuth || 0} unresolved guards · ` +
    `${s.unguardedStateChanging} unguarded writes · ${s.idorCandidates} IDOR candidates · ` +
    `${s.reachableFindings} reachable findings`
  );
}

module.exports = {
  buildSurface,
  buildImportGraph,
  reachableFrom,
  buildChains,
  impactOf,
  summarizeSurface,
};
