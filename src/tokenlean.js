'use strict';

/*
 * TLAP — Token-Lean Agent Protocol.
 *
 * Why this exists
 * ---------------
 * VibeGuard's primary consumer is not a human terminal, it is an AI agent
 * reading tool output through a context window. Every scanner in this space
 * (Semgrep, Snyk, Trivy, Strix) answers an agent with pretty-printed JSON:
 * two-space indentation, repeated object keys, the same `message` and `fix`
 * string duplicated once per occurrence, and full repo-relative paths on every
 * line. On a real repository that is thousands of tokens of pure redundancy,
 * paid for on every single tool call, in both directions of the loop.
 *
 * TLAP encodes the same information — no findings dropped silently — in a
 * line-oriented, de-duplicated, dictionary-compressed form, and can hold the
 * whole thing under a hard token budget by spending the budget on the findings
 * that actually matter first (risk-ranked), then emitting an explicit rollup of
 * whatever did not fit. An agent is never told "clean" because output was cut.
 *
 * Four compression levers, in order of how much they win:
 *   1. No pretty JSON.        Structural punctuation + repeated keys are ~55% of
 *                             a `JSON.stringify(x, null, 2)` payload.
 *   2. Cluster by rule.       `message` + `fix` are properties of the RULE, not
 *                             of the occurrence. Emit once, list the locations.
 *   3. Path dictionary.       `src/components/dashboard/` repeated 40 times
 *                             becomes `p3`.
 *   4. Risk-ranked budget.    Truncate the tail, never the head, and always say
 *                             what was truncated.
 *
 * Plus delta mode: if nothing changed since the previous scan snapshot, the
 * whole answer is one line (~20 tokens instead of ~4000).
 *
 * Zero dependencies. Deterministic: identical input produces byte-identical
 * output, which is what makes it safe to diff and to cache.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Token estimation
// ---------------------------------------------------------------------------

/*
 * Offline token estimator.
 *
 * This is an ESTIMATE, not a tokenizer. Shipping a real BPE table would mean a
 * dependency and a multi-megabyte vocab file, and VibeGuard is zero-dependency
 * and offline by contract. The model below approximates BPE behaviour on
 * code-shaped text closely enough to drive a budget:
 *
 *   - alphabetic runs  ~4 chars/token (BPE merges common subwords)
 *   - digit runs       ~3 chars/token (digits tokenize worse than letters)
 *   - punctuation      1 token each   (rarely merges in code)
 *   - newlines         1 token each
 *   - inline spaces    usually absorbed into the following token
 *
 * Measured against published tokenizer counts on source/JSON samples this lands
 * within roughly ±10%. Budgets are enforced with headroom to absorb that.
 */
function estimateTokens(str) {
  if (!str) return 0;
  const s = String(str);
  let tokens = 0;
  let i = 0;
  const n = s.length;
  while (i < n) {
    const c = s.charCodeAt(i);
    // alphabetic run
    if ((c >= 65 && c <= 90) || (c >= 97 && c <= 122)) {
      let j = i + 1;
      while (j < n) {
        const d = s.charCodeAt(j);
        if ((d >= 65 && d <= 90) || (d >= 97 && d <= 122)) j++;
        else break;
      }
      tokens += Math.ceil((j - i) / 4);
      i = j;
      continue;
    }
    // digit run
    if (c >= 48 && c <= 57) {
      let j = i + 1;
      while (j < n && s.charCodeAt(j) >= 48 && s.charCodeAt(j) <= 57) j++;
      tokens += Math.ceil((j - i) / 3);
      i = j;
      continue;
    }
    // newline run: each newline is its own token
    if (c === 10 || c === 13) {
      let j = i;
      while (j < n && (s.charCodeAt(j) === 10 || s.charCodeAt(j) === 13)) {
        if (s.charCodeAt(j) === 10) tokens += 1;
        j++;
      }
      i = j;
      continue;
    }
    // inline whitespace: absorbed into the next token, except long indent runs
    if (c === 32 || c === 9) {
      let j = i;
      while (j < n && (s.charCodeAt(j) === 32 || s.charCodeAt(j) === 9)) j++;
      const run = j - i;
      if (run > 2) tokens += Math.ceil(run / 4);
      i = j;
      continue;
    }
    // everything else: one token per character (punctuation, symbols, unicode)
    tokens += 1;
    i += 1;
  }
  return tokens;
}

// ---------------------------------------------------------------------------
// Risk ranking — decides what survives a tight budget
// ---------------------------------------------------------------------------

const SEV_WEIGHT = { critical: 1000, high: 400, medium: 120, low: 30 };
const CONF_WEIGHT = { high: 1.0, medium: 0.75, low: 0.45 };

// Rules whose findings are dataflow-confirmed or directly exploitable outrank
// pattern-only matches of the same severity — that is what an agent should
// spend a constrained budget on first.
const EXPLOITABLE_RE = /^(taint|secret|injection|backdoor|idor|auth|ssrf|rce|deser|web\.ssrf)/;
const HOTSPOT_RE =
  /(auth|login|signin|signup|password|session|token|jwt|payment|billing|checkout|charge|admin|role|permission|account|api|route|controller|middleware|webhook|upload)/i;

/*
 * Score a single finding. Higher = shown first, and last to be dropped.
 * Pure function of the finding, so ordering is stable across runs.
 */
function riskScore(f) {
  const sev = SEV_WEIGHT[f.severity] || 10;
  const conf = CONF_WEIGHT[f.confidence] || CONF_WEIGHT.high;
  let score = sev * conf;
  if (EXPLOITABLE_RE.test(f.ruleId || '')) score += 150;
  if (HOTSPOT_RE.test(f.file || '')) score += 60;
  // Dataflow-confirmed findings state so in the message; trust them more.
  if (/dataflow-confirmed|reachable|proof|callback observed/i.test(f.message || '')) score += 100;
  return score;
}

// ---------------------------------------------------------------------------
// Path dictionary
// ---------------------------------------------------------------------------

/*
 * Build a prefix dictionary for the directory parts of the finding paths.
 * A prefix earns a slot only when substituting it actually saves characters:
 * (prefixLength - tokenLength) * occurrences must clear a floor, otherwise the
 * legend line costs more than the substitution saves.
 */
function buildPathDict(files) {
  const counts = new Map();
  for (const file of files) {
    const norm = String(file).replace(/\\/g, '/');
    const idx = norm.lastIndexOf('/');
    if (idx <= 0) continue;
    const prefix = norm.slice(0, idx + 1);
    counts.set(prefix, (counts.get(prefix) || 0) + 1);
  }
  const candidates = [];
  for (const [prefix, count] of counts) {
    // Saving per use ≈ prefix length - "pN" length (2-3 chars).
    const saving = (prefix.length - 3) * count - (prefix.length + 5);
    if (count >= 2 && prefix.length >= 6 && saving > 0) {
      candidates.push({ prefix, count, saving });
    }
  }
  candidates.sort((a, b) => b.saving - a.saving || a.prefix.localeCompare(b.prefix));
  const dict = [];
  // Cap the legend: beyond ~12 entries the legend itself starts to cost more
  // than the long tail of rare prefixes saves.
  for (const c of candidates.slice(0, 12)) {
    dict.push({ token: 'p' + (dict.length + 1), prefix: c.prefix });
  }
  return dict;
}

function applyDict(file, dict) {
  const norm = String(file).replace(/\\/g, '/');
  // Longest prefix wins, so nested directories compress fully.
  let best = null;
  for (const d of dict) {
    if (norm.startsWith(d.prefix) && (!best || d.prefix.length > best.prefix.length)) best = d;
  }
  return best ? best.token + norm.slice(best.prefix.length) : norm;
}

// ---------------------------------------------------------------------------
// Clustering
// ---------------------------------------------------------------------------

const SEV_TAG = { critical: 'CRIT', high: 'HIGH', medium: 'MED', low: 'LOW' };
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

/*
 * Group findings that share a rule + message + fix. Those three strings are
 * properties of the rule, so emitting them once per cluster instead of once per
 * occurrence is lossless. Locations are kept in full.
 */
function clusterFindings(findings) {
  const groups = new Map();
  for (const f of findings) {
    const key = JSON.stringify([f.ruleId, f.severity, f.message || '', f.fix || '']);
    let g = groups.get(key);
    if (!g) {
      g = {
        ruleId: f.ruleId,
        severity: f.severity,
        message: f.message || '',
        fix: f.fix || '',
        locations: [],
        count: 0,
        score: 0,
      };
      groups.set(key, g);
    }
    g.locations.push({ file: String(f.file || '').replace(/\\/g, '/'), line: f.line || 0 });
    g.count++;
    // A cluster is ranked by its strongest member, not its average: one
    // confirmed critical in a cluster must not be buried by weak siblings.
    g.score = Math.max(g.score, riskScore(f));
  }
  const clusters = [...groups.values()];
  for (const c of clusters) {
    // Collapse locations to file -> sorted unique lines.
    const byFile = new Map();
    for (const loc of c.locations) {
      if (!byFile.has(loc.file)) byFile.set(loc.file, new Set());
      byFile.get(loc.file).add(loc.line);
    }
    c.files = [...byFile.entries()]
      .map(([file, lines]) => ({ file, lines: [...lines].sort((a, b) => a - b) }))
      .sort((a, b) => a.file.localeCompare(b.file));
  }
  clusters.sort(
    (a, b) =>
      SEV_ORDER[a.severity] - SEV_ORDER[b.severity] ||
      b.score - a.score ||
      a.ruleId.localeCompare(b.ruleId)
  );
  return clusters;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function renderCluster(c, dict, opts) {
  const locs = c.files
    .map((fl) => applyDict(fl.file, dict) + ':' + fl.lines.join(','))
    .join(' ');
  const head =
    `${SEV_TAG[c.severity] || c.severity.toUpperCase()} ${c.ruleId}` +
    (c.count > 1 ? ` x${c.count}` : '') +
    ' ' +
    locs;
  const lines = [head];
  if (c.message && !opts.noMessage) lines.push('  ' + truncOneLine(c.message, opts.maxMsg));
  if (c.fix && !opts.noFix) lines.push('  fix: ' + truncOneLine(c.fix, opts.maxFix));
  return lines.join('\n');
}

function truncOneLine(s, max) {
  const one = String(s).replace(/\s+/g, ' ').trim();
  if (!max || one.length <= max) return one;
  return one.slice(0, max - 1) + '…';
}

function countsLine(counts) {
  const parts = [];
  if (counts.critical) parts.push(counts.critical + 'C');
  if (counts.high) parts.push(counts.high + 'H');
  if (counts.medium) parts.push(counts.medium + 'M');
  if (counts.low) parts.push(counts.low + 'L');
  return parts.length ? parts.join(' ') : 'clean';
}

/*
 * Render a scan result in TLAP form.
 *
 * opts:
 *   budget   number  hard token ceiling for the whole payload (default: none)
 *   maxMsg   number  per-message character cap (default 160)
 *   maxFix   number  per-fix character cap (default 140)
 *   noFix    bool    drop remediation text entirely (agent already knows it)
 *
 * Returns { text, tokens, clusters, shown, omitted }.
 */
function renderLean(result, opts) {
  const o = Object.assign({ maxMsg: 160, maxFix: 140, noFix: false }, opts || {});
  const findings = result.findings || [];
  const counts = result.counts || { critical: 0, high: 0, medium: 0, low: 0 };

  // The header stays spelled out rather than sigil-coded. "Grade" costs about
  // two tokens per call; an agent misreading the verdict of a security scan
  // costs considerably more than that.
  const header =
    `VG Grade ${result.grade || '?'} | ${countsLine(counts)} | ` +
    `${findings.length} findings in ${result.scannedFiles || 0} files`;

  // Coverage transparency survives compression. A lean payload must never let
  // an agent read a degraded scan as an all-clear.
  const warn = [];
  if (result.engine && result.engine.mode === 'regex-only') {
    warn.push('! engine=regex-only (no AST/taint) — not an all-clear');
  }
  if (result.diagnostics && result.diagnostics.degradedFileCount > 0) {
    warn.push(`! ${result.diagnostics.degradedFileCount} file(s) partially analyzed`);
  }

  if (findings.length === 0) {
    const text = [header, ...warn].join('\n');
    return { text, tokens: estimateTokens(text), clusters: 0, shown: 0, omitted: 0 };
  }

  const clusters = clusterFindings(findings);
  const dict = buildPathDict(findings.map((f) => f.file));
  const dictLine = dict.length ? dict.map((d) => `${d.token}=${d.prefix}`).join(' ') : '';

  const fixed = [header, ...warn];
  if (dictLine) fixed.push(dictLine);
  const fixedText = fixed.join('\n');

  const budget = o.budget && o.budget > 0 ? o.budget : Infinity;
  // Reserve room for the omitted-rollup line so the truncation notice itself
  // can never be the thing that gets truncated.
  const reserve = budget === Infinity ? 0 : 40;
  let used = estimateTokens(fixedText) + reserve;

  const body = [];
  const omitted = [];
  for (const c of clusters) {
    const rendered = renderCluster(c, dict, o);
    const cost = estimateTokens(rendered) + 1;
    if (used + cost > budget) {
      omitted.push(c);
      continue;
    }
    body.push(rendered);
    used += cost;
  }

  const out = [fixedText];
  if (body.length) out.push('', body.join('\n'));

  if (omitted.length) {
    const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
    let n = 0;
    for (const c of omitted) {
      bySev[c.severity] = (bySev[c.severity] || 0) + c.count;
      n += c.count;
    }
    const topIds = omitted.slice(0, 6).map((c) => c.ruleId).join(' ');
    out.push(
      '',
      `+ ${n} more finding(s) over budget [${countsLine(bySev)}] rules: ${topIds}` +
        (omitted.length > 6 ? ` +${omitted.length - 6} rules` : '') +
        ' — raise budget to see them. NOT an all-clear.'
    );
  }

  const text = out.join('\n');
  return {
    text,
    tokens: estimateTokens(text),
    clusters: clusters.length,
    shown: clusters.length - omitted.length,
    omitted: omitted.length,
  };
}

/*
 * A fix plan in the lean dialect.
 *
 * The prose fix prompt repeats the finding message and the remediation text
 * once per occurrence plus a paragraph of instructions. In a fix loop an agent
 * pays for that on every iteration. Here the instruction is one line, the
 * remediation is stated once per rule, and the message is dropped entirely —
 * when the task is "apply the fix", the diagnosis is not what the agent needs.
 */
function renderLeanFixPlan(result, opts) {
  const o = Object.assign({ maxFix: 200, noMessage: true }, opts || {});
  const findings = result.findings || [];
  if (findings.length === 0) return 'VG Grade ' + (result.grade || 'A') + ' | clean — nothing to fix.';

  const clusters = clusterFindings(findings);
  const dict = buildPathDict(findings.map((f) => f.file));
  const out = [
    `VG fix plan | Grade ${result.grade} | ${clusters.length} rules, ${findings.length} sites`,
    'Apply the minimal safe change at each site. Rotate any leaked secret. Touch nothing else.',
  ];
  if (dict.length) out.push(dict.map((d) => `${d.token}=${d.prefix}`).join(' '));
  out.push('');

  const budget = o.budget && o.budget > 0 ? o.budget : Infinity;
  let used = estimateTokens(out.join('\n')) + (budget === Infinity ? 0 : 40);
  const omitted = [];
  for (const c of clusters) {
    const rendered = renderCluster(c, dict, o);
    const cost = estimateTokens(rendered) + 1;
    if (used + cost > budget) {
      omitted.push(c);
      continue;
    }
    out.push(rendered);
    used += cost;
  }
  if (omitted.length) {
    const n = omitted.reduce((a, c) => a + c.count, 0);
    out.push('', `+ ${n} more site(s) over budget — fix these first, then re-run. NOT a complete plan.`);
  }
  return out.join('\n');
}

// ---------------------------------------------------------------------------
// Savings measurement — the number we publish, computed honestly
// ---------------------------------------------------------------------------

/*
 * Compare TLAP against the baseline every other scanner sends an agent:
 * pretty-printed JSON of the findings array.
 */
function leanStats(result, opts) {
  const baselinePayload = {
    grade: result.grade,
    counts: result.counts,
    scannedFiles: result.scannedFiles,
    findings: (result.findings || []).map((f) => ({
      severity: f.severity,
      ruleId: f.ruleId,
      file: f.file,
      line: f.line,
      message: f.message,
      fix: f.fix,
    })),
  };
  const jsonText = JSON.stringify(baselinePayload, null, 2);
  const jsonTokens = estimateTokens(jsonText);
  const lean = renderLean(result, opts);
  const saved = jsonTokens - lean.tokens;
  return {
    jsonTokens,
    jsonChars: jsonText.length,
    leanTokens: lean.tokens,
    leanChars: lean.text.length,
    saved,
    savedPct: jsonTokens > 0 ? Math.round((saved / jsonTokens) * 1000) / 10 : 0,
    findings: (result.findings || []).length,
    clusters: lean.clusters,
    text: lean.text,
  };
}

// ---------------------------------------------------------------------------
// Delta mode — the cheapest possible answer is "nothing changed"
// ---------------------------------------------------------------------------

/*
 * A stable fingerprint of the finding set. Fingerprints already exist per
 * finding; hashing the sorted set gives a scan identity that ignores ordering
 * and file-walk nondeterminism.
 */
function snapshotOf(result) {
  const ids = (result.findings || [])
    .map((f) => f.fingerprint || `${f.ruleId}:${f.file}:${f.line}`)
    .sort();
  return {
    hash: crypto.createHash('sha256').update(ids.join('\n')).digest('hex').slice(0, 16),
    grade: result.grade,
    count: ids.length,
    ids,
  };
}

/*
 * Render only what changed against a previous snapshot.
 * Unchanged => a single line, which is the entire point.
 */
function deltaReport(result, prev, opts) {
  const snap = snapshotOf(result);
  if (prev && prev.hash === snap.hash) {
    const text = `VG Grade ${result.grade} unchanged (${snap.count} known finding(s), fp ${snap.hash}) — no new issues.`;
    return { unchanged: true, snapshot: snap, text, tokens: estimateTokens(text) };
  }
  const prevIds = new Set((prev && prev.ids) || []);
  const fresh = (result.findings || []).filter(
    (f) => !prevIds.has(f.fingerprint || `${f.ruleId}:${f.file}:${f.line}`)
  );
  const resolved = prev ? (prev.ids || []).filter((id) => !snap.ids.includes(id)).length : 0;
  const sub = Object.assign({}, result, { findings: fresh });
  const lean = renderLean(sub, opts);
  const head = prev
    ? `VG Grade ${result.grade} delta: ${fresh.length} new, ${resolved} resolved, ${snap.count} total`
    : `VG Grade ${result.grade} baseline: ${snap.count} finding(s)`;
  const text = head + (fresh.length ? '\n' + lean.text : '');
  return { unchanged: false, snapshot: snap, text, tokens: estimateTokens(text), newCount: fresh.length, resolved };
}

/*
 * Snapshot persistence.
 *
 * Owned here rather than duplicated in the CLI and the MCP server so both
 * speak to one notion of "what I have already reported". The path is always
 * built from a resolved root plus a constant relative path — the scan root is
 * never concatenated with anything caller-supplied.
 */
const SNAPSHOT_REL = path.join('.vibeguard', 'tlap-snapshot.json');

function snapshotPath(root) {
  return path.join(path.resolve(root || '.'), SNAPSHOT_REL);
}

function readSnapshot(root) {
  try {
    return JSON.parse(fs.readFileSync(snapshotPath(root), 'utf8'));
  } catch {
    return null;
  }
}

/* A snapshot is a cache. Failing to write one must never fail a scan. */
function writeSnapshot(root, snap) {
  try {
    const file = snapshotPath(root);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(snap));
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Generic budget guard for arbitrary tool text
// ---------------------------------------------------------------------------

/*
 * Last-resort ceiling applied to any tool payload that is not a scan result.
 * Keeps the head (summaries lead in every VibeGuard tool) and states exactly
 * how much was cut, so the agent knows the answer is partial.
 */
function compactText(text, budget) {
  if (!budget || budget <= 0) return text;
  const s = String(text == null ? '' : text);
  const tokens = estimateTokens(s);
  if (tokens <= budget) return s;
  // ~4 chars/token, with 5% headroom for estimator error.
  const keepChars = Math.max(200, Math.floor(budget * 4 * 0.95));
  const head = s.slice(0, keepChars);
  const cutTokens = tokens - estimateTokens(head);
  return (
    head +
    `\n\n… [truncated ~${cutTokens} tokens of ${tokens} to fit a ${budget}-token budget. ` +
    'Output is PARTIAL — not an all-clear. Raise VIBEGUARD_TOKEN_BUDGET or pass a larger budget.]'
  );
}

module.exports = {
  estimateTokens,
  riskScore,
  buildPathDict,
  applyDict,
  clusterFindings,
  renderLean,
  renderLeanFixPlan,
  leanStats,
  snapshotOf,
  snapshotPath,
  readSnapshot,
  writeSnapshot,
  deltaReport,
  compactText,
};
