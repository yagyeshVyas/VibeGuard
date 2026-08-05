#!/usr/bin/env node
/* Deep MCP tool audit: boots the server, enumerates every tool, calls each one
 * with minimal/valid args, and classifies the result:
 *   PASS          — returned a result
 *   graceful-err  — returned an isError result with a clean validation message
 *   BUG           — crash, "Unknown tool", TypeError, or empty/undefined result
 * Usage: node scripts/mcp-audit-tools.js [--json]
 */
'use strict';
const { spawn } = require('child_process');
const path = require('path');

const serverPath = path.join(__dirname, '..', 'src', 'mcp-server.js');
const child = spawn(process.execPath, [serverPath], {
  cwd: path.join(__dirname, '..'),
  env: { ...process.env, PATH: process.env.PATH },
  stdio: ['pipe', 'pipe', 'pipe'],
});

let buf = '';
const pending = new Map();
let idc = 0;

child.stdout.on('data', (d) => {
  buf += d.toString('utf8');
  let idx;
  while ((idx = buf.indexOf('\n')) !== -1) {
    const line = buf.slice(0, idx).trim();
    buf = buf.slice(idx + 1);
    if (!line) continue;
    let msg;
    try { msg = JSON.parse(line); } catch { continue; }
    if (msg.id && pending.has(msg.id)) {
      const { resolve } = pending.get(msg.id);
      pending.delete(msg.id);
      resolve(msg);
    }
  }
});
child.stderr.on('data', () => { /* banner etc — ignore */ });

function send(method, params, timeoutMs = 30000) {
  const id = ++idc;
  const msg = JSON.stringify({ jsonrpc: '2.0', id, method, params });
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => { pending.delete(id); reject(new Error(`timeout ${method}`)); }, timeoutMs);
    pending.set(id, { resolve: (m) => { clearTimeout(t); resolve(m); } });
    child.stdin.write(msg + '\n');
  });
}

// Build a minimal valid arg set from a JSON Schema (string props get samples).
function sampleArgs(schema) {
  const props = (schema && schema.properties) || {};
  const args = {};
  const required = (schema && schema.required) || [];
  const isDir = (k) => /dir|root|folder|directory/i.test(k);
  const isFile = (k) => /^file$|filename|^path$/.test(k);
  const isRule = (k) => /^rule|rule_id|ruleid/i.test(k);
  for (const [k, v] of Object.entries(props)) {
    if (!required.includes(k) && v.default === undefined) continue;
    let val;
    if (v.default !== undefined) val = v.default;
    else if (isDir(k)) val = 'src';          // real dir in the repo
    else if (isFile(k)) val = 'src/scanner.js'; // real file
    else if (isRule(k)) val = 'ast.command-injection'; // real rule id
    else if (v.type === 'string') {
      val = k === 'preset' ? 'react'      // real preset
          : k === 'command' ? 'ls -la'
          : 'test';
    } else {
      const S = { integer: 1, number: 1, boolean: true, array: ['test'], object: {} };
      val = v.enum ? v.enum[0] : S[v.type] !== undefined ? S[v.type] : 'test';
    }
    args[k] = val;
  }
  // For dir-scoped tools, point scans at the repo 'src' so they complete fast.
  if (Object.entries(args).length === 0) args.dir = 'src';
  return args;
}

function flatten(text) {
  return String(text).replace(/\s+/g, ' ').trim().slice(0, 140);
}

async function main() {
  const out = { pass: [], graceful: [], bugs: [] };
  try {
    await send('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'audit', version: '1' } });
    const list = await send('tools/list', {});
    const tools = (list.result && list.result.tools) || [];
    for (const t of tools) {
      let res;
      try {
        res = await send('tools/call', { name: t.name, arguments: sampleArgs(t.inputSchema) });
      } catch (e) {
        out.bugs.push({ tool: t.name, why: 'call crashed: ' + e.message });
        continue;
      }
      const r = res.result;
      if (!r) { out.bugs.push({ tool: t.name, why: 'empty result' }); continue; }
      if (r.isError) {
        const text = flatten(Array.isArray(r.content) ? r.content.map((c) => c.text || '').join(' ') : JSON.stringify(r));
        // Graceful validation errors name the missing arg / bad input; bugs crash.
        if (/unknown tool|typeerror|internal error|cannot read|is not a function|undefined is not/i.test(text) && !/required/i.test(text)) {
          out.bugs.push({ tool: t.name, why: text });
        } else {
          out.graceful.push({ tool: t.name, why: text });
        }
      } else {
        out.pass.push(t.name);
      }
    }
  } finally {
    child.stdin.end();
    child.kill();
  }
  const json = process.argv.includes('--json');
  if (json) { console.log(JSON.stringify(out, null, 2)); return; }
  console.log(`tools audited: ${out.pass.length + out.graceful.length + out.bugs.length}`);
  console.log(`PASS           : ${out.pass.length}`);
  console.log(`graceful-err   : ${out.graceful.length} (expected: missing-arg / not-found)`);
  for (const g of out.graceful) console.log(`   ~ ${g.tool}: ${g.why}`);
  console.log(`BUGS           : ${out.bugs.length}`);
  for (const b of out.bugs) console.log(`   ! ${b.tool}: ${b.why}`);
  process.exitCode = out.bugs.length ? 1 : 0;
}

main().catch((e) => { console.error('audit failed:', e.message); process.exitCode = 2; });
