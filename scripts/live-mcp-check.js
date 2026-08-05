#!/usr/bin/env node
'use strict';
/* Live MCP handshake test: speaks the MCP JSON-RPC protocol over stdio,
 * exactly like Claude Code / Cursor / any MCP client would. */
const { spawn } = require('child_process');
const path = require('path');

const serverPath = path.join(__dirname, '..', 'src', 'mcp-server.js');
const child = spawn(process.execPath, [serverPath], {
  cwd: path.join(__dirname, '..'),
  env: { ...process.env, PATH: process.env.PATH },
  stdio: ['pipe', 'pipe', 'pipe'],
});

// Surface spawn/exit failures instead of dying silently (as the OS pipes do).
child.on('error', (e) => {
  console.error('FATAL: could not spawn MCP server —', e.message);
  for (const p of pending.values()) p.rej(e);
  pending.clear();
  process.exitCode = 1;
});
child.on('exit', (code) => {
  if (pending.size > 0) {
    console.error('FATAL: MCP server exited early (code=' + code + ') with requests pending.');
    for (const p of pending.values()) p.rej(new Error('server exited'));
    pending.clear();
    process.exitCode = 1;
  }
});

let buf = '';
const pending = new Map();
let idc = 0;

function send(method, params) {
  const id = ++idc;
  const msg = JSON.stringify({ jsonrpc: '2.0', id, method, params });
  child.stdin.write(msg + '\n');
  return new Promise((res, rej) => pending.set(id, { res, rej }));
}

child.stdout.on('data', (d) => {
  process.stderr.write('[raw-out] ' + d.toString().slice(0, 300) + '\n');
  buf += d.toString();
  let idx;
  while ((idx = buf.indexOf('\n')) !== -1) {
    const line = buf.slice(0, idx).trim();
    buf = buf.slice(idx + 1);
    if (!line) continue;
    let msg;
    try { msg = JSON.parse(line); } catch { continue; }
    if (msg.id && pending.has(msg.id)) {
      const p = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? p.rej(new Error(JSON.stringify(msg.error))) : p.res(msg.result);
    } else if (msg.method === 'notifications/initialized') {
      // ignore
    }
  }
});

let stderr = '';
child.stderr.on('data', (d) => { stderr += d.toString(); });

(async () => {
  try {
    const t0 = Date.now();
    const init = await send('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'hermes-livecheck', version: '1.0.0' },
    });
    console.log('[1] initialize OK in', Date.now() - t0 + 'ms');
    console.log('    serverInfo:', JSON.stringify(init.serverInfo));
    console.log('    protocolVersion:', init.protocolVersion);
    console.log('    capabilities:', JSON.stringify(init.capabilities));

    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');

    const tools = await send('tools/list', {});
    console.log('[2] tools/list OK —', tools.tools.length, 'tools');
    const names = tools.tools.map((t) => t.name);
    console.log('    sample:', names.slice(0, 8).join(', '), '…');

    // Verify every tool has a name + description + inputSchema (agents need these).
    const missing = tools.tools.filter((t) => !t.name || !t.description || !t.inputSchema);
    console.log('[3] tools missing name/desc/schema:', missing.length);
    const noDesc = tools.tools.filter((t) => !t.description || t.description.length < 10);
    if (noDesc.length) console.log('    weak descriptions:', noDesc.map((t) => t.name).join(', '));

    // Actually call the flagship tool against this repo.
    const res = await send('tools/call', {
      name: 'scan_project',
      arguments: { dir: path.join(__dirname, '..', 'test', 'fixtures') },
    });
    if (res.isError) throw new Error('scan_project failed: ' + JSON.stringify(res).slice(0, 300));
    const text = (res.content || []).map((c) => c.text || '').join('');
    console.log('[4] tools/call scan_project OK —', text.slice(0, 90).replace(/\n/g, ' '));
    if (!/Grade [A-F]/.test(text)) throw new Error('scan_project result missing grade: ' + text.slice(0, 200));

    // check_code is the inline-snippet tool agents use most.
    const res2 = await send('tools/call', {
      name: 'check_code',
      arguments: { code: 'const fs=require("fs");\nconst data = fs.readFileSync(req.query.file, "utf8");\nres.send(data);', language: 'javascript' },
    });
    if (res2.isError) throw new Error('check_code failed: ' + JSON.stringify(res2).slice(0, 300));
    const text2 = (res2.content || []).map((c) => c.text || '').join('');
    console.log('[5] tools/call check_code OK — finds:', /critical|high|medium|low|path-traversal|injection/i.test(text2) ? 'findings present' : 'no findings?');

    // Unknown tool must name the tool, not "undefined" — agents rely on this error.
    const bad = await send('tools/call', { name: 'definitely_not_a_tool', arguments: {} });
    if (!bad.isError) throw new Error('unknown tool should have errored');
    const badText = (bad.content || []).map((c) => c.text || '').join('');
    if (!badText.includes('definitely_not_a_tool')) throw new Error('unknown-tool error does not name the tool: ' + badText);
    console.log('[6] unknown tool error names the tool OK —', badText.slice(0, 60));

    console.log('ALL MCP HANDSHAKE CHECKS PASSED');
  } catch (e) {
    console.error('MCP HANDSHAKE FAILED:', e.message);
    if (stderr) console.error('server stderr:', stderr.slice(0, 800));
    process.exitCode = 1;
  } finally {
    child.kill();
    // Let stdout flush naturally — process.exit() truncates piped output.
  }
})();

// Global watchdog: if the server never answers, fail loudly instead of hanging.
setTimeout(() => {
  if (pending.size > 0) {
    console.error('MCP HANDSHAKE TIMED OUT — server never responded. stderr:');
    console.error(stderr.slice(0, 1200) || '(no stderr)');
    process.exitCode = 1;
    child.kill();
  }
}, 20000).unref();
