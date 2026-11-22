'use strict';

/*
 * src/platform/mcp-http-bridge.js — Streamable HTTP <-> stdio MCP bridge.
 *
 * The bridge owns one upstream stdio MCP child. It accepts authenticated JSON-
 * RPC POSTs through createHttpGateway, forwards requests to the child, returns
 * responses, and exposes server-to-client notifications/requests on an SSE
 * stream (`GET /mcp` with `Accept: text/event-stream`).
 *
 * It is intentionally local/loopback-first. TLS/remote OAuth termination and
 * multi-session persistence are deployment concerns and are not claimed here.
 */

const { spawn } = require('child_process');
const { createHttpGateway } = require('./http-gateway');
const { createEngine } = require('../mcp-firewall');
const { ERROR_CODES, VibeGuardError } = require('./contracts');

class StdioMcpBridge {
  constructor(opts = {}) {
    if (!opts.command) throw new Error('stdio bridge requires a command');
    this.command = opts.command;
    this.args = opts.args || [];
    this.cwd = opts.cwd || process.cwd();
    this.env = opts.env || {};
    this.serverName = opts.serverName || 'http-upstream';
    this.timeoutMs = opts.timeoutMs || 30000;
    this.engine = opts.engine || null;
    this.onEvent = opts.onEvent || (() => {});
    this.child = null;
    this.buffer = '';
    this.pending = new Map();
    this.nextId = 1;
    this.closed = false;
  }

  start() {
    return new Promise((resolve, reject) => {
      const child = spawn(this.command, this.args, {
        cwd: this.cwd,
        env: { ...process.env, ...this.env },
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
        shell: false,
      });
      this.child = child;
      let started = false;
      child.once('spawn', () => { started = true; resolve(this); });
      child.once('error', (err) => { if (!started) reject(err); this.failAll(err); });
      child.stdout.on('data', (chunk) => this._onData(chunk));
      child.stderr.on('data', (chunk) => {
        if (this.onStderr) this.onStderr(chunk);
      });
      child.once('exit', (code, signal) => this.failAll(new Error(`upstream exit ${code || signal || 'unknown'}`)));
    });
  }

  _onData(chunk) {
    this.buffer += chunk.toString('utf8');
    if (this.buffer.length > 8 * 1024 * 1024) {
      this.failAll(new Error('upstream message exceeds 8 MiB'));
      try { this.child.kill(); } catch { /* ignore */ }
      return;
    }
    const lines = this.buffer.split(/\r?\n/);
    this.buffer = lines.pop();
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      let message;
      try { message = JSON.parse(trimmed); } catch {
        this.onEvent({ raw: trimmed });
        continue;
      }
      if (message && message.id != null && this.pending.has(message.id)) {
        const pending = this.pending.get(message.id);
        this.pending.delete(message.id);
        clearTimeout(pending.timer);
        let inspected = { forward: true, message };
        try { if (this.engine) inspected = this.engine.onServerMessage(this.serverName, message); } catch (err) {
          pending.reject(err);
          continue;
        }
        if (inspected.forward === false) {
          pending.reject(new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, 'upstream response blocked by content inspection'));
          continue;
        }
        pending.resolve(inspected.message || message);
        continue;
      }
      this.onEvent(message);
    }
  }

  request(message) {
    if (this.closed || !this.child) return Promise.reject(new VibeGuardError(ERROR_CODES.SANDBOX_UNAVAILABLE, 'bridge is closed'));
    const request = { ...message };
    if (request.id == null) request.id = this.nextId++;
    const id = request.id;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new VibeGuardError(ERROR_CODES.LIMIT_EXCEEDED, 'upstream request timed out'));
      }, this.timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      try {
        this.child.stdin.write(JSON.stringify(request) + '\n');
      } catch (err) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(err);
      }
    });
  }

  send(message) {
    if (!this.child) return false;
    try { this.child.stdin.write(JSON.stringify(message) + '\n'); return true; } catch { return false; }
  }

  failAll(err) {
    for (const [id, p] of this.pending) {
      clearTimeout(p.timer);
      p.reject(err);
      this.pending.delete(id);
    }
  }

  close() {
    this.closed = true;
    this.failAll(new Error('bridge closed'));
    try { this.child && this.child.kill(); } catch { /* ignore */ }
  }
}

async function createMcpHttpBridge(opts = {}) {
  const engine = opts.engine || createEngine({
    root: opts.root || process.cwd(),
    policy: {},
    logger: opts.logger || { log() {} },
  });
  const bridge = new StdioMcpBridge({ ...opts, engine });
  await bridge.start();
  const clients = new Set();
  const onStream = opts.onStream || ((req, res) => {
    res.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache',
      connection: 'keep-alive',
    });
    res.write(': connected\n\n');
    clients.add(res);
    req.on('close', () => clients.delete(res));
  });
  bridge.onEvent = (message) => {
    // Inspect server-originated requests/notifications before they reach an
    // SSE client. A blocked event is replaced with an error/removal.
    let inspected = { forward: true, message };
    try { if (engine && message) inspected = engine.onServerMessage(bridge.serverName, message); } catch { inspected = { forward: false }; }
    if (inspected.forward === false) return;
    const payload = JSON.stringify(inspected.message || message);
    for (const client of clients) {
      try { client.write(`event: message\ndata: ${payload}\n\n`); } catch { clients.delete(client); }
    }
  };
  const gateway = await createHttpGateway({
    host: opts.host,
    port: opts.port,
    authority: opts.authority,
    jwt: opts.jwt,
    policy: opts.policy,
    handler: async (message) => {
      if (!message.method && message.id != null) {
        bridge.send(message);
        return undefined;
      }
      const response = await bridge.request(message);
      if (response.error) {
        throw new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, response.error.message || 'upstream error', { status: 502 });
      }
      return response.result;
    },
    onStream,
  });
  return {
    bridge,
    gateway,
    url: gateway.url,
    close: async () => {
      for (const client of clients) { try { client.end(); } catch { /* ignore */ } }
      clients.clear();
      bridge.close();
      await gateway.close();
    },
  };
}

module.exports = { StdioMcpBridge, createMcpHttpBridge };
