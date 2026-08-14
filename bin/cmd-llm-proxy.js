'use strict';
const fs = require('fs');

// cmdLlmProxy — `vibeguard llm-proxy`: OpenAI-compatible runtime LLM guard proxy.
//
//   vibeguard llm-proxy
//   vibeguard llm-proxy --port 9000 --mode redact
//   vibeguard llm-proxy --upstream http://localhost:11434/v1 --api-key sk-...
//
// Any LLM client points base_url at http://127.0.0.1:<port>/v1 — VibeGuard
// scans every prompt AND response for prompt-injection / secrets / PII and
// blocks, redacts, or reports, then forwards to the real upstream.
// 100% local, free, zero deps. See src/llm-proxy.js for the server core.
//
// Returns 0 after starting (the server keeps the event loop alive), 2 on bad
// args. SIGINT/SIGTERM trigger a clean shutdown.

const { createGuardProxy, DEFAULT_PORT, DEFAULT_UPSTREAM, MODES } = require('../src/llm-proxy');

const USAGE = [
  'usage: vibeguard llm-proxy [--port <port>] [--upstream <base-url>] [--mode block|redact|report] [--api-key <key>]',
  '',
  'OpenAI-compatible local LLM guard proxy (Lakera Guard parity, 100% local).',
  'Point any OpenAI SDK client at http://127.0.0.1:<port>/v1 — VibeGuard scans',
  'every prompt and response for prompt-injection, secrets, and PII.',
  '',
  '  --port <n>       listen port (default 8443)',
  '  --upstream <url> upstream OpenAI-compatible base URL (default https://api.openai.com/v1)',
  '  --mode <mode>    block  — reject violating requests with 403 (default)',
  '                   redact — mask secrets/PII with [REDACTED:<ruleId>]',
  '                   report — never mutate, log violations, pass through',
  '  --api-key <key>  authorization header sent to upstream',
  '  --system-prompt-file <path>  detect the model echoing YOUR system prompt in outputs',
  '                   (default: forward the client\'s own Authorization header)',
  '',
  'examples:',
  '  vibeguard llm-proxy',
  '  vibeguard llm-proxy --port 9000 --upstream http://localhost:11434/v1 --mode redact',
  '',
].join('\n');

async function cmdLlmProxy(args, flags) {
  const f = flags || {};

  // --port
  let port = DEFAULT_PORT;
  if (f.port !== undefined) {
    port = Number(f.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      process.stderr.write(USAGE);
      process.stderr.write('llm-proxy: invalid --port (expected 1-65535)\n');
      return 2;
    }
  }

  // --upstream
  let upstream = DEFAULT_UPSTREAM;
  if (f.upstream !== undefined) {
    try {
      const u = new URL(String(f.upstream));
      if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('scheme');
      upstream = u.toString().replace(/\/+$/, '');
    } catch {
      process.stderr.write(USAGE);
      process.stderr.write('llm-proxy: invalid --upstream URL (expected http(s)://host[:port][/v1])\n');
      return 2;
    }
  }

  // --mode
  const mode = f.mode !== undefined ? String(f.mode) : 'block';
  if (!MODES.has(mode)) {
    process.stderr.write(USAGE);
    process.stderr.write(`llm-proxy: invalid --mode '${mode}' (expected block|redact|report)\n`);
    return 2;
  }

  // --api-key (accept both hyphenated and camelCase flag spellings)
  const apiKey =
    f['api-key'] !== undefined && f['api-key'] !== true ? String(f['api-key']) :
    f.apiKey !== undefined && f.apiKey !== true ? String(f.apiKey) :
    null;

  // --system-prompt-file: lines of YOUR system prompt; the proxy flags any
  // response that echoes one (prompt-leakage exfiltration).
  let systemPromptLines = [];
  if (f['system-prompt-file'] !== undefined && f['system-prompt-file'] !== true) {
    const spPath = String(f['system-prompt-file']);
    try {
      const raw = fs.readFileSync(spPath, 'utf8');
      systemPromptLines = raw.split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => l.length >= 16);
      if (systemPromptLines.length === 0) {
        process.stderr.write('llm-proxy: --system-prompt-file has no usable lines (min 16 chars each)\n');
        return 2;
      }
    } catch {
      process.stderr.write('llm-proxy: cannot read --system-prompt-file: ' + spPath + '\n');
      return 2;
    }
  }

  let gp;
  try {
    gp = createGuardProxy({ port, upstream, mode, apiKey, systemPromptLines });
  } catch (err) {
    process.stderr.write(`llm-proxy: ${err && err.message ? err.message : err}\n`);
    return 2;
  }

  gp.server.once('listening', () => {
    process.stdout.write(`[llm-proxy] listening on http://127.0.0.1:${gp.port}/v1 (mode: ${mode})\n`);
    process.stdout.write(`[llm-proxy] upstream: ${upstream}\n`);
    process.stdout.write(`[llm-proxy] point clients at base_url http://127.0.0.1:${gp.port}/v1 — Ctrl+C to stop\n`);
  });
  gp.server.on('error', (err) => {
    process.stderr.write(`llm-proxy: ${err && err.message ? err.message : err}\n`);
    process.exit(2);
  });

  let shuttingDown = false;
  const shutdown = () => {
    if (shuttingDown) return;
    shuttingDown = true;
    gp.close()
      .then(() => process.exit(0))
      .catch(() => process.exit(0));
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  return 0;
}

// Direct invocation: `node bin/cmd-llm-proxy.js [--port ...] ...`
if (require.main === module) {
  const argv = process.argv.slice(2);
  const flags = {};
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq !== -1) {
        flags[a.slice(2, eq)] = a.slice(eq + 1);
      } else {
        const name = a.slice(2);
        if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) {
          flags[name] = argv[++i];
        } else {
          flags[name] = true;
        }
      }
    } else {
      positional.push(a);
    }
  }
  cmdLlmProxy({ _: positional }, flags).then((code) => {
    if (code !== 0) process.exit(code);
  });
}

module.exports = { cmdLlmProxy };
