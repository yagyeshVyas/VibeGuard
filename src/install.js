'use strict';

/*
 * One-command installer: `vibeguard install`.
 *
 * Detects which AI coding clients are present and wires the VibeGuard MCP server
 * into each. It only WRITES config for clients whose config format/location is
 * known and stable; for anything else it prints a ready-to-paste block so you can
 * add it by hand (we don't write to guessed paths).
 *
 * Default server command is `npx -y vibeguard mcp` (works once published).
 * Use --local to point at this checkout's absolute mcp-server.js for dev.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const HOME = os.homedir();

function serverSpec(local) {
  if (local) {
    return { command: process.execPath, args: [path.resolve(__dirname, 'mcp-server.js')] };
  }
  // `npx -y vibeguard mcp` — resolves the published `vibeguard` package and runs
  // its `mcp` subcommand. (npx -y vibeguard-mcp would look for a package by that
  // name, which doesn't exist — the mcp bin lives inside the vibeguard package.)
  return { command: 'npx', args: ['-y', 'vibeguard', 'mcp'] };
}

function exists(p) {
  try {
    return fs.existsSync(p);
  } catch {
    return false;
  }
}

function backup(file) {
  try {
    if (exists(file)) fs.copyFileSync(file, file + '.vibeguard-bak');
  } catch {
    /* best effort */
  }
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return {};
  }
}

function ensureDir(file) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
}

// Merge a server entry into a JSON config using the given top-level key
// ("mcpServers" for most, "servers" for VS Code).
function writeJsonMcp(file, key, spec, name) {
  ensureDir(file);
  backup(file);
  const cfg = readJson(file);
  if (!cfg[key] || typeof cfg[key] !== 'object') cfg[key] = {};
  cfg[key][name] = { command: spec.command, args: spec.args };
  fs.writeFileSync(file, JSON.stringify(cfg, null, 2) + '\n');
  return file;
}

// -------- Per-client handlers ----------------------------------------------
// Each returns { client, status: 'installed'|'skipped'|'manual'|'error', detail }.

function installClaudeCode(spec) {
  // Write the project-scoped .mcp.json (Claude Code's documented config file) in
  // the current directory. No shelling out, no global side effects — this repo
  // gets the server, and we also print the global `claude mcp add` command.
  const file = path.join(process.cwd(), '.mcp.json');
  writeJsonMcp(file, 'mcpServers', spec, 'vibeguard');
  return {
    client: 'Claude Code',
    status: 'installed',
    detail: `${file} (project). Global: claude mcp add -s user vibeguard -- ${[spec.command, ...spec.args].join(' ')}`,
  };
}

function installCursor(spec) {
  const dir = path.join(HOME, '.cursor');
  if (!exists(dir)) return { client: 'Cursor', status: 'skipped', detail: 'not detected (~/.cursor missing)' };
  const file = path.join(dir, 'mcp.json');
  writeJsonMcp(file, 'mcpServers', spec, 'vibeguard');
  return { client: 'Cursor', status: 'installed', detail: file };
}

function installWindsurf(spec) {
  const dir = path.join(HOME, '.codeium', 'windsurf');
  if (!exists(path.join(HOME, '.codeium')))
    return { client: 'Windsurf', status: 'skipped', detail: 'not detected (~/.codeium missing)' };
  const file = path.join(dir, 'mcp_config.json');
  writeJsonMcp(file, 'mcpServers', spec, 'vibeguard');
  return { client: 'Windsurf', status: 'installed', detail: file };
}

function installCodex(spec) {
  const dir = path.join(HOME, '.codex');
  if (!exists(dir)) return { client: 'Codex CLI', status: 'skipped', detail: 'not detected (~/.codex missing)' };
  const file = path.join(dir, 'config.toml');
  let content = '';
  try {
    content = fs.readFileSync(file, 'utf8');
  } catch {
    content = '';
  }
  if (/\[mcp_servers\.vibeguard\]/.test(content)) {
    return { client: 'Codex CLI', status: 'installed', detail: 'already present in ' + file };
  }
  backup(file);
  const argsToml = spec.args.map((a) => JSON.stringify(a)).join(', ');
  const block =
    `\n[mcp_servers.vibeguard]\n` +
    `command = ${JSON.stringify(spec.command)}\n` +
    `args = [${argsToml}]\n`;
  ensureDir(file);
  fs.writeFileSync(file, (content && !content.endsWith('\n') ? content + '\n' : content) + block);
  return { client: 'Codex CLI', status: 'installed', detail: file };
}

function installVSCode(spec) {
  // VS Code (Copilot agent) reads workspace .vscode/mcp.json with a "servers" key.
  const file = path.join(process.cwd(), '.vscode', 'mcp.json');
  // Only write if a .vscode folder exists here (i.e. this is a VS Code project).
  if (!exists(path.join(process.cwd(), '.vscode'))) {
    return { client: 'VS Code', status: 'skipped', detail: 'no ./.vscode in this project' };
  }
  writeJsonMcp(file, 'servers', spec, 'vibeguard');
  return { client: 'VS Code', status: 'installed', detail: file };
}

function installAntigravity(spec) {
  // Google Antigravity uses ~/.antigravity/config.json with mcpServers key
  const dir = path.join(HOME, '.antigravity');
  if (!exists(dir)) return { client: 'Antigravity', status: 'skipped', detail: 'not detected (~/.antigravity missing)' };
  const file = path.join(dir, 'config.json');
  writeJsonMcp(file, 'mcpServers', spec, 'vibeguard');
  return { client: 'Antigravity', status: 'installed', detail: file };
}

function installContinue(spec) {
  // Continue.dev uses ~/.continue/config.json with mcpServers key
  const dir = path.join(HOME, '.continue');
  if (!exists(dir)) return { client: 'Continue', status: 'skipped', detail: 'not detected (~/.continue missing)' };
  const file = path.join(dir, 'config.json');
  writeJsonMcp(file, 'mcpServers', spec, 'vibeguard');
  return { client: 'Continue', status: 'installed', detail: file };
}

function installCline(spec) {
  // Cline (VS Code extension) uses cline_mcp_settings.json in VS Code user dir
  const dir = path.join(HOME, '.vscode', 'extensions');
  if (!exists(path.join(HOME, '.vscode')) && !exists(path.join(HOME, 'AppData', 'Roaming', 'Code')))
    return { client: 'Cline', status: 'skipped', detail: 'not detected (VS Code not found)' };
  // Cline stores MCP config in the VS Code userData directory
  const userDataDir = process.platform === 'win32'
    ? path.join(HOME, 'AppData', 'Roaming', 'Code', 'User')
    : path.join(HOME, '.vscode', 'User');
  if (!exists(userDataDir)) return { client: 'Cline', status: 'skipped', detail: 'VS Code User dir not found' };
  const file = path.join(userDataDir, 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json');
  writeJsonMcp(file, 'mcpServers', spec, 'vibeguard');
  return { client: 'Cline', status: 'installed', detail: file };
}

function installAider(spec) {
  // Aider uses ~/.aider.conf.yml — MCP via command launch
  const file = path.join(HOME, '.aider.conf.yml');
  if (!exists(file)) return { client: 'Aider', status: 'manual', detail: 'add --mcp to your aider launch or ~/.aider.conf.yml' };
  let content = '';
  try { content = fs.readFileSync(file, 'utf8'); } catch {}
  if (/vibeguard/.test(content)) return { client: 'Aider', status: 'installed', detail: 'already present' };
  backup(file);
  const block = `\n# VibeGuard MCP server\nmcp-command: ${spec.command}\nmcp-args: ${spec.args.join(' ')}\n`;
  fs.writeFileSync(file, content + block);
  return { client: 'Aider', status: 'installed', detail: file };
}

function installGeminiCLI(spec) {
  // Google Gemini CLI uses ~/.gemini/config.json with mcpServers key
  const dir = path.join(HOME, '.gemini');
  if (!exists(dir)) return { client: 'Gemini CLI', status: 'skipped', detail: 'not detected (~/.gemini missing)' };
  const file = path.join(dir, 'config.json');
  writeJsonMcp(file, 'mcpServers', spec, 'vibeguard');
  return { client: 'Gemini CLI', status: 'installed', detail: file };
}

function installRooCode(spec) {
  // Roo Code (VS Code extension) uses roo_cline_mcp_settings.json
  const userDataDir = process.platform === 'win32'
    ? path.join(HOME, 'AppData', 'Roaming', 'Code', 'User')
    : path.join(HOME, '.vscode', 'User');
  if (!exists(userDataDir)) return { client: 'Roo Code', status: 'skipped', detail: 'VS Code User dir not found' };
  const file = path.join(userDataDir, 'globalStorage', 'rooveterinaryinc.roo-cline', 'settings', 'roo_cline_mcp_settings.json');
  writeJsonMcp(file, 'mcpServers', spec, 'vibeguard');
  return { client: 'Roo Code', status: 'installed', detail: file };
}

function installOpenHands(spec) {
  // OpenHands uses ~/.openhands/config.toml similar to Codex
  const dir = path.join(HOME, '.openhands');
  if (!exists(dir)) return { client: 'OpenHands', status: 'skipped', detail: 'not detected (~/.openhands missing)' };
  const file = path.join(dir, 'config.toml');
  let content = '';
  try { content = fs.readFileSync(file, 'utf8'); } catch {}
  if (/\[mcp_servers\.vibeguard\]/.test(content)) return { client: 'OpenHands', status: 'installed', detail: 'already present' };
  backup(file);
  const argsToml = spec.args.map((a) => JSON.stringify(a)).join(', ');
  const block = `\n[mcp_servers.vibeguard]\ncommand = ${JSON.stringify(spec.command)}\nargs = [${argsToml}]\n`;
  ensureDir(file);
  fs.writeFileSync(file, (content && !content.endsWith('\n') ? content + '\n' : content) + block);
  return { client: 'OpenHands', status: 'installed', detail: file };
}

function pasteBlock(spec) {
  return JSON.stringify(
    { mcpServers: { vibeguard: { command: spec.command, args: spec.args } } },
    null,
    2
  );
}

function install(opts = {}) {
  const spec = serverSpec(opts.local);
  const results = [
    installClaudeCode(spec),
    installCursor(spec),
    installWindsurf(spec),
    installCodex(spec),
    installAntigravity(spec),
    installContinue(spec),
    installCline(spec),
    installAider(spec),
    installGeminiCLI(spec),
    installRooCode(spec),
    installOpenHands(spec),
    installVSCode(spec),
  ];
  return { spec, results, paste: pasteBlock(spec) };
}

module.exports = { install, serverSpec, pasteBlock, writeJsonMcp };
