'use strict';

/*
 * bin/cmd-mcp-firewall.js — CLI for the real-time MCP firewall.
 *
 * Modes:
 *   vibeguard mcp-firewall --server <name>        proxy a configured server
 *   vibeguard mcp-firewall --exec "<command>"     proxy an ad-hoc server
 *   vibeguard mcp-firewall --selftest             run the offline checks
 *   vibeguard mcp-firewall --check '<json>'       evaluate one tool call
 *   vibeguard mcp-firewall --status               summarize the audit log
 *   vibeguard mcp-firewall --list-servers         show configured servers
 *
 * IMPORTANT: in proxy mode stdout is reserved for JSON-RPC. Every human
 * message goes to stderr. A banner on stdout would corrupt the agent session.
 */

const fs = require('fs');
const path = require('path');
const {
  startProxy,
  runSelfTest,
  renderSelfTest,
  resolveServer,
} = require('../src/mcp-firewall');
const { loadPolicy, describePolicy, evaluateToolCall, DEFAULT_POLICY } = require('../src/agent-policy');
const { analyzeMonitorLog, renderMonitor } = require('../src/agent-monitor');

function out(text) {
  process.stdout.write(text + '\n');
}

function listServers(root) {
  const rows = [];
  for (const rel of ['.mcp.json', '.cursor/mcp.json', '.vscode/mcp.json']) {
    const file = path.join(root, rel);
    let json;
    try { json = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { continue; }
    const servers = json.mcpServers || json.servers || {};
    for (const [name, cfg] of Object.entries(servers)) {
      rows.push({ name, file: rel, command: [cfg.command, ...(cfg.args || [])].filter(Boolean).join(' ') });
    }
  }
  return rows;
}

function cmdMcpFirewall(args, flags) {
  const root = path.resolve(flags.dir || args._[1] || '.');
  const json = !!flags.json;

  if (flags.init) {
    const target = path.resolve(root, flags.policy || '.vibeguard-mcp.json');
    if (fs.existsSync(target)) {
      process.stderr.write(`refusing to overwrite existing policy: ${target}\n`);
      return 1;
    }
    const { projectRoot: _projectRoot, ...defaults } = DEFAULT_POLICY;
    fs.writeFileSync(target, JSON.stringify(defaults, null, 2) + '\n', 'utf8');
    out(`Wrote default MCP firewall policy to ${target}`);
    out('Review deniedPaths / allowedHosts / tool rules, then start the proxy with --server <name>.');
    return 0;
  }

  if (flags.selftest || flags.test) {
    const result = runSelfTest();
    if (json) out(JSON.stringify(result, null, 2));
    else out(renderSelfTest(result));
    return result.passed === result.total ? 0 : 1;
  }

  if (flags['list-servers'] || flags.list) {
    const rows = listServers(root);
    if (json) {
      out(JSON.stringify(rows, null, 2));
      return 0;
    }
    if (!rows.length) {
      out('No MCP servers configured (.mcp.json / .cursor/mcp.json / .vscode/mcp.json).');
      return 1;
    }
    out('Configured MCP servers:');
    for (const row of rows) out(`  ${row.name.padEnd(24)} ${row.file}\n    ${row.command}`);
    return 0;
  }

  if (flags.status) {
    const report = analyzeMonitorLog(path.resolve(root, flags.audit || '.vibeguard/audit/mcp-firewall.jsonl'));
    if (json) out(JSON.stringify(report, null, 2));
    else out(renderMonitor(report));
    return report.exists ? 0 : 1;
  }

  if (flags.check) {
    let call;
    try {
      call = typeof flags.check === 'string' ? JSON.parse(flags.check) : null;
    } catch (err) {
      process.stderr.write(`error: --check must be JSON: ${err.message}\n`);
      return 2;
    }
    const server = call.server || flags.server || 'cli';
    const tool = call.tool || call.name || flags.tool;
    const callArgs = call.args || call.arguments || {};
    if (!tool) {
      process.stderr.write('error: --check needs a "tool" field\n');
      return 2;
    }
    const loaded = loadPolicy(root, flags.policy);
    const verdict = evaluateToolCall({ root, policy: loaded.policy, server, tool, args: callArgs });
    if (json) out(JSON.stringify({ ...verdict, policySource: loaded.source, policyError: loaded.error }, null, 2));
    else {
      out(`VibeGuard MCP firewall: ${verdict.action.toUpperCase()} — ${tool} (${verdict.capability})`);
      for (const v of verdict.violations) out(`  [${v.level}] ${v.id}: ${v.message}`);
      if (loaded.source) out(`  policy: ${loaded.source}`);
    }
    return verdict.blocked ? 2 : verdict.action === 'warn' ? 1 : 0;
  }

  if (flags.policy && !flags.server && !flags.exec && !flags.command) {
    // Policy inspection only.
    const loaded = loadPolicy(root, flags.policy);
    const summary = describePolicy(loaded.policy, loaded.source);
    if (json) out(JSON.stringify({ ...summary, error: loaded.error }, null, 2));
    else out(JSON.stringify(summary, null, 2));
    return loaded.error ? 1 : 0;
  }

  const serverName = flags.server || args._[1];
  const exec = flags.exec || flags.command;
  if (!serverName && !exec) {
    process.stderr.write(
      'Usage:\n' +
      '  vibeguard mcp-firewall --server <name> [--dir .] [--policy file]\n' +
      '  vibeguard mcp-firewall --exec "<command>" [--strict] [--signed-audit] [--kill-on-block]\n' +
      '  vibeguard mcp-firewall --exec "<command>" --token <VGAT> --token-pub key.pem --token-key-id k\n' +
      '  vibeguard mcp-firewall --exec "<command>" --approval-token <VGAPPROVAL> --approval-pub key.pem --approval-key-id a\n' +
      '  vibeguard mcp-firewall --exec "<command>" --token <VGAT> --token-pub key.pem\n' +
      '  vibeguard mcp-firewall --selftest [--json]\n' +
      '  vibeguard mcp-firewall --check \'{"tool":"read_file","args":{"path":".env"}}\'\n' +
      '  vibeguard mcp-firewall --status\n' +
      '  vibeguard mcp-firewall --list-servers\n'
    );
    return 2;
  }

  let serverDef;
  try {
    serverDef = resolveServer(root, { serverName, command: exec });
  } catch (err) {
    process.stderr.write(`error: ${err.message}\n`);
    return 2;
  }

  process.stderr.write(
    `VibeGuard MCP firewall — proxying "${serverDef.name}"\n` +
    `  command: ${serverDef.command} ${serverDef.args.join(' ')}\n` +
    `  audit:   ${path.resolve(root, flags.audit || ((flags.strict || flags['signed-audit']) ? '.vibeguard/audit/mcp-firewall.signed.jsonl' : '.vibeguard/audit/mcp-firewall.jsonl'))}\n`
  );

  const proxy = startProxy({
    root,
    serverName: serverName || undefined,
    command: exec || undefined,
    policyPath: flags.policy,
    auditFile: flags.audit || undefined,
    strict: flags.strict === true,
    signedAudit: flags['signed-audit'] === true,
    signedAuditFile: flags.audit || undefined,
    killOnBlock: flags['kill-on-block'] === true,
    token: flags.token,
    tokenPublicKey: flags['token-pub'],
    tokenIssuer: flags['token-issuer'],
    tokenTenant: flags['token-tenant'],
    tokenKeyId: flags['token-key-id'],
    approvalToken: flags['approval-token'],
    approvalPublicKey: flags['approval-pub'],
    approvalIssuer: flags['approval-issuer'],
    approvalTenant: flags['approval-tenant'],
    approvalKeyId: flags['approval-key-id'],
    maxBlocks: flags['max-blocks'] ? Number(flags['max-blocks']) : 0,
    maxRssMb: flags['max-rss'] ? Number(flags['max-rss']) : 0,
  });

  proxy.child.once('spawn', () => {
    process.stderr.write(`  firewall active (policy: ${proxy.engine.policySource || 'built-in defaults'})\n`);
  });

  // Keep the process alive; the proxy owns stdout/stdin from here.
  return null;
}

module.exports = { cmdMcpFirewall, listServers };
