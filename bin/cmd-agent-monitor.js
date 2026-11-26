'use strict';

/*
 * bin/cmd-agent-monitor.js — one-shot or live view of agent runtime events.
 *
 *   vibeguard agent-monitor [dir] [--json] [--audit file]
 *   vibeguard agent-monitor [dir] --watch [--interval 1000]
 *
 * In --watch mode this process stays alive and streams new audit entries.
 * The CLI main() must not call process.exit() for this command.
 */

const path = require('path');
const { analyzeMonitorLog, renderMonitor, watchAudit, formatEvent } = require('../src/agent-monitor');
const { exitWhenFlushed } = require('../src/cli-exit');

function cmdAgentMonitor(args, flags) {
  const root = path.resolve(flags.dir || args._[1] || '.');
  const auditFile = path.resolve(root, flags.audit || '.vibeguard/audit/mcp-firewall.jsonl');

  if (!flags.watch) {
    const report = analyzeMonitorLog(auditFile);
    if (flags.json) process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    else process.stdout.write(renderMonitor(report) + '\n');
    return report.exists ? (report.blocked > 0 || !report.chainValid ? 1 : 0) : 1;
  }

  const initial = analyzeMonitorLog(auditFile);
  if (!flags.json) {
    process.stdout.write(renderMonitor(initial) + '\n');
    process.stdout.write('\nwatching for new events (Ctrl+C to stop)\n\n');
  }
  const watcher = watchAudit(auditFile, {
    interval: Number(flags.interval || 1000),
    onEvent(entry) {
      if (flags.json) process.stdout.write(JSON.stringify(entry) + '\n');
      else process.stdout.write(formatEvent(entry) + '\n');
    },
  });
  // Drain the streamed events before leaving: process.exit() would drop what a
  // piped stdout still has queued.
  const stop = () => { watcher.stop(); exitWhenFlushed(0); };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
  return null; // keep running
}

module.exports = { cmdAgentMonitor };
