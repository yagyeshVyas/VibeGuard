'use strict';

/*
 * bin/cmd-platform.js — CLI for the additive v2 security primitives:
 *   vibeguard policy validate <file> [--pub <pem>]
 *   vibeguard policy sign <file> --key <pem> [--out <file>]
 *   vibeguard audit verify <log> [--pub <pem>]
 *   vibeguard sandbox backends [--json]
 *
 * Legacy commands remain in bin/cli.js. Nothing here silently weakens them.
 */

const fs = require('fs');
const path = require('path');
const { verifyPolicy, loadPolicyFile, signPolicy } = require('../src/platform/policy');
const { SignedAuditLog } = require('../src/platform/signed-audit');
const { publicKeyToJwk, loadPublicKey } = require('../src/platform/identity');

function out(text) { process.stdout.write(text + '\n'); }

function cmdPolicy(args, flags) {
  const action = args._[1];
  const fileArg = args._[2] || flags.file;
  if (!action || !fileArg) {
    process.stderr.write('Usage: vibeguard policy <validate|sign> <file> [--pub key.pem] [--key private.pem] [--out file]\n');
    return 2;
  }
  const file = path.resolve(fileArg);
  let policy;
  try { policy = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (err) {
    process.stderr.write(`error: cannot read policy: ${err.message}\n`);
    return 2;
  }

  if (action === 'validate') {
    if (policy.schemaVersion !== '2.0') {
      process.stderr.write('INVALID: policy schemaVersion must be 2.0 (legacy .vibeguard-mcp.json is not a v2 policy)\n');
      return 1;
    }
    let verification = null;
    if (flags.pub) {
      verification = verifyPolicy(policy, { publicKey: loadPublicKey(fs.readFileSync(path.resolve(flags.pub))) });
    }
    if (policy.mode === 'strict' && !verification) {
      process.stderr.write('error: strict policy requires --pub for signature verification\n');
      return 1;
    }
    if (verification && !verification.valid) {
      process.stderr.write(`INVALID: ${verification.reason}\n`);
      return 1;
    }
    try {
      if (policy.mode === 'strict') loadPolicyFile(file, { publicKey: flags.pub ? loadPublicKey(fs.readFileSync(path.resolve(flags.pub))) : undefined });
      out(`valid policy: ${policy.policyId || '(no id)'} @ ${policy.policyVersion || '?'} mode=${policy.mode} signature=${verification ? 'verified' : policy.signature ? 'present-unverified' : 'none'}`);
      return 0;
    } catch (err) {
      process.stderr.write(`INVALID: ${err.message}\n`);
      return 1;
    }
  }

  if (action === 'sign') {
    if (!flags.key) {
      process.stderr.write('error: policy sign requires --key <private-key.pem>\n');
      return 2;
    }
    const privateKey = fs.readFileSync(path.resolve(flags.key));
    const signed = signPolicy(policy, { privateKey, keyId: flags['key-id'] || 'policy-key' });
    const outFile = fs.existsSync(file) && flags.out ? path.resolve(flags.out) : (flags.out ? path.resolve(flags.out) : file.replace(/\.json$/i, '') + '.signed.json');
    fs.writeFileSync(outFile, JSON.stringify(signed, null, 2) + '\n', { mode: 0o600 });
    out(`signed policy written to ${outFile}`);
    return 0;
  }
  process.stderr.write(`unknown policy action: ${action}\n`);
  return 2;
}

function cmdAuditVerify(args, flags) {
  const log = args._[1] || flags.file;
  if (!log) { process.stderr.write('Usage: vibeguard audit verify <log.jsonl> --pub <key.pem> [--anchor file] [--json]\n'); return 2; }
  const publicKey = flags.pub ? loadPublicKey(fs.readFileSync(path.resolve(flags.pub))) : undefined;
  const result = SignedAuditLog.verifyFile(path.resolve(log), { publicKey, anchorFile: flags.anchor ? path.resolve(flags.anchor) : undefined });
  if (flags.json) out(JSON.stringify({ ...result, signatureChecked: !!publicKey }, null, 2));
  else {
    out(`signed audit: ${publicKey ? (result.valid ? 'VALID' : 'INVALID') : 'UNVERIFIED'} — ${result.entries} entries`);
    if (!publicKey) out('  No --pub supplied: the hash chain was checked, but Ed25519 signatures were NOT verified.');
    for (const reason of result.reasons || []) out(`  ${reason}`);
  }
  return publicKey && result.valid ? 0 : 1;
}

async function cmdSandbox(args, flags) {
  const action = args._[1] || 'backends';
  if (action === 'verify') {
    let backend;
    if (process.platform === 'win32') {
      const { WindowsJobSandbox } = require('../src/platform/windows-sandbox');
      backend = new WindowsJobSandbox();
    } else {
      const { getLinuxBackend } = require('../src/platform/os-sandbox');
      backend = getLinuxBackend();
    }
    if (!backend.available()) { process.stderr.write('OS backend unavailable on this host\n'); return 2; }
    const ok = await backend.verify();
    out(JSON.stringify({ backend: backend.id, verified: ok, verification: backend.verification, limitations: backend.limitations }, null, 2));
    return ok ? 0 : 1;
  }
  if (action === 'backends') {
    const { defaultManager } = require('../src/platform/sandbox-manager');
    const data = defaultManager().list();
    if (flags.json) out(JSON.stringify(data, null, 2));
    else {
      out('Sandbox backends:');
      for (const b of data) out(`  ${b.id.padEnd(12)} class=${b.isolationClass.padEnd(9)} verified=${b.verified ? 'yes' : 'NO'}  ${b.limitations.join('; ')}`);
      out('No OS-level backend is verified in this build. Do not claim isolation.');
    }
    return 0;
  }
  process.stderr.write('Usage: vibeguard sandbox <backends|verify> [--json]\n');
  return 2;
}

function cmdAisvs(flags) {
  const { getAisvsReport } = require('../src/platform/aisvs');
  const r = getAisvsReport();
  if (flags.json) { out(JSON.stringify(r, null, 2)); return 0; }
  out(`${r.framework}`);
  out(`controls: ${r.controls.length} — ${JSON.stringify(r.counts)}`);
  for (const c of r.controls) out(`  ${c.id.padEnd(16)} ${c.status.padEnd(16)} ${c.title}`);
  return 0;
}

async function cmdPlatform(args, flags) {
  const cmd = args._[0];
  if (cmd === 'policy') return cmdPolicy(args, flags);
  if (cmd === 'audit') return cmdAuditVerify(args, flags);
  if (cmd === 'aisvs') return cmdAisvs(flags);
  if (cmd === 'sandbox' && (args._[1] === 'backends' || args._[1] === 'verify')) return cmdSandbox(args, flags);
  process.stderr.write('Usage: vibeguard <policy|audit|sandbox>\n');
  return 2;
}

module.exports = { cmdPolicy, cmdAuditVerify, cmdSandbox, cmdAisvs, cmdPlatform, publicKeyToJwk };
