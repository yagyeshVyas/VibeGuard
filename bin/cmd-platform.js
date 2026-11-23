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
const http = require('http');
const { verifyPolicy, loadPolicyFile, signPolicy } = require('../src/platform/policy');
const { SignedAuditLog } = require('../src/platform/signed-audit');
const { publicKeyToJwk, publicKeyToPem, loadPublicKey, generateKeyPair, IdentityAuthority } = require('../src/platform/identity');
const { ApprovalBroker } = require('../src/platform/approval');
const { actionDigest } = require('../src/platform/canonical');
const { createApprovalService, hashPassword } = require('../src/platform/approval-service');

function out(text) { process.stdout.write(text + '\n'); }
function err(text) { process.stderr.write(text + '\n'); }

function splitList(value) {
  return String(value || '').split(',').map((x) => x.trim()).filter(Boolean);
}

function readKeyFlag(value, label) {
  if (!value) throw new Error(`${label} is required`);
  return fs.readFileSync(path.resolve(String(value)));
}

function parseAction(flags) {
  const raw = flags.action || flags['action-json'];
  if (!raw) throw new Error('--action <json> is required');
  const text = String(raw).startsWith('@') ? fs.readFileSync(path.resolve(String(raw).slice(1)), 'utf8') : String(raw);
  try { return JSON.parse(text); } catch (e) { throw new Error(`invalid --action JSON: ${e.message}`); }
}

function httpJson(url, { method = 'GET', token, cookie, body, timeout = 15000 } = {}) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); } catch { return reject(new Error(`invalid URL: ${url}`)); }
    const payload = body === undefined ? null : JSON.stringify(body);
    const headers = { accept: 'application/json' };
    if (payload !== null) {
      headers['content-type'] = 'application/json';
      headers['content-length'] = Buffer.byteLength(payload);
    }
    if (token) headers.authorization = `Bearer ${token}`;
    if (cookie) headers.cookie = cookie;
    const req = http.request({ hostname: u.hostname, port: u.port, path: u.pathname + u.search, method, headers, agent: false }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        let parsed = null;
        try { parsed = data ? JSON.parse(data) : null; } catch { parsed = { raw: data }; }
        resolve({ status: res.statusCode, headers: res.headers, body: parsed });
      });
    });
    req.on('error', reject);
    req.setTimeout(timeout, () => req.destroy(new Error('request timed out')));
    if (payload !== null) req.write(payload);
    req.end();
  });
}

function approvalUsage() {
  return [
    'Usage: vibeguard approval <serve|issue|request|status|list|decide|verify|hash-password> [options]',
    '  serve          --users users.json [--signing-keys keys.json] [--key approval.pem] [--identity-key identity.pem] [--store approvals.json] [--audit audit.jsonl] [--port 8787] [--host 127.0.0.1]',
    '  issue          --key identity.pem --principal agent:acme/ci [--capabilities approval.request,approval.read] [--issuer human:acme/security] [--tenant acme] [--ttl 300]',
    '  request        --url http://127.0.0.1:8787 --token <agent-token> --action <json> [--reason text] [--ttl 300]',
    '  status         --url ... --token <token> --ticket tkt_...',
    '  list           --url ... --token <token>',
    '  decide         --url ... --ticket tkt_... (--password <pw> --principal human:acme/alice | --token <human-token> --proof <VGAPPROVER>) [--deny] [--reason text]',
    '  verify         --token <VGAPPROVAL> --pub approval.pub.pem --action <json> [--issuer ...] [--tenant ...] [--used used.json]',
    '  hash-password  (password from VG_APPROVAL_PASSWORD or stdin; prints a scrypt hash for users.json)',
  ].join('\n');
}

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
      const { WindowsAppContainerSandbox } = require('../src/platform/windows-appcontainer');
      backend = new WindowsAppContainerSandbox();
    } else if (process.platform === 'darwin') {
      const { MacVMSandbox } = require('../src/platform/macos-vm');
      backend = new MacVMSandbox();
    } else {
      const { getLinuxBackend } = require('../src/platform/os-sandbox');
      backend = getLinuxBackend();
    }
    const ok = await backend.verify();
    out(JSON.stringify({ backend: backend.id, isolationClass: backend.isolationClass, verified: ok, verification: backend.verification, verifiedAt: backend.verifiedAt, evidence: backend.evidence, limitations: backend.limitations }, null, 2));
    return ok ? 0 : 1;
  }
  if (action === 'backends') {
    const { defaultManager } = require('../src/platform/sandbox-manager');
    const data = defaultManager().list();
    if (flags.json) out(JSON.stringify(data, null, 2));
    else {
      out('Sandbox backends:');
      for (const b of data) out(`  ${b.id.padEnd(20)} class=${b.isolationClass.padEnd(12)} verified=${b.verified ? 'yes' : 'NO'}  ${b.limitations.join('; ')}`);
      const verified = data.filter((b) => b.verified);
      out(verified.length
        ? `Verified on this host: ${verified.map((b) => `${b.id} (${b.isolationClass})`).join(', ')}`
        : 'No OS-level backend is verified on this host. Run "vibeguard sandbox verify" and do not claim isolation until it passes.');
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
  if (cmd === 'approval') return cmdApproval(args, flags);
  if (cmd === 'sandbox' && (args._[1] === 'backends' || args._[1] === 'verify')) return cmdSandbox(args, flags);
  process.stderr.write('Usage: vibeguard <policy|audit|approval|sandbox>\n');
  return 2;
}


async function cmdApproval(args, flags) {
  const action = args._[1] || 'help';
  if (action === 'help' || flags.help) { out(approvalUsage()); return 0; }

  if (action === 'hash-password') {
    let password = flags.password || process.env.VG_APPROVAL_PASSWORD;
    if (!password && !process.stdin.isTTY) {
      try { password = fs.readFileSync(0, 'utf8').trim(); } catch { /* fallthrough */ }
    }
    if (!password) { err('set VG_APPROVAL_PASSWORD or pipe the password on stdin'); return 2; }
    out(hashPassword(password));
    return 0;
  }

  if (action === 'serve') {
    const tenant = flags.tenant || 'local';
    const issuer = flags.issuer || `human:${tenant}/approval`;
    const brokerIssuer = flags['approval-issuer'] || issuer;
    const brokerKey = flags.key ? readKeyFlag(flags.key, '--key') : generateKeyPair().privateKey;
    const identityKey = flags['identity-key'] ? readKeyFlag(flags['identity-key'], '--identity-key') : generateKeyPair().privateKey;
    const authority = new IdentityAuthority({ issuer, tenant, privateKey: identityKey, keyId: flags['key-id'] || undefined });
    const broker = new ApprovalBroker({ issuer: brokerIssuer, tenant, privateKey: brokerKey, keyId: flags['approval-key-id'] || flags['key-id'] || undefined });
    const signingKeys = {};
    if (flags['signing-keys']) {
      let mapping;
      try { mapping = JSON.parse(fs.readFileSync(path.resolve(flags['signing-keys']), 'utf8')); } catch (e) { err(`cannot read --signing-keys: ${e.message}`); return 2; }
      for (const [principal, keyPath] of Object.entries(mapping)) {
        if (!String(principal).startsWith('human:')) { err(`signing key principal must be human: ${principal}`); return 2; }
        try { signingKeys[principal] = fs.readFileSync(path.resolve(keyPath), 'utf8'); } catch (e) { err(`cannot read signing key for ${principal}: ${e.message}`); return 2; }
      }
    }
    const usersFile = flags.users ? path.resolve(flags.users) : undefined;
    if (!usersFile && !flags['allow-bearer-only']) err('warning: no --users file; browser login is disabled and only bearer human tokens can decide');
    const storeFile = path.resolve(flags.store || path.join(process.cwd(), '.vibeguard', 'approvals.json'));
    const auditFile = path.resolve(flags.audit || path.join(path.dirname(storeFile), 'approval-audit.jsonl'));
    const service = await createApprovalService({
      broker,
      authority,
      storeFile,
      auditFile,
      usersFile,
      approverSigningKeys: signingKeys,
      adminPrincipals: splitList(flags.admin),
      host: flags.host || '127.0.0.1',
      port: flags.port || 8787,
      allowRemote: flags['allow-remote'] === true,
      secureCookies: flags['secure-cookies'] === true,
      sessionTtlSeconds: flags['session-ttl'] ? Number(flags['session-ttl']) : undefined,
      requiredApprovals: flags.required ? Number(flags.required) : undefined,
      allowClientQuorum: flags['allow-client-quorum'] === true,
    });
    out(JSON.stringify({
      url: service.url,
      tenant,
      issuer,
      approvalPublicKey: publicKeyToPem(broker.publicKey),
      identityPublicKey: publicKeyToPem(authority.publicKey),
      auditPublicKey: service.audit ? publicKeyToPem(service.audit.publicKey) : null,
      store: storeFile,
      audit: auditFile,
      note: 'Keep private keys out of the agent runtime. Use approval issue to mint short-lived agent tokens.',
    }, null, 2));
    const shutdown = () => { service.close().finally(() => process.exit(0)); };
    process.once('SIGINT', shutdown);
    process.once('SIGTERM', shutdown);
    // Keep the CLI process alive while the HTTP service is running; main()
    // calls process.exit() after the command returns, so return a pending
    // promise and let the signal handler shut the service down.
    return new Promise(() => {});
  }

  if (action === 'issue') {
    const tenant = flags.tenant || 'local';
    const issuer = flags.issuer || `human:${tenant}/security`;
    if (!flags.key) { err('--key <identity-private.pem> is required'); return 2; }
    const authority = new IdentityAuthority({ issuer, tenant, privateKey: readKeyFlag(flags.key, '--key'), keyId: flags['key-id'] || undefined });
    const principal = flags.principal;
    if (!principal) { err('--principal is required'); return 2; }
    const defaults = String(principal).startsWith('human:') ? 'approval.decide,approval.read' : 'approval.request,approval.read';
    const capabilities = splitList(flags.capabilities || defaults);
    const t = authority.issue({ principal, capabilities, ttlSeconds: flags.ttl ? Number(flags.ttl) : 300 });
    out(JSON.stringify({ token: t.token, principal, capabilities, expiresAt: t.payload.exp, publicKey: publicKeyToPem(authority.publicKey) }, null, 2));
    return 0;
  }

  if (action === 'request') {
    const url = String(flags.url || 'http://127.0.0.1:8787').replace(/\/$/, '') + '/approval/request';
    if (!flags.token) { err('--token <agent-token> is required'); return 2; }
    const r = await httpJson(url, { method: 'POST', token: flags.token, body: {
      action: parseAction(flags),
      reason: flags.reason,
      ttlSeconds: flags.ttl ? Number(flags.ttl) : undefined,
      requiredApprovals: flags.required ? Number(flags.required) : undefined,
    } });
    out(JSON.stringify(r.body, null, 2));
    return r.status >= 200 && r.status < 300 ? 0 : 1;
  }

  if (action === 'status') {
    if (!flags.token || !flags.ticket) { err('--token and --ticket are required'); return 2; }
    const url = String(flags.url || 'http://127.0.0.1:8787').replace(/\/$/, '') + '/approval/ticket/' + encodeURIComponent(flags.ticket);
    const r = await httpJson(url, { token: flags.token });
    out(JSON.stringify(r.body, null, 2));
    return r.status >= 200 && r.status < 300 ? 0 : 1;
  }

  if (action === 'list') {
    if (!flags.token) { err('--token is required'); return 2; }
    const url = String(flags.url || 'http://127.0.0.1:8787').replace(/\/$/, '') + '/approval/tickets';
    const r = await httpJson(url, { token: flags.token });
    out(JSON.stringify(r.body, null, 2));
    return r.status >= 200 && r.status < 300 ? 0 : 1;
  }

  if (action === 'decide') {
    if (!flags.ticket) { err('--ticket is required'); return 2; }
    const base = String(flags.url || 'http://127.0.0.1:8787').replace(/\/$/, '');
    let r;
    if (flags.token) {
      if (!flags.proof) { err('--proof <VGAPPROVER> is required with --token'); return 2; }
      r = await httpJson(base + '/approval/decision', { method: 'POST', token: flags.token, body: {
        ticketId: flags.ticket,
        approve: flags.deny !== true,
        proof: flags.proof,
        reason: flags.reason,
      } });
    } else {
      const password = flags.password || process.env.VG_APPROVAL_PASSWORD;
      if (!password || !flags.principal) { err('--principal and --password (or VG_APPROVAL_PASSWORD) are required'); return 2; }
      const login = await httpJson(base + '/auth/login', { method: 'POST', body: { principal: flags.principal, password } });
      if (login.status !== 200) { out(JSON.stringify(login.body, null, 2)); return 1; }
      const setCookie = login.headers['set-cookie'] || [];
      const cookieHeader = (Array.isArray(setCookie) ? setCookie : [setCookie]).map((c) => String(c).split(';')[0]).join('; ');
      r = await httpJson(base + '/approval/decision', { method: 'POST', body: {
        ticketId: flags.ticket,
        decision: flags.deny === true ? 'deny' : 'approve',
        reason: flags.reason,
        _csrf: login.body.csrfToken,
      }, cookie: cookieHeader });
    }
    out(JSON.stringify(r.body, null, 2));
    return r.status >= 200 && r.status < 300 ? 0 : 1;
  }

  if (action === 'verify') {
    if (!flags.token || !flags.pub) { err('--token and --pub are required'); return 2; }
    const tenant = flags.tenant || 'local';
    const broker = new ApprovalBroker({
      issuer: flags.issuer || `human:${tenant}/approval`,
      tenant,
      publicKey: loadPublicKey(readKeyFlag(flags.pub, '--pub')),
      usedTokensFile: flags.used ? path.resolve(flags.used) : undefined,
    });
    const digest = actionDigest(parseAction(flags));
    const result = broker.verifyStandalone(flags.token, digest);
    out(JSON.stringify(result, null, 2));
    return 0;
  }

  err(approvalUsage());
  return 2;
}

module.exports = { cmdPolicy, cmdAuditVerify, cmdSandbox, cmdAisvs, cmdPlatform, cmdApproval, publicKeyToJwk };
