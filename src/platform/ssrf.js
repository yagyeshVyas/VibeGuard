'use strict';

/*
 * src/platform/ssrf.js — destination validation for remote MCP/egress.
 *
 * Resolves a hostname and rejects private, loopback, link-local, metadata and
 * other non-public ranges. Returns a pinned IP that callers should connect to
 * (with the original Host/SNI) to reduce DNS-rebinding windows.
 *
 * This is a validation primitive, not a full HTTP client. It performs no
 * request itself and has no external dependencies.
 */

const dns = require('dns').promises;
const net = require('net');
const { ERROR_CODES, VibeGuardError } = require('./contracts');

const METADATA_HOSTS = new Set([
  'metadata.google.internal',
  'metadata.goog',
  '169.254.169.254',
  '100.100.100.200',
  'fd00:ec2::254',
]);

function ipv4ToInt(ip) {
  return ip.split('.').reduce((acc, n) => (acc << 8) + Number(n), 0) >>> 0;
}

function isPrivateIPv4(ip) {
  if (!net.isIPv4(ip)) return false;
  const v = ipv4ToInt(ip);
  const inRange = (base, bits) => {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (v & mask) === (ipv4ToInt(base) & mask);
  };
  return (
    inRange('0.0.0.0', 8) ||
    inRange('10.0.0.0', 8) ||
    inRange('100.64.0.0', 10) ||
    inRange('127.0.0.0', 8) ||
    inRange('169.254.0.0', 16) ||
    inRange('172.16.0.0', 12) ||
    inRange('192.0.0.0', 24) ||
    inRange('192.168.0.0', 16) ||
    inRange('198.18.0.0', 15) ||
    inRange('224.0.0.0', 4) ||
    inRange('240.0.0.0', 4)
  );
}

function isPrivateIPv6(ip) {
  if (!net.isIPv6(ip)) return false;
  const lower = ip.toLowerCase();
  if (lower === '::' || lower === '::1') return true;
  const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateIPv4(mapped[1]);
  if (/^fc|^fd/.test(lower)) return true; // unique local fc00::/7
  if (/^fe8|^fe9|^fea|^feb/.test(lower)) return true; // link-local fe80::/10
  if (lower.startsWith('2001:db8:')) return true; // documentation
  if (lower.startsWith('ff')) return true; // multicast
  return false;
}

function isPrivateAddress(ip) {
  return isPrivateIPv4(ip) || isPrivateIPv6(ip);
}

function hostMatches(host, patterns) {
  return (patterns || []).some((p) => {
    const pattern = String(p).toLowerCase();
    const h = String(host).toLowerCase();
    if (pattern === h) return true;
    if (pattern.startsWith('*.')) return h.endsWith(pattern.slice(1));
    return false;
  });
}

async function assertAllowedUrl(raw, opts = {}) {
  let url;
  try { url = new URL(String(raw)); } catch { throw new VibeGuardError(ERROR_CODES.SSRF_BLOCKED, 'invalid URL'); }
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new VibeGuardError(ERROR_CODES.SSRF_BLOCKED, `unsupported URL scheme: ${url.protocol}`);
  }
  if (url.username || url.password) throw new VibeGuardError(ERROR_CODES.SSRF_BLOCKED, 'URL credentials are not allowed');
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (METADATA_HOSTS.has(host)) throw new VibeGuardError(ERROR_CODES.SSRF_BLOCKED, 'cloud metadata endpoint is blocked by policy');
  if (Array.isArray(opts.allowedHosts) && opts.allowedHosts.length && !hostMatches(host, opts.allowedHosts)) {
    throw new VibeGuardError(ERROR_CODES.SSRF_BLOCKED, `host is not allowlisted: ${host}`);
  }
  if (hostMatches(host, opts.deniedHosts || [])) throw new VibeGuardError(ERROR_CODES.SSRF_BLOCKED, `host is denied: ${host}`);

  let addresses;
  if (net.isIP(host)) {
    addresses = [{ address: host, family: net.isIPv4(host) ? 4 : 6 }];
  } else {
    const resolver = opts.resolve || ((h) => dns.lookup(h, { all: true, verbatim: true }));
    try { addresses = await resolver(host); } catch (err) {
      throw new VibeGuardError(ERROR_CODES.SSRF_BLOCKED, `DNS resolution failed: ${err.message}`);
    }
  }
  if (!Array.isArray(addresses) || addresses.length === 0) {
    throw new VibeGuardError(ERROR_CODES.SSRF_BLOCKED, 'no DNS addresses');
  }
  const allowLoopback = opts.allowLoopback === true;
  const allowPrivate = opts.allowPrivate === true;
  for (const entry of addresses) {
    const ip = String(entry.address || entry);
    if (isPrivateAddress(ip)) {
      if (net.isIPv4(ip) && /^127\./.test(ip) && allowLoopback) continue;
      if (!allowPrivate) throw new VibeGuardError(ERROR_CODES.SSRF_BLOCKED, `private/loopback address blocked: ${ip}`);
    }
  }
  return {
    url: url.toString(),
    host,
    port: url.port ? Number(url.port) : (url.protocol === 'https:' ? 443 : 80),
    pinnedAddress: addresses[0].address || String(addresses[0]),
    addresses: addresses.map((a) => a.address || String(a)),
  };
}

module.exports = {
  assertAllowedUrl,
  isPrivateAddress,
  isPrivateIPv4,
  isPrivateIPv6,
  METADATA_HOSTS,
};
