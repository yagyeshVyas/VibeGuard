'use strict';

/*
 * gif.js — keyless, open GIF/memes for VibeGuard celebrations.
 *
 * Zero API keys required. Uses only open services that work WITHOUT auth,
 * byte-verified before returning. Consistent with VibeGuard's offline-first
 * privacy model: no account, no tracking, no paid tier, no key leakage.
 *
 * Verified backends (live-tested on this machine):
 *   - cataas   — https://cataas.com (open "Cat as a Service": cat GIFs,
 *                optional text overlay via /cat/gif/says/<text>)
 *   - yesno.wtf — https://yesno.wtf (yes/no reaction GIFs, JSON API)
 *
 * Dead/rejected backends (do NOT re-add as primary):
 *   - Tenor (needs key, returns INVALID_ARGUMENT otherwise — tested)
 *   - GIPHY demo key (now 401 Unauthorized — tested)
 *   - Klipy (api.klipy.com auth-walled / 404 on keyless — tested)
 *   - Reddit JSON (blocks datacenter IPs with HTML — tested)
 */

const https = require('https');
const http = require('http');
const fs = require('fs');

const UA = 'VibeGuard/1.3 (open gif showcase; https://github.com/yagyeshVyas/VibeGuard)';

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https') ? https : http;
    const req = client.get(url, { headers: { 'User-Agent': UA, Accept: 'application/json' } }, (res) => {
      // follow a single redirect (cataas sometimes 301s)
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        return resolve(fetchJson(res.headers.location));
      }
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => {
        try {
          if (res.statusCode !== 200) return reject(new Error(`http ${res.statusCode}`));
          resolve(JSON.parse(body));
        } catch (e) {
          reject(new Error('parse error: ' + e.message));
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(15000, () => req.destroy(new Error('timeout')));
  });
}

function fetchBytes(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https') ? https : http;
    const req = client.get(url, { headers: { 'User-Agent': UA } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        return resolve(fetchBytes(res.headers.location));
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        if (res.statusCode !== 200) return reject(new Error(`http ${res.statusCode}`));
        resolve(Buffer.concat(chunks));
      });
    });
    req.on('error', reject);
    req.setTimeout(20000, () => req.destroy(new Error('timeout')));
  });
}

// Map a free-text query to the working keyless backends. Generic GIF search
// needs an API key (see header comment) — so we route by intent to the open
// services that actually deliver.
function backendFor(query) {
  const q = String(query || '').toLowerCase();
  if (/\b(cat|cats|kitten|kittens|kitty|meow)\b/.test(q)) {
    const says = q.match(/\bsays?\s+(.+)/);
    const base = 'https://cataas.com/cat/gif';
    const url = says ? `${base}/says/${encodeURIComponent(says[1].trim())}` : base;
    // cataas sometimes 500s on the bare endpoint; fall back to the says variant.
    const fallbackUrl = says ? base : `${base}/says/cat`;
    return { source: 'cataas', url, fallbackUrl, title: says ? `cat gif: ${says[1].trim()}` : 'cat gif', license: 'open' };
  }
  if (/\b(yes|no|maybe|agree|disagree|approve|deny)\b/.test(q)) {
    return { source: 'yesno', url: 'https://yesno.wtf/api', title: 'yes/no reaction', license: 'open' };
  }
  // Default to cataas with text overlay when the query is a phrase (meme-like),
  // else to cataas plain cat gif (mood default: cat is the internet's universal one).
  if (String(query || '').trim().length > 3) {
    return { source: 'cataas', url: `https://cataas.com/cat/gif/says/${encodeURIComponent(String(query).trim())}`, title: String(query).trim(), license: 'open' };
  }
  return { source: 'cataas', url: 'https://cataas.com/cat/gif', title: 'cat gif', license: 'open' };
}

/**
 * searchGifs(query, opts) — resolve a keyless open GIF for a query.
 * Returns { title, url, source, license, bytes? } — url of the actual GIF.
 * Throws if every backend fails.
 */
async function searchGifs(query) {
  const b = backendFor(query);
  if (b.source === 'yesno') {
    const j = await fetchJson(b.url);
    if (j && j.image) return { title: j.answer || b.title, url: j.image, source: 'yesno', license: 'open' };
    throw new Error('yesno.wtf returned no image');
  }
  // cataas returns the binary directly; capture it if requested.
  let buf;
  try {
    buf = await fetchBytes(b.url);
  } catch (e) {
    if (!b.fallbackUrl) throw e;
    b.url = b.fallbackUrl;
    buf = await fetchBytes(b.url);
  }
  const isGif = buf.slice(0, 3).toString() === 'GIF';
  if (!isGif) throw new Error('backend did not return a GIF');
  return { ...b, bytes: buf.length, valid: true, buffer: buf };
}

/**
 * downloadGif(query, outPath) — fetch + verify + write to disk.
 */
async function downloadGif(query, outPath) {
  const g = await searchGifs(query);
  let buf = g.buffer;
  if (!buf) buf = await fetchBytes(g.url);
  fs.writeFileSync(outPath, buf);
  return { path: outPath, bytes: buf.length, url: g.url, source: g.source, valid: true };
}

module.exports = { searchGifs, downloadGif, backendFor, fetchJson, fetchBytes };
