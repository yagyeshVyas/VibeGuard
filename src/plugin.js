'use strict';

/*
 * Plugin system for VibeGuard.
 *
 * Auto-discovers npm packages matching `vibeguard-rules-*` or `@vibeguard/rules-*`,
 * plus local paths from .vibeguardrc.json `plugins` array.
 *
 * A plugin exports an object: { name, version, description, rules: [ruleShape] }
 * where ruleShape matches VibeGuard's line rule shape:
 *   { id, severity, confidence, title, re, skipComments, message, fix, owasp, cwe, compliance }
 *
 * Loaded plugins' rules are merged into the scanner's line rules at scan time.
 */

const fs = require('fs');
const path = require('path');

let _loaded = null;

function loadPlugins(root, config) {
  if (_loaded) return _loaded;
  _loaded = { rules: [], errors: [] };

  const pluginNames = [];
  // Auto-discovery: scan node_modules for vibeguard-rules-* / @vibeguard/rules-*
  try {
    const nmDir = path.join(root, 'node_modules');
    if (fs.existsSync(nmDir)) {
      for (const entry of fs.readdirSync(nmDir)) {
        if (entry.startsWith('vibeguard-rules-')) pluginNames.push(entry);
        if (entry.startsWith('@')) {
          const scopedDir = path.join(nmDir, entry);
          try {
            for (const sub of fs.readdirSync(scopedDir)) {
              if (entry === '@vibeguard' && sub.startsWith('rules-')) {
                pluginNames.push(`${entry}/${sub}`);
              }
            }
          } catch {}
        }
      }
    }
  } catch {}

  // Config-specified plugins
  if (config && Array.isArray(config.plugins)) {
    for (const p of config.plugins) {
      if (typeof p === 'string' && !pluginNames.includes(p)) pluginNames.push(p);
    }
  }

  for (const name of pluginNames) {
    try {
      let mod;
      if (name.startsWith('./') || name.startsWith('../') || name.startsWith('/')) {
        mod = require(path.resolve(root, name));
      } else {
        mod = require(name);
      }
      if (mod && mod.rules && Array.isArray(mod.rules)) {
        _loaded.rules.push(...mod.rules);
      }
    } catch (err) {
      _loaded.errors.push(`${name}: ${err.message}`);
    }
  }

  return _loaded;
}

function getPluginRules() {
  return _loaded ? _loaded.rules : [];
}

function resetPlugins() {
  _loaded = null;
}

module.exports = { loadPlugins, getPluginRules, resetPlugins };
