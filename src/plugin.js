'use strict';

/*
 * Plugin system v2 for VibeGuard.
 *
 * Auto-discovers npm packages matching `vibeguard-rules-*` or `@vibeguard/rules-*`,
 * plus local paths from .vibeguardrc.json `plugins` array.
 *
 * A plugin exports an object:
 *   {
 *     name, version, description,
 *     rules: [lineRuleShape],          // v1 — line rules (regex per line)
 *     fileRules: [fileRuleShape],      // v2 — whole-file rules (run(content, lines, relPath))
 *     crossFileRules: [crossRuleShape], // v2 — cross-file rules (run(files) where files = [{rel, content}])
 *     astVisitors: [astVisitorShape],  // v2 — AST visitor functions (see ast.js)
 *     taintSources: [sourcePattern],   // v2 — additional taint source patterns (regex)
 *     taintSinks: [sinkShape],          // v2 — additional taint sinks
 *   }
 *
 * v1 plugins (rules-only) are fully backwards compatible.
 * v2 plugins can hook into file-level analysis, cross-file analysis, AST passes,
 * and the taint engine — extending VibeGuard's depth without forking core.
 *
 * Loaded plugins' rules are merged into the scanner at scan time.
 */

const fs = require('fs');
const path = require('path');

let _loaded = null;

function loadPlugins(root, config) {
  if (_loaded) return _loaded;
  _loaded = {
    rules: [],
    fileRules: [],
    crossFileRules: [],
    astVisitors: [],
    taintSources: [],
    taintSinks: [],
    errors: [],
  };

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
        // Resolve from the project root so node_modules inside root is searched
        try {
          mod = require(name);
        } catch {
          // Try resolving from the root directory
          const candidate = path.join(root, 'node_modules', name);
          mod = require(candidate);
        }
      }
      if (!mod) continue;

      // v1: line rules (backwards compatible)
      if (mod.rules && Array.isArray(mod.rules)) {
        _loaded.rules.push(...mod.rules);
      }

      // v2: file-level rules
      if (mod.fileRules && Array.isArray(mod.fileRules)) {
        _loaded.fileRules.push(...mod.fileRules);
      }

      // v2: cross-file rules
      if (mod.crossFileRules && Array.isArray(mod.crossFileRules)) {
        _loaded.crossFileRules.push(...mod.crossFileRules);
      }

      // v2: AST visitors
      if (mod.astVisitors && Array.isArray(mod.astVisitors)) {
        _loaded.astVisitors.push(...mod.astVisitors);
      }

      // v2: taint sources (additional regex patterns)
      if (mod.taintSources && Array.isArray(mod.taintSources)) {
        _loaded.taintSources.push(...mod.taintSources);
      }

      // v2: taint sinks (additional sink definitions)
      if (mod.taintSinks && Array.isArray(mod.taintSinks)) {
        _loaded.taintSinks.push(...mod.taintSinks);
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

function getPluginFileRules() {
  return _loaded ? _loaded.fileRules : [];
}

function getPluginCrossFileRules() {
  return _loaded ? _loaded.crossFileRules : [];
}

function getPluginAstVisitors() {
  return _loaded ? _loaded.astVisitors : [];
}

function getPluginTaintSources() {
  return _loaded ? _loaded.taintSources : [];
}

function getPluginTaintSinks() {
  return _loaded ? _loaded.taintSinks : [];
}

function getPluginErrors() {
  return _loaded ? _loaded.errors : [];
}

function resetPlugins() {
  _loaded = null;
}

module.exports = {
  loadPlugins,
  getPluginRules,
  getPluginFileRules,
  getPluginCrossFileRules,
  getPluginAstVisitors,
  getPluginTaintSources,
  getPluginTaintSinks,
  getPluginErrors,
  resetPlugins,
};
