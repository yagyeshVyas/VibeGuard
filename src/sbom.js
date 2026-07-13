'use strict';

/*
 * VibeGuard SBOM Generator.
 *
 * Generates a CycloneDX 1.5 Software Bill of Materials from:
 * - package-lock.json (dependency tree with integrity hashes)
 * - Source code import/require graph (actual usage)
 *
 * 100% local. Zero network. Zero dependencies.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function readJsonSafe(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

function extractPackageName(spec) {
  // Handle scoped and non-scoped, strip version range chars
  const cleaned = spec.replace(/^[@\w/.-]+/, '').trim();
  return spec.split('@').filter(Boolean)[0] ? spec.startsWith('@')
    ? '@' + spec.split('@')[1]
    : spec.split('@')[0] : spec;
}

function parseLockfile(lockfile) {
  if (!lockfile) return [];
  const components = [];

  // lockfileVersion 2/3 (npm 7+)
  if (lockfile.packages) {
    for (const [pkgPath, info] of Object.entries(lockfile.packages)) {
      if (!pkgPath || pkgPath === '') continue;
      const name = pkgPath.replace(/^node_modules\//, '');
      if (!name || name.includes('node_modules/')) continue; // skip nested transitive for now
      components.push({
        name,
        version: info.version || 'unknown',
        type: 'library',
        'bom-ref': `pkg:npm/${name}@${info.version || 'unknown'}`,
        ...(info.license ? { licenses: [{ license: { id: info.license } }] } : {}),
        ...(info.resolved ? { externalReferences: [{ type: 'distribution', url: info.resolved }] } : {}),
        ...(info.integrity ? { hashes: [{ alg: info.integrity.split('-')[0] || 'sha512', content: info.integrity.split('-')[1] || '' }] } : {}),
      });
    }
    return components;
  }

  // lockfileVersion 1 (npm 5-6)
  if (lockfile.dependencies) {
    for (const [name, info] of Object.entries(lockfile.dependencies)) {
      components.push({
        name,
        version: info.version || 'unknown',
        type: 'library',
        'bom-ref': `pkg:npm/${name}@${info.version || 'unknown'}`,
        ...(info.resolved ? { externalReferences: [{ type: 'distribution', url: info.resolved }] } : {}),
        ...(info.integrity ? { hashes: [{ alg: info.integrity.split('-')[0] || 'sha512', content: info.integrity.split('-')[1] || '' }] } : {}),
      });
    }
    return components;
  }

  return components;
}

function parsePackageJson(pkgJson) {
  if (!pkgJson) return null;
  return {
    name: pkgJson.name || 'unnamed-project',
    version: pkgJson.version || '0.0.0',
    type: 'application',
    'bom-ref': `pkg:npm/${pkgJson.name || 'unnamed'}@${pkgJson.version || '0.0.0'}`,
    ...(pkgJson.license ? { licenses: [{ license: { id: pkgJson.license } }] } : {}),
  };
}

function buildImportGraph(dir) {
  const { walk } = require('./scanner');
  const files = walk(dir, []);
  const imports = {};

  for (const file of files) {
    if (!/\.(js|jsx|ts|tsx|mjs|cjs)$/.test(file)) continue;
    try {
      const content = fs.readFileSync(file, 'utf8');
      const relPath = path.relative(dir, file);

      // require('x') and require("x")
      const requireMatches = content.match(/require\(\s*['"]([^'"]+)['"]\s*\)/g) || [];
      for (const m of requireMatches) {
        const dep = m.match(/require\(\s*['"]([^'"]+)['"]\s*\)/);
        if (dep && !dep[1].startsWith('.') && !dep[1].startsWith('/')) {
          const pkgName = dep[1].startsWith('@') ? dep[1].split('/').slice(0, 2).join('/') : dep[1].split('/')[0];
          if (!imports[pkgName]) imports[pkgName] = [];
          if (!imports[pkgName].includes(relPath)) imports[pkgName].push(relPath);
        }
      }

      // import ... from 'x' and import 'x'
      const importMatches = content.match(/import\s+[^'"]*['"]([^'"]+)['"]/g) || [];
      for (const m of importMatches) {
        const dep = m.match(/['"]([^'"]+)['"]/);
        if (dep && !dep[1].startsWith('.') && !dep[1].startsWith('/')) {
          const pkgName = dep[1].startsWith('@') ? dep[1].split('/').slice(0, 2).join('/') : dep[1].split('/')[0];
          if (!imports[pkgName]) imports[pkgName] = [];
          if (!imports[pkgName].includes(relPath)) imports[pkgName].push(relPath);
        }
      }
    } catch {}
  }

  return imports;
}

function generateSBOM(dir) {
  const pkgJson = readJsonSafe(path.join(dir, 'package.json'));
  const lockfile = readJsonSafe(path.join(dir, 'package-lock.json'));
  const importGraph = buildImportGraph(dir);

  const rootComponent = parsePackageJson(pkgJson);
  const components = parseLockfile(lockfile);

  // Mark components as "used" if they appear in the import graph
  for (const comp of components) {
    if (importGraph[comp.name]) {
      comp.properties = comp.properties || [];
      comp.properties.push({ name: 'vibeguard:imported', value: 'true' });
      comp.properties.push({ name: 'vibeguard:imported_by', value: importGraph[comp.name].join(', ') });
    }
  }

  const bom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: 'urn:uuid:' + crypto.randomUUID(),
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: 'VibeGuard', name: 'vibeguard-sbom', version: '1.0.0' }],
      component: rootComponent || undefined,
    },
    components,
  };

  // Dependency references (flat — just root → each component)
  if (rootComponent && components.length > 0) {
    bom.dependencies = components.map(c => ({
      ref: rootComponent['bom-ref'],
      dependsOn: [c['bom-ref']],
    }));
  }

  return bom;
}

module.exports = { generateSBOM, parseLockfile, parsePackageJson, buildImportGraph };
