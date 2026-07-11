'use strict';

/*
 * Slopsquat detection — detect hallucinated/fictional npm packages.
 *
 * AI coding assistants sometimes "invent" package names that don't exist
 * on the npm registry. If a developer installs one, an attacker can register
 * it and plant malicious code (dependency confusion at the slopsquat level).
 *
 * Strategy:
 *   1. Parse imports/requires from source files
 *   2. Check each package against a known-good list (top 1000 npm packages)
 *   3. Query npm registry (HEAD /package-name) to verify existence
 *   4. Flag packages that don't exist on the registry
 */

const https = require('https');
const fs = require('fs');
const path = require('path');

const IMPORT_RE = /(?:require\s*\(\s*['"]([^'"]+)['"]\s*\)|import\s+(?:[\s\S]*?\s+from\s+)?['"]([^'"]+)['"])/g;
const SCOPED_RE = /^@([^/]+)\/([^/]+)/;

// Top npm packages that are definitely real — short-circuit registry calls
const KNOWN_PACKAGES = new Set([
  'react', 'react-dom', 'next', 'vue', 'vue-router', '@vue/server-renderer',
  'express', 'fastify', 'koa', 'hapi', '@hapi/hapi', 'polka',
  'axios', 'node-fetch', 'got', 'superagent', 'undici',
  'lodash', 'ramda', 'date-fns', 'dayjs', 'luxon', 'moment',
  'chalk', 'colorette', 'kleur', 'picocolors',
  'zod', 'joi', 'yup', 'ajv', 'io-ts',
  'prisma', '@prisma/client', 'drizzle-orm', 'kysely', 'mikro-orm',
  'hono', '@hono/node-server',
  'jsonwebtoken', 'bcrypt', 'bcryptjs', 'argon2', 'passport',
  'stripe', '@stripe/stripe-js',
  'openai', 'anthropic-ai/sdk', '@anthropic-ai/sdk',
  'dotenv', 'cross-env', 'rimraf', 'nanoid', 'uuid',
  'typescript', 'ts-node', 'tsx', 'esbuild', 'vite', 'webpack',
  'eslint', 'prettier', 'jest', 'vitest', 'mocha', 'chai',
  'tailwindcss', 'postcss', 'autoprefixer',
  'framer-motion', 'motion', '@radix-ui/react-dialog',
  'clsx', 'tailwind-merge', 'cva', 'class-variance-authority',
  'ws', 'socket.io', 'socket.io-client',
  'mongoose', 'mongodb', 'pg', 'mysql2', 'sqlite3', 'better-sqlite3',
  'redis', 'ioredis', '@upstash/redis',
  'graphql', '@apollo/server', 'urql', '@urql/core',
  'nexus', 'tRPC', '@trpc/server', '@trpc/client',
  'zustand', 'jotai', 'recoil', 'redux', '@reduxjs/toolkit', 'react-query', '@tanstack/react-query',
  'dompurify', 'sanitize-html', 'xss',
  'helmet', 'cors', 'compression', 'morgan', 'body-parser',
  'sharp', 'canvas', 'jimp',
  'resend', '@resend/resend-node',
  'convex', 'turso', '@libsql/client',
  'expo', 'expo-secure-store', 'expo-constants',
  'react-native', 'react-native-web',
  'clerk', '@clerk/nextjs', '@clerk/backend',
  'next-auth', '@auth/core',
  'better-auth',
  'firebase', 'firebase-admin',
  'pino', 'winston', 'debug',
  'glob', 'fast-glob', 'tinyglobby', 'chokidar',
  'commander', 'yargs', 'meow', 'cac',
  'ajv', 'ajv-formats',
  'seedrandom', 'nanoid-dictionary',
]);

function extractImports(content) {
  const pkgs = new Set();
  let m;
  while ((m = IMPORT_RE.exec(content)) !== null) {
    const pkg = m[1] || m[2];
    if (!pkg) continue;
    if (pkg.startsWith('.')) continue;
    if (pkg.startsWith('node:') || pkg.startsWith('bun:')) continue;
    const bare = pkg.split('/')[0];
    if (pkg.startsWith('@')) {
      const sm = SCOPED_RE.exec(pkg);
      if (sm) pkgs.add(`@${sm[1]}/${sm[2]}`);
    } else {
      pkgs.add(bare);
    }
  }
  return [...pkgs];
}

function checkNpmExists(pkgName) {
  return new Promise((resolve) => {
    if (KNOWN_PACKAGES.has(pkgName)) return resolve(true);
    const url = `https://registry.npmjs.org/${encodeURIComponent(pkgName).replace(/%2F/g, '/')}`;
    https
      .get(url, { timeout: 8000 }, (res) => {
        resolve(res.statusCode === 200);
      })
      .on('error', () => resolve(null))
      .on('timeout', function () {
        this.destroy();
        resolve(null);
      });
  });
}

async function scanSlopsquat(root, files) {
  const imports = new Set();
  for (const file of files) {
    try {
      const content = fs.readFileSync(file, 'utf8');
      for (const pkg of extractImports(content)) imports.add(pkg);
    } catch {}
  }

  const findings = [];
  const batch = [...imports];
  for (let i = 0; i < batch.length; i += 10) {
    const chunk = batch.slice(i, i + 10);
    const results = await Promise.all(
      chunk.map(async (pkg) => {
        const exists = await checkNpmExists(pkg);
        return { pkg, exists };
      })
    );
    for (const r of results) {
      if (r.exists === false) {
        findings.push({
          ruleId: 'supply-chain.slopsquat',
          file: 'imports',
          line: 1,
          column: 1,
          severity: 'medium',
          confidence: 'medium',
          title: `Possibly hallucinated package: ${r.pkg}`,
          snippet: r.pkg,
          message: `Package "${r.pkg}" does not exist on the npm registry. An attacker can register it and inject malicious code. If this is a private/internal package, configure your registry correctly.`,
          fix: `Verify the package name spelling. If internal, configure .npmrc scopes. If from an AI suggestion, remove it.`,
          owasp: 'A08:2025 Software and Data Integrity Failures',
          cwe: 'CWE-494',
        });
      }
    }
  }

  return { findings, checked: batch.length };
}

module.exports = { scanSlopsquat, extractImports, checkNpmExists, KNOWN_PACKAGES };
