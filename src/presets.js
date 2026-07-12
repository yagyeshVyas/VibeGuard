'use strict';

/*
 * VibeGuard Rule Pack Presets.
 *
 * Pre-configured rule sets for common stacks. Users can apply a preset
 * to quickly enable only the rules relevant to their technology stack,
 * reducing noise and improving signal-to-noise ratio.
 *
 * Usage: vibeguard preset nextjs
 *        vibeguard preset django
 *        vibeguard preset aws
 */

const PRESETS = {
  nextjs: {
    name: 'Next.js + React',
    description: 'Rules for Next.js apps with React, API routes, Server Actions',
    include: ['nextjs.', 'react.', 'authjs.', 'clerk.', 'supabase.', 'stripe.', 'resend.', 'uploadthing.', 'ai.', 'secret.', 'injection.', 'code.', 'web.', 'cookie.', 'csp.', 'header.', 'data.', 'deploy.vercel'],
    exclude: ['go.', 'ruby.', 'php.', 'java.', 'rust.', 'kotlin.', 'swift.', 'django.', 'flask.', 'rails.', 'laravel.', 'spring.', 'tf.', 'k8s.'],
  },
  react: {
    name: 'React SPA',
    description: 'Rules for React single-page apps',
    include: ['react.', 'xss.', 'secret.', 'injection.', 'code.', 'web.', 'cookie.', 'csp.', 'data.'],
    exclude: ['go.', 'ruby.', 'php.', 'java.', 'rust.', 'kotlin.', 'swift.', 'django.', 'flask.', 'rails.', 'laravel.', 'spring.', 'tf.', 'k8s.', 'nextjs.'],
  },
  django: {
    name: 'Django + Python',
    description: 'Rules for Django web apps',
    include: ['django.', 'py.', 'secret.', 'injection.', 'code.', 'web.', 'cookie.', 'data.', 'auth.', 'crypto.'],
    exclude: ['go.', 'ruby.', 'php.', 'java.', 'rust.', 'kotlin.', 'swift.', 'react.', 'nextjs.', 'clerk.', 'authjs.', 'drizzle.', 'prisma.', 'hono.', 'trpc.'],
  },
  flask: {
    name: 'Flask + Python',
    description: 'Rules for Flask web apps',
    include: ['flask.', 'py.', 'secret.', 'injection.', 'code.', 'web.', 'cookie.', 'data.', 'auth.', 'crypto.'],
    exclude: ['go.', 'ruby.', 'php.', 'java.', 'rust.', 'kotlin.', 'swift.', 'react.', 'nextjs.', 'django.', 'clerk.', 'authjs.', 'drizzle.', 'prisma.', 'hono.', 'trpc.'],
  },
  rails: {
    name: 'Ruby on Rails',
    description: 'Rules for Rails web apps',
    include: ['rails.', 'ruby.', 'secret.', 'injection.', 'code.', 'web.', 'cookie.', 'data.', 'auth.', 'crypto.'],
    exclude: ['go.', 'py.', 'php.', 'java.', 'rust.', 'kotlin.', 'swift.', 'react.', 'nextjs.', 'django.', 'flask.', 'clerk.', 'authjs.', 'drizzle.', 'prisma.', 'hono.', 'trpc.'],
  },
  spring: {
    name: 'Spring Boot + Java',
    description: 'Rules for Spring Boot Java apps',
    include: ['spring.', 'java.', 'secret.', 'injection.', 'code.', 'web.', 'cookie.', 'data.', 'auth.', 'crypto.'],
    exclude: ['go.', 'py.', 'ruby.', 'php.', 'rust.', 'kotlin.', 'swift.', 'react.', 'nextjs.', 'django.', 'flask.', 'rails.', 'clerk.', 'authjs.', 'drizzle.', 'prisma.', 'hono.', 'trpc.'],
  },
  aws: {
    name: 'AWS Infrastructure',
    description: 'Rules for AWS/Terraform infrastructure',
    include: ['tf.', 'cloud.', 'secret.aws', 'deploy.k8s', 'deploy.docker', 'k8s.', 'docker.', 'compose.'],
    exclude: ['react.', 'nextjs.', 'django.', 'flask.', 'rails.', 'spring.', 'clerk.', 'authjs.', 'hono.', 'trpc.', 'drizzle.', 'prisma.', 'sveltekit.', 'nuxt.', 'astro.'],
  },
  gcp: {
    name: 'GCP Infrastructure',
    description: 'Rules for Google Cloud Platform',
    include: ['tf.', 'cloud.', 'secret.gcp', 'deploy.k8s', 'deploy.docker', 'k8s.', 'docker.', 'compose.'],
    exclude: ['react.', 'nextjs.', 'django.', 'flask.', 'rails.', 'spring.', 'clerk.', 'authjs.', 'hono.', 'trpc.', 'drizzle.', 'prisma.', 'sveltekit.', 'nuxt.', 'astro.'],
  },
  azure: {
    name: 'Azure Infrastructure',
    description: 'Rules for Azure infrastructure',
    include: ['tf.', 'cloud.', 'secret.azure', 'deploy.k8s', 'deploy.docker', 'k8s.', 'docker.', 'compose.'],
    exclude: ['react.', 'nextjs.', 'django.', 'flask.', 'rails.', 'spring.', 'clerk.', 'authjs.', 'hono.', 'trpc.', 'drizzle.', 'prisma.', 'sveltekit.', 'nuxt.', 'astro.'],
  },
  api: {
    name: 'API Server',
    description: 'Rules for REST/GraphQL API servers',
    include: ['api.', 'auth.', 'secret.', 'injection.', 'code.', 'web.', 'cookie.', 'data.', 'graphql.', 'ws.', 'header.', 'crypto.', 'error.', 'ratelimit.', 'validation.', 'dos.'],
    exclude: ['react.', 'nextjs.', 'mobile.', 'go.', 'rust.', 'kotlin.', 'swift.', 'rails.', 'laravel.', 'spring.', 'tf.', 'k8s.', 'docker.', 'compose.'],
  },
  mobile: {
    name: 'Mobile App',
    description: 'Rules for React Native / native mobile apps',
    include: ['mobile.', 'react.', 'secret.', 'injection.', 'data.', 'auth.', 'crypto.', 'xss.'],
    exclude: ['go.', 'ruby.', 'php.', 'java.', 'rust.', 'django.', 'flask.', 'rails.', 'laravel.', 'spring.', 'tf.', 'k8s.', 'docker.', 'compose.', 'nextjs.', 'graphql.', 'ws.', 'deploy.'],
  },
  fullstack: {
    name: 'Full Stack (all rules)',
    description: 'All rules enabled — maximum coverage',
    include: ['*'],
    exclude: [],
  },
};

function listPresets() {
  return Object.entries(PRESETS).map(([key, p]) => ({
    key,
    name: p.name,
    description: p.description,
    includeCount: p.include.length,
    excludeCount: p.exclude.length,
  }));
}

function getPreset(key) {
  return PRESETS[key] || null;
}

function applyPreset(key) {
  const preset = PRESETS[key];
  if (!preset) return null;
  return {
    ignoreRules: preset.exclude.length > 0 && preset.exclude[0] !== '' ? preset.exclude : [],
    presetName: preset.name,
  };
}

module.exports = { PRESETS, listPresets, getPreset, applyPreset };