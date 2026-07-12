#!/usr/bin/env node
'use strict';
// daemon-run.js — entry point for the background daemon process.
// Spawned by daemon.js startDaemon(). Runs the daemon loop.

const path = require('path');
const { runDaemon } = require('./daemon');

const rootDir = path.resolve(process.argv[2] || '.');
const verbose = process.argv.includes('--verbose');

runDaemon(rootDir, { verbose });