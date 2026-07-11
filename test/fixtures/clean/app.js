// Realistic, SAFE code. VibeGuard must produce ZERO findings here.
'use strict';
const express = require('express');
const { execFile } = require('child_process');
const app = express();

// Secrets loaded from env — safe.
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const dbPassword = process.env.DB_PASSWORD;
const config = { apiKey: process.env.API_KEY, secret: `${process.env.SECRET}` };

// Public BaaS keys — designed to be public, must NOT be flagged.
const firebaseConfig = {
  apiKey: 'AIzaSyD-1234567890abcdefghijklmnopqrstuv',
  authDomain: 'demo.firebaseapp.com',
};
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCanonpublic';
const NEXT_PUBLIC_STRIPE_KEY = 'pk_live_51H8xkLpublishableKeyIsPublic';

// Placeholder / template values — must NOT be flagged.
const example = { password: 'your_password_here', token: 'changeme' };

// Parameterized SQL — the correct way, must NOT be flagged.
async function getUser(db, id) {
  return db.query('SELECT * FROM users WHERE id = $1', [id]);
}
async function search(db, term) {
  return db.query('SELECT * FROM items WHERE name LIKE $1 AND active = true', [term]);
}

// execFile with array args — safe, must NOT be flagged as command injection.
function ping(host) {
  execFile('ping', ['-c', '1', host], () => {});
}

// CORS restricted to an allowlist — safe.
const allowed = ['https://app.example.com'];
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowed.includes(origin)) res.header('Access-Control-Allow-Origin', origin);
  next();
});

// https + localhost http — both fine.
const API = 'https://api.example.com/v1';
const LOCAL = 'http://localhost:3000';
const LOOPBACK = 'http://127.0.0.1:5432';

// A comment mentioning eval() and a fake sk-key should be ignored by code rules.
// e.g. do not use eval() here; historically we had exec("rm " + path) — removed.

module.exports = { getUser, search, ping, API, LOCAL, LOOPBACK, config };
