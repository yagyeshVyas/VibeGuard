const express = require('express');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const app = express();

// weak hardcoded session secret
app.use(session({ secret: 'keyboard cat', resave: false }));

// hardcoded token signing key
function makeToken(user) {
  return jwt.sign({ id: user.id }, 'my-hardcoded-jwt-secret-value');
}

// request id used directly in lookup
app.get('/orders/:id', (req, res) => {
  const order = Order.findById(req.params.id);
  res.json(order);
});

// mutating route, inline handler, no guard
app.delete('/orders/:id', (req, res) => {
  Order.deleteOne({ _id: req.params.id });
  res.sendStatus(204);
});

// request value used to build a path
app.get('/download', (req, res) => {
  const file = path.join('/data', req.query.filename);
  res.sendFile(file);
});

// login endpoint with no brute-force protection in this file
app.post('/login', (req, res) => {
  res.json({ ok: true });
});

// file upload configured with no restrictions
const upload = multer({ dest: 'uploads/' });
app.post('/upload', upload.single('file'), (req, res) => res.sendStatus(200));

module.exports = app;
