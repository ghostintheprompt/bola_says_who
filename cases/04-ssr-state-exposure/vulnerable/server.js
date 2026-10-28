// VULNERABLE: /app ships the same hydrate-from-state shell to every
// authenticated user. The initial-state blob embeds, in plaintext:
//   - the authorization decision itself (isActive)
//   - the account's profileId (an identifier useful for pivoting elsewhere)
//   - the protected scene name, whose code path is referenced for all users
// Two defects in one response: sensitive authorization state is exposed to the
// client (CWE-200), and because the client decides from the isActive flag, an
// edit to that flag in transit flips a disabled account to the dashboard.

const express = require('express');
const { freshState, login, requireAuth } = require('../seed');

function page(user) {
  const state = {
    profileId: user.profileId,
    isActive: user.status === 'active',
    scene: 'FellowProjectsScene',
  };
  return [
    '<!doctype html><html><head><title>App</title></head><body>',
    '<div id="root"></div>',
    '<script id="__APP_STATE__" type="application/json">',
    JSON.stringify(state),
    '</script>',
    '</body></html>',
  ].join('');
}

function createApp() {
  const state = freshState();
  const app = express();
  app.use(express.json());

  app.post('/login', (req, res) => {
    const { username, password } = req.body || {};
    const token = login(state, username, password);
    if (!token) return res.status(401).json({ error: 'invalid credentials' });
    res.json({ token });
  });

  app.get('/app', requireAuth(state), (req, res) => {
    res.type('html').send(page(req.user));
  });

  return { app, state };
}

module.exports = { createApp };
