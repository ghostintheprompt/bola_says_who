// Server-rendered account state minimizes unnecessary client metadata. The
// protected-resource route independently enforces current account status.
// Rendering alone cannot prevent an owner from editing their local screen.

const express = require('express');
const { freshState, login, requireAuth } = require('../seed');

function disabledPage() {
  return [
    '<!doctype html><html><head><title>App</title></head><body>',
    '<div id="root"><div data-view="account-disabled">Account disabled</div></div>',
    '</body></html>',
  ].join('');
}

function dashboardPage() {
  // The protected scene markup is only ever sent to an authorized user.
  return [
    '<!doctype html><html><head><title>App</title></head><body>',
    '<div id="root"><div data-view="dashboard" data-scene="FellowProjectsScene">...</div></div>',
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
    res.type('html').send(req.user.status === 'active' ? dashboardPage() : disabledPage());
  });


  // Synthetic protected resource: UI edits confer no authority here.
  app.get('/api/restricted-brief', requireAuth(state), (req, res) => {
    if (req.user.status !== 'active') return res.status(403).json({ code: 'ACCOUNT_DISABLED' });
    res.json({ brief: 'FIXTURE-RESTRICTED-BRIEF', owner: req.user.id });
  });

  return { app, state };
}

module.exports = { createApp };
