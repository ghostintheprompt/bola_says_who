// FIXED: the server makes the decision and renders the authoritative view for
// it. A disabled account receives a page whose #root already contains the
// account-disabled view, with no isActive flag, no profileId, and no reference
// to the protected scene — nothing sensitive to read and nothing to flip. An
// active account receives the dashboard view. The client hydrates the view the
// server rendered rather than recomputing access from a shipped flag.

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

  return { app, state };
}

module.exports = { createApp };
