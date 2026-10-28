// FIXED: the server makes the authorization decision and says so explicitly.
// A disabled account gets 403 with a machine-readable code; the projects
// payload is never served for it at all. An enabled account with no projects
// gets a normal 200 { projects: [] } — now unambiguously different from a
// lockout. The client no longer has to guess from data presence, so there is
// no empty-vs-disabled ambiguity left for an injected payload to exploit.

const express = require('express');
const { freshState, login, requireAuth } = require('../seed');

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

  app.get('/api/projects', requireAuth(state), (req, res) => {
    if (req.user.status === 'disabled') {
      return res.status(403).json({ error: 'account disabled', code: 'ACCOUNT_DISABLED' });
    }
    res.status(200).json({ projects: state.projects[req.userId] || [] });
  });

  return { app, state };
}

module.exports = { createApp };
