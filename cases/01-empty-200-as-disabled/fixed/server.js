// Account status is checked server-side on both project and protected-resource
// routes. The client receives an explicit disabled result; an active empty
// account remains usable. UI response rewriting cannot grant server authority.

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


  // Synthetic protected resource: UI edits confer no authority here.
  app.get('/api/restricted-brief', requireAuth(state), (req, res) => {
    if (req.user.status !== 'active') return res.status(403).json({ code: 'ACCOUNT_DISABLED' });
    res.json({ brief: 'FIXTURE-RESTRICTED-BRIEF', owner: req.user.id });
  });

  return { app, state };
}

module.exports = { createApp };
