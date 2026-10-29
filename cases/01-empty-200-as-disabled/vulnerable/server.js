// UI ambiguity: disabled and active-empty sessions receive the same project list.
// A separate protected-resource route below deliberately omits the account-status
// check. Only that HTTP data retrieval proves the server-side failure.

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
    // BUG: status is never consulted. A disabled account is served a 200
    // with an empty list, indistinguishable from an active empty account.
    const projects = req.user.status === 'disabled' ? [] : state.projects[req.userId] || [];
    res.status(200).json({ projects });
  });


  // Synthetic protected resource: UI edits confer no authority here.
  app.get('/api/restricted-brief', requireAuth(state), (req, res) => {
    res.json({ brief: 'FIXTURE-RESTRICTED-BRIEF', owner: req.user.id });
  });

  return { app, state };
}

module.exports = { createApp };
