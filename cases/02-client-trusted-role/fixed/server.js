// FIXED: the endpoint derives the role from the authenticated session's own
// server-side record and ignores any client-asserted role entirely. A
// student session asking for the fellow dashboard — with or without an
// x-role: fellow header — is refused.

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

  app.get('/api/dashboard', requireAuth(state), (req, res) => {
    // The x-role header is never read. Role comes from the session record.
    const role = req.sessionUser.role;
    if (role === 'fellow') return res.status(200).json(state.fellowDashboard);
    res.status(200).json({ role: 'student', payouts: [] });
  });

  return { app, state };
}

module.exports = { createApp };
