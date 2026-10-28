// VULNERABLE: the dashboard endpoint decides which role's content to serve
// from a role the CLIENT asserts (the x-role header, modeling a mutable
// non-HttpOnly role cookie the server trusts for routing). A student session
// that asserts x-role: fellow is handed the fellow dashboard. The session is
// authenticated; the role it claims is not verified against the server's own
// record.

const express = require('express');
const { freshState, login, requireAuth, clientAssertedRole } = require('../seed');

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
    // BUG: trusts the client-asserted role instead of req.sessionUser.role.
    const role = clientAssertedRole(req) || req.sessionUser.role;
    if (role === 'fellow') return res.status(200).json(state.fellowDashboard);
    res.status(200).json({ role: 'student', payouts: [] });
  });

  return { app, state };
}

module.exports = { createApp };
