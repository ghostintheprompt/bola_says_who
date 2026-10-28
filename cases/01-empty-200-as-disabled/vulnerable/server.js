// VULNERABLE: the projects endpoint returns 200 with a list for every
// authenticated account. A disabled account is handled by simply not
// including its projects — the server returns 200 { projects: [] }, the
// exact same response an enabled-but-empty account gets.
//
// There is no authorization decision on the wire. "Disabled" exists only as
// an inference the client makes from an empty list. That makes the client
// the sole authority on account state, which is the whole defect: anything
// that supplies a non-empty list to the client (a proxy, an extension, an
// injected response) flips it from the disabled screen to the dashboard.

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

  return { app, state };
}

module.exports = { createApp };
