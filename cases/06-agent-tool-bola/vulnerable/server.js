// VULNERABLE: the agent tool trusts the fellowId in the tool call. Whatever id
// the model was handed, including one slipped in by prompt injection, is served,
// because the tool confirms the caller is authenticated but never that the acting
// session owns the id. The agent's capability to name an id becomes permission to
// read it.

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

  // Tool surface the agent calls. The body carries the fellowId the model chose.
  app.post('/tool/get-payments', requireAuth(state), (req, res) => {
    const requested = (req.body || {}).fellowId;
    const record = Object.hasOwn(state.payouts, requested) ? state.payouts[requested] : null;
    if (!record) return res.status(404).json({ error: 'not found' });
    // BUG: no check that record.ownerId === req.userId
    res.json({ fellowId: requested, email: record.email, unpaidEarnings: record.unpaidEarnings });
  });

  return { app, state };
}

module.exports = { createApp };
