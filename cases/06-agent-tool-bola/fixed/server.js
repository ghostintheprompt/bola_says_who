// FIXED: a policy monitor sits in front of the tool. The agent is still capable
// of naming any accountId, but permission is resolved from the acting session. A
// request for an id the session does not own is denied with 403 and appended to
// an escalation log, because the attempt is the signal worth keeping rather than
// noise to swallow. Capability is not permission.

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

  app.post('/tool/get-payments', requireAuth(state), (req, res) => {
    const requested = (req.body || {}).accountId;
    const record = Object.hasOwn(state.payouts, requested) ? state.payouts[requested] : null;
    if (!record) return res.status(404).json({ error: 'not found' });
    if (record.ownerId !== req.userId) {
      state.escalations.push({ session: req.userId, requested, at: Date.now() });
      return res.status(403).json({ error: 'forbidden', code: 'OWNERSHIP' });
    }
    res.json({ accountId: requested, email: record.email, unpaidEarnings: record.unpaidEarnings });
  });

  return { app, state };
}

module.exports = { createApp };
