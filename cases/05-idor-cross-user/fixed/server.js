// FIXED: identical except the handler confirms the requesting session owns the
// profileId before returning anything. A request for a profile the caller does
// not own gets 403, not the record.

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

  app.get('/api/profile/:profileId', requireAuth(state), (req, res) => {
    const profile = Object.hasOwn(state.profiles, req.params.profileId) ? state.profiles[req.params.profileId] : null;
    if (!profile) return res.status(404).json({ error: 'not found' });
    if (profile.ownerId !== req.userId) {
      return res.status(403).json({ error: 'forbidden' });
    }
    res.json({ email: profile.email, unpaidEarnings: profile.unpaidEarnings });
  });

  return { app, state };
}

module.exports = { createApp };
