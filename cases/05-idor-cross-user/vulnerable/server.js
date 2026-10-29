// VULNERABLE: GET /api/profile/:profileId returns whatever profile matches the
// ID in the URL, having checked only that the caller is logged in as someone.
// There is no check that the requesting session owns that profileId, so any
// authenticated worker can read another worker's contact details and earnings
// by supplying their profileId — the exact pivot the original notes proposed
// (swap the identifier, pull another worker's data).

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
    // BUG: no check that profile.ownerId === req.userId
    res.json({ email: profile.email, unpaidEarnings: profile.unpaidEarnings });
  });

  return { app, state };
}

module.exports = { createApp };
