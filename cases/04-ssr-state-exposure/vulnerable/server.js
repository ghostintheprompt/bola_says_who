// The page exposes its own account state and a scene name. Editing the flag
// changes the local hydration result. Those fields alone are not proof of a
// sensitive disclosure. The separate protected-resource route deliberately
// omits status enforcement so an actual unauthorized data read is measurable.

const express = require('express');
const { freshState, login, requireAuth } = require('../seed');

function page(user) {
  const state = {
    profileId: user.profileId,
    isActive: user.status === 'active',
    scene: 'FellowProjectsScene',
  };
  return [
    '<!doctype html><html><head><title>App</title></head><body>',
    '<div id="root"></div>',
    '<script id="__APP_STATE__" type="application/json">',
    JSON.stringify(state),
    '</script>',
    '</body></html>',
  ].join('');
}

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

  app.get('/app', requireAuth(state), (req, res) => {
    res.type('html').send(page(req.user));
  });


  // Synthetic protected resource: UI edits confer no authority here.
  app.get('/api/restricted-brief', requireAuth(state), (req, res) => {
    res.json({ brief: 'FIXTURE-RESTRICTED-BRIEF', owner: req.user.id });
  });

  return { app, state };
}

module.exports = { createApp };
