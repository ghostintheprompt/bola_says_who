// Shared fixture + session helper for case 04. Models a server-side-rendered
// app that ships an initial state blob to the browser to hydrate from. The
// question under test: does that blob carry the authorization decision (and
// the identifiers behind it) in plaintext the client then trusts, or does the
// server render an authoritative view and keep the decision to itself?

const crypto = require('crypto');

function freshState() {
  const users = {
    active: { username: 'active', password: 'pw-act-1', id: 'u_active', profileId: 'prof_active_8842', status: 'active' },
    disabled: { username: 'disabled', password: 'pw-dis-1', id: 'u_disabled', profileId: 'prof_disabled_1077', status: 'disabled' },
  };
  const sessions = {}; // token -> userId
  return { users, sessions };
}

function login(state, username, password) {
  const user = state.users[username];
  if (!user || user.password !== password) return null;
  const token = crypto.randomBytes(16).toString('hex');
  state.sessions[token] = user.id;
  return token;
}

function requireAuth(state) {
  return (req, res, next) => {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    const userId = token && state.sessions[token];
    if (!userId) return res.status(401).send('<!doctype html><title>401</title>unauthenticated');
    req.user = Object.values(state.users).find((u) => u.id === userId);
    next();
  };
}

module.exports = { freshState, login, requireAuth };
