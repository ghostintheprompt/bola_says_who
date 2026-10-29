// Shared fixture + session helper for case 05. Models a profile endpoint keyed
// by a profileId that the client holds and controls — the same identifier shape
// exposed in case 04's state blob. The question: does the server confirm the
// requesting session owns the profileId before returning it?

const crypto = require('crypto');

function freshState() {
  const users = {
    alice: { username: 'alice', password: 'pw-alice-1', id: 'u_alice', profileId: 'prof_alice_8842' },
    bob: { username: 'bob', password: 'pw-bob-1', id: 'u_bob', profileId: 'prof_bob_1077' },
  };

  // Profile records, keyed by profileId, carrying data one worker should never
  // read for another: contact details and payout totals.
  const profiles = {
    prof_alice_8842: { ownerId: 'u_alice', email: 'alice@example.test', unpaidEarnings: 1200 },
    prof_bob_1077: { ownerId: 'u_bob', email: 'bob@example.test', unpaidEarnings: 9800 },
  };

  const sessions = Object.create(null); // token -> userId
  return { users, profiles, sessions };
}

function login(state, username, password) {
  const user = typeof username === 'string' && Object.hasOwn(state.users, username) ? state.users[username] : null;
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
    if (!userId) return res.status(401).json({ error: 'unauthenticated' });
    req.userId = userId;
    next();
  };
}

module.exports = { freshState, login, requireAuth };
