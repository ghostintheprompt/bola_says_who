// Case 06: an agent tool that fetches payments by a model-supplied accountId.
// The agent is authenticated as the session it acts for. The question is whether
// the tool layer enforces that the acting session owns the id the agent passed,
// or whether a steered argument (a prompt-injected accountId) reads anyone. The
// fixed side resolves permission from the session and records every over-ceiling
// attempt, because capability is not permission.

const crypto = require('crypto');

function freshState() {
  const users = {
    alice: { username: 'alice', password: 'pw-alice-1', id: 'u_alice', accountId: 'account_alice_8842' },
    bob: { username: 'bob', password: 'pw-bob-1', id: 'u_bob', accountId: 'account_bob_1077' },
  };

  // Payout records keyed by accountId, the id an agent tool would pass.
  const payouts = {
    account_alice_8842: { ownerId: 'u_alice', email: 'alice@example.test', unpaidEarnings: 1200 },
    account_bob_1077: { ownerId: 'u_bob', email: 'bob@example.test', unpaidEarnings: 9800 },
  };

  const sessions = Object.create(null); // token -> userId
  const escalations = []; // append-only record of denied over-ceiling attempts
  return { users, payouts, sessions, escalations };
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
    const acting = Object.values(state.users).find((u) => u.id === userId);
    req.ownAccountId = acting ? acting.accountId : null;
    next();
  };
}

module.exports = { freshState, login, requireAuth };
