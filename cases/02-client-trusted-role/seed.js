// Shared fixture + session helper for case 02. The server's real record of
// each user's role lives here, server-side. The whole question under test is
// whether the endpoint honors that record or a role the client asserts for
// itself (modeling a mutable, non-HttpOnly role cookie read by the server).

const crypto = require('crypto');

function freshState() {
  const users = {
    student: { username: 'student', password: 'pw-stu-1', id: 'u_student', role: 'student' },
    fellow: { username: 'fellow', password: 'pw-fel-1', id: 'u_fellow', role: 'fellow' },
  };

  // Content gated to the 'fellow' role. A student must never receive this.
  const fellowDashboard = { role: 'fellow', payouts: [{ id: 'pay_1', amount: 5000 }] };

  const sessions = {}; // token -> userId
  return { users, fellowDashboard, sessions };
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
    if (!userId) return res.status(401).json({ error: 'unauthenticated' });
    req.userId = userId;
    req.sessionUser = Object.values(state.users).find((u) => u.id === userId);
    next();
  };
}

// Models reading the role the client asserts — e.g. a non-HttpOnly cookie
// the browser (or an attacker with console access) can set at will. Here it
// arrives as a request header the caller fully controls.
function clientAssertedRole(req) {
  return req.headers['x-role'] || null;
}

module.exports = { freshState, login, requireAuth, clientAssertedRole };
