// Shared fixture + session helper for case 01. The vulnerable and fixed
// servers differ by exactly one thing: whether a disabled account is
// reported to the client as an explicit authorization decision, or left
// to be inferred from the shape of a 200 response.

const crypto = require('crypto');

function freshState() {
  // Three accounts chosen to expose the ambiguity:
  //   active_full  — an enabled contractor with projects
  //   active_empty — an enabled contractor who simply has no projects yet
  //   disabled     — a flagged/deactivated account
  // The whole bug lives in telling active_empty and disabled apart.
  const users = {
    active_full: { username: 'active_full', password: 'pw-full-1', id: 'u_full', status: 'active' },
    active_empty: { username: 'active_empty', password: 'pw-empty-1', id: 'u_empty', status: 'active' },
    disabled: { username: 'disabled', password: 'pw-dis-1', id: 'u_dis', status: 'disabled' },
  };

  const projects = {
    u_full: [{ id: 'p1', title: 'Rubric pass', status: 'open' }],
    u_empty: [],
    u_dis: [{ id: 'p9', title: 'Should never ship to client', status: 'open' }],
  };

  const sessions = {}; // token -> userId
  return { users, projects, sessions };
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
    req.user = Object.values(state.users).find((u) => u.id === userId);
    next();
  };
}

module.exports = { freshState, login, requireAuth };
