// Target-agnostic detectors. Each takes only a base URL and the fixture
// credentials the operator legitimately holds (their own accounts), makes
// black-box HTTP observations, and returns a verdict with the evidence it
// used. Neither probe is ever told whether the server it is hitting is the
// vulnerable or the fixed one — the verdict is derived purely from what the
// server does on the wire. This is the empirical half the theoretical proof
// underwrites: run it against an unknown backend and it reports the boundary
// state rather than presupposing it.

async function login(base, username, password) {
  const res = await fetch(`${base}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) return null;
  return (await res.json()).token;
}

// Detector for the empty-200-as-disabled class. Compares a disabled account's
// response to a known active-but-empty account's response. If the server emits
// no distinguishable authorization signal for the disabled account — same
// status, same body shape as the active-empty one — the decision is not on the
// wire, so it must be happening client-side: VULNERABLE. If the disabled
// account gets a non-200 or an explicit deny code, the server states the
// decision: SOUND.
async function probeEmptyStateAuthz(base, creds) {
  const emptyToken = await login(base, creds.activeEmpty.u, creds.activeEmpty.p);
  const disabledToken = await login(base, creds.disabled.u, creds.disabled.p);

  async function fetchProjects(token) {
    const res = await fetch(`${base}/api/projects`, {
      headers: { authorization: `Bearer ${token}` },
    });
    return { status: res.status, body: await res.json().catch(() => ({})) };
  }

  const empty = await fetchProjects(emptyToken);
  const disabled = await fetchProjects(disabledToken);

  // An explicit non-200, or a 200 carrying a deny code, is a real signal.
  const hasExplicitSignal =
    disabled.status !== 200 ||
    (disabled.body && typeof disabled.body.code === 'string' && /disabled|forbidden|denied/i.test(disabled.body.code));

  // Otherwise: is the disabled response indistinguishable from active-empty?
  const indistinguishable =
    disabled.status === empty.status &&
    JSON.stringify(disabled.body) === JSON.stringify(empty.body);

  const verdict = !hasExplicitSignal && indistinguishable ? 'VULNERABLE' : 'SOUND';
  return {
    verdict,
    evidence: { empty, disabled, hasExplicitSignal, indistinguishable },
  };
}

// Detector for the client-trusted-role class. Logs in as a low-privilege
// account, reads its baseline dashboard, then re-requests while asserting an
// elevated role. If the asserted role changes what the server returns —
// elevated content reaching a low-privilege session — the server trusts a
// caller-supplied authorization key: VULNERABLE.
async function probeClientTrustedRole(base, creds) {
  const token = await login(base, creds.lowPriv.u, creds.lowPriv.p);

  async function dashboard(assertedRole) {
    const headers = { authorization: `Bearer ${token}` };
    if (assertedRole) headers['x-role'] = assertedRole;
    const res = await fetch(`${base}/api/dashboard`, { headers });
    return { status: res.status, body: await res.json().catch(() => ({})) };
  }

  const baseline = await dashboard(null);
  const escalated = await dashboard(creds.elevatedRole);

  // Vulnerable iff asserting the elevated role flips the response to the
  // elevated role's content on a session that did not have it by default.
  const flipped =
    baseline.body.role !== creds.elevatedRole &&
    escalated.body.role === creds.elevatedRole;

  return {
    verdict: flipped ? 'VULNERABLE' : 'SOUND',
    evidence: { baseline, escalated, flipped },
  };
}

module.exports = { probeEmptyStateAuthz, probeClientTrustedRole };
