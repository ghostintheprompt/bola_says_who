// Case 01 verification, run against both servers.
//
//   1. Functionality — the fix doesn't break the legitimate cases: an active
//      account with projects still renders the dashboard, and an active
//      account with no projects is NOT treated as locked out.
//   2. Ambiguity probe — can the client tell a disabled account apart from an
//      empty-but-active one using only what the server sends? On the
//      vulnerable server the two responses are identical, so the client is
//      forced to guess; on the fixed server the server states the decision.
//   3. Injection probe — model the response-injection bypass non-destructively:
//      feed the client a swapped (non-empty) payload for the disabled account
//      and see whether its render decision flips. Nothing is sent to any real
//      system; this swaps a response object inside the test itself.

const assert = require('node:assert');
const { createApp: createVulnerable } = require('./vulnerable/server');
const { createApp: createFixed } = require('./fixed/server');
const { renderDecision, renderDecisionExplicit } = require('./frontend');

async function withServer(createApp, fn) {
  const { app } = createApp();
  const server = app.listen(0, '127.0.0.1');
  await new Promise((resolve, reject) => { server.once('listening', resolve); server.once('error', reject); });
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    await fn(base);
  } finally {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
}

async function login(base, username, password) {
  const res = await fetch(`${base}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  return (await res.json()).token;
}

async function getProjects(base, token) {
  const res = await fetch(`${base}/api/projects`, {
    headers: { authorization: `Bearer ${token}` },
  });
  const body = await res.json().catch(() => ({}));
  return { status: res.status, body };
}

let passed = 0;
let failed = 0;
function report(name, ok, detail) {
  if (ok) { passed++; console.log(`  PASS  ${name}`); }
  else { failed++; console.log(`  FAIL  ${name} — ${detail}`); }
}

async function run() {
  console.log('== vulnerable server ==');
  await withServer(createVulnerable, async (base) => {
    const full = await getProjects(base, await login(base, 'active_full', 'pw-full-1'));
    report('functionality: active account with projects renders dashboard',
      renderDecision(full.status, full.body) === 'DASHBOARD',
      `got ${renderDecision(full.status, full.body)}`);

    const empty = await getProjects(base, await login(base, 'active_empty', 'pw-empty-1'));
    const disabled = await getProjects(base, await login(base, 'disabled', 'pw-dis-1'));

    // The defect itself: disabled and active-empty are byte-identical on the wire.
    report('vulnerability: disabled and active-empty responses are indistinguishable',
      empty.status === disabled.status &&
      JSON.stringify(empty.body) === JSON.stringify(disabled.body),
      `empty=${empty.status}:${JSON.stringify(empty.body)} disabled=${disabled.status}:${JSON.stringify(disabled.body)}`);

    // Consequence: an injected non-empty payload flips the disabled client to the dashboard.
    const injected = { status: 200, body: { projects: [{ id: 'x', title: 'injected', status: 'open' }] } };
    report('vulnerability: injected payload flips disabled account to DASHBOARD',
      renderDecision(disabled.status, disabled.body) === 'ACCOUNT_DISABLED' &&
      renderDecision(injected.status, injected.body) === 'DASHBOARD',
      `baseline=${renderDecision(disabled.status, disabled.body)} injected=${renderDecision(injected.status, injected.body)}`);
  });

  console.log('== fixed server ==');
  await withServer(createFixed, async (base) => {
    const full = await getProjects(base, await login(base, 'active_full', 'pw-full-1'));
    report('functionality: active account with projects still renders dashboard',
      renderDecisionExplicit(full.status, full.body) === 'DASHBOARD',
      `got ${renderDecisionExplicit(full.status, full.body)}`);

    const empty = await getProjects(base, await login(base, 'active_empty', 'pw-empty-1'));
    report('functionality: active-empty account is NOT treated as disabled',
      empty.status === 200 && renderDecisionExplicit(empty.status, empty.body) === 'DASHBOARD',
      `got ${empty.status} ${renderDecisionExplicit(empty.status, empty.body)}`);

    const disabled = await getProjects(base, await login(base, 'disabled', 'pw-dis-1'));
    report('fixed: disabled account gets an explicit 403 decision, no projects served',
      disabled.status === 403 && disabled.body.code === 'ACCOUNT_DISABLED' &&
      disabled.body.projects === undefined,
      `got ${disabled.status} ${JSON.stringify(disabled.body)}`);

    // Body-only injection while retaining the 403: this rendering control stays
    // disabled. Rewriting status too redraws it; see tests/boundaries.js.
    const injected = { status: 403, body: { code: 'ACCOUNT_DISABLED', projects: [{ id: 'x' }] } };
    report('fixed: injected projects on a 403 do not unlock the dashboard',
      renderDecisionExplicit(injected.status, injected.body) === 'ACCOUNT_DISABLED',
      `got ${renderDecisionExplicit(injected.status, injected.body)}`);
  });

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

run().catch(error => { console.error(error); process.exitCode = 1; });
