// Case 06 verification, run against both servers.
//   1. Functionality — the agent reads its own payouts through the tool.
//   2. Vulnerability — a steered fellowId (a prompt-injected tool argument) reads
//      another account on the vulnerable server.
//   3. Permission + monitor — the fixed server denies the over-ceiling argument
//      with 403 and records the attempt instead of swallowing it.
//
// Non-destructive: every id belongs to this lab's own fixtures.

const { createApp: createVulnerable } = require('./vulnerable/server');
const { createApp: createFixed } = require('./fixed/server');

async function withServer(createApp, fn) {
  const { app, state } = createApp();
  const server = app.listen(0, '127.0.0.1');
  await new Promise((resolve, reject) => { server.once('listening', resolve); server.once('error', reject); });
  const base = `http://127.0.0.1:${server.address().port}`;
  try { await fn(base, state); } finally { await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); }
}

async function login(base, u, p) {
  const res = await fetch(`${base}/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: u, password: p }),
  });
  return (await res.json()).token;
}

async function callTool(base, token, fellowId) {
  const res = await fetch(`${base}/tool/get-payments`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ fellowId }),
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

let passed = 0, failed = 0;
function report(name, ok, detail) {
  if (ok) { passed++; console.log(`  PASS  ${name}`); }
  else { failed++; console.log(`  FAIL  ${name} — ${detail}`); }
}

async function run() {
  console.log('== vulnerable server ==');
  await withServer(createVulnerable, async (base) => {
    const alice = await login(base, 'alice', 'pw-alice-1');

    const own = await callTool(base, alice, 'fellow_alice_8842');
    report('functionality: agent reads its own payouts', own.status === 200 && own.body.unpaidEarnings === 1200, JSON.stringify(own));

    const injected = await callTool(base, alice, 'fellow_bob_1077');
    report("vulnerability: a steered fellowId reads another account's payouts",
      injected.status === 200 && injected.body.email === 'bob@example.test' && injected.body.unpaidEarnings === 9800,
      JSON.stringify(injected));
  });

  console.log('== fixed server ==');
  await withServer(createFixed, async (base, state) => {
    const alice = await login(base, 'alice', 'pw-alice-1');

    const own = await callTool(base, alice, 'fellow_alice_8842');
    report('functionality: agent still reads its own payouts', own.status === 200 && own.body.unpaidEarnings === 1200, JSON.stringify(own));

    const injected = await callTool(base, alice, 'fellow_bob_1077');
    report('permission: the over-ceiling tool argument is denied', injected.status === 403 && injected.body.code === 'OWNERSHIP', JSON.stringify(injected));

    report('monitor: the denied attempt is recorded, not swallowed',
      state.escalations.length === 1 && state.escalations[0].requested === 'fellow_bob_1077',
      JSON.stringify(state.escalations));
  });

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

run().catch((error) => { console.error(error); process.exitCode = 1; });
