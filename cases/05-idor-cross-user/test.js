// Case 05 verification, run against both servers.
//   1. Functionality — a worker reading their own profile still works.
//   2. Vulnerability — can a logged-in worker read another worker's profile by
//      supplying its profileId? Every request carries a real session this test
//      logged in; the only thing under test is server-side object-level
//      authorization on an ID the caller already holds.
//
// Non-destructive: both profileIds belong to this lab's own fixtures. This is
// the confirmed answer to the pivot the original notes only proposed trying.

const { createApp: createVulnerable } = require('./vulnerable/server');
const { createApp: createFixed } = require('./fixed/server');

async function withServer(createApp, fn) {
  const { app } = createApp();
  const server = app.listen(0, '127.0.0.1');
  await new Promise((resolve, reject) => { server.once('listening', resolve); server.once('error', reject); });
  const base = `http://127.0.0.1:${server.address().port}`;
  try { await fn(base); } finally { await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())); }
}

async function login(base, u, p) {
  const res = await fetch(`${base}/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: u, password: p }),
  });
  return (await res.json()).token;
}

async function getProfile(base, token, profileId) {
  const res = await fetch(`${base}/api/profile/${profileId}`, {
    headers: { authorization: `Bearer ${token}` },
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
    const aliceToken = await login(base, 'alice', 'pw-alice-1');

    const own = await getProfile(base, aliceToken, 'prof_alice_8842');
    report('functionality: alice reads her own profile',
      own.status === 200 && own.body.email === 'alice@example.test', JSON.stringify(own));

    const other = await getProfile(base, aliceToken, 'prof_bob_1077');
    report("vulnerability: alice CAN read bob's profile by profileId (IDOR confirmed)",
      other.status === 200 && other.body.email === 'bob@example.test' && other.body.unpaidEarnings === 9800,
      JSON.stringify(other));
  });

  console.log('== fixed server ==');
  await withServer(createFixed, async (base) => {
    const aliceToken = await login(base, 'alice', 'pw-alice-1');

    const own = await getProfile(base, aliceToken, 'prof_alice_8842');
    report('functionality: alice still reads her own profile',
      own.status === 200 && own.body.email === 'alice@example.test', JSON.stringify(own));

    const other = await getProfile(base, aliceToken, 'prof_bob_1077');
    report("fixed: alice can no longer read bob's profile",
      other.status === 403, `expected 403, got ${other.status}`);
  });

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

run().catch(error => { console.error(error); process.exitCode = 1; });
