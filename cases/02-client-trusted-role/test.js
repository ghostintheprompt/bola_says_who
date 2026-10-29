// Case 02 verification, run against both servers.
//
//   1. Functionality — a real fellow session still gets the fellow dashboard.
//   2. Vulnerability — a student session that asserts x-role: fellow (modeling
//      a mutable role cookie the server trusts) receives the fellow dashboard
//      on the vulnerable server, and is denied it on the fixed one.
//
// Every request uses a session this test logged in with real credentials. The
// only thing under test is whether the server trusts a role the client asserts
// over the role on the session's own server-side record.

const { createApp: createVulnerable } = require('./vulnerable/server');
const { createApp: createFixed } = require('./fixed/server');

async function withServer(createApp, fn) {
  const { app } = createApp();
  const server = app.listen(0, '127.0.0.1');
  await new Promise((resolve, reject) => { server.once('listening', resolve); server.once('error', reject); });
  const base = `http://127.0.0.1:${server.address().port}`;
  try { await fn(base); } finally { await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())); }
}

async function login(base, username, password) {
  const res = await fetch(`${base}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  return (await res.json()).token;
}

async function getDashboard(base, token, assertedRole) {
  const headers = { authorization: `Bearer ${token}` };
  if (assertedRole) headers['x-role'] = assertedRole;
  const res = await fetch(`${base}/api/dashboard`, { headers });
  return { status: res.status, body: await res.json().catch(() => ({})) };
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
    const fellow = await getDashboard(base, await login(base, 'fellow', 'pw-fel-1'));
    report('functionality: real fellow gets the fellow dashboard',
      fellow.body.role === 'fellow' && Array.isArray(fellow.body.payouts) && fellow.body.payouts.length > 0,
      JSON.stringify(fellow.body));

    const studentToken = await login(base, 'student', 'pw-stu-1');
    const asStudent = await getDashboard(base, studentToken);
    report('baseline: student session alone gets the student dashboard',
      asStudent.body.role === 'student' && asStudent.body.payouts.length === 0,
      JSON.stringify(asStudent.body));

    const escalated = await getDashboard(base, studentToken, 'fellow');
    report('vulnerability: student asserting x-role=fellow gets the FELLOW dashboard',
      escalated.body.role === 'fellow' && escalated.body.payouts.length > 0,
      JSON.stringify(escalated.body));
  });

  console.log('== fixed server ==');
  await withServer(createFixed, async (base) => {
    const fellow = await getDashboard(base, await login(base, 'fellow', 'pw-fel-1'));
    report('functionality: real fellow still gets the fellow dashboard',
      fellow.body.role === 'fellow' && fellow.body.payouts.length > 0,
      JSON.stringify(fellow.body));

    const studentToken = await login(base, 'student', 'pw-stu-1');
    const escalated = await getDashboard(base, studentToken, 'fellow');
    report('fixed: student asserting x-role=fellow is kept on the student dashboard',
      escalated.body.role === 'student' && escalated.body.payouts.length === 0,
      JSON.stringify(escalated.body));
  });

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

run().catch(error => { console.error(error); process.exitCode = 1; });
