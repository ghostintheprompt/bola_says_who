// Paired metadata and local-hydration observations. Protected-resource
// enforcement and revocation are exercised separately in tests/boundaries.js.
const { createApp: createVulnerable } = require('./vulnerable/server');
const { createApp: createFixed } = require('./fixed/server');
const { hydrateFromFlag, hydrateFromServerView } = require('./client');

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

async function getApp(base, token) {
  const res = await fetch(`${base}/app`, { headers: { authorization: `Bearer ${token}` } });
  return res.text();
}

let passed = 0, failed = 0;
function report(name, ok, detail) {
  if (ok) { passed++; console.log(`  PASS  ${name}`); }
  else { failed++; console.log(`  FAIL  ${name} — ${detail}`); }
}

async function run() {
  console.log('== vulnerable server ==');
  await withServer(createVulnerable, async (base) => {
    const activeHtml = await getApp(base, await login(base, 'active', 'pw-act-1'));
    report('functionality: active account hydrates to DASHBOARD',
      hydrateFromFlag(activeHtml) === 'DASHBOARD', hydrateFromFlag(activeHtml));

    const disabledHtml = await getApp(base, await login(base, 'disabled', 'pw-dis-1'));

    const exposed = disabledHtml.includes('"isActive"') &&
      disabledHtml.includes('prof_disabled_1077') &&
      disabledHtml.includes('FellowProjectsScene');
    report('observation: disabled page includes its own state and scene metadata',
      exposed, 'expected all three plaintext tokens in the HTML');

    const baseline = hydrateFromFlag(disabledHtml);
    const injectedHtml = disabledHtml.replace('"isActive":false', '"isActive":true');
    const injected = hydrateFromFlag(injectedHtml);
    report('vulnerability: flipping isActive in transit flips disabled account to DASHBOARD',
      baseline === 'ACCOUNT_DISABLED' && injected === 'DASHBOARD',
      `baseline=${baseline} injected=${injected}`);
  });

  console.log('== fixed server ==');
  await withServer(createFixed, async (base) => {
    const activeHtml = await getApp(base, await login(base, 'active', 'pw-act-1'));
    report('functionality: active account still hydrates to DASHBOARD',
      hydrateFromServerView(activeHtml) === 'DASHBOARD', hydrateFromServerView(activeHtml));

    const disabledHtml = await getApp(base, await login(base, 'disabled', 'pw-dis-1'));

    const noExposure = !disabledHtml.includes('isActive') &&
      !disabledHtml.includes('prof_disabled_1077') &&
      !disabledHtml.includes('FellowProjectsScene');
    report('metadata minimization: disabled page omits state and scene identifiers',
      noExposure, 'expected none of the sensitive tokens in the HTML');

    // This particular flag replacement finds no match in the fixed page.
    // Arbitrary rewriting can still redraw a local screen; it grants no backend access.
    const injectedHtml = disabledHtml.replace('"isActive":false', '"isActive":true');
    report('fixed: injection attempt is inert, view stays ACCOUNT_DISABLED',
      hydrateFromServerView(injectedHtml) === 'ACCOUNT_DISABLED',
      hydrateFromServerView(injectedHtml));
  });

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

run().catch(error => { console.error(error); process.exitCode = 1; });
