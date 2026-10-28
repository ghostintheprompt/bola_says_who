// Case 04 verification, run against both servers.
//
// Proves two linked defects and their fix:
//   A. Exposure (CWE-200) — does a disabled account's page carry the
//      authorization flag, its profileId, and the protected scene name in
//      plaintext the client receives?
//   B. Injection consequence — if so, does editing that flag in transit flip
//      the hydrated view to the dashboard? (modeled by a string edit on the
//      HTML the test holds; nothing is sent to any real system.)
// The fix is proven to close both: no sensitive state is shipped for a
// disabled account, so there is nothing to read and nothing to flip.

const { createApp: createVulnerable } = require('./vulnerable/server');
const { createApp: createFixed } = require('./fixed/server');
const { hydrateFromFlag, hydrateFromServerView } = require('./client');

async function withServer(createApp, fn) {
  const { app } = createApp();
  const server = app.listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;
  try { await fn(base); } finally { server.close(); }
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
    report('vulnerability (CWE-200): disabled page exposes isActive flag, profileId, and protected scene',
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
    report('fixed (CWE-200 closed): disabled page ships no flag, no profileId, no protected scene',
      noExposure, 'expected none of the sensitive tokens in the HTML');

    // The same injection attempt: there is no flag to flip, and the server
    // rendered the authoritative view, so the hydrated result stays disabled.
    const injectedHtml = disabledHtml.replace('"isActive":false', '"isActive":true');
    report('fixed: injection attempt is inert, view stays ACCOUNT_DISABLED',
      hydrateFromServerView(injectedHtml) === 'ACCOUNT_DISABLED',
      hydrateFromServerView(injectedHtml));
  });

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

run();
