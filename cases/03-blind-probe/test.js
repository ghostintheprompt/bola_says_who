// Shuffle four known fixture types; probes receive credentials but no labels.
// Repeated classifications measure these contracts, not general accuracy.

const assert = require('node:assert');
const { createApp: vuln01 } = require('../01-empty-200-as-disabled/vulnerable/server');
const { createApp: fixed01 } = require('../01-empty-200-as-disabled/fixed/server');
const { createApp: vuln02 } = require('../02-client-trusted-role/vulnerable/server');
const { createApp: fixed02 } = require('../02-client-trusted-role/fixed/server');
const { probeEmptyStateAuthz, probeClientTrustedRole } = require('./probe');

const EMPTY_STATE_CREDS = {
  activeEmpty: { u: 'active_empty', p: 'pw-empty-1' },
  disabled: { u: 'disabled', p: 'pw-dis-1' },
};
const ROLE_CREDS = {
  lowPriv: { u: 'student', p: 'pw-stu-1' },
  highPriv: { u: 'fellow', p: 'pw-fel-1' },
  elevatedRole: 'fellow',
};

const ROUNDS = 8;

function shuffle(arr) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

async function withServer(createApp, fn) {
  const { app } = createApp();
  const server = app.listen(0, '127.0.0.1');
  await new Promise((resolve, reject) => { server.once('listening', resolve); server.once('error', reject); });
  const base = `http://127.0.0.1:${server.address().port}`;
  try { return await fn(base); } finally { await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())); }
}

let total = 0;
let correct = 0;
let failed = 0;

async function classify(target) {
  // The probe never receives target.truth.
  return withServer(target.createApp, async (base) => {
    const result = await target.probe(base, target.creds);
    return result.verdict;
  });
}

async function run() {
  // Ground-truth set: each real server with its known classification.
  const targets = [
    { name: 'empty-state/vulnerable', createApp: vuln01, probe: probeEmptyStateAuthz, creds: EMPTY_STATE_CREDS, truth: 'VULNERABLE' },
    { name: 'empty-state/fixed', createApp: fixed01, probe: probeEmptyStateAuthz, creds: EMPTY_STATE_CREDS, truth: 'SOUND' },
    { name: 'client-role/vulnerable', createApp: vuln02, probe: probeClientTrustedRole, creds: ROLE_CREDS, truth: 'VULNERABLE' },
    { name: 'client-role/fixed', createApp: fixed02, probe: probeClientTrustedRole, creds: ROLE_CREDS, truth: 'SOUND' },
  ];

  for (let round = 1; round <= ROUNDS; round++) {
    const order = shuffle(targets);
    const verdicts = [];
    for (const target of order) {
      const verdict = await classify(target);
      total++;
      const ok = verdict === target.truth;
      if (ok) correct++; else failed++;
      verdicts.push(`${target.name}->${verdict}${ok ? '' : ` (WRONG, truth ${target.truth})`}`);
    }
    console.log(`  round ${round}: ${verdicts.join(', ')}`);
  }

  const allCorrect = failed === 0;
  console.log(`\n  blind classification: ${correct}/${total} correct across ${ROUNDS} randomized rounds`);
  console.log(allCorrect ? '  PASS  probe classifies every shuffled target correctly, label withheld' :
    '  FAIL  probe misclassified at least one target');

  if (!allCorrect) process.exit(1);
  // A guard that this was a real test: all four target types were exercised.
  assert.strictEqual(total, ROUNDS * 4);
}

run().catch(error => { console.error(error); process.exitCode = 1; });
