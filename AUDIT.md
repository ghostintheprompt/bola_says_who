# Audit — October 28, 2026

## Findings and repairs

The initial suite passed its own assertions. Cases 01 and 04 established rendering behavior but overstated server-side impact. The vulnerable case 01 server already withheld disabled accounts' project lists. Case 04 exposed the same account's state; no sensitive-data consequence was established by those fields alone. Both demonstrations remain, with paired restricted-brief endpoints added to test actual status enforcement over HTTP. The fixed handler rejects a disabled session even after a successful login and subsequent revocation.

The original case 01 injected response changed status to 200, while its fixed comparison retained 403. Those were not identical interventions. The new boundary suite explicitly demonstrates that rewriting the entire response redraws the fixed client too. Backend resource denial, rather than interface integrity, carries the fix claim.

The original probes returned SOUND for broad unrecognized behavior. They now require exact positive controls and expected output, record supporting responses, reject redirects, bound transport time, and return INCONCLUSIVE for login failures, malformed JSON, server errors, or unexpected shapes. Ten negative controls exercise these branches. The 32 shuffled classifications cover the same four paired fixtures, not 32 independent targets.

Session stores now use null-prototype objects, fixture usernames require own keys, and profile lookups reject inherited properties. These supporting changes apply to both vulnerable and fixed sides so an accidental prototype lookup cannot confound the intended defect. Tests cover forged inherited-key session tokens and profile IDs.

Test servers bind only loopback and await startup/teardown. Docker uses npm ci and includes the added tests. There is no production-authentication claim: seeded passwords, in-memory sessions, absent expiry/rate limiting and small data fixtures are deliberate test infrastructure.

## Verification

Direct npm test: 93 successful logged checks, no failures. Breakdown: 7+5+32+6+4 original checks/classifications, plus39 boundary assertions. Docker Compose build and container run also passed the same93checks. npm audit reported zero known advisories at audit time; this is advisory coverage, not a security guarantee. Evidence logs are in evidence/. No external platform was contacted, and no live-site or assigned CVE claim is made.

## Technical retention

All five original cases remain. Vulnerable/fixed routes, client render/hydration models, blind classifiers and cross-user fixture read remain runnable. Added backend and negative controls strengthen the mechanisms. Original private case notes and identifying data are excluded from this repository and distribution archive.
