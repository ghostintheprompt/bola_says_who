# Says Who

The dashboard says no. The endpoint still needs to mean it.

Five cases, four paired Express backends, synthetic accounts, real HTTP requests. Each case separates a client rendering change from a protected-resource read, then runs the same requests against the fixed server. The whole thing is a bench that models the classes so you can run them.

## Run

Node.js 22 or newer:

```sh
npm ci
npm test
```

Or run the same suite in a container:

```sh
docker compose build
docker compose run --rm lab
```

Tests start ephemeral servers bound to `127.0.0.1`, await startup and shutdown, and seed a fresh in-memory state per server. There is no persistent service, exposed container port, external target configuration, or live-platform scan. Login issues random session tokens. The fixture credentials in the source are test data, not production secrets. This is a research fixture rather than a production identity provider.

## Cases and actual boundaries

| Case | Vulnerable behavior | Fixed behavior | Evidence |
| --- | --- | --- | --- |
| [01: Empty 200](cases/01-empty-200-as-disabled/) | Active-empty and disabled sessions get the same projects response. A separate restricted-brief endpoint omits status enforcement. | Projects explicitly deny a disabled session; the resource endpoint also checks current status. | Seven original checks plus protected-resource and revocation controls. |
| [02: Client-trusted role](cases/02-client-trusted-role/) | A student session asserting `x-role: fellow` receives the seeded fellow payout data. | The endpoint reads the role from the server-side session record and returns only student data. | Five paired checks. |
| [03: Blind fixture classification](cases/03-blind-probe/) | Probes inspect the behavior of unlabeled servers from cases 01 and 02. | `SOUND` requires the expected positive control and precise denial behavior. Both student and genuine fellow positive controls are required. Missing evidence returns `INCONCLUSIVE`. | 32 correct classifications over eight shuffled rounds, plus 12 inconclusive-response checks. |
| [04: Server-rendered state](cases/04-ssr-state-exposure/) | Editing a shipped flag redraws the local dashboard. A separate resource endpoint omits the account-status check. | Server rendering minimizes metadata; the resource endpoint independently enforces status. | Six original checks plus protected-resource and revocation controls. |
| [05: Cross-user profile](cases/05-idor-cross-user/) | Alice's valid session retrieves Bob's seeded email and earnings by supplying his profile ID. | The same request receives 403 because the session does not own the profile. | Four original checks plus second-owner, unknown-record, anonymous, and inherited-key controls. |
| [06: Agent tool BOLA](cases/06-agent-tool-bola/) | An agent tool keyed on a model-supplied accountId serves another account's payouts when the argument is steered. | A policy monitor resolves permission from the acting session, denies the over-ceiling id with 403, and records the attempt. | Functionality, the steered-argument read, the denial, and the logged escalation. |

The current direct suite logs **100 successful checks**: 27 paired assertions, 32 repeated classifications, and 41 boundary/control assertions. These are logged checks, not 100 independent vulnerabilities or 100 unique attack paths. `tests/boundaries.js` exercises the additional controls. See [AUDIT.md](AUDIT.md) for the evidence and remaining limits.

## Red: change the request, observe the resource

Case 02 changes one client-asserted role header while retaining the same authenticated student session. The relevant difference is which server-side role source the endpoint uses:

```js
// Vulnerable handler: the caller can select a higher role.
const role = clientAssertedRole(req) || req.sessionUser.role;
```

```js
// Fixed handler: the authenticated session supplies the role.
const role = req.sessionUser.role;
```

Case 05 keeps Alice's session and changes only the requested object ID. The response must demonstrate the cross-user data read. A visible profile ID, a public scene name, or a changed local DOM does not establish that result.

## Blue: enforce each protected request

The restricted-brief route in cases 01 and 04 checks current account status before returning data:

```js
app.get('/api/restricted-brief', requireAuth(state), (req, res) => {
  if (req.user.status !== 'active') return res.status(403).json({ code: 'ACCOUNT_DISABLED' });
  res.json({ brief: 'FIXTURE-RESTRICTED-BRIEF', owner: req.user.id });
});
```

The profile route in case 05 verifies ownership before serializing the record. Tests retain the valid owner request, check the other owner, reject unauthenticated calls, and revoke an already authenticated account in the status cases. A fix that denies everybody fails the positive control.

A browser owner can rewrite an entire response, including its HTTP status, or change any local HTML. The fixed client can still be made to display a dashboard. That does not change the session or unlock a protected backend. The lab explicitly tests this distinction rather than claiming a 403 makes the interface tamper-proof.

## Capability is not permission

Case 06 moves the same failure to an agent's tool layer. A tool keyed on a model-supplied id is a cross-account read waiting for a steered argument, and a prompt injection is one way that argument gets steered. A better system prompt does not close that. A monitor at the tool boundary does: it resolves permission from the acting session, serves only what that session owns, and records the over-ceiling attempt instead of discarding it. The agent stays capable of asking. It stops being permitted to receive. See [raised_eyebrow_harness](https://github.com/ghostintheprompt/raised_eyebrow_harness) for the runtime monitor this case gestures at.

## Classification limits

The probes have no ground-truth label input. The harness knows which paired server it started, shuffles the four targets, and compares the returned verdict afterward. Repeated rounds exercise ordering. They do not measure real-world accuracy, independence, or a broad scan population, and the results apply to the fixture contracts they were built for.

Failed login, redirect, malformed JSON, server error, or an unexpected response shape produces `INCONCLUSIVE`. A missing proof of exploitation is not proof of sound authorization.

Cases 01 and 04 keep their UI demonstrations, with protected-resource routes so the server-side consequence is directly testable rather than asserted.

## Taxonomy

Cases 01 and 04 model missing account-status enforcement at the resource endpoint: [CWE-862](https://cwe.mitre.org/data/definitions/862.html). Case 02 models an incorrect role decision: [CWE-863](https://cwe.mitre.org/data/definitions/863.html), with [OWASP API5:2023](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/) as the function-level reference. Case 05 models missing object ownership enforcement: CWE-862 and [OWASP API1:2023](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/).

[CWE-602](https://cwe.mitre.org/data/definitions/602.html) covers relying on the client to enforce server protections, which is the thread running through every case here.

## Next builds

Extend blind classification to cases 04 and 05. Add a signed-claim variant with explicit revocation behavior. Add state-changing operations and replay controls. Those are separate experiments, not capabilities already present here.
