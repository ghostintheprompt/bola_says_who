# data_driven_authz_lab

A reproducible lab for authorization-bypass classes that live in the gap
between what a server *knows* and what it *tells the client* — built the same
way as [`cve_lab`](../cve_lab) and [`transit_fare_lab`](../transit_fare_lab):
one case per directory, a vulnerable and a fixed build of the same server
differing by exactly the control under test, and a two-part verification
(functionality + vulnerability) run against both, not described.

## Why this exists

A modern single-page app decides what to render from whatever the server
returns — in an API response or in the initial state shipped with the HTML.
When the server encodes an authorization outcome as the presence of data, an
empty `200`, a plaintext flag, or a caller-supplied role, the decision
effectively moves into the browser — the one surface an attacker fully
controls. Each case below models one such failure, proves it is exploitable
against a backend built for the question, and proves a specific fix closes it.

## Method

Each case is a **matched pair**: the `vulnerable/` and `fixed/` servers are
identical except for the single authorization check under test, so the diff
*is* the finding — no confounding rewrite. Every exploit demonstration is a
non-destructive probe that proves a boundary holds or does not; no weaponized
payload is ever sent to anything but this lab's own seeded fixtures. Every
claim is run before it is written down.

Case 03 adds a **blind detector**: the real vulnerable and fixed servers are
shuffled into unlabeled slots across randomized rounds, and a target-agnostic
probe — given only a URL and the operator's own fixture credentials, never the
ground-truth label — must classify each correctly from observed behavior alone.
This separates a genuine detector from a label-reader.

## Cases

- [`01-empty-200-as-disabled`](./cases/01-empty-200-as-disabled/) — a disabled
  account is served `200 { projects: [] }`, byte-identical to an active account
  with no projects; the client infers "disabled" from the empty list, so an
  injected non-empty payload flips it to the dashboard. Fix: explicit
  `403 { code: "ACCOUNT_DISABLED" }`, payload withheld. **7/7.**
- [`02-client-trusted-role`](./cases/02-client-trusted-role/) — the dashboard
  endpoint routes on a client-asserted role header (a mutable, non-`HttpOnly`
  role cookie's stand-in); a student asserting the fellow role gets the fellow
  dashboard. Fix: role derived from the session's server-side record. **5/5.**
- [`03-blind-probe`](./cases/03-blind-probe/) — target-agnostic detectors for
  cases 01 and 02, scored against the shuffled real servers with labels
  withheld. **32/32 correct across 8 randomized rounds.**
- [`04-ssr-state-exposure`](./cases/04-ssr-state-exposure/) — the server-
  rendered page embeds the authorization flag (`isActive`), the account's
  `profileId`, and the protected scene name in a plaintext initial-state blob
  the client hydrates from. Two defects in one response: sensitive state is
  exposed (CWE-200), and editing the flag in transit flips a disabled account
  to the dashboard. Fix: the server renders the authoritative view and ships no
  flag, no identifier, and no protected markup to a disabled account. **6/6.**
- [`05-idor-cross-user`](./cases/05-idor-cross-user/) — `GET /api/profile/:id`
  checks authentication but not ownership, so any logged-in worker reads
  another worker's contact details and earnings by supplying their `profileId`
  (the same identifier exposed in case 04). Fix: confirm the session owns the
  `profileId` before returning it. **4/4.**

## Framework mapping

Mapped only where the behavior actually fits; loose taxonomy is worse than
none.

| Case | CWE | OWASP |
|------|-----|-------|
| 01 | CWE-602 (Client-Side Enforcement of Server-Side Security), CWE-807 (Reliance on Untrusted Inputs in a Security Decision), CWE-285 (Improper Authorization), CWE-754 (Improper Check for Exceptional Conditions) | Top 10 2021 A01: Broken Access Control; API Security Top 10 2023 API1: Broken Object Level Authorization |
| 02 | CWE-284 (Improper Access Control), CWE-639 (Authorization Bypass Through User-Controlled Key) | Top 10 2021 A01; API Security Top 10 2023 API5: Broken Function Level Authorization |
| 04 | CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor), CWE-602, CWE-807 | Top 10 2021 A01; A05: Security Misconfiguration |
| 05 | CWE-639, CWE-284 | Top 10 2021 A01; API Security Top 10 2023 API1: Broken Object Level Authorization |

NIST SP 800-53 control objective across all cases: AC-3 (Access Enforcement) —
the enforcement point must be the server, not a client-side inference.

**Deliberately not mapped:** MITRE ATT&CK and ATLAS. These are web-application
authorization defects reproduced in a controlled lab, not observed adversary
TTP sequences (ATT&CK) and not attacks on an ML model or its supply chain
(ATLAS). Forcing either mapping would misrepresent the evidence.

## Evidence, assumptions, and confidence

- **Lab result (high confidence, directly observed and reproducible):** every
  vulnerable build is exploitable and every fixed build defeats the identical
  probe. Verified by `npm test` and in-container, 7/7 + 5/5 + 32/32 + 6/6 +
  4/4, same output either way.
- **Theoretical result (high confidence, deductive):** these classes are
  vulnerabilities wherever they exist — an authorization outcome carried by
  attacker-controllable input (an empty body, a plaintext flag, a supplied
  role or object ID) is not a control. The lab demonstrates this; it does not
  depend on the lab for its truth.
- **Field provenance (reported, not independently verified here):** the classes
  were modeled from behavior observed on a real contractor-platform account-
  state screen. The live target is **not named, probed, or touched** by this
  lab. Whether that platform currently exhibits these behaviors is a separate
  claim this lab does **not** establish; confirming it would require authorized
  testing against that system and is out of scope here.
- **Scope discipline:** case 05 answers, against this lab's own fixtures, the
  cross-user pivot the source notes only *proposed* trying. It is proven here
  precisely because it is **not** run against any real account — the controlled
  backend is what makes confirming the boundary legitimate.

## Running it

Directly:

```bash
npm install
npm test
```

Containerized:

```bash
docker compose build
docker compose run --rm lab
```

Both run identically — confirmed, same 7/7 + 5/5 + 32/32 + 6/6 + 4/4 output
either way. Each `test.js` spins up both servers on an ephemeral local port,
logs in with real fixture credentials, runs the checks, and prints pass/fail
per check — non-destructively, against fixture data this lab owns and seeds
itself. Nothing here talks to any real platform.

## Queued next, not started

- A signed-claim fix variant: the client reads an `is_active` claim from a
  signed session token it cannot forge, instead of inferring state from the
  response body or a shipped flag at all.
- Extending the case 03 blind detector to cover cases 04 and 05.
- A session-replay case: whether a fare-style deduction or a state-changing
  mutation can be replayed or reordered.
