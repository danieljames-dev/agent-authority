# Threat model

Scoped to the primitives in `src/`. Named adversaries, stated properties, and —
the part most threat models omit — what is *not* defended.

## The setting

One owner. Several machines. One or more autonomous coding agents with elevated
privileges on those machines. Exactly one machine may hold write authority at a
time. The owner signs authority records **offline**; no running process ever
holds a private key.

That last point does most of the work: a fully compromised verifying process
cannot mint authority, only fail to enforce it — and failing to enforce it stops
that process from acting, which is the safe direction.

---

## Adversaries

### A1 — A compromised or confused builder agent

Has code execution as the ordinary user. Wants to write where it may not, or
keep writing after its grant lapsed.

| Defence | Where |
|---|---|
| Chain walked from genesis every check, no cached writer | `ledger.js` |
| Envelope bound to observed host, repo, origin, baseline | `envelope.js` |
| Expiry checked against a caller-supplied clock it does not control | `envelope.js` |
| Operations outside the allow list refused | `envelope.js` |

**Residual:** it can do anything the ordinary user can do that does not route
through these checks. This is an authority layer, not a sandbox.

### A2 — A compromised auditor agent

The agent that checks the builder's work. Wants to write, or to approve itself.

| Defence | Where |
|---|---|
| `role: "auditor"` refuses write operations **even when the signed envelope allows one** | `envelope.js` |
| Deny evaluated before allow, not overridable | `envelope.js` |

Role separation a signature can waive is not separation. If the owner can be
persuaded to sign one bad envelope, the auditor must still not be able to write —
otherwise running a second agent buys nothing.

### A3 — Prompt injection reaching an agent

Hostile text in a file, an issue, or a dependency, aiming to get the agent to
request something outside its grant.

Injection is treated as **inevitable**, not preventable. The defence is that a
persuaded agent still cannot exceed its envelope: the text can change what the
agent *wants*, and changes nothing about what it *may do*. Every check is
performed against measurements the injected text cannot alter.

**Residual:** an agent can be induced to do anything already inside its grant.
Grants should be small for this reason and no other.

### A4 — Replay of a previously valid request

A retried call, a restarted broker, or a captured message re-sent.

| Defence | Where |
|---|---|
| Write-ahead record before execution | `replay.js` |
| Key digests the whole context, not just an id | `replay.js` |
| Indeterminate state refuses rather than retries | `replay.js` |
| Canonical bytes, so key reordering cannot mint a second key | `canonical.js` |

### A5 — The confused deputy after a reboot

An envelope that was valid, on a machine that has since moved on: different
commit, different checkout, restored backup.

Caught by `BASELINE_MISMATCH` and `REPO_MISMATCH`. The envelope describes a world;
if the world has changed, the grant does not apply. This is why the baseline
commit is in the envelope at all.

### A6 — An attacker who can edit the ledger on disk

| Attempt | Result |
|---|---|
| Edit a record's body | `BAD_SIGNATURE` |
| Re-sign with their own key | `BAD_SIGNATURE` — the trust root is external |
| Delete a middle epoch to fake a clean handover | `EPOCH_GAP` |
| Re-order records | `EPOCH_GAP` |
| Splice a re-signed record into the chain | `BROKEN_CHAIN` |
| Forge a direct writer-to-writer handover | `ILLEGAL_TRANSITION` |

**Residual — the significant one.** An attacker who can rewrite the *entire*
ledger and any external record of its tip can roll the system back to an earlier
state that is internally consistent and correctly signed. Nothing inside a
self-contained ledger can detect deletion of its own most recent history; that
requires an **external monotonic witness** — a second party that remembers the
highest epoch it has seen and refuses to go backwards. This library does not
include one. The property is not claimed.

---

## Not defended, stated plainly

- **Same-user malware.** Anything running as the owner can read what the owner
  reads. Privilege separation here is between *roles*, not between the owner and
  their own machine.
- **A compromised signing environment.** If the owner's private key is taken, the
  attacker is the owner. Offline signing narrows the window; it does not close it.
- **Rollback without an external witness.** See A6.
- **Anything after authorization.** This decides *whether* an operation may run.
  What it then does is out of scope.
- **Denial of service.** A corrupted ledger fails closed, which means nobody
  writes. That is deliberate — refusing to act is the correct failure for an
  authority system, and it is also a way to stop all work.

---

## Properties actually claimed

1. No running process can mint authority; it can only verify it.
2. A valid chain proves nothing without the correct external trust root.
3. A caller cannot supply both sides of any comparison.
4. An auditor role cannot obtain a write, regardless of what is signed.
5. A privileged operation runs at most once per request context, across restarts.
6. Every rejection is distinguishable by code, so an attack and an operating
   system quirk are never reported identically.

Each is covered by tests in `test/`, named for the property rather than the
function — so when one goes red, the useful information is which property just
stopped holding.
