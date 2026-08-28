# agent-authority

**Cryptographic authority boundaries for autonomous agents.**

If you let a coding agent run with elevated privileges on a real machine, you
need an answer to one question: *what stops it from granting itself more?*

"We told it not to" is not an answer. Neither is a well-written system prompt.
The thing you would be trusting is the same thing that might be compromised, or
confused, or simply wrong.

This is a small, dependency-free library of the primitives that do answer it —
extracted as a standalone reference from a larger private system, and written
here from scratch so it can be read end to end in one sitting.

```
634 lines of source · 713 lines of tests · 51 tests · 0 dependencies
```

Every number above is reproducible:

```bash
cat src/*.js | wc -l      # source
cat test/*.js | wc -l     # tests
npm test                  # 51 passing
node -e "console.log(Object.keys(require('./package.json').dependencies).length)"
```

---

## The four ideas

### 1. The trust root lives outside the thing it authenticates

`verifyLedger(records, ownerPublicKey)` takes the public key as an argument. It
is never read from the ledger.

A ledger carrying its own trust root is self-authenticating, which is another
way of saying unauthenticated — an attacker who can rewrite the records rewrites
the key too. There is a test that builds a *completely valid* chain signed by an
attacker and shows it verifying against the attacker's key and failing against
the owner's. Possession of a well-formed chain proves nothing on its own.

### 2. A caller may supply a claim; it may never supply the measurement

This is the one I'd defend hardest.

An envelope says *this machine, this repo, this baseline commit*. Those are
claims made when it was signed. Authorization compares each claim against a
measurement taken now. The failure mode is subtle: the natural signature

```js
authorize(envelope, request)   // where request conveniently carries the hostname
```

lets the caller supply **both sides of every comparison**. The check still
passes. Nothing looks broken. It just stopped proving anything.

Here that is structurally impossible rather than discouraged. `authorize`
demands a value that only `observe()` can produce, and membership is tracked in
a module-private `WeakSet` the caller cannot reach.

> The first version used a branding symbol. A test that tried to launder a real
> measurement — `{ ...observation, hostname: "elsewhere" }` — caught it: **object
> spread copies enumerable symbol keys**, so the brand survived the edit. That
> test is still in the suite.

### 3. Authority moves through a gap, never directly

Machine A hands back to `QUIESCENT`; only then may machine B take `WRITER`. A
direct A → B transfer is refused **even when correctly signed**, because it is
indistinguishable from a replay of an older handover and there is no instant in
it where authority is provably held by nobody.

The chain is walked from genesis on every check. There is no cached "current
writer" — a cached capability is one that outlives its evidence.

### 4. Record the intent before doing the thing

An authorization says a request is *permitted*. It does not say it has not
already run.

The replay guard writes "attempted" durably **before** execution, then the
outcome after. Recording afterwards is the obvious implementation and it is
wrong: a crash in between leaves an operation that happened with no evidence,
so the retry does it again. Recording first leaves an operation that *may* have
happened and is marked as attempted — and for anything privileged, "refuse a
possible duplicate" is the safe side of that ambiguity. It surfaces as its own
`INDETERMINATE` condition so an operator resolves it deliberately, rather than
the system silently guessing.

---

## Failure is closed, and distinguishable

Every rejection carries a code. This matters more than it looks: a gap in the
epoch sequence and a stray file in the ledger directory are different events —
one is an attack and the other is an operating system. A system that reports
both as "invalid ledger" trains its operator to ignore both.

`EPOCH_GAP` · `BROKEN_CHAIN` · `BAD_SIGNATURE` · `ILLEGAL_TRANSITION` ·
`UNOBSERVED_FACTS` · `MACHINE_MISMATCH` · `BASELINE_MISMATCH` · `ROLE_FORBIDS` ·
`INDETERMINATE`

---

## Architecture rules that fail the build

`test/architecture.test.js` asserts properties of the source, not its behaviour:

| Rule | Why |
|---|---|
| no network imports | an authority decision that can call out can be influenced by whoever answers |
| no process spawning | same |
| no `eval` / `new Function` / `vm` | same |
| **no `JSON.stringify` outside the serializer** | it preserves insertion order, so a digest over it can differ for two equal values — defeating both the hash chain and the replay guard |
| zero dependencies | every dependency is a party that can change what this does without a commit here |
| no machine paths or hostnames anywhere | see below |

That last rule exists because of a real mistake. In an earlier private project
of mine the same rule existed, was correct, and was scoped to a single
directory — so a Windows user path and a machine name sat in a *different*
directory, in a public repository, for weeks. The rule was right and its
enforcement surface was narrower than its intent. Here it walks the whole
repository.

Written down in a README, each of these is a request. Written here, it's a
failing build.

---

## Usage

```js
import { generateKeyPairSync } from "node:crypto";
import { signRecord, nextRecord, verifyLedger, isWriter, WRITER, QUIESCENT } from "./src/ledger.js";
import { observe, authorize } from "./src/envelope.js";
import { ReplayGuard, MemoryStore, requestKey } from "./src/replay.js";

const owner = generateKeyPairSync("ed25519");

// Authority: laptop hands to desktop, through QUIESCENT.
const ledger = [];
for (const step of [
  { state: WRITER, machine: "laptop" },
  { state: QUIESCENT },
  { state: WRITER, machine: "desktop" },
]) {
  ledger.push(signRecord(nextRecord(ledger, { ...step, issuedAt: new Date().toISOString() }), owner.privateKey));
}
isWriter(ledger, owner.publicKey, "desktop");   // true
isWriter(ledger, owner.publicKey, "laptop");    // false

// Authorization: facts are measured here, never passed in.
const facts = observe({
  hostname: () => "desktop",
  repoRoot: () => "/srv/project",
  gitOrigin: () => "git@example.com:acme/project.git",
  headCommit: () => "a1b2c3d4",
});
authorize({ envelope, request, facts, ownerPublicKey: owner.publicKey, now: new Date() });

// Execution: at most once, ever.
const guard = new ReplayGuard(new MemoryStore());
await guard.once(requestKey({ ...ctx }), async () => doThePrivilegedThing());
```

---

## What this is not

- **Not a sandbox.** It decides who may act. It does not contain what they do
  once permitted. Same-user malware is outside what any of this can promise.
- **Not a key management system.** Signing happens elsewhere, offline. Nothing
  here ever holds a private key; the verifying process cannot mint authority
  even if fully compromised.
- **Not battle-tested.** It is a clear, tested reference implementation of ideas
  that came out of a larger system. Read it, take the ideas, don't deploy it
  because a README told you to.
- **Not a full ledger implementation.** There is no external monotonic witness,
  so an attacker with write access to the whole ledger *and* the anchor can roll
  it back to an earlier consistent state. That's a known residual risk, stated
  rather than hidden. See `docs/THREAT-MODEL.md`.

## Further reading

- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) — named adversaries, what is and isn't defended
- [`docs/INCIDENT-agent-governance.md`](docs/INCIDENT-agent-governance.md) — an agent (me, working on the parent project) overstepped its authority; what it did, why it was wrong, and what it changed

MIT licensed.
