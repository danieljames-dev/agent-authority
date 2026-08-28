/**
 * Envelope tests.
 *
 * The first test is the one that matters. Everything else is a consequence of it.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import { signRecord } from "../src/ledger.js";
import { observe, authorize, AuthorizationError } from "../src/envelope.js";

const owner = generateKeyPairSync("ed25519");
const attacker = generateKeyPairSync("ed25519");

const WORLD = {
  hostname: () => "build-01",
  repoRoot: () => "/srv/project",
  gitOrigin: () => "git@example.com:acme/project.git",
  headCommit: () => "a1b2c3d4",
};

function envelope(overrides = {}, key = owner.privateKey) {
  return signRecord(
    {
      role: "builder",
      machine: "build-01",
      repoRoot: "/srv/project",
      gitOrigin: "git@example.com:acme/project.git",
      baselineCommit: "a1b2c3d4",
      allow: ["repo.write", "repo.commit"],
      deny: ["repo.push"],
      expiresAt: "2027-01-01T00:00:00.000Z",
      ...overrides,
    },
    key
  );
}

const NOW = new Date("2026-06-01T00:00:00.000Z");

function call(over = {}) {
  return authorize({
    envelope: envelope(over.envelope),
    request: { operation: "repo.write", requestId: "r-1", ...over.request },
    facts: over.facts ?? observe(over.ports ?? WORLD),
    ownerPublicKey: owner.publicKey,
    now: over.now ?? NOW,
    ...over.extra,
  });
}

function failsWith(fn, code) {
  let caught;
  try {
    fn();
  } catch (e) {
    caught = e;
  }
  assert.ok(caught, `expected ${code}, nothing thrown`);
  assert.ok(caught instanceof AuthorizationError, `expected AuthorizationError, got ${caught.name}`);
  assert.equal(caught.code, code, `expected ${code}, got ${caught.code}`);
  return caught;
}

// ── the rule ────────────────────────────────────────────────────────────────

test("a caller cannot supply the facts it is being checked against", () => {
  // This is the entire point of the module. An object with exactly the right
  // shape, describing a world in which everything matches, is refused — because
  // it was asserted rather than measured.
  const forged = {
    hostname: "build-01",
    repoRoot: "/srv/project",
    gitOrigin: "git@example.com:acme/project.git",
    headCommit: "a1b2c3d4",
  };
  failsWith(() => call({ facts: forged }), "UNOBSERVED_FACTS");

  // The identical values, measured rather than claimed, are fine.
  assert.equal(call({ facts: observe(WORLD) }).permitted, true);
});

test("observations cannot be re-branded by copying them", () => {
  // Spreading an observation drops the private symbol, so a caller cannot take
  // a real measurement, edit one field, and pass it off as measured.
  const real = observe(WORLD);
  failsWith(() => call({ facts: { ...real, hostname: "somewhere-else" } }), "UNOBSERVED_FACTS");
});

test("a permitted request is permitted", () => {
  const decision = call();
  assert.equal(decision.permitted, true);
  assert.equal(decision.role, "builder");
  assert.equal(decision.requestId, "r-1");
});

// ── claim vs measurement ────────────────────────────────────────────────────

test("an envelope for another machine does not authorize this one", () => {
  const err = failsWith(
    () => call({ ports: { ...WORLD, hostname: () => "laptop-99" } }),
    "MACHINE_MISMATCH"
  );
  assert.equal(err.detail.claimed, "build-01");
  assert.equal(err.detail.observed, "laptop-99");
});

test("an envelope stops applying once the repository moves past its baseline", () => {
  // The confused-deputy case after a reboot: the envelope is still valid, still
  // signed, still unexpired — but the tree it described is gone.
  const err = failsWith(
    () => call({ ports: { ...WORLD, headCommit: () => "deadbeef" } }),
    "BASELINE_MISMATCH"
  );
  assert.equal(err.detail.observed, "deadbeef");
});

test("an envelope copied to a different repository does not travel with it", () => {
  failsWith(() => call({ ports: { ...WORLD, repoRoot: () => "/srv/other" } }), "REPO_MISMATCH");
  failsWith(
    () => call({ ports: { ...WORLD, gitOrigin: () => "git@example.com:acme/other.git" } }),
    "ORIGIN_MISMATCH"
  );
});

// ── the envelope itself ─────────────────────────────────────────────────────

test("an envelope edited after signing is refused", () => {
  const tampered = { ...envelope(), allow: ["repo.write", "repo.commit", "repo.push"] };
  failsWith(
    () =>
      authorize({
        envelope: tampered,
        request: { operation: "repo.push", requestId: "r-1" },
        facts: observe(WORLD),
        ownerPublicKey: owner.publicKey,
        now: NOW,
      }),
    "BAD_ENVELOPE_SIGNATURE"
  );
});

test("an envelope signed by anyone else is refused", () => {
  failsWith(
    () =>
      authorize({
        envelope: envelope({}, attacker.privateKey),
        request: { operation: "repo.write", requestId: "r-1" },
        facts: observe(WORLD),
        ownerPublicKey: owner.publicKey,
        now: NOW,
      }),
    "BAD_ENVELOPE_SIGNATURE"
  );
});

test("an expired envelope is refused even when everything else matches", () => {
  failsWith(() => call({ now: new Date("2027-06-01T00:00:00.000Z") }), "EXPIRED");
});

// ── allow, deny, and role ───────────────────────────────────────────────────

test("deny beats allow", () => {
  // A contradiction is read restrictively. The alternative — last-rule-wins, or
  // allow-beats-deny — means a mistake in an allow list silently widens
  // authority, which is the direction you never want a mistake to go.
  failsWith(
    () => call({ envelope: { allow: ["repo.push"], deny: ["repo.push"] }, request: { operation: "repo.push" } }),
    "DENIED"
  );
});

test("an operation absent from the allow list is refused", () => {
  failsWith(() => call({ request: { operation: "service.install" } }), "NOT_ALLOWED");
});

test("an auditor cannot be granted a write, even by a correctly signed envelope", () => {
  // The owner signed an envelope that explicitly allows the auditor to write.
  // It is still refused. Role separation that a signature can waive is not
  // separation — and the auditor exists precisely to check the builder's work.
  const err = failsWith(
    () =>
      call({
        envelope: { role: "auditor", allow: ["repo.write"], deny: [] },
        request: { operation: "repo.write" },
      }),
    "ROLE_FORBIDS"
  );
  assert.equal(err.detail.role, "auditor");
});

test("an auditor may still perform read operations", () => {
  const decision = call({
    envelope: { role: "auditor", allow: ["repo.read"], deny: [] },
    request: { operation: "repo.read" },
  });
  assert.equal(decision.permitted, true);
});

// ── the ports themselves ────────────────────────────────────────────────────

test("a missing or silent port fails closed rather than defaulting", () => {
  const { hostname, ...missing } = WORLD;
  failsWith(() => observe(missing), "MISSING_PORT");
  failsWith(() => observe({ ...WORLD, repoRoot: () => "" }), "BAD_OBSERVATION");
});
