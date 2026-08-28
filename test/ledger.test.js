/**
 * Ledger tests.
 *
 * The happy path is three tests. The rest are adversarial, and each one is named
 * for the attack it refuses rather than the function it calls — because when one
 * of these fails, the useful information is which attack just became possible.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import {
  WRITER,
  QUIESCENT,
  LedgerError,
  signRecord,
  verifyLedger,
  isWriter,
  nextRecord,
  digestOf,
} from "../src/ledger.js";

const owner = generateKeyPairSync("ed25519");
const attacker = generateKeyPairSync("ed25519");

const AT = "2026-01-01T00:00:00.000Z";

/** Build a signed chain from a list of {state, machine} steps. */
function chain(steps, key = owner.privateKey) {
  const records = [];
  for (const step of steps) {
    records.push(signRecord(nextRecord(records, { ...step, issuedAt: AT }), key));
  }
  return records;
}

function stripSig(record) {
  const { signature, ...body } = record;
  return body;
}

/**
 * Assert that `fn` fails closed with a specific code, and hand the error back
 * so a test can check its detail. `assert.throws` returns undefined, and a
 * distinguishable failure code is the whole contract here — "it threw
 * something" is not what any of these tests mean to assert.
 */
function failsWith(fn, code) {
  let caught;
  try {
    fn();
  } catch (e) {
    caught = e;
  }
  assert.ok(caught, `expected ${code}, but nothing was thrown`);
  assert.ok(caught instanceof LedgerError, `expected LedgerError, got ${caught.name}`);
  assert.equal(caught.code, code, `expected ${code}, got ${caught.code}`);
  return caught;
}

const HANDOVER = [
  { state: WRITER, machine: "laptop" },
  { state: QUIESCENT },
  { state: WRITER, machine: "desktop" },
];

// ── the happy path ──────────────────────────────────────────────────────────

test("a genesis record establishes a writer", () => {
  const tip = verifyLedger(chain([{ state: WRITER, machine: "laptop" }]), owner.publicKey);
  assert.equal(tip.epoch, 1);
  assert.equal(tip.state, WRITER);
  assert.equal(tip.machine, "laptop");
});

test("authority moves between machines through QUIESCENT", () => {
  const tip = verifyLedger(chain(HANDOVER), owner.publicKey);
  assert.equal(tip.epoch, 3);
  assert.equal(tip.machine, "desktop");
});

test("isWriter answers for the tip only, not for history", () => {
  const records = chain(HANDOVER);
  assert.equal(isWriter(records, owner.publicKey, "desktop"), true);
  // laptop held authority at epoch 1 and does not hold it now.
  assert.equal(isWriter(records, owner.publicKey, "laptop"), false);
});

// ── adversarial ─────────────────────────────────────────────────────────────

test("refuses a direct writer-to-writer handover even when correctly signed", () => {
  // Both records are genuinely owner-signed and the chain is intact. It is
  // still refused: a direct transfer cannot be told apart from a replay of an
  // older one, and there is no instant in it where authority is provably held
  // by nobody.
  const err = failsWith(
    () =>
      verifyLedger(
        chain([
          { state: WRITER, machine: "laptop" },
          { state: WRITER, machine: "desktop" },
        ]),
        owner.publicKey
      ),
    "ILLEGAL_TRANSITION"
  );
  assert.equal(err.detail.from, "laptop");
  assert.equal(err.detail.to, "desktop");
});

test("detects a truncation that removes a middle epoch", () => {
  // The classic attack: drop the QUIESCENT record so the remaining two look
  // like a clean handover. Enumerating epochs and checking contiguity catches
  // it; probing for tip+1 would not.
  const full = chain(HANDOVER);
  const err = failsWith(() => verifyLedger([full[0], full[2]], owner.publicKey), "EPOCH_GAP");
  assert.equal(err.detail.expected, 2);
  assert.equal(err.detail.found, 3);
});

test("detects a record whose body was edited after signing", () => {
  const records = chain(HANDOVER);
  records[2] = { ...records[2], machine: "attacker-box" };
  failsWith(() => verifyLedger(records, owner.publicKey), "BAD_SIGNATURE");
});

test("a ledger signed by the wrong key verifies against nothing", () => {
  // The chain is internally consistent and correctly hash-linked. It is signed
  // by the attacker throughout. Because the trust root is supplied by the
  // caller and never read from the ledger, this is simply not the owner's
  // ledger.
  const forged = chain(HANDOVER, attacker.privateKey);
  failsWith(() => verifyLedger(forged, owner.publicKey), "BAD_SIGNATURE");

  // ...and it verifies perfectly against the attacker's own key, which is the
  // point: possession of a valid chain proves nothing without the right root.
  assert.equal(verifyLedger(forged, attacker.publicKey).machine, "desktop");
});

test("detects a re-ordered chain", () => {
  const r = chain(HANDOVER);
  failsWith(() => verifyLedger([r[0], r[2], r[1]], owner.publicKey), "EPOCH_GAP");
});

test("detects a spliced record that breaks the hash link", () => {
  const records = chain(HANDOVER);
  // Re-sign epoch 2 with a different timestamp: valid signature, valid epoch,
  // but every later record now points at a digest that no longer exists.
  records[1] = signRecord(
    { ...stripSig(records[1]), issuedAt: "2026-06-06T00:00:00.000Z" },
    owner.privateKey
  );
  failsWith(() => verifyLedger(records, owner.publicKey), "BROKEN_CHAIN");
});

test("genesis cannot start QUIESCENT", () => {
  failsWith(() => verifyLedger(chain([{ state: QUIESCENT }]), owner.publicKey), "MALFORMED_RECORD");
});

test("an empty ledger proves nothing", () => {
  failsWith(() => verifyLedger([], owner.publicKey), "EMPTY_LEDGER");
});

test("isWriter fails closed on every broken ledger", () => {
  const good = chain(HANDOVER);
  for (const broken of [
    [],
    [good[0], good[2]],
    chain(HANDOVER, attacker.privateKey),
    [{ epoch: 1, state: WRITER, machine: "desktop", previousRecordDigest: null }],
  ]) {
    assert.equal(isWriter(broken, owner.publicKey, "desktop"), false);
  }
});

test("the signature is not part of what it signs", () => {
  // If the digest covered the signature, no record could ever chain to another,
  // because the digest would change the moment it was signed.
  const [genesis] = chain([{ state: WRITER, machine: "laptop" }]);
  assert.equal(digestOf(genesis), digestOf({ ...genesis, signature: "different" }));
});
