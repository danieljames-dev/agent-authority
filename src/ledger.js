/**
 * A signed, hash-chained authority ledger.
 *
 * The problem it solves: several machines and several autonomous agents can all
 * reach the same repository. Exactly one of them may hold write authority at a
 * time. Nothing in that sentence can be enforced by asking politely, because the
 * thing you would be asking is the same thing that might be compromised.
 *
 * Three design choices carry the weight.
 *
 * 1. THE TRUST ROOT IS EXTERNAL.
 *    `verifyLedger` takes the owner's public key as an argument. It is never
 *    read from the ledger. A ledger that carried its own trust root would be
 *    self-authenticating, which is another way of saying unauthenticated: an
 *    attacker who can rewrite the ledger would simply rewrite the key too.
 *
 * 2. THE CHAIN IS WALKED FROM GENESIS, EVERY TIME.
 *    There is no cached "current writer". Authority is a property of the whole
 *    chain, so it is recomputed from the whole chain. This is slower and it is
 *    the point — a cached capability is a capability that outlives its evidence.
 *
 * 3. AUTHORITY MOVES THROUGH QUIESCENT, NEVER DIRECTLY.
 *    Machine A hands back to QUIESCENT; only then may machine B take WRITER.
 *    A direct A -> B transfer is refused even when correctly signed. The reason
 *    is that a direct transfer is indistinguishable from a replay of an old
 *    handover, and there is no moment in it where zero machines believe they
 *    hold authority. The QUIESCENT step makes the gap explicit and auditable.
 *
 * Failure is always closed, and always distinguishable: a gap in the epoch
 * sequence and a stray file in the ledger directory produce different errors,
 * because one is an attack and the other is Windows.
 */

import { createHash, sign as edSign, verify as edVerify } from "node:crypto";
import { canonicalize } from "./canonical.js";

export const WRITER = "WRITER";
export const QUIESCENT = "QUIESCENT";

export class LedgerError extends Error {
  constructor(code, message, detail = {}) {
    super(`${code}: ${message}`);
    this.name = "LedgerError";
    this.code = code;
    this.detail = detail;
  }
}

/** Bytes that get signed. The signature is never part of what it signs. */
function bodyOf(record) {
  const { signature, ...body } = record;
  return canonicalize(body);
}

export function digestOf(record) {
  return createHash("sha256").update(bodyOf(record)).digest("hex");
}

/**
 * Sign a record. Deliberately separate from verification: in the system this
 * models, signing happens offline with the owner key and verification happens
 * in the running process, which never holds a private key at all.
 */
export function signRecord(body, privateKey) {
  if ("signature" in body) {
    throw new LedgerError("ALREADY_SIGNED", "body already carries a signature");
  }
  const signature = edSign(null, canonicalize(body), privateKey).toString("base64");
  return { ...body, signature };
}

function requireShape(record, index) {
  const at = `record[${index}]`;
  if (!Number.isSafeInteger(record.epoch) || record.epoch < 1) {
    throw new LedgerError("MALFORMED_RECORD", `${at}: epoch must be an integer >= 1`);
  }
  if (record.state !== WRITER && record.state !== QUIESCENT) {
    throw new LedgerError("MALFORMED_RECORD", `${at}: unknown state ${record.state}`);
  }
  if (record.state === WRITER && typeof record.machine !== "string") {
    throw new LedgerError("MALFORMED_RECORD", `${at}: WRITER requires a machine`);
  }
  if (record.state === QUIESCENT && record.machine !== null) {
    throw new LedgerError("MALFORMED_RECORD", `${at}: QUIESCENT must not name a machine`);
  }
  if (typeof record.signature !== "string" || record.signature.length === 0) {
    throw new LedgerError("MALFORMED_RECORD", `${at}: missing signature`);
  }
}

/**
 * Verify a complete ledger and return its tip.
 *
 * @param {object[]} records  ordered, epoch 1 first
 * @param {KeyObject} ownerPublicKey  supplied by the caller, never by the ledger
 */
export function verifyLedger(records, ownerPublicKey) {
  if (!Array.isArray(records) || records.length === 0) {
    throw new LedgerError("EMPTY_LEDGER", "a ledger with no genesis proves nothing");
  }

  let previousDigest = null;

  for (let i = 0; i < records.length; i++) {
    const record = records[i];
    requireShape(record, i);

    // Epochs must be contiguous from 1. Enumerating what is present and
    // checking for gaps — rather than probing for tip+1 — is what catches a
    // truncation attack that removes epoch 2 but leaves epoch 3 in place.
    if (record.epoch !== i + 1) {
      throw new LedgerError(
        "EPOCH_GAP",
        `expected epoch ${i + 1}, found ${record.epoch}`,
        { expected: i + 1, found: record.epoch }
      );
    }

    if (record.previousRecordDigest !== previousDigest) {
      throw new LedgerError(
        "BROKEN_CHAIN",
        `record ${record.epoch} does not follow its predecessor`,
        { expected: previousDigest, found: record.previousRecordDigest }
      );
    }

    const ok = edVerify(
      null,
      bodyOf(record),
      ownerPublicKey,
      Buffer.from(record.signature, "base64")
    );
    if (!ok) {
      throw new LedgerError("BAD_SIGNATURE", `record ${record.epoch} is not owner-signed`, {
        epoch: record.epoch,
      });
    }

    if (i > 0) {
      const prev = records[i - 1];
      // WRITER -> WRITER is refused even when both records verify. See the
      // header: a direct handover cannot be told apart from a replayed one.
      if (prev.state === WRITER && record.state === WRITER) {
        throw new LedgerError(
          "ILLEGAL_TRANSITION",
          `${prev.machine} -> ${record.machine} must pass through ${QUIESCENT}`,
          { from: prev.machine, to: record.machine }
        );
      }
    } else if (record.state !== WRITER) {
      throw new LedgerError("MALFORMED_RECORD", "genesis must establish a WRITER");
    }

    previousDigest = digestOf(record);
  }

  const tip = records[records.length - 1];
  return {
    epoch: tip.epoch,
    state: tip.state,
    machine: tip.machine,
    tipDigest: previousDigest,
  };
}

/**
 * The only question callers should ask. Returns a boolean rather than throwing,
 * because "is this machine allowed to write" has a defined answer even when the
 * ledger is broken — and that answer is no.
 */
export function isWriter(records, ownerPublicKey, machine) {
  try {
    const tip = verifyLedger(records, ownerPublicKey);
    return tip.state === WRITER && tip.machine === machine;
  } catch {
    return false;
  }
}

/** Build the next record in a chain. Does not sign it. */
export function nextRecord(records, { state, machine, issuedAt }) {
  const previous = records.length ? records[records.length - 1] : null;
  return {
    epoch: previous ? previous.epoch + 1 : 1,
    previousRecordDigest: previous ? digestOf(previous) : null,
    state,
    machine: state === WRITER ? machine : null,
    issuedAt,
  };
}
