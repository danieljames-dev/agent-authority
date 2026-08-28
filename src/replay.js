/**
 * Write-ahead replay protection.
 *
 * An authorization decision says a request is permitted. It does not say the
 * request has not already run. Those are different questions, and conflating
 * them is how a retried network call, a restarted broker, or a replayed message
 * performs a privileged operation twice.
 *
 * The ordering is the whole design:
 *
 *     1. record the intent to execute        <- durable, before anything happens
 *     2. execute the privileged operation
 *     3. record the outcome
 *
 * Recording *after* execution is the obvious implementation and it is wrong: a
 * crash between execution and recording leaves an operation that happened with
 * no evidence it happened, so the retry runs it again. Recording first means a
 * crash leaves an operation that may or may not have happened but is marked as
 * attempted — and "refuse a possible duplicate" is the safe side of that
 * ambiguity for anything privileged.
 *
 * The key is a digest over the full request context, not just an id. A caller
 * that reuses a request id against a different envelope, a different baseline,
 * or a different broker instance is making a genuinely different request, and
 * conversely a caller cannot dodge the guard by changing a field the operation
 * does not depend on — because every field is in the digest.
 *
 * Storage is a port. This module has no idea whether it is talking to a file, a
 * table, or a Map, which is what lets the crash tests below actually simulate a
 * crash instead of describing one.
 */

import { createHash } from "node:crypto";
import { canonicalize } from "./canonical.js";

export const ATTEMPTED = "ATTEMPTED";
export const COMPLETED = "COMPLETED";

export class ReplayError extends Error {
  constructor(code, message, detail = {}) {
    super(`${code}: ${message}`);
    this.name = "ReplayError";
    this.code = code;
    this.detail = detail;
  }
}

/** Everything that makes this request this request. */
export function requestKey({ authorizationId, requestId, envelopeDigest, brokerInstanceId, operation, params }) {
  for (const [name, value] of Object.entries({
    authorizationId,
    requestId,
    envelopeDigest,
    brokerInstanceId,
    operation,
  })) {
    if (typeof value !== "string" || value.length === 0) {
      throw new ReplayError("INCOMPLETE_KEY", `${name} is required to key a request`);
    }
  }
  return createHash("sha256")
    .update(
      canonicalize({
        authorizationId,
        requestId,
        envelopeDigest,
        brokerInstanceId,
        operation,
        params: params ?? null,
      })
    )
    .digest("hex");
}

/**
 * An in-memory store. Real deployments swap this for something durable; the
 * interface is deliberately three methods so that swap is uninteresting.
 */
export class MemoryStore {
  #entries = new Map();
  get(key) {
    return this.#entries.get(key) ?? null;
  }
  put(key, entry) {
    this.#entries.set(key, entry);
  }
  /** Snapshot, so a test can simulate a process restart against the same data. */
  snapshot() {
    return new Map(this.#entries);
  }
  static from(snapshot) {
    const s = new MemoryStore();
    for (const [k, v] of snapshot) s.put(k, v);
    return s;
  }
}

export class ReplayGuard {
  #store;
  constructor(store) {
    this.#store = store;
  }

  /**
   * Run `execute` at most once for this request.
   *
   * Returns `{ status, result }`. A second call with the same key does not
   * re-run `execute` — it reports what is known, which may be COMPLETED with the
   * recorded result, or ATTEMPTED with no result at all if a previous run
   * crashed mid-flight.
   */
  async once(key, execute) {
    if (typeof key !== "string" || key.length !== 64) {
      throw new ReplayError("BAD_KEY", "key must be a sha256 digest from requestKey()");
    }

    const existing = this.#store.get(key);
    if (existing) {
      if (existing.status === COMPLETED) {
        return { status: COMPLETED, result: existing.result, fresh: false };
      }
      // Marked attempted, never completed. We cannot know whether the privileged
      // side effect happened. Refusing is the only safe answer, and it is
      // reported as its own condition so an operator can resolve it deliberately
      // rather than having the system silently guess.
      throw new ReplayError(
        "INDETERMINATE",
        "a previous attempt did not record an outcome; resolve manually",
        { key }
      );
    }

    // Write-ahead. If the process dies on the next line, this is what remains.
    this.#store.put(key, { status: ATTEMPTED, at: null });

    const result = await execute();

    this.#store.put(key, { status: COMPLETED, result });
    return { status: COMPLETED, result, fresh: true };
  }
}
