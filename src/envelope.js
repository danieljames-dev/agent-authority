/**
 * Capability envelopes, and the rule that makes them mean anything.
 *
 * An envelope is a signed grant: this role, on this machine, in this repository,
 * from this baseline commit, may perform these operation classes, until this
 * time. Every field in it is a CLAIM made at signing time.
 *
 * The rule:
 *
 *     A claim is only ever compared against a measurement taken here, now.
 *     The caller may supply the claim. The caller may never supply the
 *     measurement.
 *
 * This sounds obvious and is very easy to lose. The natural shape for an
 * authorization function is `authorize(envelope, request)`, where the request
 * conveniently carries the current machine name and commit — and at that moment
 * the caller is supplying both sides of every comparison, so the envelope is
 * decorative. The check still passes. Nothing looks wrong. It just no longer
 * proves anything.
 *
 * Here that mistake is made structurally impossible rather than discouraged:
 * `authorize` demands an `Observations` value, and `Observations` can only be
 * produced by `observe()`, which calls the fact ports itself. An object literal
 * with the right keys is rejected, because it was never measured. There is no
 * documentation to ignore and no convention to forget — the wrong call does not
 * type-check at runtime.
 */

import { verify as edVerify } from "node:crypto";
import { canonicalize } from "./canonical.js";

/**
 * Module-private registry of values this module actually measured. Not exported,
 * so nothing outside this file can add to it. This is the whole enforcement.
 *
 * A WeakSet rather than a branding symbol, deliberately. Object spread copies
 * enumerable symbol keys, so a symbol brand survives
 * `{ ...observation, hostname: "elsewhere" }` — which would let a caller take a
 * real measurement, edit one field, and launder it back in as measured.
 * Membership of a set the caller cannot reach survives no copy at all.
 *
 * The first implementation here used a symbol. The laundering test in
 * test/envelope.test.js is what caught it.
 */
const observedFacts = new WeakSet();

export class AuthorizationError extends Error {
  constructor(code, message, detail = {}) {
    super(`${code}: ${message}`);
    this.name = "AuthorizationError";
    this.code = code;
    this.detail = detail;
  }
}

/**
 * Take a measurement of the world.
 *
 * `ports` are the only route to reality: each is a function returning a fact.
 * In production these read the actual hostname, the actual repository root and
 * the actual git HEAD. In tests they are stubs — which is fine, because the
 * boundary being defended is "the request cannot describe the world", not
 * "tests cannot".
 */
export function observe(ports) {
  const required = ["hostname", "repoRoot", "gitOrigin", "headCommit"];
  const facts = {};
  for (const key of required) {
    if (typeof ports[key] !== "function") {
      throw new AuthorizationError("MISSING_PORT", `no port supplied for ${key}`);
    }
    const value = ports[key]();
    if (typeof value !== "string" || value.length === 0) {
      throw new AuthorizationError("BAD_OBSERVATION", `${key} port returned no value`);
    }
    facts[key] = value;
  }
  const measurement = Object.freeze(facts);
  observedFacts.add(measurement);
  return measurement;
}

function assertObserved(value) {
  if (typeof value !== "object" || value === null || !observedFacts.has(value)) {
    throw new AuthorizationError(
      "UNOBSERVED_FACTS",
      "facts must come from observe(); a caller-supplied object is not a measurement"
    );
  }
}

function bodyOf(envelope) {
  const { signature, ...body } = envelope;
  return canonicalize(body);
}

/**
 * Decide whether one request is permitted.
 *
 * Note what is NOT a parameter: anything describing the current machine, repo or
 * commit. Those arrive only inside `facts`, and only `observe()` can build one.
 */
export function authorize({ envelope, request, facts, ownerPublicKey, now }) {
  assertObserved(facts);

  if (!edVerify(null, bodyOf(envelope), ownerPublicKey, Buffer.from(envelope.signature, "base64"))) {
    throw new AuthorizationError("BAD_ENVELOPE_SIGNATURE", "envelope is not owner-signed");
  }

  if (!(now instanceof Date) || Number.isNaN(now.getTime())) {
    throw new AuthorizationError("BAD_CLOCK", "now must be a valid Date");
  }
  if (now.toISOString() >= envelope.expiresAt) {
    throw new AuthorizationError("EXPIRED", `envelope expired at ${envelope.expiresAt}`, {
      expiresAt: envelope.expiresAt,
    });
  }

  // Claim vs measurement, one pair at a time. Each mismatch gets its own code:
  // "the envelope was issued for another machine" and "the repository has moved
  // on since the envelope was issued" are different incidents.
  const pairs = [
    ["MACHINE_MISMATCH", "machine", envelope.machine, facts.hostname],
    ["REPO_MISMATCH", "repoRoot", envelope.repoRoot, facts.repoRoot],
    ["ORIGIN_MISMATCH", "gitOrigin", envelope.gitOrigin, facts.gitOrigin],
    ["BASELINE_MISMATCH", "baselineCommit", envelope.baselineCommit, facts.headCommit],
  ];
  for (const [code, field, claimed, measured] of pairs) {
    if (claimed !== measured) {
      throw new AuthorizationError(code, `${field}: envelope claims a different world`, {
        field,
        claimed,
        observed: measured,
      });
    }
  }

  // Deny is evaluated before allow and is not overridable. An envelope that both
  // allows and denies an operation denies it — the safe reading of a
  // contradiction is the restrictive one.
  if (envelope.deny.includes(request.operation)) {
    throw new AuthorizationError("DENIED", `${request.operation} is explicitly denied`, {
      operation: request.operation,
    });
  }
  if (!envelope.allow.includes(request.operation)) {
    throw new AuthorizationError("NOT_ALLOWED", `${request.operation} is not in the allow list`, {
      operation: request.operation,
    });
  }

  // Roles are structural, not advisory. An auditor envelope cannot be granted a
  // write operation even if someone puts one in its allow list, because the
  // separation between the agent that builds and the agent that checks the build
  // is the only reason a second agent is worth running at all.
  if (envelope.role === "auditor" && WRITE_OPERATIONS.has(request.operation)) {
    throw new AuthorizationError(
      "ROLE_FORBIDS",
      "an auditor may never be granted a write operation",
      { role: envelope.role, operation: request.operation }
    );
  }

  return Object.freeze({
    permitted: true,
    role: envelope.role,
    operation: request.operation,
    requestId: request.requestId,
  });
}

export const WRITE_OPERATIONS = new Set([
  "repo.write",
  "repo.commit",
  "repo.push",
  "service.install",
]);
