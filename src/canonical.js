/**
 * Deterministic serialization.
 *
 * Every signature and every digest in this project is taken over the output of
 * this function, never over `JSON.stringify`. The reason is narrow and it
 * matters: `JSON.stringify` preserves insertion order, so two objects that are
 * equal by value can serialize to different bytes and therefore produce
 * different digests. An attacker who can influence key order can then present
 * the "same" record twice and have it verify once and fail once — or, worse,
 * have a replay guard keyed on a digest fail to recognise a replay.
 *
 * Rules, all of which exist to remove a degree of freedom an attacker could use:
 *
 *   - object keys are sorted by code unit
 *   - only finite, safe integers and finite doubles are allowed; NaN, Infinity
 *     and -0 are rejected rather than coerced, because JSON has no
 *     representation for them and every language disagrees about the fallback
 *   - strings are normalised to Unicode NFC, so two visually identical strings
 *     cannot produce two digests
 *   - lone surrogates are rejected; they survive JSON.stringify but are not
 *     valid text and round-trip differently through other languages
 *   - `undefined`, functions and symbols are rejected rather than silently
 *     dropped, because silently dropping a field changes the meaning of a
 *     signed record
 *   - only plain objects and arrays are accepted; a Date or a Map has no
 *     canonical JSON form and guessing one is how implementations diverge
 */

const MAX_DEPTH = 64;

export class CanonicalError extends Error {
  constructor(code, path, message) {
    super(`${code} at ${path || "<root>"}: ${message}`);
    this.name = "CanonicalError";
    this.code = code;
    this.path = path;
  }
}

function isPlainObject(v) {
  if (v === null || typeof v !== "object") return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function checkString(s, path) {
  // Reject lone surrogates. String.prototype.normalize will happily carry them
  // through, and they are the classic way to make two "equal" strings differ.
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new CanonicalError("LONE_SURROGATE", path, "unpaired high surrogate");
      }
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      throw new CanonicalError("LONE_SURROGATE", path, "unpaired low surrogate");
    }
  }
  return s.normalize("NFC");
}

function encode(value, path, depth) {
  if (depth > MAX_DEPTH) {
    throw new CanonicalError("DEPTH_EXCEEDED", path, `deeper than ${MAX_DEPTH}`);
  }

  if (value === null) return "null";

  const t = typeof value;

  if (t === "boolean") return value ? "true" : "false";

  if (t === "number") {
    if (!Number.isFinite(value)) {
      throw new CanonicalError("NON_FINITE_NUMBER", path, String(value));
    }
    if (Object.is(value, -0)) {
      // -0 and 0 are the same value to ===, but serialize differently in some
      // implementations. Reject rather than pick a winner.
      throw new CanonicalError("NEGATIVE_ZERO", path, "-0 has no canonical form");
    }
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new CanonicalError("UNSAFE_INTEGER", path, `${value} exceeds 2^53-1`);
    }
    return JSON.stringify(value);
  }

  if (t === "string") return JSON.stringify(checkString(value, path));

  if (t === "undefined") {
    throw new CanonicalError("UNDEFINED", path, "undefined would be silently dropped");
  }
  if (t === "function" || t === "symbol") {
    throw new CanonicalError("UNSUPPORTED_TYPE", path, t);
  }
  if (t === "bigint") {
    throw new CanonicalError("UNSUPPORTED_TYPE", path, "bigint has no JSON form");
  }

  if (Array.isArray(value)) {
    const parts = value.map((v, i) => encode(v, `${path}[${i}]`, depth + 1));
    return `[${parts.join(",")}]`;
  }

  if (!isPlainObject(value)) {
    throw new CanonicalError(
      "UNSUPPORTED_TYPE",
      path,
      `${value.constructor?.name ?? "object"} is not a plain object`
    );
  }

  const keys = Object.keys(value).sort();
  const parts = keys.map((k) => {
    const kp = path ? `${path}.${k}` : k;
    return `${JSON.stringify(checkString(k, kp))}:${encode(value[k], kp, depth + 1)}`;
  });
  return `{${parts.join(",")}}`;
}

/** Canonical UTF-8 bytes for `value`. Throws CanonicalError on anything ambiguous. */
export function canonicalize(value) {
  return Buffer.from(encode(value, "", 0), "utf8");
}
