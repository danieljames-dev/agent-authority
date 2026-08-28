import { test } from "node:test";
import assert from "node:assert/strict";

import { canonicalize, CanonicalError } from "../src/canonical.js";

const str = (v) => canonicalize(v).toString("utf8");

function failsWith(v, code) {
  let caught;
  try {
    canonicalize(v);
  } catch (e) {
    caught = e;
  }
  assert.ok(caught, `expected ${code}, nothing thrown`);
  assert.ok(caught instanceof CanonicalError, `expected CanonicalError, got ${caught.name}`);
  assert.equal(caught.code, code, `expected ${code}, got ${caught.code}`);
  return caught;
}

test("key order cannot change the bytes", () => {
  // The property every signature in this project rests on.
  assert.equal(str({ b: 1, a: 2 }), str({ a: 2, b: 1 }));
  assert.equal(str({ z: { y: 1, x: 2 } }), str({ z: { x: 2, y: 1 } }));
});

test("array order does change the bytes", () => {
  // Arrays are ordered data, not a bag. Sorting them would silently equate two
  // different values.
  assert.notEqual(str([1, 2]), str([2, 1]));
});

test("visually identical strings normalise to one form", () => {
  // "é" as one code point, and as "e" plus a combining accent. Without NFC these
  // are two different digests for the same name.
  const composed = "café";
  const decomposed = "café";
  assert.notEqual(composed, decomposed);
  assert.equal(str(composed), str(decomposed));
});

test("numbers with no single representation are refused, not guessed", () => {
  failsWith(NaN, "NON_FINITE_NUMBER");
  failsWith(Infinity, "NON_FINITE_NUMBER");
  failsWith(-0, "NEGATIVE_ZERO");
  failsWith(2 ** 53, "UNSAFE_INTEGER");
});

test("undefined is refused rather than dropped", () => {
  // JSON.stringify removes it silently, which changes the meaning of a signed
  // record without changing anything visible at the call site.
  failsWith({ a: 1, b: undefined }, "UNDEFINED");
});

test("lone surrogates are refused", () => {
  failsWith("\ud800", "LONE_SURROGATE");
  failsWith({ k: "ok\udc00" }, "LONE_SURROGATE");
});

test("only plain objects and arrays are accepted", () => {
  failsWith(new Date(0), "UNSUPPORTED_TYPE");
  failsWith(new Map(), "UNSUPPORTED_TYPE");
  failsWith(10n, "UNSUPPORTED_TYPE");
  failsWith({ fn() {} }, "UNSUPPORTED_TYPE");
});

test("errors name the path so a rejection is actionable", () => {
  const err = failsWith({ outer: { inner: [1, NaN] } }, "NON_FINITE_NUMBER");
  assert.equal(err.path, "outer.inner[1]");
});

test("deeply nested input is refused rather than overflowing the stack", () => {
  let deep = 1;
  for (let i = 0; i < 200; i++) deep = { deep };
  failsWith(deep, "DEPTH_EXCEEDED");
});

test("output is valid JSON", () => {
  const value = { b: [1, 2, { c: "x" }], a: null, d: true };
  assert.deepEqual(JSON.parse(str(value)), value);
});
