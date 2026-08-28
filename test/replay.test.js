import { test } from "node:test";
import assert from "node:assert/strict";

import { ReplayGuard, MemoryStore, requestKey, ReplayError, COMPLETED } from "../src/replay.js";

const BASE = {
  authorizationId: "auth-1",
  requestId: "req-1",
  envelopeDigest: "e".repeat(64),
  brokerInstanceId: "broker-a",
  operation: "repo.commit",
};

function failsWith(fn, code) {
  let caught;
  try {
    fn();
  } catch (e) {
    caught = e;
  }
  assert.ok(caught, `expected ${code}, nothing thrown`);
  assert.equal(caught.code, code, `expected ${code}, got ${caught.code}`);
  return caught;
}

test("the same request executes once and reports the same result twice", async () => {
  const guard = new ReplayGuard(new MemoryStore());
  const key = requestKey(BASE);
  let runs = 0;

  const first = await guard.once(key, async () => {
    runs++;
    return "committed";
  });
  const second = await guard.once(key, async () => {
    runs++;
    return "committed again";
  });

  assert.equal(runs, 1);
  assert.equal(first.fresh, true);
  assert.equal(second.fresh, false);
  assert.equal(second.result, "committed");
});

test("the guard survives a restart", async () => {
  // A new process, a new guard, the same durable data. The operation must not
  // run a second time.
  const store = new MemoryStore();
  const key = requestKey(BASE);
  let runs = 0;

  await new ReplayGuard(store).once(key, async () => {
    runs++;
    return "done";
  });

  const restarted = new ReplayGuard(MemoryStore.from(store.snapshot()));
  const after = await restarted.once(key, async () => {
    runs++;
    return "done twice";
  });

  assert.equal(runs, 1);
  assert.equal(after.status, COMPLETED);
  assert.equal(after.result, "done");
});

test("a crash between write-ahead and completion is refused, not retried", async () => {
  // This is the case the ordering exists for. The privileged side effect may or
  // may not have happened. Guessing either way is worse than stopping.
  const store = new MemoryStore();
  const key = requestKey(BASE);

  await assert.rejects(
    new ReplayGuard(store).once(key, async () => {
      throw new Error("power loss");
    }),
    /power loss/
  );

  const restarted = new ReplayGuard(MemoryStore.from(store.snapshot()));
  let ranAgain = false;
  await assert.rejects(
    restarted.once(key, async () => {
      ranAgain = true;
      return "should never happen";
    }),
    (e) => e instanceof ReplayError && e.code === "INDETERMINATE"
  );
  assert.equal(ranAgain, false);
});

test("changing any part of the request context makes it a different request", async () => {
  const guard = new ReplayGuard(new MemoryStore());
  let runs = 0;
  const run = (over) =>
    guard.once(requestKey({ ...BASE, ...over }), async () => {
      runs++;
      return runs;
    });

  await run({});
  await run({ requestId: "req-2" });
  await run({ envelopeDigest: "f".repeat(64) });
  await run({ brokerInstanceId: "broker-b" });
  await run({ operation: "repo.write" });
  await run({ params: { path: "a.txt" } });

  assert.equal(runs, 6);
});

test("key order in params cannot produce two keys for one request", () => {
  // The reason canonicalize exists. JSON.stringify would give these different
  // digests, and a replay guard that can be dodged by reordering a field is not
  // a replay guard.
  const a = requestKey({ ...BASE, params: { alpha: 1, beta: 2 } });
  const b = requestKey({ ...BASE, params: { beta: 2, alpha: 1 } });
  assert.equal(a, b);
});

test("an incompletely identified request cannot be keyed at all", () => {
  failsWith(() => requestKey({ ...BASE, brokerInstanceId: "" }), "INCOMPLETE_KEY");
  failsWith(() => requestKey({ ...BASE, envelopeDigest: undefined }), "INCOMPLETE_KEY");
});

test("a key that did not come from requestKey is refused", async () => {
  const guard = new ReplayGuard(new MemoryStore());
  await assert.rejects(
    guard.once("short", async () => "x"),
    (e) => e instanceof ReplayError && e.code === "BAD_KEY"
  );
});
