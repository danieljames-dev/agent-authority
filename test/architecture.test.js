/**
 * Architecture fitness tests.
 *
 * These assert properties of the source itself rather than of its behaviour. The
 * reason they exist: the security properties in this project depend on a few
 * boundaries that are easy to state, easy to agree with, and easy to erode one
 * convenient import at a time. A rule written in a README is a request. A rule
 * written here fails the build.
 *
 * Each test below corresponds to a claim the README makes. If a claim stops
 * being true, a test goes red rather than a document going quietly stale.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const srcDir = join(root, "src");

const sources = readdirSync(srcDir)
  .filter((f) => f.endsWith(".js"))
  .map((f) => ({ file: f, text: readFileSync(join(srcDir, f), "utf8") }));

test("there is source to check", () => {
  assert.ok(sources.length >= 4, `expected the src modules, found ${sources.length}`);
});

test("the library reaches the network through nothing", () => {
  // An authority decision that can make a network call is an authority decision
  // that can be influenced by whoever answers.
  const banned = ["node:http", "node:https", "node:net", "node:dgram", "fetch(", "XMLHttpRequest"];
  for (const { file, text } of sources) {
    for (const token of banned) {
      assert.ok(!text.includes(token), `${file} reaches the network via ${token}`);
    }
  }
});

test("the library spawns no processes", () => {
  const banned = ["node:child_process", "execSync", "spawnSync", "execFileSync"];
  for (const { file, text } of sources) {
    for (const token of banned) {
      assert.ok(!text.includes(token), `${file} spawns a process via ${token}`);
    }
  }
});

test("nothing evaluates code at runtime", () => {
  for (const { file, text } of sources) {
    for (const token of ["eval(", "new Function(", "node:vm"]) {
      assert.ok(!text.includes(token), `${file} evaluates code via ${token}`);
    }
  }
});

test("no signature or digest is taken over JSON.stringify", () => {
  // The single most load-bearing rule in the project. JSON.stringify preserves
  // insertion order, so a digest over it can differ for two equal values —
  // which defeats both the hash chain and the replay guard.
  for (const { file, text } of sources) {
    if (file === "canonical.js") continue; // it legitimately uses it for scalars
    assert.ok(
      !text.includes("JSON.stringify"),
      `${file} uses JSON.stringify; digests and signatures must use canonicalize()`
    );
  }
});

test("the package declares no runtime dependencies", () => {
  // Every dependency is a party that can change what this code does without a
  // commit here. For a library whose whole job is deciding who may act, that
  // trade is not worth making.
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  assert.deepEqual(pkg.dependencies, {}, "runtime dependencies were added");
  assert.deepEqual(pkg.devDependencies, {}, "dev dependencies were added");
});

test("no machine-specific path or hostname is committed", () => {
  // Written after a real incident: an earlier project of mine leaked a Windows
  // user path and a machine name into a public repository, because the rule
  // banning them was scoped to one directory and the values lived in another.
  // Here the check covers everything the repository ships.
  const files = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === "node_modules" || entry.name === ".git") continue;
      const p = join(dir, entry.name);
      if (entry.isDirectory()) walk(p);
      else if (/\.(js|json|md)$/.test(entry.name)) files.push(p);
    }
  };
  walk(root);

  const patterns = [
    [/C:\\Users\\[A-Za-z0-9._-]+/, "a Windows user-profile path"],
    [/\/(?:home|Users)\/[A-Za-z0-9._-]+\//, "a Unix home path"],
    [/\b(?:DESKTOP|LAPTOP)-[A-Z0-9]{7,}\b/, "a Windows machine name"],
  ];
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    for (const [re, what] of patterns) {
      const hit = text.match(re);
      assert.ok(!hit, `${file} contains ${what}: ${hit?.[0]}`);
    }
  }
});
