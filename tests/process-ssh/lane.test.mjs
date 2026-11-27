import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createOwnedRoot, isDedicatedProcessSshServerTest, parseOptions, repoRoot, testEnvironment, validateOwnedRoot } from "./lane.mjs";

test("only the two exact normalized server paths leave ordinary discovery", () => {
  assert.equal(isDedicatedProcessSshServerTest("server/src/__tests__/process-adapter-ssh-target.test.ts"), true);
  assert.equal(isDedicatedProcessSshServerTest(".\\server\\src\\__tests__\\process-adapter-ssh-lifecycle.test.ts"), true);
  for (const value of ["server/src/__tests__/other-ssh.test.ts", "server/src/adapters/process.test.ts",
    "server/src/__tests__/process-adapter-ssh-target.test.ts.copy"]) assert.equal(isDedicatedProcessSshServerTest(value), false);
});
test("entry options cannot inject targets, modules or source-pin bypasses", () => {
  assert.equal(parseOptions([]).lane, "unit");
  for (const args of [["--lane", "live"], ["--host", "example.invalid"], ["--source-pin", "ignore"], ["--lane"]]) {
    assert.throws(() => parseOptions(args));
  }
});
test("owned root binding preserves identity env and rejects a changed ownership binding", () => {
  const before = { home: process.env.HOME, codex: process.env.CODEX_HOME };
  assert.throws(() => createOwnedRoot(repoRoot));
  const owned = createOwnedRoot(os.tmpdir());
  try {
    assert.equal(validateOwnedRoot(owned.root, owned.id), owned.root);
    const env = testEnvironment({ ...process.env, FIXTURE_AMBIENT_SECRET: "synthetic-ambient" }, owned, "unit");
    assert.equal(env.HOME, before.home); assert.equal(env.CODEX_HOME, before.codex);
    assert.equal(env.FIXTURE_AMBIENT_SECRET, undefined);
    assert.equal(process.env.HOME, before.home); assert.equal(process.env.CODEX_HOME, before.codex);
    assert.throws(() => validateOwnedRoot(owned.root, "wrong-owner"));
  } finally { validateOwnedRoot(owned.root, owned.id); fs.rmSync(owned.root, { recursive: true, force: true }); }
});
