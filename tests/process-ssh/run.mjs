#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { createOwnedRoot, lanes, parseOptions, repoRoot, testEnvironment } from "./lane.mjs";

const options = parseOptions(process.argv.slice(2));
if (options.help) {
  console.log("node tests/process-ssh/run.mjs [--lane unit|ssh|all] [--root-parent DIR] [--list]");
} else if (options.list) {
  console.log(JSON.stringify({ lane: options.lane, ...lanes[options.lane], changesHome: false,
    realLoopbackSsh: options.lane !== "unit", liveProviderOrOperatorTargets: false }, null, 2));
} else {
  const before = { home: process.env.HOME, codex: process.env.CODEX_HOME };
  const owned = createOwnedRoot(options.parent);
  const env = testEnvironment(process.env, owned, options.lane);
  mkdirSync(env.PAPERCLIP_HOME, { mode: 0o700 });
  const reportPath = path.join(owned.root, "vitest.json");
  const args = [path.join(repoRoot, "node_modules/vitest/vitest.mjs"), "run", "--config",
    path.join(repoRoot, "tests/process-ssh/vitest.config.mjs"), "--reporter=default", "--reporter=json",
    `--outputFile.json=${reportPath}`];
  const result = spawnSync(process.execPath, args, { cwd: repoRoot, env, stdio: "inherit", timeout: 240_000 });
  let report;
  try { report = JSON.parse(readFileSync(reportPath, "utf8")); } catch { report = null; }
  const identityUnchanged = process.env.HOME === before.home && process.env.CODEX_HOME === before.codex;
  const passed = !result.error && result.status === 0 && identityUnchanged && report?.success === true &&
    report.numTotalTests === lanes[options.lane].count && report.numPassedTests === lanes[options.lane].count &&
    report.numFailedTests === 0 && report.numPendingTests === 0;
  const source = path.join(repoRoot, "packages/adapter-utils/src/ssh.ts");
  const summary = { lane: options.lane, expected: lanes[options.lane].count, passed,
    total: report?.numTotalTests ?? 0, passing: report?.numPassedTests ?? 0,
    failures: report?.numFailedTests ?? null, pending: report?.numPendingTests ?? null,
    exitCode: result.status, signal: result.signal, launchError: result.error?.code ?? null,
    homeAndCodexHomeUnchanged: identityUnchanged,
    sshSourceSha256: createHash("sha256").update(readFileSync(source)).digest("hex"),
    cleanupQualification: "Per-fixture receipts only; runner exit never certifies remote work cleanup",
    rootRetained: true };
  writeFileSync(path.join(owned.root, "lane-result.json"), JSON.stringify(summary, null, 2) + "\n", { mode: 0o600 });
  console.log(`Process SSH ${options.lane}: ${passed ? "PASS" : "FAIL"}; evidence retained at ${owned.root}`);
  // Retain this private root on success and failure. In particular, timeout,
  // missing reports and unknown fixture cleanup never trigger broad deletion.
  process.exitCode = passed ? 0 : 1;
}
