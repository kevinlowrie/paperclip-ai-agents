import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { execute } from "../../server/src/adapters/process/execute.js";
import { runningProcesses } from "../../packages/adapter-utils/src/server-utils.js";
import { afterAll, beforeAll, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { runSshCommand } from "../../packages/adapter-utils/src/ssh.js";
import { createLoopbackFixture } from "../../server/src/__tests__/fixtures/process-ssh-target/loopback.js";
import { PRIVATE_CANARIES } from "../../server/src/__tests__/fixtures/process-ssh-target/constants.js";
const localProbe = fileURLToPath(new URL("../../server/src/__tests__/fixtures/process-ssh-target/probe.cjs", import.meta.url));
let fixture: Awaited<ReturnType<typeof createLoopbackFixture>>;
beforeAll(async () => { fixture = await createLoopbackFixture(process.env.PAPERCLIP_PROCESS_SSH_TEST_ROOT!); }, 15000);
afterAll(async () => { await fixture?.close(); }, 15000);
it("transfers actual private stdin/env over real isolated fixture SSH without private argv or ambient projection", async () => {
  const app = path.join(fixture.root, "private-probe.cjs");
  await fs.writeFile(app, `const fs=require("node:fs"),crypto=require("node:crypto");
const parts=[];const timer=setTimeout(()=>process.exit(99),1500);
process.stdin.on("data",x=>parts.push(x));process.stdin.on("end",()=>{
clearTimeout(timer);const input=Buffer.concat(parts);const hash=x=>crypto.createHash("sha256").update(x).digest("hex");
fs.writeFileSync(${JSON.stringify(path.join(fixture.root, "private-probe.done"))},"done",{mode:384});
process.stdout.write(JSON.stringify({inputHash:hash(input),envHash:hash(process.env.FIXTURE_PRIVATE||""),ambientPresent:!!process.env.FIXTURE_AMBIENT_PROVIDER}));});`, { mode: 0o600 });
  const input = "binary\u0000input\r\n雪\n" + PRIVATE_CANARIES[1];
  const command = "/usr/bin/node '" + app + "' # " + PRIVATE_CANARIES[2];
  const result = await runSshCommand(fixture.config, command, { inputMode: "private_v1", deadlineEpochMs: Date.now()+5000,
    timeoutMs: 3000, env: { FIXTURE_PRIVATE: PRIVATE_CANARIES[0] }, stdin: input });
  const body = JSON.parse(result.stdout);
  const hash = (value: string) => createHash("sha256").update(value).digest("hex");
  expect(body).toEqual({ inputHash: hash(input), envHash: hash(PRIVATE_CANARIES[0]), ambientPresent: false });
  const calls = await fixture.capturesNow(); expect(calls).toHaveLength(1);
  expect(calls[0]).toMatchObject({ wireReached: true, unsafeProfile: false, privateArgv: false });
  for (const canary of PRIVATE_CANARIES) expect(JSON.stringify(calls[0].args)).not.toContain(canary);
  expect(await fs.readFile(path.join(fixture.root,"private-probe.done"),"utf8")).toBe("done");
});

function localContext(overrides: Record<string, unknown>) {
  return {
    runId: randomUUID(), agent: { id: "11111111-1111-4111-8111-111111111111", companyId: "22222222-2222-4222-8222-222222222222",
      name: "synthetic-process", adapterType: "process", adapterConfig: {} },
    runtime: { sessionId: null, sessionParams: null, sessionDisplayId: null, taskKey: null }, context: {},
    config: { command: process.execPath, args: [localProbe, "pause", "unused"], cwd: fixture.root, timeoutSec: 1, graceSec: 0.05 },
    onLog: async () => {}, ...overrides,
  };
}
it("cancels the exact published local child and forwards readiness/dispatch/spawn once", async () => {
  const controller = new AbortController(); const order: string[] = [];
  const ready = vi.fn(async () => { order.push("ready"); });
  const dispatch = vi.fn(() => { order.push("dispatch"); });
  const spawn = vi.fn(async () => { order.push("spawn"); controller.abort(); });
  const ctx = localContext({ signal: controller.signal, onCancellationReady: ready, onDispatch: dispatch, onSpawn: spawn });
  const result = await execute(ctx);
  expect(result.errorCode).toBe("process_cancelled");
  expect(["SIGTERM", "SIGKILL"]).toContain(result.signal);
  expect(order).toEqual(["ready", "dispatch", "spawn"]);
  expect(runningProcesses.has(ctx.runId)).toBe(false);
});
it("settles its owned local child after actual spawn bookkeeping rejection", async () => {
  const spawn = vi.fn(async () => { throw new Error("fixture bookkeeping rejection"); });
  const ctx = localContext({ onSpawn: spawn }); const result = await execute(ctx);
  expect(result.errorCode).toBe("process_spawn_bookkeeping_failed");
  expect(["SIGTERM", "SIGKILL"]).toContain(result.signal);
  expect(spawn).toHaveBeenCalledTimes(1); expect(runningProcesses.has(ctx.runId)).toBe(false);
});

it("awaits actual late spawn bookkeeping before publishing a completed local result", async () => {
  const spawn = vi.fn(async () => { await new Promise(resolve => setTimeout(resolve, 250)); throw new Error("late fixture persistence rejection"); });
  const ctx = localContext({ onSpawn: spawn, config: { command: process.execPath,
    args: [localProbe, "inspect", "unused"], cwd: fixture.root, timeoutSec: 1, graceSec: 0.05 } });
  const result = await execute(ctx);
  expect(result.errorCode).toBe("process_spawn_bookkeeping_failed");
  expect(spawn).toHaveBeenCalledTimes(1);
  expect(runningProcesses.has(ctx.runId)).toBe(false);
});

it("preserves a private credential cleanup failure instead of publishing success", async () => {
  const original = fs.rm.bind(fs); const retained = new Map<string, { ino: number; uid: number }>();
  const fault = vi.spyOn(fs, "rm").mockImplementation(async (...args) => {
    if (typeof args[0] === "string" && path.basename(args[0]).startsWith("paperclip-ssh-key-")) {
      const stat = await fs.stat(args[0]); retained.set(args[0], { ino: stat.ino, uid: stat.uid });
      throw Object.assign(new Error("fixture cleanup IO failure"), { code: "EIO" });
    }
    return original(...args);
  });
  try {
    const pending = runSshCommand(fixture.config, "printf fixture-ok", { inputMode: "private_v1",
      deadlineEpochMs: Date.now()+5000, timeoutMs: 3000, env: {}, stdin: "" });
    await expect(pending).rejects.toThrow(/cleanup/i);
    const failure = await pending.catch(error => error);
    expect(failure.cleanupReferences).toEqual([...retained.keys()]);
    for (const dir of retained.keys()) expect(JSON.stringify(failure)).not.toContain(dir);
  } finally {
    fault.mockRestore();
    // Independent fixture oracle cleans only the exact retained test key folder.
    // It cannot turn the target's ignored failure into a passing assertion.
    for (const [dir, expected] of retained) {
      const stat = await fs.stat(dir);
      if (stat.ino !== expected.ino || stat.uid !== expected.uid) throw new Error("fixture credential ownership changed");
      await original(dir, { recursive: true, force: true });
    }
  }
});
