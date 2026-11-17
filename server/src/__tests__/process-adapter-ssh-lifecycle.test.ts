import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { runAdapterExecutionTargetProcess } from "@paperclipai/adapter-utils/execution-target";
import { createLoopbackFixture, exists, probe, waitForFile } from "./fixtures/process-ssh-target/loopback.js";

const parent = process.env.PAPERCLIP_PROCESS_SSH_TEST_ROOT;
if (!parent || !path.isAbsolute(parent)) throw new Error("explicit fixture root required");
let fixture: Awaited<ReturnType<typeof createLoopbackFixture>>;
beforeAll(async () => { fixture = await createLoopbackFixture(parent); }, 15000);
afterAll(async () => { await fixture?.close(); }, 15000);
afterEach(() => vi.unstubAllEnvs());

describe("B2 real loopback SSH lifecycle characterization", () => {
  it("joins one bounded real remote command without treating it as application teardown", async () => {
    const marker = path.join(fixture.root, "natural");
    const owned = fixture.startSafeProbe(marker, 100);
    const result = await owned.exit;
    await waitForFile(marker + ".done");
    expect(result).toMatchObject({ code: 0, signal: null });
    const started = JSON.parse(await readFile(marker + ".started", "utf8"));
    const done = JSON.parse(await readFile(marker + ".done", "utf8"));
    expect(done.pid).toBe(started.pid);
    expect(done.finishedAt).toBeGreaterThanOrEqual(started.startedAt);
  });
  it("demonstrates real local SSH death does not prove the owned bounded remote command stopped", async () => {
    const marker = path.join(fixture.root, "transport-lost");
    const owned = fixture.startSafeProbe(marker, 1500);
    await waitForFile(marker + ".tick");
    const before = Number(await readFile(marker + ".tick", "utf8"));
    expect(owned.child.pid).toBeGreaterThan(1);
    owned.child.kill("SIGKILL");
    const localExit = await owned.exit;
    expect(localExit.signal).toBe("SIGKILL");
    expect(await exists(marker + ".done")).toBe(false);
    await new Promise(resolve => setTimeout(resolve, 100));
    expect(Number(await readFile(marker + ".tick", "utf8"))).toBeGreaterThan(before);
    // Retain the exact fixture marker until its own completion; never kill an
    // unknown/reused remote PID or report the transport death as cleanup.
    await waitForFile(marker + ".done");
  });
  it("the existing selected-target helper cannot certify stop when the unsafe baseline is refused before wire", async () => {
    vi.stubEnv("PATH", fixture.bin + ":/usr/bin:/bin:/usr/sbin");
    const onProcessStopped = vi.fn();
    const result = await runAdapterExecutionTargetProcess(randomUUID(), fixture.target, process.execPath,
      [probe, "sentinel", path.join(fixture.root, "should-not-run")], {
        cwd: fixture.root, env: {}, timeoutSec: 2, graceSec: 0.1,
        onLog: async () => {}, onProcessStopped,
      });
    const calls = await fixture.capturesNow();
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({ unsafeProfile: true, wireReached: false });
    expect(await exists(path.join(fixture.root, "should-not-run"))).toBe(false);
    // Observer returns SSH transport failure255; neither local refusal nor
    // a released lease is proof of remote work teardown.
    expect(onProcessStopped, "local client refusal is not a verified remote stop").not.toHaveBeenCalled();
    expect(result).not.toHaveProperty("terminalResultCleanup.stopped", true);
  });
});
