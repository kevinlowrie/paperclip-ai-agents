import { randomUUID } from "node:crypto";
import { access, mkdir, mkdtemp, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AdapterExecutionContext, AdapterExecutionResult } from "../adapters/types.js";

const { configResolver } = vi.hoisted(() => ({ configResolver: vi.fn() }));
vi.mock("../services/environment-config.js", () => ({ resolveEnvironmentDriverConfigForRuntime: configResolver }));
vi.mock("../instrumentation.js", () => ({ getStartupTracer: () => null }));

import { execute } from "../adapters/process/execute.js";
import { resolveEnvironmentExecutionTarget } from "../services/environment-execution-target.js";
import { isEnvironmentDriverSupportedForAdapter, supportedEnvironmentDriversForAdapter } from "@paperclipai/shared";

const probe = fileURLToPath(new URL("./fixtures/process-ssh-target/probe.cjs", import.meta.url));
const parent = process.env.PAPERCLIP_PROCESS_SSH_TEST_ROOT;
if (!parent || !path.isAbsolute(parent)) throw new Error("Explicit absolute PAPERCLIP_PROCESS_SSH_TEST_ROOT required");
const initialHome = process.env.HOME;
const initialCodexHome = process.env.CODEX_HOME;
let caseDir: string;
let sentinel: string;

beforeEach(async () => {
  await mkdir(parent, { recursive: true, mode: 0o700 });
  caseDir = await mkdtemp(path.join(parent, "target-"));
  sentinel = path.join(caseDir, "configured-command.marker");
  configResolver.mockReset();
});
afterEach(() => {
  vi.unstubAllEnvs();
  expect(process.env.HOME).toBe(initialHome);
  expect(process.env.CODEX_HOME).toBe(initialCodexHome);
});

function context(overrides: Partial<AdapterExecutionContext> = {}): AdapterExecutionContext {
  return {
    runId: randomUUID(),
    agent: { id: "11111111-1111-4111-8111-111111111111", companyId: "22222222-2222-4222-8222-222222222222",
      name: "synthetic-process", adapterType: "process", adapterConfig: {} },
    runtime: { sessionId: null, sessionParams: null, sessionDisplayId: null, taskKey: null },
    context: {},
    config: { command: process.execPath, args: [probe, "sentinel", sentinel], cwd: caseDir },
    onLog: async () => {}, ...overrides,
  };
}
function sshTarget() {
  return { kind: "remote", transport: "ssh", environmentId: "env-fixture", leaseId: "lease-fixture",
    remoteCwd: "/synthetic/remote-workspace", spec: { host: "127.0.0.1", port: 1, username: "fixture",
      remoteWorkspacePath: "/synthetic/remote-workspace", remoteCwd: "/synthetic/remote-workspace",
      privateKey: null, knownHosts: null, strictHostKeyChecking: true } } as const;
}
async function exists(file: string) {
  return access(file).then(() => true, () => false);
}
async function outcome(ctx: AdapterExecutionContext) {
  try { return { result: await execute(ctx), error: null }; }
  catch (error) { return { result: null, error }; }
}
function rejected(value: Awaited<ReturnType<typeof outcome>>) {
  return value.error !== null || Boolean(value.result?.errorCode) || (value.result?.exitCode ?? 0) !== 0;
}

// These invoke the real adapter. The sentinel proves a selected target was not
// silently ignored. No SSH connection occurs in this refusal group.
describe("A1/A2 real process adapter selected-target refusal", () => {
  it("refuses selected raw SSH before configured-command dispatch when owned control is unavailable", async () => {
    const onSpawn = vi.fn(async () => {});
    const onDispatch = vi.fn();
    const value = await outcome(context({ executionTarget: sshTarget(), onSpawn, onDispatch }));
    expect(await exists(sentinel), "selected remote target executed locally").toBe(false);
    expect(value.error).toBeNull();
    expect(value.result).toMatchObject({ errorCode: "process_ssh_owned_control_unavailable",
      executionRecovery: { kind: "bootstrap", providerWorkStarted: false } });
    expect(onSpawn).not.toHaveBeenCalled();
    expect(onDispatch).not.toHaveBeenCalled();
  });

  const malformed: [string, unknown][] = [
    ["unknown target kind", { kind: "other" }],
    ["SSH without spec", { kind: "remote", transport: "ssh", remoteCwd: "/synthetic" }],
    ["invalid SSH port", { ...sshTarget(), spec: { ...sshTarget().spec, port: -1 } }],
    ["relative remote cwd", { ...sshTarget(), remoteCwd: "relative", spec: { ...sshTarget().spec, remoteCwd: "relative" } }],
    ["unsupported sandbox", { kind: "remote", transport: "sandbox", providerKey: "fixture", remoteCwd: "/synthetic" }],
    ["unsupported plugin transport", { kind: "remote", transport: "plugin", remoteCwd: "/synthetic" }],
  ];
  it.each(malformed)("rejects %s without local fallback", async (_label, executionTarget) => {
    const value = await outcome(context({ executionTarget: executionTarget as never }));
    expect(await exists(sentinel), "invalid target was coerced to local execution").toBe(false);
    expect(rejected(value)).toBe(true);
  });

  it("does not fall back from malformed canonical target to a legacy remote target", async () => {
    const value = await outcome(context({ executionTarget: { kind: "bad" } as never,
      executionTransport: { remoteExecution: { ...sshTarget().spec } } }));
    expect(await exists(sentinel)).toBe(false);
    expect(rejected(value)).toBe(true);
  });
  it("rejects conflicting canonical and legacy destinations", async () => {
    const value = await outcome(context({ executionTarget: sshTarget(), executionTransport: {
      remoteExecution: { ...sshTarget().spec, host: "192.0.2.1", port: 22 } } }));
    expect(await exists(sentinel)).toBe(false);
    expect(rejected(value)).toBe(true);
  });
  it("does not treat legacy-only selected SSH as a local invocation", async () => {
    const value = await outcome(context({ executionTransport: { remoteExecution: { ...sshTarget().spec } } }));
    expect(await exists(sentinel)).toBe(false);
    expect(value.result?.errorCode).toBe("process_ssh_owned_control_unavailable");
  });
  it("honors a signal already cancelled before a local command dispatch", async () => {
    const controller = new AbortController(); controller.abort();
    const value = await outcome(context({ signal: controller.signal }));
    expect(await exists(sentinel)).toBe(false);
    expect(rejected(value)).toBe(true);
  });
  it("registers cancellation before dispatch and catches late cancellation in the ready callback", async () => {
    const controller = new AbortController();
    const ready = vi.fn(async () => { controller.abort(); });
    const value = await outcome(context({ signal: controller.signal, onCancellationReady: ready }));
    expect(ready).toHaveBeenCalledTimes(1);
    expect(await exists(sentinel)).toBe(false);
    expect(rejected(value)).toBe(true);
  });
});

describe("A3 actual resolver and capability denial controls", () => {
  it("keeps process SSH unsupported and does not resolve a credential config", async () => {
    const target = await resolveEnvironmentExecutionTarget({ db: {} as never,
      companyId: "22222222-2222-4222-8222-222222222222", adapterType: "process",
      environment: { id: "env-fixture", driver: "ssh", config: {} },
      leaseId: "lease-fixture", leaseMetadata: {}, lease: null, environmentRuntime: null });
    expect(target).toBeNull();
    expect(configResolver).not.toHaveBeenCalled();
  });
  it("does not advertise process SSH, sandbox or plugin runs while ownership is unqualified", () => {
    expect(supportedEnvironmentDriversForAdapter("process")).toEqual(["local"]);
    for (const driver of ["ssh", "sandbox", "plugin"]) {
      expect(isEnvironmentDriverSupportedForAdapter("process", driver)).toBe(false);
    }
  });
  it("retains a known supported adapter's exact company/lease SSH target resolution", async () => {
    configResolver.mockResolvedValue({ driver: "ssh", config: sshTarget().spec });
    const companyId = "22222222-2222-4222-8222-222222222222";
    const target = await resolveEnvironmentExecutionTarget({ db: {} as never, companyId, adapterType: "codex_local",
      environment: { id: "env-fixture", driver: "ssh", config: {} },
      leaseId: "lease-fixture", leaseMetadata: { remoteCwd: "/synthetic/lease-workspace" },
      lease: null, environmentRuntime: null });
    expect(configResolver.mock.calls[0]?.[1]).toBe(companyId);
    expect(target).toMatchObject({ kind: "remote", transport: "ssh", leaseId: "lease-fixture",
      environmentId: "env-fixture", remoteCwd: "/synthetic/lease-workspace" });
  });
});

describe("C1 real local process compatibility controls", () => {
  it("keeps no-target local dispatch and onSpawn working", async () => {
    const onSpawn = vi.fn(async () => {});
    const result = await execute(context({ onSpawn }));
    expect(result.exitCode).toBe(0);
    expect(await readFile(sentinel, "utf8")).toBe("configured command ran\n");
    expect(onSpawn).toHaveBeenCalledTimes(1);
  });
  it("keeps canonical local execution, args, cwd and explicit environment", async () => {
    const result = await execute(context({ executionTarget: { kind: "local" },
      config: { command: process.execPath, args: [probe, "inspect", "unused", "one", "two words"], cwd: caseDir,
        env: { FIXTURE_VALUE: "literal '$value'\nline" } } }));
    const body = JSON.parse(String(result.resultJson?.stdout));
    expect(body).toMatchObject({ cwd: caseDir, args: ["one", "two words"], env: { FIXTURE_VALUE: "literal '$value'\nline" } });
  });
  it("keeps the harness run token distinct from forbidden config and ambient keys", async () => {
    vi.stubEnv("PAPERCLIP_API_KEY", "fixture-ambient-canary");
    const onMeta = vi.fn(async () => {});
    const ctx = context({ authToken: "fixture-run-canary", onMeta,
      config: { command: process.execPath, args: [probe, "inspect", "unused"], cwd: caseDir,
        env: { PAPERCLIP_API_KEY: "fixture-config-canary", PAPERCLIP_RUN_ID: "wrong-run" } } });
    const result = await execute(ctx);
    expect(JSON.parse(String(result.resultJson?.stdout)).env).toMatchObject({
      PAPERCLIP_API_KEY: "fixture-run-canary", PAPERCLIP_RUN_ID: ctx.runId });
    const meta = JSON.stringify(onMeta.mock.calls);
    for (const canary of ["fixture-ambient-canary", "fixture-config-canary", "fixture-run-canary"]) expect(meta).not.toContain(canary);
  });
  it("keeps ambient Paperclip API keys absent when no harness token was supplied", async () => {
    vi.stubEnv("PAPERCLIP_API_KEY", "fixture-ambient-canary");
    const result = await execute(context({ config: { command: process.execPath,
      args: [probe, "inspect", "unused"], cwd: caseDir } }));
    expect(JSON.parse(String(result.resultJson?.stdout)).env.PAPERCLIP_API_KEY).toBeNull();
  });
  it("preserves nonzero exit output and status", async () => {
    const result = await execute(context({ config: { command: process.execPath, args: [probe, "nonzero", "unused"], cwd: caseDir } }));
    expect(result).toMatchObject({ exitCode: 23, timedOut: false, resultJson: {
      stdout: "fixture-stdout\n", stderr: "fixture-stderr\n" } });
  });
  it("preserves a bounded local timeout", async () => {
    const result = await execute(context({ config: { command: process.execPath,
      args: [probe, "pause", "unused"], cwd: caseDir, timeoutSec: 0.1, graceSec: 0.05 } }));
    expect(result.timedOut).toBe(true);
  });
  it("preserves missing-command rejection", async () => {
    await expect(execute(context({ config: { cwd: caseDir } }))).rejects.toThrow("Process adapter missing command");
  });
});
