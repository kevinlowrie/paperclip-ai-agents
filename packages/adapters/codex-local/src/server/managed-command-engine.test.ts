import { createHash } from "node:crypto";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const seam = vi.hoisted(() => ({
  executeAcp: vi.fn(async () => ({ exitCode: 0, signal: null, timedOut: false })),
  testAcp: vi.fn(async () => ({
    adapterType: "codex_local",
    status: "pass" as const,
    checks: [],
    testedAt: new Date().toISOString(),
  })),
  prepareCli: vi.fn(async () => { throw new Error("unexpected CLI preparation"); }),
  runCli: vi.fn(async () => { throw new Error("unexpected CLI dispatch"); }),
  stageManagedCommand: vi.fn(async () => { throw new Error("unexpected managed file staging"); }),
}));

vi.mock("./acp.js", async (importOriginal) => ({
  ...await importOriginal<typeof import("./acp.js")>(),
  createCodexAcpExecutor: () => seam.executeAcp,
  testCodexAcpEnvironment: seam.testAcp,
}));
vi.mock("@paperclipai/adapter-utils/execution-target", async (importOriginal) => ({
  ...await importOriginal<typeof import("@paperclipai/adapter-utils/execution-target")>(),
  prepareAdapterExecutionTargetRuntime: seam.prepareCli,
  runAdapterExecutionTargetProcess: seam.runCli,
}));
vi.mock("./managed-command.js", () => ({ stageManagedCommand: seam.stageManagedCommand }));

import { resolveCodexExecutionEngineForRun } from "./acp.js";
import { execute } from "./execute.js";
import { testEnvironment } from "./test.js";

const originalNodeVersion = process.version;
const fixtureDirectories: string[] = [];

beforeEach(() => {
  Object.defineProperty(process, "version", { value: "v24.11.0" });
  vi.clearAllMocks();
});

afterEach(async () => {
  Object.defineProperty(process, "version", { value: originalNodeVersion });
  while (fixtureDirectories.length) {
    await rm(fixtureDirectories.pop()!, { recursive: true, force: true });
  }
});

async function fixture(engine: "acp" | "auto" | "cli" | undefined) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "codex-engine-managed-")));
  fixtureDirectories.push(root);
  const sourceDir = path.join(root, "operator");
  const cwd = path.join(root, "workspace");
  const codexHome = path.join(root, "codex-home");
  for (const dir of [sourceDir, cwd, codexHome]) await mkdir(dir);
  const entrypoint = "wrapper.mjs";
  const contents = "export const wrapperFixture = true;\n";
  await writeFile(path.join(sourceDir, entrypoint), contents);
  const managedCommand = {
    sourceDir,
    entrypoint,
    files: [{ path: entrypoint, sha256: createHash("sha256").update(contents).digest("hex") }],
  };
  const config = {
    ...(engine === undefined ? {} : { engine }),
    cwd,
    // A configured shell command lets the real resolver see an available ACP
    // lane without attempting a provider or depending on a codex-acp binary.
    agentCommand: "node /workspace/fixture-acp.mjs",
    env: { CODEX_HOME: codexHome, OPENAI_API_KEY: "fixture-key" },
  };
  const runner = { execute: vi.fn(async () => { throw new Error("unexpected sandbox dispatch"); }) };
  const executionTarget = {
    kind: "remote" as const,
    transport: "sandbox" as const,
    remoteCwd: "/workspace",
    runner,
  };
  const run = {
    runId: "fixture-run",
    agent: {
      id: "fixture-agent",
      companyId: "fixture-company",
      name: "Fixture",
      adapterType: "codex_local",
      adapterConfig: {},
    },
    runtime: { sessionId: null, sessionParams: null, sessionDisplayId: null, taskKey: null },
    config,
    context: { paperclipWorkspace: { cwd, source: "project_primary" } },
    executionTarget,
    onLog: vi.fn(async () => {}),
  };
  const diagnostic = { adapterType: "codex_local", companyId: "fixture-company", config, executionTarget };
  return { run, diagnostic, runner, managedCommand };
}

describe("managed command engine compatibility", () => {
  const acpSelections = ["acp", undefined, "auto"] as const;

  it.each(acpSelections)("rejects managed execution before dispatch for engine=%s", async (engine) => {
    const { run, managedCommand, runner } = await fixture(engine);
    const result = await execute({ ...run, config: { ...run.config, managedCommand } });

    expect(seam.executeAcp).not.toHaveBeenCalled();
    expect(seam.prepareCli).not.toHaveBeenCalled();
    expect(seam.runCli).not.toHaveBeenCalled();
    expect(seam.stageManagedCommand).not.toHaveBeenCalled();
    expect(runner.execute).not.toHaveBeenCalled();
    expect(result).toMatchObject({
      exitCode: 1,
      errorCode: "adapter_engine_unavailable",
      resultJson: { executionRecovery: { kind: "bootstrap", providerWorkStarted: false } },
    });
    expect(result.errorMessage).toMatch(/managed.?command/i);
    expect(result.errorMessage).toContain("engine=cli");
  });

  it.each(acpSelections)("reports managed ACP as unavailable in the environment test for engine=%s", async (engine) => {
    const { diagnostic, managedCommand, runner } = await fixture(engine);
    const result = await testEnvironment({
      ...diagnostic,
      config: { ...diagnostic.config, managedCommand },
    });

    expect(seam.testAcp).not.toHaveBeenCalled();
    expect(seam.prepareCli).not.toHaveBeenCalled();
    expect(seam.runCli).not.toHaveBeenCalled();
    expect(seam.stageManagedCommand).not.toHaveBeenCalled();
    expect(runner.execute).not.toHaveBeenCalled();
    expect(result.status).toBe("fail");
    expect(result.checks).toContainEqual(expect.objectContaining({
      code: "adapter_engine_unavailable",
      level: "error",
      message: expect.stringMatching(/managed.?command/i),
    }));
  });

  it.each(acpSelections)("preserves ordinary ACP selection for engine=%s", async (engine) => {
    const { run, diagnostic } = await fixture(engine);
    await expect(execute(run)).resolves.toMatchObject({ exitCode: 0 });
    await expect(testEnvironment(diagnostic)).resolves.toMatchObject({ status: "pass" });
    expect(seam.executeAcp).toHaveBeenCalledTimes(1);
    expect(seam.testAcp).toHaveBeenCalledTimes(1);
    expect(seam.prepareCli).not.toHaveBeenCalled();
  });

  it("still selects explicit CLI for a managed command", async () => {
    const { run, managedCommand } = await fixture("cli");
    await expect(resolveCodexExecutionEngineForRun({
      executionTarget: run.executionTarget,
      config: { ...run.config, managedCommand },
    })).resolves.toEqual({ engine: "cli", explicit: true });
  });
});
