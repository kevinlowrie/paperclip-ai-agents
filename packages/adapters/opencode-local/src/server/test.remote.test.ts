import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AdapterExecutionTarget } from "@paperclipai/adapter-utils/execution-target";

const {
  ensureAdapterExecutionTargetDirectory,
  ensureAdapterExecutionTargetCommandResolvable,
  maybeRunSandboxInstallCommand,
  runAdapterExecutionTargetProcess,
  describeAdapterExecutionTarget,
  resolveAdapterExecutionTargetCwd,
  prepareAdapterExecutionTargetRuntime,
} = vi.hoisted(() => {
  const restoreWorkspace = vi.fn(async () => {});
  return {
    ensureAdapterExecutionTargetDirectory: vi.fn(async () => {}),
    ensureAdapterExecutionTargetCommandResolvable: vi.fn(async () => {}),
    maybeRunSandboxInstallCommand: vi.fn(async () => null),
    runAdapterExecutionTargetProcess: vi.fn(async () => ({
      exitCode: 0,
      signal: null,
      timedOut: false,
      stdout: [
        JSON.stringify({ type: "step_start", sessionID: "session-1" }),
        JSON.stringify({ type: "text", sessionID: "session-1", part: { text: "hello" } }),
        JSON.stringify({
          type: "step_finish",
          sessionID: "session-1",
          part: { cost: 0.001, tokens: { input: 1, output: 1, reasoning: 0, cache: { read: 0, write: 0 } } },
        }),
      ].join("\n"),
      stderr: "",
      pid: 123,
      startedAt: new Date().toISOString(),
    })),
    describeAdapterExecutionTarget: vi.fn(() => "QA Cloudflare"),
    resolveAdapterExecutionTargetCwd: vi.fn((target, configuredCwd, fallbackCwd) => {
      if (typeof configuredCwd === "string" && configuredCwd.trim().length > 0) return configuredCwd;
      if (target && typeof target === "object" && "remoteCwd" in target && typeof target.remoteCwd === "string") {
        return target.remoteCwd;
      }
      return fallbackCwd;
    }),
    prepareAdapterExecutionTargetRuntime: vi.fn(async () => ({
      target: null,
      workspaceRemoteDir: "/remote/workspace/.paperclip-runtime/runs/test/workspace",
      runtimeRootDir: "/remote/workspace/.paperclip-runtime/runs/test/workspace/.paperclip-runtime/opencode",
      assetDirs: {
        xdgConfig: "/remote/workspace/.paperclip-runtime/runs/test/workspace/.paperclip-runtime/opencode/xdgConfig",
      },
      restoreWorkspace,
    })),
  };
});

vi.mock("@paperclipai/adapter-utils/execution-target", async () => {
  const actual = await vi.importActual<typeof import("@paperclipai/adapter-utils/execution-target")>(
    "@paperclipai/adapter-utils/execution-target",
  );
  return {
    ...actual,
    ensureAdapterExecutionTargetDirectory,
    ensureAdapterExecutionTargetCommandResolvable,
    maybeRunSandboxInstallCommand,
    runAdapterExecutionTargetProcess,
    describeAdapterExecutionTarget,
    resolveAdapterExecutionTargetCwd,
    prepareAdapterExecutionTargetRuntime,
  };
});

import { testEnvironment } from "./test.js";

describe("opencode remote environment diagnostics", () => {
  const configHomes: string[] = [];
  let configHome: string;

  beforeEach(async () => {
    configHome = await mkdtemp(path.join(os.tmpdir(), "paperclip-opencode-test-config-"));
    vi.stubEnv("XDG_CONFIG_HOME", configHome);
    vi.stubEnv("PAPERCLIP_OPENCODE_SMALL_MODEL", "ambient/host-only-model");
    vi.stubEnv("DATABASE_URL", "ambient-db-sentinel");
    vi.stubEnv("ANTHROPIC_API_KEY", "ambient-host-key-sentinel");
  });

  afterEach(async () => {
    vi.clearAllMocks();
    vi.unstubAllEnvs();
    await rm(configHome, { recursive: true, force: true });
    await Promise.all(configHomes.splice(0).map(dir => rm(dir, { recursive: true, force: true })));
  });

  it.each([false, true])("stages remote runtime config assets for sandbox hello probes (managed=%s)", async (managed) => {
    const configHome = await mkdtemp(path.join(os.tmpdir(), "opencode-remote-test-config-"));
    configHomes.push(configHome);
    const remoteTarget: AdapterExecutionTarget = {
      kind: "remote",
      transport: "sandbox",
      providerKey: "cloudflare",
      remoteCwd: "/remote/workspace",
      runner: {
        execute: async () => ({
          exitCode: 0,
          signal: null,
          timedOut: false,
          stdout: "",
          stderr: "",
          pid: null,
          startedAt: new Date().toISOString(),
        }),
      },
    };

    const result = await testEnvironment({
      companyId: "company-1",
      adapterType: "opencode_local",
      config: {
        command: "opencode",
        model: "anthropic/claude-sonnet-4-5",
        dangerouslySkipPermissions: false,
        ...(managed ? {
          managedAiConnection: { provider: "openrouter", method: "api_key" },
        } : {}),
        env: {
          XDG_CONFIG_HOME: configHome,
          OPENCODE_CONFIG: "/host-only/config/opencode.json",
          OPENCODE_CONFIG_DIR: "/host-only/config",
          PAPERCLIP_OPENCODE_PROVIDERS: JSON.stringify({
            anthropic: {
              npm: "@ai-sdk/anthropic",
              options: { apiKey: "{env:SCOPED_PROVIDER_KEY}" },
              models: { "claude-sonnet-4-5": { name: "Claude Sonnet" }, "other-model": {} },
            },
          }),
          SCOPED_PROVIDER_KEY: "scoped-test-key",
          ...(managed ? { OPENAI_API_KEY: "", OPENROUTER_API_KEY: "fixture", HOME: "/var/folders/qa-managed", XDG_DATA_HOME: "/var/folders/qa-managed/data" } : {}),
        },
      },
      executionTarget: remoteTarget,
      environmentName: "QA Cloudflare",
    });

    expect(result.status).toBe("pass");
    expect(prepareAdapterExecutionTargetRuntime).toHaveBeenCalledTimes(1);
    const runtimeCalls = prepareAdapterExecutionTargetRuntime.mock.calls as unknown as Array<
      [{ adapterKey: string; assets?: Array<{ key: string; localDir: string }> }]
    >;
    const runtimeInput = runtimeCalls[0]?.[0];
    expect(runtimeInput?.adapterKey).toBe("opencode");
    expect(runtimeInput?.assets).toEqual([
      expect.objectContaining({
        key: "xdgConfig",
      }),
    ]);
    const probeCall = runAdapterExecutionTargetProcess.mock.calls[0] as unknown as
      | [string, AdapterExecutionTarget, string, string[], { cwd: string; env: Record<string, string> }]
      | undefined;
    const directoryOptions = (ensureAdapterExecutionTargetDirectory.mock.calls as unknown as unknown[][])[0]?.[3] as
      | { env?: Record<string, string> }
      | undefined;
    const installOptions = (maybeRunSandboxInstallCommand.mock.calls as unknown as unknown[][])[0]?.[0] as
      | { env?: Record<string, string> }
      | undefined;
    const resolutionEnv = (ensureAdapterExecutionTargetCommandResolvable.mock.calls as unknown as unknown[][])[0]?.[3] as
      | Record<string, string>
      | undefined;
    expect(directoryOptions?.env?.SCOPED_PROVIDER_KEY).toBeUndefined();
    expect(installOptions?.env?.SCOPED_PROVIDER_KEY).toBeUndefined();
    expect(resolutionEnv?.SCOPED_PROVIDER_KEY).toBeUndefined();
    expect(probeCall?.[4].cwd).toBe("/remote/workspace/.paperclip-runtime/runs/test/workspace");
    if (managed) {
      expect(probeCall?.[4].env.HOME).toContain("/remote/workspace/.paperclip-runtime/runs/test/workspace/.paperclip-runtime/opencode/home/");
      expect(probeCall?.[4].env.XDG_DATA_HOME).toBe(`${probeCall?.[4].env.HOME}/data`);
      expect(probeCall?.[4].env.XDG_CACHE_HOME).toBe(`${probeCall?.[4].env.HOME}/cache`);
    }
    expect(probeCall?.[4].env.XDG_CONFIG_HOME).toBe(
      "/remote/workspace/.paperclip-runtime/runs/test/workspace/.paperclip-runtime/opencode/xdgConfig",
    );
    expect(probeCall?.[4].env.OPENCODE_CONFIG).toBe(
      "/remote/workspace/.paperclip-runtime/runs/test/workspace/.paperclip-runtime/opencode/xdgConfig/opencode/opencode.json",
    );
    expect(probeCall?.[4].env.OPENCODE_CONFIG_DIR).toBeUndefined();
    expect(probeCall?.[4].env.SCOPED_PROVIDER_KEY).toBe("scoped-test-key");
    expect(probeCall?.[4].env.OPENAI_API_KEY).toBe(managed ? "" : undefined);
    expect(probeCall?.[4].env.DATABASE_URL).toBeUndefined();
    expect(probeCall?.[4].env.ANTHROPIC_API_KEY).toBeUndefined();
    expect(probeCall?.[4].env.PAPERCLIP_OPENCODE_SMALL_MODEL).toBeUndefined();
    expect(probeCall?.[4].env.PAPERCLIP_OPENCODE_PROVIDERS).toBeUndefined();
    expect(probeCall?.[4].env.PATH).toBeDefined();
    expect(probeCall?.[4].env.XDG_DATA_HOME).toContain("/home/");
    expect(probeCall?.[4].env.XDG_RUNTIME_DIR).toBe(`${probeCall?.[4].env.HOME}/runtime`);
  });

  it("rejects missing scoped key before any remote runner or process call", async () => {
    const remoteExecute = vi.fn(async () => ({
      exitCode: 0, signal: null, timedOut: false, stdout: "", stderr: "", pid: null,
      startedAt: new Date().toISOString(),
    }));
    const remoteTarget: AdapterExecutionTarget = {
      kind: "remote", transport: "sandbox", providerKey: "cloudflare", remoteCwd: "/remote/workspace",
      runner: { execute: remoteExecute },
    };
    const result = await testEnvironment({
      companyId: "company-1",
      adapterType: "opencode_local",
      config: {
        model: "example/model",
        env: { PAPERCLIP_OPENCODE_PROVIDERS: JSON.stringify({ example: { options: { apiKey: "{env:MISSING_SCOPED_KEY}" }, models: { model: {} } } }) },
      },
      executionTarget: remoteTarget,
    });
    expect(result.status).toBe("fail");
    expect(result.checks).toContainEqual(expect.objectContaining({
      code: "opencode_remote_profile_invalid",
      level: "error",
      message: expect.stringContaining("MISSING_SCOPED_KEY is missing or empty"),
    }));
    expect(prepareAdapterExecutionTargetRuntime).not.toHaveBeenCalled();
    expect(ensureAdapterExecutionTargetDirectory).not.toHaveBeenCalled();
    expect(runAdapterExecutionTargetProcess).not.toHaveBeenCalled();
    expect(remoteExecute).not.toHaveBeenCalled();
  });
});
