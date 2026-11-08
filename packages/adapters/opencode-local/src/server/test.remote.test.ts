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

const TEST_CA_PEM = `-----BEGIN CERTIFICATE-----
MIICFDCCAX2gAwIBAgIUbAcXH/gLdZYHDyCg5uD9QkoU6dIwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQT3BlbkNvZGUgdGVzdCBDQTAgFw0yNjExMDcyMTUzNDla
GA8yMTI2MTAxNDIxNTM0OVowGzEZMBcGA1UEAwwQT3BlbkNvZGUgdGVzdCBDQTCB
nzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAt6JhKkjqhmQqsAVduWHKAjedHpgq
mq9V64pHCUqCAQY1+iwLuk8y7Z7vVvEtYmwylbRX9fHpb1dvcd6bdvotPiCGErxQ
C5FcoQZcOp4NX/CfMzHhrV4T5Gun5UDENjiF5JMTeASEOB2fXO9xIi2SQz88lLH6
Zu2dah78veBx4pMCAwEAAaNTMFEwHQYDVR0OBBYEFMA2LZmKGJhTf6LFANr/inEa
gZs5MB8GA1UdIwQYMBaAFMA2LZmKGJhTf6LFANr/inEagZs5MA8GA1UdEwEB/wQF
MAMBAf8wDQYJKoZIhvcNAQELBQADgYEAs+N7JG+Sj0YZllh7Qb1vKxTb1WBxz6VW
pj3iscD8veHT1r5Q9Qhh9fU+n2NrcOh6HxXrmRDoj18iVNxvRXxMmJ19ovzhXfxg
SGOiW1iUdiPtY5hNAiORBB4f+Fo7ReTP2S8JyFqy6U682uE1YxyjwElrotZjKXWv
nvUmXExeOTA=
-----END CERTIFICATE-----
`;

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
        remoteMcpServers: [{ name: "search", url: "https://search.internal/mcp", tokenEnvName: "CONTEXT_KEY" }],
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
          CONTEXT_KEY: "fixture-context-bearer",
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
    expect(directoryOptions?.env?.CONTEXT_KEY).toBeUndefined();
    expect(installOptions?.env?.SCOPED_PROVIDER_KEY).toBeUndefined();
    expect(installOptions?.env?.CONTEXT_KEY).toBeUndefined();
    expect(resolutionEnv?.SCOPED_PROVIDER_KEY).toBeUndefined();
    expect(resolutionEnv?.CONTEXT_KEY).toBeUndefined();
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
    expect(probeCall?.[4].env.CONTEXT_KEY).toBe("fixture-context-bearer");
    expect(probeCall?.[4].env.OPENAI_API_KEY).toBe(managed ? "" : undefined);
    expect(probeCall?.[4].env.DATABASE_URL).toBeUndefined();
    expect(probeCall?.[4].env.ANTHROPIC_API_KEY).toBeUndefined();
    expect(probeCall?.[4].env.PAPERCLIP_OPENCODE_SMALL_MODEL).toBeUndefined();
    expect(probeCall?.[4].env.PAPERCLIP_OPENCODE_PROVIDERS).toBeUndefined();
    expect(probeCall?.[4].env.PATH).toBeDefined();
    expect(probeCall?.[4].env.XDG_DATA_HOME).toContain("/home/");
    expect(probeCall?.[4].env.XDG_RUNTIME_DIR).toBe(`${probeCall?.[4].env.HOME}/runtime`);
    expect(JSON.stringify(runtimeInput)).not.toContain("fixture-context-bearer");
    expect(JSON.stringify(result)).not.toContain("fixture-context-bearer");
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

  it("redacts MCP credentials echoed by a failed remote hello probe", async () => {
    const secret = "fixture-context-bearer-echoed";
    runAdapterExecutionTargetProcess.mockResolvedValueOnce({
      exitCode: 1,
      signal: null,
      timedOut: false,
      stdout: "",
      stderr: `remote auth failure: ${secret}`,
      pid: 123,
      startedAt: new Date().toISOString(),
    });
    const remoteTarget: AdapterExecutionTarget = {
      kind: "remote", transport: "sandbox", providerKey: "cloudflare", remoteCwd: "/remote/workspace",
      runner: { execute: vi.fn(async () => ({
        exitCode: 0, signal: null, timedOut: false, stdout: "", stderr: "", pid: null,
        startedAt: new Date().toISOString(),
      })) },
    };
    const result = await testEnvironment({
      companyId: "company-1",
      adapterType: "opencode_local",
      config: {
        command: "opencode",
        model: "anthropic/claude-sonnet-4-5",
        remoteMcpServers: [{ name: "search", url: "https://search.internal/mcp", tokenEnvName: "CONTEXT_KEY" }],
        env: {
          PAPERCLIP_OPENCODE_PROVIDERS: JSON.stringify({
            anthropic: { options: { apiKey: "{env:SCOPED_PROVIDER_KEY}" }, models: { "claude-sonnet-4-5": {} } },
          }),
          SCOPED_PROVIDER_KEY: "fixture-model-key",
          CONTEXT_KEY: secret,
        },
      },
      executionTarget: remoteTarget,
    });
    expect(result.status).toBe("fail");
    expect(JSON.stringify(result)).not.toContain(secret);
    expect(JSON.stringify(result)).toContain("[redacted]");
  });

  it.each(["NODE_TLS_REJECT_UNAUTHORIZED", "NODE_EXTRA_CA_CERTS"])(
    "rejects reserved remote TLS credential binding %s before remote setup",
    async (reservedName) => {
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
          trustedCaPem: TEST_CA_PEM,
          env: {
            PAPERCLIP_OPENCODE_PROVIDERS: JSON.stringify({
              example: { options: { apiKey: `{env:${reservedName}}` }, models: { model: {} } },
            }),
            [reservedName]: "fixture-credential-value",
          },
        },
        executionTarget: remoteTarget,
      });

      expect(result.status).toBe("fail");
      expect(result.checks).toContainEqual(expect.objectContaining({
        code: "opencode_remote_profile_invalid",
        level: "error",
        message: expect.stringContaining(`credential binding ${reservedName} uses a reserved TLS-control`),
      }));
      expect(prepareAdapterExecutionTargetRuntime).not.toHaveBeenCalled();
      expect(ensureAdapterExecutionTargetDirectory).not.toHaveBeenCalled();
      expect(runAdapterExecutionTargetProcess).not.toHaveBeenCalled();
      expect(remoteExecute).not.toHaveBeenCalled();
    },
  );

  it("stages and reapplies remote additive trust after env setup, and fails closed when staging omits xdgConfig", async () => {
    const remoteTarget: AdapterExecutionTarget = {
      kind: "remote", transport: "sandbox", providerKey: "cloudflare", remoteCwd: "/remote/workspace",
      runner: { execute: vi.fn(async () => ({
        exitCode: 0, signal: null, timedOut: false, stdout: "", stderr: "", pid: null,
        startedAt: new Date().toISOString(),
      })) },
    };
    const result = await testEnvironment({
      companyId: "company-1",
      adapterType: "opencode_local",
      config: {
        command: "opencode",
        model: "anthropic/claude-sonnet-4-5",
        trustedCaPem: TEST_CA_PEM,
        env: {
          PAPERCLIP_OPENCODE_PROVIDERS: JSON.stringify({
            anthropic: {
              options: { apiKey: "{env:SCOPED_PROVIDER_KEY}" },
              models: { "claude-sonnet-4-5": {} },
            },
          }),
          SCOPED_PROVIDER_KEY: "fixture-scoped-key",
          SSL_CERT_FILE: "/host/replace.pem",
          SSL_CERT_DIR: "/host/certs",
          REQUESTS_CA_BUNDLE: "/host/requests.pem",
          NODE_OPTIONS: "--use-openssl-ca",
          NODE_TLS_REJECT_UNAUTHORIZED: "0",
          OPENSSL_CONF: "/host/openssl.cnf",
        },
      },
      executionTarget: remoteTarget,
    });

    expect(result.status).toBe("pass");
    const runtimeInput = (prepareAdapterExecutionTargetRuntime.mock.calls as unknown as Array<[
      { assets?: Array<{ key: string; localDir: string }> },
    ]>)[0]?.[0];
    const configAsset = runtimeInput?.assets?.find((asset) => asset.key === "xdgConfig");
    expect(configAsset?.localDir).toBeDefined();
    const probeCall = runAdapterExecutionTargetProcess.mock.calls[0] as unknown as
      | [string, AdapterExecutionTarget, string, string[], { env: Record<string, string> }]
      | undefined;
    expect(probeCall?.[4].env.NODE_EXTRA_CA_CERTS).toBe(
      "/remote/workspace/.paperclip-runtime/runs/test/workspace/.paperclip-runtime/opencode/xdgConfig/trust/ca.pem",
    );
    for (const name of ["SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "NODE_OPTIONS", "NODE_TLS_REJECT_UNAUTHORIZED", "OPENSSL_CONF"]) {
      expect(probeCall?.[4].env[name]).toBeUndefined();
    }

    const remoteExecute = remoteTarget.runner?.execute;
    prepareAdapterExecutionTargetRuntime.mockImplementationOnce(async () => ({
      target: null,
      workspaceRemoteDir: "/remote/workspace/.paperclip-runtime/runs/test/workspace",
      runtimeRootDir: "/remote/workspace/.paperclip-runtime/runs/test/workspace/.paperclip-runtime/opencode",
      assetDirs: {},
      restoreWorkspace: vi.fn(async () => {}),
    }) as never);
    runAdapterExecutionTargetProcess.mockClear();
    const missingAsset = await testEnvironment({
      companyId: "company-1",
      adapterType: "opencode_local",
      config: {
        command: "opencode",
        model: "anthropic/claude-sonnet-4-5",
        trustedCaPem: TEST_CA_PEM,
        env: {
          PAPERCLIP_OPENCODE_PROVIDERS: JSON.stringify({
            anthropic: { options: { apiKey: "{env:SCOPED_PROVIDER_KEY}" }, models: { "claude-sonnet-4-5": {} } },
          }),
          SCOPED_PROVIDER_KEY: "fixture-scoped-key",
        },
      },
      executionTarget: remoteTarget,
    });
    expect(missingAsset.status).toBe("fail");
    expect(missingAsset.checks).toContainEqual(expect.objectContaining({
      code: "opencode_remote_trust_stage_failed",
      level: "error",
    }));
    expect(runAdapterExecutionTargetProcess).not.toHaveBeenCalled();
    expect(remoteExecute).not.toHaveBeenCalled();
  });
});
