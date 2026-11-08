import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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

const {
  runChildProcess,
  ensureCommandResolvable,
  resolveCommandForLogs,
  prepareWorkspaceForSshExecution,
  restoreWorkspaceFromSshExecution,
  runSshCommand,
  syncDirectoryToSsh,
  startAdapterExecutionTargetPaperclipBridge,
} = vi.hoisted(() => ({
  runChildProcess: vi.fn(async (_runId: string, _command: string, args: string[]) => {
    if (args.includes("models")) {
      return {
        exitCode: 0,
        signal: null,
        timedOut: false,
        stdout: "opencode/gpt-5-nano\nopenai/gpt-4.1\n",
        stderr: "",
        pid: 122,
        startedAt: new Date().toISOString(),
      };
    }
    return {
      exitCode: 0,
      signal: null,
      timedOut: false,
      stdout: [
        JSON.stringify({ type: "step_start", sessionID: "session_123" }),
        JSON.stringify({ type: "text", sessionID: "session_123", part: { text: "hello" } }),
        JSON.stringify({
          type: "step_finish",
          sessionID: "session_123",
          part: { cost: 0.001, tokens: { input: 1, output: 1, reasoning: 0, cache: { read: 0, write: 0 } } },
        }),
      ].join("\n"),
      stderr: "",
      pid: 123,
      startedAt: new Date().toISOString(),
    };
  }),
  ensureCommandResolvable: vi.fn(async () => undefined),
  resolveCommandForLogs: vi.fn(async () => "ssh://fixture@127.0.0.1:2222/remote/workspace :: opencode"),
  prepareWorkspaceForSshExecution: vi.fn(async () => ({ gitBacked: false })),
  restoreWorkspaceFromSshExecution: vi.fn(async () => undefined),
  runSshCommand: vi.fn(async () => ({
    stdout: "/home/agent",
    stderr: "",
    exitCode: 0,
  })),
  syncDirectoryToSsh: vi.fn(async () => undefined),
  startAdapterExecutionTargetPaperclipBridge: vi.fn(async () => ({
    env: {
      PAPERCLIP_API_URL: "http://127.0.0.1:4310",
      PAPERCLIP_API_KEY: "bridge-token",
      PAPERCLIP_API_BRIDGE_MODE: "queue_v1",
    },
    stop: async () => {},
  })),
}));

vi.mock("@paperclipai/adapter-utils/server-utils", async () => {
  const actual = await vi.importActual<typeof import("@paperclipai/adapter-utils/server-utils")>(
    "@paperclipai/adapter-utils/server-utils",
  );
  return {
    ...actual,
    ensureCommandResolvable,
    resolveCommandForLogs,
    runChildProcess,
  };
});

vi.mock("@paperclipai/adapter-utils/ssh", async () => {
  const actual = await vi.importActual<typeof import("@paperclipai/adapter-utils/ssh")>(
    "@paperclipai/adapter-utils/ssh",
  );
  return {
    ...actual,
    prepareWorkspaceForSshExecution,
    restoreWorkspaceFromSshExecution,
    runSshCommand,
    syncDirectoryToSsh,
  };
});

vi.mock("@paperclipai/adapter-utils/execution-target", async () => {
  const actual = await vi.importActual<typeof import("@paperclipai/adapter-utils/execution-target")>(
    "@paperclipai/adapter-utils/execution-target",
  );
  return {
    ...actual,
    startAdapterExecutionTargetPaperclipBridge,
  };
});

import { execute } from "./execute.js";

describe("opencode remote execution", () => {
  const cleanupDirs: string[] = [];
  const originalOpenCodeAllowAllModels = process.env.OPENCODE_ALLOW_ALL_MODELS;

  beforeEach(async () => {
    const configHome = await mkdtemp(path.join(os.tmpdir(), "paperclip-opencode-test-config-"));
    cleanupDirs.push(configHome);
    vi.stubEnv("XDG_CONFIG_HOME", configHome);
    vi.stubEnv("DATABASE_URL", "ambient-db-sentinel");
    vi.stubEnv("OPENROUTER_API_KEY", "ambient-provider-key-sentinel");
    vi.stubEnv("PAPERCLIP_OPENCODE_SMALL_MODEL", "ambient/host-only-model");
    delete process.env.OPENCODE_ALLOW_ALL_MODELS;
  });

  afterEach(async () => {
    vi.clearAllMocks();
    vi.unstubAllEnvs();
    if (originalOpenCodeAllowAllModels === undefined) {
      delete process.env.OPENCODE_ALLOW_ALL_MODELS;
    } else {
      process.env.OPENCODE_ALLOW_ALL_MODELS = originalOpenCodeAllowAllModels;
    }
    while (cleanupDirs.length > 0) {
      const dir = cleanupDirs.pop();
      if (!dir) continue;
      await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  it.each([false, true])("prepares the workspace, syncs OpenCode skills, and restores workspace changes for remote SSH execution (managed=%s)", async (managed) => {
    const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-opencode-remote-"));
    cleanupDirs.push(rootDir);
    const workspaceDir = path.join(rootDir, "workspace");
    const alternateWorkspaceDir = path.join(rootDir, "workspace-other");
    const managedRemoteWorkspace = "/remote/workspace/.paperclip-runtime/runs/run-1/workspace";
    await mkdir(workspaceDir, { recursive: true });
    await mkdir(alternateWorkspaceDir, { recursive: true });

    const result = await execute({
      runId: "run-1",
      authToken: "trusted-host-bearer-sentinel",
      agent: {
        id: "agent-1",
        companyId: "company-1",
        name: "OpenCode Builder",
        adapterType: "opencode_local",
        adapterConfig: {},
      },
      runtime: {
        sessionId: null,
        sessionParams: null,
        sessionDisplayId: null,
        taskKey: null,
      },
      config: {
        command: "opencode",
        model: "opencode/gpt-5-nano",
        trustedCaPem: TEST_CA_PEM,
        remoteMcpServers: [{ name: "search", url: "https://search.internal/mcp", tokenEnvName: "CONTEXT_KEY" }],
        ...(managed ? {
          managedAiConnection: { provider: "openrouter", method: "api_key" },
        } : {}),
        env: {
          XDG_CONFIG_HOME: path.join(rootDir, "config"),
          OPENCODE_CONFIG: "/host-only/config/opencode.json",
          OPENCODE_CONFIG_DIR: "/host-only/config",
          PAPERCLIP_OPENCODE_PROVIDERS: JSON.stringify({
            opencode: { options: { apiKey: "{env:SCOPED_PROVIDER_KEY}" }, models: { "gpt-5-nano": {} } },
          }),
          SCOPED_PROVIDER_KEY: "fixture-scoped-key",
          CONTEXT_KEY: "fixture-context-bearer",
          SSL_CERT_FILE: "/host/replacement-roots.pem",
          SSL_CERT_DIR: "/host/cert-dir",
          REQUESTS_CA_BUNDLE: "/host/request-roots.pem",
          NODE_OPTIONS: "--require /host/preload.js",
          NODE_TLS_REJECT_UNAUTHORIZED: "0",
          OPENSSL_CONF: "/host/openssl.cnf",
          ...(managed ? { HOME: "/var/folders/qa-managed", XDG_DATA_HOME: "/var/folders/qa-managed/data" } : {}),
        },
      },
      context: {
        paperclipWorkspace: {
          cwd: workspaceDir,
          source: "project_primary",
        },
        paperclipWorkspaces: [
          {
            workspaceId: "workspace-1",
            cwd: workspaceDir,
            repoUrl: "https://github.com/paperclipai/paperclip.git",
            repoRef: "main",
          },
          {
            workspaceId: "workspace-2",
            cwd: alternateWorkspaceDir,
            repoUrl: "https://github.com/paperclipai/paperclip.git",
            repoRef: "feature/other",
          },
        ],
      },
      executionTransport: {
        remoteExecution: {
          host: "127.0.0.1",
          port: 2222,
          username: "fixture",
          remoteWorkspacePath: "/remote/workspace",
          remoteCwd: "/remote/workspace",
          privateKey: "PRIVATE KEY",
          knownHosts: "[127.0.0.1]:2222 ssh-ed25519 AAAA",
          strictHostKeyChecking: true,
        },
      },
      onLog: async () => {},
    });

    expect(result.sessionParams).toMatchObject({
      sessionId: "session_123",
      cwd: managedRemoteWorkspace,
      remoteExecution: {
        transport: "ssh",
        host: "127.0.0.1",
        port: 2222,
        username: "fixture",
        remoteCwd: managedRemoteWorkspace,
      },
    });
    expect(prepareWorkspaceForSshExecution).toHaveBeenCalledTimes(1);
    expect(syncDirectoryToSsh).toHaveBeenCalledTimes(2);
    expect(syncDirectoryToSsh).toHaveBeenCalledWith(expect.objectContaining({
      remoteDir: `${managedRemoteWorkspace}/.paperclip-runtime/opencode/xdgConfig`,
    }));
    expect(syncDirectoryToSsh).toHaveBeenCalledWith(expect.objectContaining({
      remoteDir: `${managedRemoteWorkspace}/.paperclip-runtime/opencode/skills`,
      followSymlinks: true,
    }));
    expect(runSshCommand).toHaveBeenCalledWith(
      expect.anything(),
      expect.stringContaining(".claude/skills"),
      expect.anything(),
    );
    const runCall = runChildProcess.mock.calls.find((entry) => Array.isArray(entry[2]) && entry[2].includes("run")) as
      | [string, string, string[], { env: Record<string, string>; remoteExecution?: { remoteCwd: string } | null }]
      | undefined;
    const modelProbeCall = runChildProcess.mock.calls.find((entry) => Array.isArray(entry[2]) && entry[2].includes("models")) as
      | [string, string, string[], { env: Record<string, string>; remoteExecution?: { remoteCwd: string } | null }]
      | undefined;
    expect(modelProbeCall?.[2]).toEqual(["models"]);
    for (const runnerCall of runChildProcess.mock.calls as unknown as Array<[
      string,
      string,
      string[],
      { env?: Record<string, string> },
    ]>) {
      if (runnerCall[2].includes("run")) {
        expect(runnerCall[3].env?.CONTEXT_KEY).toBe("fixture-context-bearer");
      } else {
        expect(runnerCall[3].env?.CONTEXT_KEY).toBeUndefined();
      }
    }
    // The model probe runs after the runtime workspace is prepared (so XDG
    // points at the managed subdirectory) but the SSH session targets the
    // original target remoteCwd — the per-run subdirectory is layered
    // underneath via XDG/runtime config rather than by switching the cwd.
    expect(modelProbeCall?.[3].env.XDG_CONFIG_HOME).toBe(
      `${managedRemoteWorkspace}/.paperclip-runtime/opencode/xdgConfig`,
    );
    expect(modelProbeCall?.[3].env.NODE_EXTRA_CA_CERTS).toBe(
      `${managedRemoteWorkspace}/.paperclip-runtime/opencode/xdgConfig/trust/ca.pem`,
    );
    expect(modelProbeCall?.[3].remoteExecution?.remoteCwd).toBe("/remote/workspace");
    const call = runCall as
      | [string, string, string[], { env: Record<string, string>; remoteExecution?: { remoteCwd: string } | null }]
      | undefined;
    expect(call?.[3].env.PAPERCLIP_WORKSPACE_CWD).toBe(managedRemoteWorkspace);
    const home = `${managedRemoteWorkspace}/.paperclip-runtime/opencode/home/run-1`;
    expect(call?.[3].env.HOME).toBe(home);
    expect(call?.[3].env.XDG_DATA_HOME).toBe(`${home}/data`);
    expect(modelProbeCall?.[3].env.XDG_DATA_HOME).toBe(`${home}/data`);
    expect(call?.[3].env.XDG_RUNTIME_DIR).toBe(`${home}/runtime`);
    expect(modelProbeCall?.[3].env.SCOPED_PROVIDER_KEY).toBe("fixture-scoped-key");
    expect(modelProbeCall?.[3].env.CONTEXT_KEY).toBeUndefined();
    expect(modelProbeCall?.[3].env.PAPERCLIP_API_KEY).toBeUndefined();
    expect(runSshCommand).toHaveBeenCalledWith(
      expect.anything(),
      expect.stringContaining(`${home}/.claude/skills`),
      expect.anything(),
    );
    expect(JSON.parse(call?.[3].env.PAPERCLIP_WORKSPACES_JSON ?? "[]")).toEqual([
      {
        workspaceId: "workspace-1",
        cwd: managedRemoteWorkspace,
        repoUrl: "https://github.com/paperclipai/paperclip.git",
        repoRef: "main",
      },
      {
        workspaceId: "workspace-2",
        repoUrl: "https://github.com/paperclipai/paperclip.git",
        repoRef: "feature/other",
      },
    ]);
    expect(call?.[3].env.PAPERCLIP_API_URL).toBe("http://127.0.0.1:4310");
    expect(call?.[3].env.PAPERCLIP_API_BRIDGE_MODE).toBe("queue_v1");
    expect(call?.[3].env.DATABASE_URL).toBeUndefined();
    expect(call?.[3].env.OPENROUTER_API_KEY).not.toBe("ambient-provider-key-sentinel");
    expect(call?.[3].env.PAPERCLIP_OPENCODE_SMALL_MODEL).toBeUndefined();
    expect(call?.[3].env.PAPERCLIP_OPENCODE_PROVIDERS).toBeUndefined();
    expect(call?.[3].env.XDG_CONFIG_HOME).toBe(`${managedRemoteWorkspace}/.paperclip-runtime/opencode/xdgConfig`);
    expect(call?.[3].env.OPENCODE_CONFIG).toBe(
      `${managedRemoteWorkspace}/.paperclip-runtime/opencode/xdgConfig/opencode/opencode.json`,
    );
    expect(call?.[3].env.OPENCODE_CONFIG_DIR).toBeUndefined();
    expect(call?.[3].env.HOME).toBe(`${managedRemoteWorkspace}/.paperclip-runtime/opencode/home/run-1`);
    expect(call?.[3].env.SCOPED_PROVIDER_KEY).toBe("fixture-scoped-key");
    expect(call?.[3].env.CONTEXT_KEY).toBe("fixture-context-bearer");
    expect(call?.[3].env.NODE_EXTRA_CA_CERTS).toBe(
      `${managedRemoteWorkspace}/.paperclip-runtime/opencode/xdgConfig/trust/ca.pem`,
    );
    for (const name of ["SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "NODE_OPTIONS", "NODE_TLS_REJECT_UNAUTHORIZED", "OPENSSL_CONF"]) {
      expect(call?.[3].env[name]).toBeUndefined();
    }
    expect(call?.[3].remoteExecution?.remoteCwd).toBe(managedRemoteWorkspace);
    expect(startAdapterExecutionTargetPaperclipBridge).toHaveBeenCalledTimes(1);
    expect(startAdapterExecutionTargetPaperclipBridge).toHaveBeenCalledWith(
      expect.objectContaining({ hostApiToken: "trusted-host-bearer-sentinel" }),
    );
    expect(call?.[3].env.PAPERCLIP_API_KEY).toBe("bridge-token");
    // Setup, model discovery, shell staging and final spawn all receive target
    // state. The host bearer must stay in the controller and bridge constructor.
    expect(JSON.stringify(runChildProcess.mock.calls)).not.toContain("trusted-host-bearer-sentinel");
    expect(JSON.stringify(runSshCommand.mock.calls)).not.toContain("trusted-host-bearer-sentinel");
    expect(JSON.stringify(syncDirectoryToSsh.mock.calls)).not.toContain("trusted-host-bearer-sentinel");
    expect(JSON.stringify(ensureCommandResolvable.mock.calls)).not.toContain("trusted-host-bearer-sentinel");
    for (const calls of [runSshCommand.mock.calls, syncDirectoryToSsh.mock.calls, ensureCommandResolvable.mock.calls]) {
      expect(JSON.stringify(calls)).not.toContain("fixture-context-bearer");
    }
    expect(restoreWorkspaceFromSshExecution).toHaveBeenCalledTimes(1);
    expect(ensureCommandResolvable).toHaveBeenCalled();
    for (const callArgs of ensureCommandResolvable.mock.calls as unknown as unknown[][]) {
      const commandEnv = callArgs[2] as Record<string, string>;
      expect(commandEnv.SCOPED_PROVIDER_KEY).toBeUndefined();
    }
  });

  it("points remote instruction references at the staged execution copy", async () => {
    const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-opencode-remote-instructions-"));
    cleanupDirs.push(rootDir);
    const workspaceDir = path.join(rootDir, "workspace");
    const controllerInstructions = path.join(rootDir, "controller", "AGENTS.md");
    const stagedInstructions =
      "/remote/workspace/.paperclip-runtime/instruction-edits-run-instructions/instructions/AGENTS.md";
    await mkdir(workspaceDir, { recursive: true });
    await mkdir(path.dirname(controllerInstructions), { recursive: true });
    await writeFile(controllerInstructions, "Use the checked-in instructions.");

    let invocationMeta: { prompt?: string } | undefined;
    await execute({
      runId: "run-instructions",
      agent: {
        id: "agent-1",
        companyId: "company-1",
        name: "OpenCode Builder",
        adapterType: "opencode_local",
        adapterConfig: {},
      },
      runtime: { sessionId: null, sessionParams: null, sessionDisplayId: null, taskKey: null },
      config: {
        command: "opencode",
        model: "opencode/gpt-5-nano",
        instructionsFilePath: controllerInstructions,
        instructionsExecutionFilePath: stagedInstructions,
        env: {
          PAPERCLIP_OPENCODE_PROVIDERS: JSON.stringify({
            opencode: { options: { apiKey: "{env:SCOPED_PROVIDER_KEY}" }, models: { "gpt-5-nano": {} } },
          }),
          SCOPED_PROVIDER_KEY: "fixture-scoped-key",
        },
      },
      context: {
        paperclipWorkspace: { cwd: workspaceDir, source: "project_primary" },
      },
      executionTransport: {
        remoteExecution: {
          host: "127.0.0.1",
          port: 2222,
          username: "fixture",
          remoteWorkspacePath: "/remote/workspace",
          remoteCwd: "/remote/workspace",
          privateKey: "PRIVATE KEY",
          knownHosts: "[127.0.0.1]:2222 ssh-ed25519 AAAA",
          strictHostKeyChecking: true,
        },
      },
      onLog: async () => {},
      onMeta: async (meta) => {
        invocationMeta = meta;
      },
    });

    expect(invocationMeta?.prompt).toContain("Use the checked-in instructions.");
    expect(invocationMeta?.prompt).toContain(
      `available in this execution environment at ${stagedInstructions}`,
    );
    expect(invocationMeta?.prompt).toContain(
      `relative file references from ${path.posix.dirname(stagedInstructions)}/`,
    );
    expect(invocationMeta?.prompt).not.toContain(controllerInstructions);
  });

  it("fails before the remote run when the configured model is unavailable on the SSH target", async () => {
    runChildProcess.mockImplementationOnce(async () => ({
      exitCode: 0,
      signal: null,
      timedOut: false,
      stdout: "openai/gpt-4.1\n",
      stderr: "",
      pid: 456,
      startedAt: new Date().toISOString(),
    }));

    const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-opencode-remote-model-"));
    cleanupDirs.push(rootDir);
    const workspaceDir = path.join(rootDir, "workspace");
    await mkdir(workspaceDir, { recursive: true });

    await expect(() =>
      execute({
        runId: "run-ssh-model-missing",
        agent: {
          id: "agent-1",
          companyId: "company-1",
          name: "OpenCode Builder",
          adapterType: "opencode_local",
          adapterConfig: {},
        },
        runtime: {
          sessionId: null,
          sessionParams: null,
          sessionDisplayId: null,
          taskKey: null,
        },
        config: {
          command: "opencode",
          model: "opencode/gpt-5-nano",
          env: {
            PAPERCLIP_OPENCODE_PROVIDERS: JSON.stringify({
              opencode: { options: { apiKey: "{env:SCOPED_PROVIDER_KEY}" }, models: { "gpt-5-nano": {} } },
            }),
            SCOPED_PROVIDER_KEY: "fixture-scoped-key",
          },
        },
        context: {
          paperclipWorkspace: {
            cwd: workspaceDir,
            source: "project_primary",
          },
        },
        executionTransport: {
          remoteExecution: {
            host: "127.0.0.1",
            port: 2222,
            username: "fixture",
            remoteWorkspacePath: "/remote/workspace",
            remoteCwd: "/remote/workspace",
            privateKey: "PRIVATE KEY",
            knownHosts: "[127.0.0.1]:2222 ssh-ed25519 AAAA",
            strictHostKeyChecking: true,
          },
        },
        onLog: async () => {},
      }),
    ).rejects.toThrow("Configured OpenCode model is unavailable on the remote execution target");

    expect(runChildProcess).toHaveBeenCalledTimes(1);
    expect((runChildProcess.mock.calls[0]?.[2] as string[] | undefined) ?? []).toEqual(["models"]);
    expect(startAdapterExecutionTargetPaperclipBridge).not.toHaveBeenCalled();
  });

  it("rejects an unresolved selected key binding before any remote command", async () => {
    const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-opencode-remote-no-key-"));
    cleanupDirs.push(rootDir);
    const workspaceDir = path.join(rootDir, "workspace");
    await mkdir(workspaceDir, { recursive: true });

    await expect(execute({
      runId: "run-ssh-no-key",
      agent: {
        id: "agent-1", companyId: "company-1", name: "OpenCode Builder",
        adapterType: "opencode_local", adapterConfig: {},
      },
      runtime: { sessionId: null, sessionParams: null, sessionDisplayId: null, taskKey: null },
      config: {
        command: "opencode",
        model: "opencode/gpt-5-nano",
        env: {
          PAPERCLIP_OPENCODE_PROVIDERS: JSON.stringify({
            opencode: { options: { apiKey: "{env:MISSING_SCOPED_KEY}" }, models: { "gpt-5-nano": {} } },
          }),
        },
      },
      context: { paperclipWorkspace: { cwd: workspaceDir, source: "project_primary" } },
      executionTransport: {
        remoteExecution: {
          host: "127.0.0.1", port: 2222, username: "fixture", remoteWorkspacePath: "/remote/workspace",
          remoteCwd: "/remote/workspace", privateKey: "PRIVATE KEY",
          knownHosts: "[127.0.0.1]:2222 ssh-ed25519 AAAA", strictHostKeyChecking: true,
        },
      },
      onLog: async () => {},
    })).rejects.toThrow("MISSING_SCOPED_KEY is missing or empty");

    expect(runChildProcess).not.toHaveBeenCalled();
    expect(runSshCommand).not.toHaveBeenCalled();
    expect(syncDirectoryToSsh).not.toHaveBeenCalled();
  });

  it("resumes saved OpenCode sessions for remote SSH execution only when the identity matches", async () => {
    const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-opencode-remote-resume-"));
    cleanupDirs.push(rootDir);
    const workspaceDir = path.join(rootDir, "workspace");
    const managedRemoteWorkspace = "/remote/workspace/.paperclip-runtime/runs/run-ssh-resume/workspace";
    await mkdir(workspaceDir, { recursive: true });

    await execute({
      runId: "run-ssh-resume",
      agent: {
        id: "agent-1",
        companyId: "company-1",
        name: "OpenCode Builder",
        adapterType: "opencode_local",
        adapterConfig: {},
      },
      runtime: {
        sessionId: "session-123",
        sessionParams: {
          sessionId: "session-123",
          cwd: managedRemoteWorkspace,
          remoteExecution: {
            transport: "ssh",
            host: "127.0.0.1",
            port: 2222,
            username: "fixture",
            remoteCwd: managedRemoteWorkspace,
          },
        },
        sessionDisplayId: "session-123",
        taskKey: null,
      },
      config: {
        command: "opencode",
        model: "opencode/gpt-5-nano",
        env: {
          PAPERCLIP_OPENCODE_PROVIDERS: JSON.stringify({
            opencode: { options: { apiKey: "{env:SCOPED_PROVIDER_KEY}" }, models: { "gpt-5-nano": {} } },
          }),
          SCOPED_PROVIDER_KEY: "fixture-scoped-key",
        },
      },
      context: {
        paperclipWorkspace: {
          cwd: workspaceDir,
          source: "project_primary",
        },
      },
      executionTransport: {
        remoteExecution: {
          host: "127.0.0.1",
          port: 2222,
          username: "fixture",
          remoteWorkspacePath: "/remote/workspace",
          remoteCwd: "/remote/workspace",
          privateKey: "PRIVATE KEY",
          knownHosts: "[127.0.0.1]:2222 ssh-ed25519 AAAA",
          strictHostKeyChecking: true,
        },
      },
      onLog: async () => {},
    });

    const call = runChildProcess.mock.calls.find((entry) => Array.isArray(entry[2]) && entry[2].includes("run")) as
      | [string, string, string[]]
      | undefined;
    expect(call?.[2]).toContain("--session");
    expect(call?.[2]).toContain("session-123");
  });
});
