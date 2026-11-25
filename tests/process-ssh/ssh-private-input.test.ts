import fs from "node:fs/promises";
import path from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { runSshCommand } from "../../packages/adapter-utils/src/ssh.js";
import { createPreWireObserver } from "../../server/src/__tests__/fixtures/process-ssh-target/observer-fixture.js";
import { PRIVATE_CANARIES } from "../../server/src/__tests__/fixtures/process-ssh-target/constants.js";

const parent = process.env.PAPERCLIP_PROCESS_SSH_TEST_ROOT;
if (!parent || !path.isAbsolute(parent)) throw new Error("explicit private fixture root required");
const originalHome = process.env.HOME;
const originalCodexHome = process.env.CODEX_HOME;
let observer: Awaited<ReturnType<typeof createPreWireObserver>>;
beforeAll(async () => { observer = await createPreWireObserver(parent); }, 10000);
afterEach(() => {
  vi.unstubAllEnvs();
  expect(process.env.HOME).toBe(originalHome);
  expect(process.env.CODEX_HOME).toBe(originalCodexHome);
});
afterAll(async () => {
  const calls = await observer?.readCalls() ?? [];
  expect(calls.every(call => call.wireReached === false)).toBe(true);
  if (observer) await fs.writeFile(path.join(observer.root, "prewire-receipt.json"), JSON.stringify({
    calls: calls.length, allWireNotReached: true, homeUnchanged: process.env.HOME === originalHome,
    codexHomeUnchanged: process.env.CODEX_HOME === originalCodexHome }), { mode: 0o600 });
});

type Options = Parameters<typeof runSshCommand>[2] & {
  inputMode?: "legacy" | "private_v1" | "unrecognized";
  deadlineEpochMs?: number;
};
const env = { FIXTURE_PRIVATE: PRIVATE_CANARIES[0] };
const command = "printf fixture-nonsecret-command";
function privateOptions(extra: Options = {}): Options {
  return { inputMode: "private_v1", deadlineEpochMs: Date.now() + 5000,
    env, stdin: PRIVATE_CANARIES[1], timeoutMs: 1000, ...extra };
}
async function observe(options: Options, remoteCommand = command) {
  vi.stubEnv("PATH", observer.bin + ":/usr/bin:/bin:/usr/sbin");
  const before = new Set((await observer.readCalls()).map(call => call.id));
  let error: unknown;
  try { await runSshCommand(observer.config, remoteCommand, options); }
  catch (caught) { error = caught; }
  const calls = (await observer.readCalls()).filter(call => !before.has(call.id));
  return { calls, error };
}
function frame(options: Options, remoteCommand: string) {
  const segments = [Buffer.from(JSON.stringify(options?.env ?? {})), Buffer.from(remoteCommand), Buffer.from(options?.stdin ?? "")];
  const header = Buffer.from("PAPERCLIP_SSH_PRIVATE_V1\n" + segments.map(part => String(part.length) + "\n").join(""));
  return Buffer.concat([header, ...segments]);
}

describe("B1 private_v1 pre-wire custody RED (actual runSshCommand, no real wire claim)", () => {
  it("keeps supplied env/command/stdin canaries out of ORIGINAL helper argv", async () => {
    const value = await observe(privateOptions(), `printf ${PRIVATE_CANARIES[2]}`);
    expect(value.calls).toHaveLength(1);
    expect(value.calls[0].wireReached).toBe(false);
    for (const canary of PRIVATE_CANARIES) expect(JSON.stringify(value.calls[0].args)).not.toContain(canary);
  });
  it.each([["empty", ""], ["binary UTF8", "stdin\u0000bytes\r\n雪 ' $()\n" + PRIVATE_CANARIES[1]]])("preserves exact framed stdin bytes and EOF for %s input", async (_label, stdin) => {
    const options = privateOptions({ stdin, env: { FIXTURE_PRIVATE: PRIVATE_CANARIES[0], QUOTES: "a'\n$literal" } });
    const value = await observe(options);
    expect(value.calls).toHaveLength(1);
    expect(Buffer.from(value.calls[0].input)).toEqual(frame(options, command));
  });
  it("uses a profile-free constant transport bootstrap", async () => {
    const value = await observe(privateOptions());
    expect(value.calls).toHaveLength(1);
    expect(value.calls[0].unsafeProfile).toBe(false);
  });
  it("selects explicit no-config/no-agent/no-proxy policy before fixture safety flags", async () => {
    const value = await observe(privateOptions());
    const args: string[] = value.calls[0].args;
    expect(args).toEqual(expect.arrayContaining(["-F", "/dev/null", "IdentityAgent=none", "IdentitiesOnly=yes",
      "ProxyCommand=none", "ProxyJump=none", "StrictHostKeyChecking=yes"]));
  });
  it("does not project an unselected ambient provider canary into the local SSH transport environment", async () => {
    vi.stubEnv("FIXTURE_AMBIENT_PROVIDER", "fixture-ambient-provider-canary");
    const value = await observe(privateOptions());
    expect(value.calls).toHaveLength(1);
    expect(value.calls[0].ambientCanaryPresent).toBe(false);
  });
  it("does not expose supplied values in helper-thrown transport diagnostics", async () => {
    const value = await observe(privateOptions(), `printf ${PRIVATE_CANARIES[2]}`);
    expect(value.error).toBeDefined();
    const diagnostic = String(value.error) + JSON.stringify(value.error);
    for (const canary of PRIVATE_CANARIES) expect(diagnostic).not.toContain(canary);
  });
  it.each([
    ["missing deadline", { deadlineEpochMs: undefined }],
    ["expired deadline", { deadlineEpochMs: 0 }],
    ["noninteger deadline", { deadlineEpochMs: 1.5 }],
    ["deadline more than60seconds away", { deadlineEpochMs: Date.now() + 120000 }],
    ["unrecognized mode", { inputMode: "unrecognized" }],
    ["too many env entries", { env: Object.fromEntries(Array.from({ length: 65 }, (_, index) => ["ENV_" + index, "v"])) }],
    ["oversized env JSON", { env: { LARGE: "x".repeat(65536) } }],
    ["oversized application input", { stdin: "x".repeat(1048577) }],
  ] as [string, Options][])("rejects %s before SSH spawn", async (_label, patch) => {
    const value = await observe(privateOptions(patch));
    expect(value.error).toBeDefined();
    expect(value.calls, "invalid private input reached SSH executable").toHaveLength(0);
  });
  it("rejects oversized command before SSH spawn", async () => {
    const value = await observe(privateOptions(), "x".repeat(16385));
    expect(value.error).toBeDefined();
    expect(value.calls).toHaveLength(0);
  });
  it("charges asynchronous auth preparation to the same absolute deadline", async () => {
    const original = fs.writeFile.bind(fs);
    const write = vi.spyOn(fs, "writeFile").mockImplementation(async (...args) => {
      if (String(args[0]).includes("paperclip-ssh-key-")) await new Promise(resolve => setTimeout(resolve, 200));
      return original(...args);
    });
    try {
      const value = await observe(privateOptions({ deadlineEpochMs: Date.now() + 100 }));
      expect(value.error).toBeDefined();
      expect(value.calls, "expired setup budget still dispatched SSH").toHaveLength(0);
    } finally { write.mockRestore(); }
  });
});

describe("B1 non-opt-in compatibility and input validation controls", () => {
  it("keeps omitted and explicit legacy mode argv/profile semantics equal without executing profiles", async () => {
    const omitted = await observe({ env, stdin: "", timeoutMs: 1000 });
    const legacy = await observe({ inputMode: "legacy", env, stdin: "", timeoutMs: 1000 });
    expect(omitted.calls).toHaveLength(1); expect(legacy.calls).toHaveLength(1);
    expect(omitted.calls[0]).toMatchObject({ unsafeProfile: true, wireReached: false });
    expect(legacy.calls[0]).toMatchObject({ unsafeProfile: true, wireReached: false });
    expect(omitted.calls[0].args.at(-1)).toBe(legacy.calls[0].args.at(-1));
    expect(JSON.stringify(omitted.calls[0].args)).toContain(PRIVATE_CANARIES[0]);
    expect(omitted.calls[0].input).toEqual(Buffer.alloc(0));
  });
  it("rejects an invalid environment name before invoking SSH", async () => {
    const value = await observe(privateOptions({ env: { "INVALID-NAME": "fixture-value" } }));
    expect(value.error).toBeDefined(); expect(value.calls).toHaveLength(0);
  });
});
