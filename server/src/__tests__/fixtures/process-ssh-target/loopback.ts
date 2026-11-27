import { execFile, spawn } from "node:child_process";
import fs from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { vi } from "vitest";
import {
  buildSshEnvLabFixtureConfig, getSshEnvLabSupport, readSshEnvLabFixtureStatus,
  shellQuote, startSshEnvLabFixture, stopSshEnvLabFixture,
  type SshEnvLabFixtureState,
} from "@paperclipai/adapter-utils/ssh";
import { buildLocalProcessSandboxSpawnTarget } from "@paperclipai/adapter-utils/local-process-sandbox";

const exec = promisify(execFile);
const observer = fileURLToPath(new URL("./ssh-observer.cjs", import.meta.url));
export const probe = fileURLToPath(new URL("./probe.cjs", import.meta.url));
const isolation = fileURLToPath(new URL("./isolation.cjs", import.meta.url));
import { PRIVATE_CANARIES } from "./constants.js";

export async function exists(file: string) { return fs.access(file).then(() => true, () => false); }
export async function waitForFile(file: string, budgetMs = 7000) {
  const deadline = Date.now() + budgetMs;
  while (Date.now() < deadline) {
    if (await exists(file)) return;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  throw new Error("fixture-owned marker deadline exceeded");
}
async function processIdentity(pid: number) {
  try {
    const stat = await fs.readFile(`/proc/${pid}/stat`, "utf8");
    const ticks = stat.slice(stat.lastIndexOf(") ") + 2).split(/\s+/)[19];
    const command = await fs.readFile(`/proc/${pid}/cmdline`, "utf8");
    const namespace = await fs.readlink(`/proc/${pid}/ns/pid`);
    return { pid, ticks, command, namespace };
  } catch (error) {
    if (["ENOENT", "ESRCH"].includes((error as NodeJS.ErrnoException).code ?? "")) return null;
    throw new Error("fixture process identity remains unknown after IO failure", { cause: error });
  }
}
async function ownedLineage(pid: number) {
  const found: NonNullable<Awaited<ReturnType<typeof processIdentity>>>[] = [];
  const queue = [pid];
  for (let i = 0; i < queue.length && i < 32; i++) {
    const current = queue[i];
    const identity = await processIdentity(current);
    if (!identity) continue;
    found.push(identity);
    const children = await fs.readFile(`/proc/${current}/task/${current}/children`, "utf8").catch(error => {
      if (["ENOENT", "ESRCH"].includes((error as NodeJS.ErrnoException).code ?? "")) return "";
      throw new Error("fixture child lineage unknown after IO failure", { cause: error });
    });
    queue.push(...children.trim().split(/\s+/).filter(Boolean).map(Number));
  }
  if (queue.length > 32) throw new Error("fixture lineage exceeds owned traversal bound");
  return found;
}
function safeSshArgs(state: SshEnvLabFixtureState) {
  return ["-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
    "-o", "ProxyCommand=none", "-o", "ProxyJump=none", "-o", "StrictHostKeyChecking=yes",
    "-o", "GlobalKnownHostsFile=/dev/null", "-o", `UserKnownHostsFile=${state.knownHostsPath}`,
    "-i", state.clientPrivateKeyPath, "-p", String(state.port), `${state.username}@127.0.0.1`];
}
async function portClosed(port: number) {
  return new Promise<boolean>(resolve => {
    const socket = net.connect({ host: "127.0.0.1", port });
    socket.once("connect", () => { socket.destroy(); resolve(false); });
    socket.once("error", error => { socket.destroy(); resolve((error as NodeJS.ErrnoException).code === "ECONNREFUSED"); });
    socket.setTimeout(500, () => { socket.destroy(); resolve(false); });
  });
}

export async function createLoopbackFixture(parent: string) {
  if (!path.isAbsolute(parent)) throw new Error("explicit absolute fixture root required");
  const initialHome = process.env.HOME;
  const initialCodexHome = process.env.CODEX_HOME;
  const root = await fs.mkdtemp(path.join(parent, "loopback-"));
  await fs.chmod(root, 0o700);
  const captures = path.join(root, "captures");
  const bin = path.join(root, "bin");
  await fs.mkdir(captures, { mode: 0o700 }); await fs.mkdir(bin, { mode: 0o700 });
  const localProbe = path.join(root, "probe.cjs");
  const localIsolation = path.join(root, "isolation.cjs");
  const expectedPath = path.join(root, "unchanged-home.private.json");
  await fs.copyFile(probe, localProbe); await fs.copyFile(isolation, localIsolation);
  await fs.writeFile(expectedPath, JSON.stringify({ home: initialHome, codexHome: initialCodexHome }), { mode: 0o600 });
  // Forward existing nonsecret identity values unchanged, never assign a new
  // HOME/CODEX_HOME or inherit ambient provider/agent/cache credentials.
  const daemonEnv = Object.fromEntries(Object.entries(process.env).filter(([name, value]) =>
    typeof value === "string" && ["HOME", "CODEX_HOME", "LANG", "LC_ALL", "TZ"].includes(name)));
  daemonEnv.PATH = "/usr/bin:/bin:/usr/sbin";
  daemonEnv.TMPDIR = root;
  for (const file of ["/usr/bin/bwrap", "/usr/sbin/sshd"]) {
    if (await fs.realpath(file) !== file) throw new Error("fixture executable pin does not match actual system path");
  }
  const sandbox = await buildLocalProcessSandboxSpawnTarget({ executable: "/usr/sbin/sshd", args: [], cwd: root,
    options: { workspaceDir: root, filesystemScope: "workspace", command: "/usr/bin/bwrap" } });
  if (sandbox.command !== "/usr/bin/bwrap" || Object.keys(sandbox.env ?? {}).length) {
    throw new Error("unexpected fixture sandbox command/environment");
  }
  // Fixture-only merged-/usr compatibility: remove four redundant alias
  // bind triples, with no added mount, only when the existing RO/usr+symlinks
  // prove the identical filesystem view. Preserve original argv as evidence.
  const beforeNormalization = [...sandbox.args];
  const normalized = [...sandbox.args];
  const aliasProofs: Record<string, unknown>[] = [];
  function countTriple(args: string[], first: string, second: string, third: string) {
    return args.filter((value, index) => value === first && args[index + 1] === second && args[index + 2] === third).length;
  }
  if (countTriple(normalized, "--ro-bind", "/usr", "/usr") !== 1) throw new Error("fixture readonly/usr predicate failed");
  for (const alias of ["/bin", "/sbin", "/lib", "/lib64"]) {
    const link = "usr" + alias;
    const expectedReal = "/usr" + alias;
    const ownStat = await fs.lstat(alias);
    const actualLink = await fs.readlink(alias);
    const real = await fs.realpath(alias);
    const left = await fs.stat(alias); const right = await fs.stat(expectedReal);
    if (!ownStat.isSymbolicLink() || actualLink !== link || real !== expectedReal ||
        left.ino !== right.ino || left.dev !== right.dev ||
        countTriple(normalized, "--symlink", link, alias) !== 1 ||
        countTriple(normalized, "--ro-bind", alias, alias) !== 1) {
      throw new Error("fixture merged/usr predicate failed; no alternate sandbox");
    }
    const index = normalized.findIndex((value, i) => value === "--ro-bind" && normalized[i + 1] === alias && normalized[i + 2] === alias);
    normalized.splice(index, 3);
    aliasProofs.push({ alias, link: actualLink, real, sameFile: true, inode: left.ino, device: left.dev });
  }
  sandbox.args = normalized;
  await fs.writeFile(path.join(root, "argv-normalization.private.json"), JSON.stringify({
    sourceSha256: "7252504b9d1a609bd28d96aec968993651813876f6e81cc3a890efc3892592c8",
    before: beforeNormalization, after: normalized, aliasProofs,
    removedOnly: aliasProofs.map(item => ["--ro-bind", item.alias, item.alias]),
  }), { mode: 0o600 });
  await fs.writeFile(path.join(root, "bwrap-argv.private.json"), JSON.stringify({ command: sandbox.command,
    args: sandbox.args, cwd: sandbox.cwd, envKeys: Object.keys(daemonEnv), networkScope: null }), { mode: 0o600 });
  const cut = sandbox.args.lastIndexOf("--");
  const preflightArgs = [...sandbox.args.slice(0, cut + 1), process.execPath, localIsolation, expectedPath];
  try {
    const result = await exec(sandbox.command, preflightArgs, { cwd: sandbox.cwd, env: daemonEnv,
      timeout: 5000, maxBuffer: 32768 });
    const report = JSON.parse(result.stdout);
    if (!report.inaccessible || !report.homeUnchanged || !report.codexHomeUnchanged) throw new Error("fixture filesystem isolation not qualified");
    await fs.writeFile(path.join(root, "preflight.private.json"), JSON.stringify({ status: "qualified", ...report }), { mode: 0o600 });
  } catch (error) {
    await fs.writeFile(path.join(root, "preflight.private.json"), JSON.stringify({ status: "infrastructure_blocked",
      message: String(error) }), { mode: 0o600 });
    throw new Error("required existing filesystem-isolated SSH fixture unavailable; no unsafe alternative");
  }
  const statePath = path.join(root, "listener", "state.json");
  const observerConfig = path.join(root, "observer.json");
  await fs.writeFile(observerConfig, JSON.stringify({ captures, port: 1, username: os.userInfo().username,
    canaries: PRIVATE_CANARIES }), { mode: 0o600 });
  await fs.writeFile(path.join(bin, "ssh"), `#!/bin/sh\nexec ${shellQuote(process.execPath)} ${shellQuote(observer)} ${shellQuote(observerConfig)} "$@"\n`, { mode: 0o700 });
  await fs.writeFile(path.join(bin, "sshd"), `#!/bin/sh\nexec ${shellQuote(sandbox.command)} ${sandbox.args.map(shellQuote).join(" ")} "$@"\n`, { mode: 0o700 });
  vi.stubEnv("PATH", bin + ":/usr/bin:/bin:/usr/sbin");
  const support = await getSshEnvLabSupport();
  if (!support.supported) throw new Error("required real SSH fixture unavailable: " + support.reason);
  const originalWrite = fs.writeFile.bind(fs);
  const writeObserver = vi.spyOn(fs, "writeFile").mockImplementation(async (...args) => {
    if (args[0] === path.join(root, "listener", "sshd_config")) {
      args[1] = String(args[1]) + "\nPermitUserRC no\nPermitUserEnvironment no\n";
      const port = Number(String(args[1]).match(/^Port (\d+)$/m)?.[1]);
      await originalWrite(observerConfig, JSON.stringify({ captures, port, username: os.userInfo().username,
        canaries: PRIVATE_CANARIES }), { mode: 0o600 });
    }
    return originalWrite(...args);
  });
  const globalFixture = globalThis as typeof globalThis & { __paperclipSshFixture?: {
    daemonEnv: Record<string, string>; readiness(state: SshEnvLabFixtureState): Promise<void>;
  } };
  globalFixture.__paperclipSshFixture = { daemonEnv, readiness: async state => {
    // Loader replaces only the fixture's legacy readiness call, not the target
    // helper or production command path. It requires actual safe SSH success.
    const command = [process.execPath, localIsolation, expectedPath].map(shellQuote).join(" ");
    const result = await exec("/usr/bin/ssh", [...safeSshArgs(state), command], { env: daemonEnv,
      timeout: 2500, maxBuffer: 32768 });
    const report = JSON.parse(result.stdout);
    if (!report.inaccessible || !report.homeUnchanged || !report.codexHomeUnchanged) throw new Error("real SSH startup isolation not qualified");
    await originalWrite(path.join(root, "ssh-startup-isolation.private.json"), JSON.stringify(report), { mode: 0o600 });
  } };
  let state: SshEnvLabFixtureState;
  try { state = await startSshEnvLabFixture({ statePath, readinessTimeoutMs: 5000 }); }
  finally { writeObserver.mockRestore(); delete globalFixture.__paperclipSshFixture; }
  const config = await buildSshEnvLabFixtureConfig(state);
  await fs.writeFile(path.join(root, "retained-state.private.json"), JSON.stringify(state), { mode: 0o600 });
  const lineage = await ownedLineage(state.pid);
  const outerPidNamespace = await fs.readlink("/proc/self/ns/pid");
  if (!lineage.some(item => item.command.includes(state.sshdConfigPath)) ||
      !lineage.some(item => item.namespace !== outerPidNamespace)) throw new Error("fixture bwrap/sshd lineage not qualified; state retained");
  await fs.writeFile(path.join(root, "lineage.private.json"), JSON.stringify(lineage), { mode: 0o600 });
  const target = { kind: "remote", transport: "ssh", environmentId: "fixture-environment", leaseId: "fixture-lease",
    remoteCwd: state.workspaceDir, spec: { ...config, remoteCwd: state.workspaceDir } } as const;
  const ownedProbes: { marker: string; exit: Promise<unknown> }[] = [];
  function startSafeProbe(marker: string, durationMs: number) {
    const command = [process.execPath, localProbe, "remote-bounded", marker, String(durationMs), "0"].map(shellQuote).join(" ");
    const child = spawn("/usr/bin/ssh", [...safeSshArgs(state), command], {
      detached: true, stdio: ["ignore", "pipe", "pipe"], env: daemonEnv });
    let stdout = ""; let stderr = "";
    child.stdout.on("data", chunk => { stdout += chunk; }); child.stderr.on("data", chunk => { stderr += chunk; });
    const exit = new Promise<{ code: number | null; signal: string | null; stdout: string; stderr: string }>((resolve, reject) => {
      child.once("error", reject); child.once("close", (code, signal) => resolve({ code, signal, stdout, stderr }));
    });
    ownedProbes.push({ marker, exit }); return { child, exit };
  }
  async function capturesNow() {
    const names = await fs.readdir(captures);
    return Promise.all(names.sort().map(async name => ({
      ...JSON.parse(await fs.readFile(path.join(captures, name, "original.json"), "utf8")),
      input: await fs.readFile(path.join(captures, name, "input.bin")),
    })));
  }
  async function close() {
    const failures: string[] = [];
    const deadline = Date.now() + 7000;
    const remaining = () => Math.max(1, deadline - Date.now());
    const boundedJoin = async (exit: Promise<unknown>) => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([exit, new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error("owned SSH join still unknown")), remaining());
        })]);
      } finally { clearTimeout(timer); }
    };
    for (const owned of ownedProbes) {
      try { await waitForFile(owned.marker + ".done", remaining()); await boundedJoin(owned.exit); }
      catch { failures.push("owned probe completion unknown"); }
    }
    if (process.env.HOME !== initialHome || process.env.CODEX_HOME !== initialCodexHome) failures.push("parent identity environment changed");
    if (!failures.length) {
      try {
      const beforeStop = await ownedLineage(state.pid);
      await fs.writeFile(path.join(root, "before-stop-lineage.private.json"), JSON.stringify(beforeStop), { mode: 0o600 });
      await stopSshEnvLabFixture(state);
      for (const prior of [...lineage, ...beforeStop]) {
        const current = await processIdentity(prior.pid);
        if (current && current.ticks === prior.ticks) failures.push("tracked fixture process remains");
      }
      if (!await portClosed(state.port)) failures.push("fixture port still open");
      if ((await readSshEnvLabFixtureStatus(statePath)).running) failures.push("fixture listener remains");
      } catch { failures.push("fixture stop or absence evidence unknown"); }
    }
    await fs.writeFile(path.join(root, failures.length ? "cleanup-unknown.json" : "teardown.json"), JSON.stringify({
      listenerStopped: failures.length === 0, probesCompleted: ownedProbes.length, failures,
      homeUnchanged: process.env.HOME === initialHome, codexHomeUnchanged: process.env.CODEX_HOME === initialCodexHome,
      namespaceLineageGone: failures.length === 0 }), { mode: 0o600 });
    if (failures.length) throw new Error("fixture cleanup unknown; original ownership/root retained");
  }
  return { root, bin, captures, state, config, target, startSafeProbe, capturesNow, close };
}
