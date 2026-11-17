import { randomUUID } from "node:crypto";
import { chmodSync, lstatSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
export const serverDedicatedTests = Object.freeze([
  "server/src/__tests__/process-adapter-ssh-target.test.ts",
  "server/src/__tests__/process-adapter-ssh-lifecycle.test.ts",
]);
const unit = Object.freeze([serverDedicatedTests[0], "packages/adapter-utils/src/ssh-private-input.test.ts"]);
const ssh = Object.freeze([serverDedicatedTests[1], "tests/process-ssh/supplemental.test.ts"]);
export const lanes = Object.freeze({ unit: { files: unit, count: 41 }, ssh: { files: ssh, count: 8 },
  all: { files: Object.freeze([...unit, ...ssh]), count: 49 } });
export function isDedicatedProcessSshServerTest(candidate) {
  return serverDedicatedTests.includes(candidate.replaceAll("\\", "/").replace(/^\.\//, ""));
}
export function parseOptions(args) {
  const options = { lane: "unit", parent: os.tmpdir(), list: false, help: false };
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--") continue;
    if (arg === "--list") { options.list = true; continue; }
    if (arg === "--help") { options.help = true; continue; }
    if (arg === "--lane" || arg === "--root-parent") {
      const value = args[++i]; if (!value || value.startsWith("--")) throw new Error("Missing test-lane option value");
      options[arg === "--lane" ? "lane" : "parent"] = value; continue;
    }
    if (arg.startsWith("--lane=")) { options.lane = arg.slice(7); continue; }
    if (arg.startsWith("--root-parent=")) { options.parent = arg.slice(14); continue; }
    throw new Error("Unknown process SSH test-lane option");
  }
  if (!Object.hasOwn(lanes, options.lane)) throw new Error("Use --lane unit, ssh or all");
  return options;
}
const markerName = ".process-ssh-test-owner.json";
export function createOwnedRoot(parent) {
  const canonicalParent = realpathSync(path.resolve(parent));
  if (!/^[A-Za-z0-9_./-]+$/.test(canonicalParent) || canonicalParent.length > 64) {
    throw new Error("Use a short POSIX temporary parent, for example /tmp or /dev/shm");
  }
  const relative = path.relative(repoRoot, canonicalParent);
  if (!relative || (!relative.startsWith("..") && !path.isAbsolute(relative))) {
    throw new Error("Test credentials/artifacts require a root outside the checkout");
  }
  const root = realpathSync(mkdtempSync(path.join(canonicalParent, "pssh-")));
  chmodSync(root, 0o700);
  const stat = lstatSync(root); const id = randomUUID();
  writeFileSync(path.join(root, markerName), JSON.stringify({ schema: "process-ssh-test-root/v1", root, id,
    inode: stat.ino, device: stat.dev, uid: stat.uid }) + "\n", { mode: 0o600, flag: "wx" });
  return { root, id };
}
export function validateOwnedRoot(root, id) {
  if (!root || !id || !path.isAbsolute(root)) throw new Error("Use node tests/process-ssh/run.mjs to bind an owned test root");
  const stat = lstatSync(root); const marker = path.join(root, markerName); const markerStat = lstatSync(marker);
  if (stat.isSymbolicLink() || !stat.isDirectory() || realpathSync(root) !== root || (stat.mode & 0o777) !== 0o700 ||
      markerStat.isSymbolicLink() || !markerStat.isFile() || (markerStat.mode & 0o777) !== 0o600 ||
      (typeof process.getuid === "function" && stat.uid !== process.getuid())) throw new Error("Unsafe process SSH test root");
  const owner = JSON.parse(readFileSync(marker, "utf8"));
  if (owner.schema !== "process-ssh-test-root/v1" || owner.root !== root || owner.id !== id ||
      owner.inode !== stat.ino || owner.device !== stat.dev || owner.uid !== stat.uid) throw new Error("Process SSH test-root ownership changed");
  return root;
}
export function testEnvironment(inherited, owned, lane) {
  const names = new Set(["PATH", "HOME", "CODEX_HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TZ", "SystemRoot", "PATHEXT", "CI"]);
  const env = Object.fromEntries(Object.entries(inherited).filter(([name, value]) => names.has(name) && typeof value === "string"));
  return { ...env, NODE_ENV: "production", PAPERCLIP_PROCESS_SSH_TEST_ROOT: owned.root,
    PAPERCLIP_PROCESS_SSH_ROOT_ID: owned.id, PAPERCLIP_PROCESS_SSH_LANE: lane,
    PAPERCLIP_HOME: path.join(owned.root, "app"), PAPERCLIP_CONFIG: path.join(owned.root, "app", "config.json"),
    PAPERCLIP_MANAGED_RUNTIME_HTTPS: "off", TMPDIR: owned.root };
}
