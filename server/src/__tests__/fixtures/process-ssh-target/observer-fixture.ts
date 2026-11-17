import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { buildKnownHostsEntry, shellQuote } from "@paperclipai/adapter-utils/ssh";
import { PRIVATE_CANARIES } from "./constants.js";

const exec = promisify(execFile);
const observer = fileURLToPath(new URL("./ssh-observer.cjs", import.meta.url));
export async function createPreWireObserver(parent: string) {
  if (!path.isAbsolute(parent)) throw new Error("explicit private fixture root required");
  const root = await fs.mkdtemp(path.join(parent, "prewire-"));
  await fs.chmod(root, 0o700);
  const bin = path.join(root, "bin");
  const captures = path.join(root, "captures");
  await fs.mkdir(bin, { mode: 0o700 }); await fs.mkdir(captures, { mode: 0o700 });
  const key = path.join(root, "synthetic-key");
  await exec("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", key], { timeout: 5000 });
  const configPath = path.join(root, "observer.json");
  await fs.writeFile(configPath, JSON.stringify({ captures, port: 1, username: os.userInfo().username,
    canaries: PRIVATE_CANARIES, permitWire: false }), { mode: 0o600 });
  await fs.writeFile(path.join(bin, "ssh"), `#!/bin/sh\nexec ${shellQuote(process.execPath)} ${shellQuote(observer)} ${shellQuote(configPath)} "$@"\n`, { mode: 0o700 });
  const config = { host: "127.0.0.1", port: 1, username: os.userInfo().username,
    remoteWorkspacePath: root, privateKey: await fs.readFile(key, "utf8"),
    knownHosts: buildKnownHostsEntry({ host: "127.0.0.1", port: 1, publicKey: await fs.readFile(key + ".pub", "utf8") }),
    strictHostKeyChecking: true };
  async function readCalls() {
    const names = await fs.readdir(captures);
    return Promise.all(names.sort().map(async name => ({
      id: name, ...JSON.parse(await fs.readFile(path.join(captures, name, "original.json"), "utf8")),
      input: await fs.readFile(path.join(captures, name, "input.bin")),
    })));
  }
  return { root, bin, config, readCalls };
}
