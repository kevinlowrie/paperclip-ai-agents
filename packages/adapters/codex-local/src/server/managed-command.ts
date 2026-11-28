import fs from "node:fs/promises";
import { constants } from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";

export type StagedManagedCommand = { directory: string; entrypoint: string };
const fail = () => new Error("Managed command package is invalid or changed");
function relativeFile(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/.test(value)
    || value.split("/").some((p) => p === "." || p === "..")) throw fail();
  return value;
}
/** Adapter configuration only. Never infer this package from task/workspace content. */
export async function stageManagedCommand(value: unknown): Promise<StagedManagedCommand> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw fail();
  const config = value as Record<string, unknown>;
  if (Object.keys(config).some((k) => !["sourceDir", "entrypoint", "files"].includes(k))) throw fail();
  if (typeof config.sourceDir !== "string" || !path.isAbsolute(config.sourceDir)) throw fail();
  const sourceDir = path.resolve(config.sourceDir);
  // Reject observed symlinks in the source path. Digest pins also bind bytes
  // across later mutations; this is not an atomic directory containment lock.
  if (await fs.realpath(sourceDir) !== sourceDir || !(await fs.lstat(sourceDir)).isDirectory()) throw fail();
  const entrypoint = relativeFile(config.entrypoint);
  if (!Array.isArray(config.files) || config.files.length < 1 || config.files.length > 16) throw fail();
  const seen = new Set<string>();
  const files: { name: string; bytes: Buffer }[] = [];
  let total = 0;
  for (const item of config.files) {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw fail();
    if (Object.keys(item).some((k) => !["path", "sha256"].includes(k))) throw fail();
    const name = relativeFile(item.path);
    if (seen.has(name) || typeof item.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(item.sha256)) throw fail();
    seen.add(name);
    const filename = path.join(sourceDir, name);
    if (await fs.realpath(filename) !== filename) throw fail();
    const handle = await fs.open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const stat = await handle.stat();
      if (!stat.isFile() || stat.size > 1024 * 1024) throw fail();
      // Bound memory even when a mutable source grows after fstat.
      const buffer = Buffer.alloc(1024 * 1024 + 1);
      let length = 0;
      while (length < buffer.length) {
        const read = await handle.read(buffer, length, buffer.length - length, null);
        if (read.bytesRead === 0) break;
        length += read.bytesRead;
      }
      const bytes = buffer.subarray(0, length);
      total += bytes.length;
      if (bytes.length > 1024 * 1024 || total > 2 * 1024 * 1024
        || createHash("sha256").update(bytes).digest("hex") !== item.sha256) throw fail();
      files.push({name, bytes});
    } finally { await handle.close(); }
  }
  if (!seen.has(entrypoint)) throw fail();
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-managed-command-"));
  try {
    await fs.chmod(directory, 0o700);
    for (const file of files) {
      const destination = path.join(directory, file.name);
      await fs.mkdir(path.dirname(destination), {recursive:true, mode:0o700});
      // Write the exact bytes hashed above, never reopen the mutable source.
      await fs.writeFile(destination, file.bytes, {flag:"wx", mode:file.name === entrypoint ? 0o700 : 0o600});
    }
    return {directory, entrypoint};
  } catch (error) {
    await fs.rm(directory, {recursive:true, force:true});
    throw error;
  }
}
export function managedCommandPath(staged: StagedManagedCommand, remoteDirectory: string | undefined): string {
  if (!remoteDirectory || !path.posix.isAbsolute(remoteDirectory)) throw fail();
  return path.posix.join(remoteDirectory, staged.entrypoint);
}
