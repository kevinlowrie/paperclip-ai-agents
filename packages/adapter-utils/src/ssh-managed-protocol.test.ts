import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { expect, it, vi } from "vitest";
import { runSshCommand } from "./ssh.js";

vi.mock("./server-utils.js", () => ({}));

it("preserves trusted protocol stdout exactly while keeping ordinary output and errors redacted", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "ssh-protocol-"));
  const oldPath = process.env.PATH;
  const canary = "fixture-private-secret";
  try {
    const ssh = path.join(root, "ssh");
    await writeFile(ssh, `#!/bin/sh\ncat >/dev/null\nprintf '%s' '{"path":"/artifacts/C-output.json"}'\nprintf '%s' '${canary}' >&2\n`);
    await chmod(ssh, 0o700);
    process.env.PATH = `${root}:/usr/bin:/bin`;
    const config = {host:"fixture.invalid",port:22,username:"fixture",remoteWorkspacePath:"/fixture",
      privateKey:"fixture-key",knownHosts:"fixture-host-key",strictHostKeyChecking:true};
    const options = {inputMode:"private_v1" as const,deadlineEpochMs:Date.now()+5000,
      env:{LANG:"C",FIXTURE_SECRET:canary},stdin:"fixture-input",timeoutMs:3000};
    const ordinary = await runSshCommand(config, "fixture-command", options);
    expect(ordinary.stdout).toContain("[redacted]");
    expect(ordinary.stderr).not.toContain(canary);
    const trusted = await runSshCommand(config, "fixture-command", {...options, privateStdout:"trusted_protocol_v1"});
    expect(JSON.parse(trusted.stdout)).toEqual({path:"/artifacts/C-output.json"});
    expect(trusted.stderr).not.toContain(canary);
    await writeFile(ssh, `#!/bin/sh\ncat >/dev/null\nprintf '%s' '${canary}' >&2\nexit 1\n`);
    const error = await runSshCommand(config, "fixture-command", {...options, privateStdout:"trusted_protocol_v1"}).catch(e => e);
    expect(String(error) + JSON.stringify(error)).not.toContain(canary);
    await expect(runSshCommand(config, "fixture-command", {...options, inputMode:"legacy", privateStdout:"trusted_protocol_v1"}))
      .rejects.toThrow("requires private transport");
    await writeFile(ssh, `#!/bin/sh\ncat >/dev/null\nprintf '%s' '12345678901234567890'\n`);
    await expect(runSshCommand(config, "fixture-command", {...options, maxBuffer:8, privateStdout:"trusted_protocol_v1"}))
      .rejects.toThrow("Private SSH command failed");
    await writeFile(ssh, `#!/bin/sh\ncat >/dev/null\nprintf '\\342'\nsleep 0.05\nprintf '\\230\\203'\n`);
    expect((await runSshCommand(config,"fixture-command",{...options,privateStdout:"trusted_protocol_v1"})).stdout).toBe("☃");
    await writeFile(ssh, `#!/bin/sh\ncat >/dev/null\nprintf '\\377'\n`);
    await expect(runSshCommand(config,"fixture-command",{...options,privateStdout:"trusted_protocol_v1"}))
      .rejects.toThrow("Private SSH command failed");
  } finally {
    process.env.PATH = oldPath;
    await rm(root, {recursive:true,force:true});
  }
});
