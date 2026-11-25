import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const expectedSha = "42c8fb2905b8583d14609aa472c59917c98c9fadf5b87fb5c57d133b52a60ea9";
const replacements = [
  [
    "      const config = await buildSshEnvLabFixtureConfig(state);\n      await ensureSshWorkspaceReady(config);",
    "      const config = await buildSshEnvLabFixtureConfig(state);\n      await (globalThis as any).__paperclipSshFixture.readiness(state, config);"
  ],
  [
    "  const child = spawn(sshdPath, [\"-D\", \"-f\", sshdConfigPath, \"-E\", sshdLogPath], {\n    detached: true,\n    stdio: \"ignore\",\n  });",
    "  const child = spawn(sshdPath, [\"-D\", \"-f\", sshdConfigPath, \"-E\", sshdLogPath], {\n    detached: true,\n    stdio: \"ignore\",\n    env: (globalThis as any).__paperclipSshFixture.daemonEnv,\n  });"
  ]
];

export function sshFixtureIsolationPlugin(sourcePath) {
  return {
    name: "process-ssh-fixture-isolation-only", enforce: "pre",
    transform(code, id) {
      if (id.split("?")[0] !== sourcePath) return;
      if (createHash("sha256").update(readFileSync(sourcePath)).digest("hex") !== expectedSha) {
        throw new Error("fixture source pin changed; independent review required");
      }
      let transformed = code;
      for (const [before, after] of replacements) {
        if (transformed.split(before).length !== 2) throw new Error("fixture-only transform is no longer unique");
        transformed = transformed.replace(before, after);
      }
      return { code: transformed, map: null };
    },
  };
}
