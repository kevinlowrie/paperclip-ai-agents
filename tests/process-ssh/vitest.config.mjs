import { defineConfig } from "vitest/config";
import path from "node:path";
import { lanes, repoRoot, validateOwnedRoot } from "./lane.mjs";
import { sshFixtureIsolationPlugin } from "./fixture-loader.mjs";

const lane = process.env.PAPERCLIP_PROCESS_SSH_LANE;
if (!Object.hasOwn(lanes, lane ?? "")) throw new Error("Use the public process SSH test-lane entry");
const root = validateOwnedRoot(process.env.PAPERCLIP_PROCESS_SSH_TEST_ROOT, process.env.PAPERCLIP_PROCESS_SSH_ROOT_ID);
export default defineConfig({
  root: repoRoot,
  cacheDir: path.join(root, "vite-cache"),
  plugins: [sshFixtureIsolationPlugin(path.join(repoRoot, "packages/adapter-utils/src/ssh.ts"))],
  server: { fs: { allow: [repoRoot, root] } },
  test: {
    name: `process-ssh-${lane}`, environment: "node", include: [...lanes[lane].files],
    setupFiles: [], pool: "forks", maxWorkers: 1, fileParallelism: false,
    isolate: true, testTimeout: 10000, hookTimeout: 15000, teardownTimeout: 15000,
    env: { PAPERCLIP_PROCESS_SSH_TEST_ROOT: root, NODE_ENV: "production" },
  },
});
