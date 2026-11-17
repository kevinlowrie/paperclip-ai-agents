import { defineConfig } from "vitest/config";
import path from "node:path";
import { repoRoot, validateOwnedRoot } from "../process-ssh/lane.mjs";
import { sshFixtureIsolationPlugin } from "../process-ssh/fixture-loader.mjs";
const root=validateOwnedRoot(process.env.PAPERCLIP_PROCESS_SSH_TEST_ROOT,process.env.PAPERCLIP_PROCESS_SSH_ROOT_ID);
if(!process.env.HOMIE_C2_FIXTURE_CLI)throw new Error("Explicit pinned delivery fixture CLI required");
export default defineConfig({
 resolve:{alias:{"drizzle-orm":path.join(repoRoot,"server/node_modules/drizzle-orm"),"@paperclipai/plugin-sdk":path.join(repoRoot,"packages/plugins/sdk/src/index.ts")}},
 root:repoRoot,cacheDir:path.join(root,"c2-vite"),
 plugins:[sshFixtureIsolationPlugin(path.join(repoRoot,"packages/adapter-utils/src/ssh.ts"))],
 server:{fs:{allow:[repoRoot,root]}},
 test:{name:"c2-native-lease-controls",include:["tests/process-ssh-c2/lease-safety.test.ts"],
 setupFiles:[],environment:"node",pool:"forks",maxWorkers:1,fileParallelism:false,isolate:true,
 testTimeout:30000,hookTimeout:90000,teardownTimeout:30000,
 env:{NODE_ENV:"production",PAPERCLIP_PROCESS_SSH_TEST_ROOT:root}}
});
