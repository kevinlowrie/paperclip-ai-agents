import {spawnSync} from "node:child_process";
import {mkdirSync,writeFileSync,readFileSync} from "node:fs";
import path from "node:path";
import {createOwnedRoot,testEnvironment,repoRoot} from "../process-ssh/lane.mjs";
if(process.argv.length!==3||!path.isAbsolute(process.argv[2])||!process.argv[2].endsWith("/prepare_native.py"))throw new Error("Pass the explicit frozen delivery fixture CLI");
const owned=createOwnedRoot("/dev/shm"),env=testEnvironment(process.env,owned,"all");
mkdirSync(env.PAPERCLIP_HOME,{mode:0o700});
env.HOMIE_C2_FIXTURE_CLI=process.argv[2];
env.PAPERCLIP_SECRETS_MASTER_KEY_FILE=path.join(owned.root,"master.key");
env.SANDBOX_ORPHAN_CLEANUP_SPOOL_DIR=path.join(owned.root,"spool");
const report=path.join(owned.root,"assembly-vitest.json");
const args=[path.join(repoRoot,"node_modules/vitest/vitest.mjs"),"run","--config","tests/process-ssh-c2-assembly/vitest.config.mjs",
 "--reporter=default","--reporter=json","--outputFile.json="+report];
const result=spawnSync(process.execPath,args,{cwd:repoRoot,env,stdio:"inherit",timeout:180000});
let counts=null;try{counts=JSON.parse(readFileSync(report,"utf8"))}catch{}
writeFileSync(path.join(owned.root,"assembly-entry.json"),JSON.stringify({exit:result.status,error:result.error?.code??null,
 total:counts?.numTotalTests,passing:counts?.numPassedTests,failures:counts?.numFailedTests,pending:counts?.numPendingTests,
 sourceOnly:true,rootRetained:true,HOME_CODEX_unchanged:env.HOME===process.env.HOME&&env.CODEX_HOME===process.env.CODEX_HOME},null,2),{mode:0o600});
console.log("ASSEMBLY_SOURCE_ROOT="+owned.root);
process.exitCode=result.status??2;
