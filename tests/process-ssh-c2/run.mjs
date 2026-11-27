import { spawnSync } from "node:child_process";
import { mkdirSync,writeFileSync,readFileSync } from "node:fs";
import path from "node:path";
import { createOwnedRoot,testEnvironment,repoRoot } from "../process-ssh/lane.mjs";
if(process.argv.length!==3)throw new Error("Pass one explicit pinned delivery prepare_native.py fixture CLI");
const cli=process.argv[2];if(!path.isAbsolute(cli)||!cli.endsWith("/prepare_native.py"))throw new Error("Invalid fixture CLI");
const owned=createOwnedRoot("/dev/shm"),env=testEnvironment(process.env,owned,"all");
mkdirSync(env.PAPERCLIP_HOME,{mode:0o700});
env.HOMIE_C2_FIXTURE_CLI=cli;
env.PAPERCLIP_SECRETS_MASTER_KEY_FILE=path.join(owned.root,"fixture-master.key");
env.SANDBOX_ORPHAN_CLEANUP_SPOOL_DIR=path.join(owned.root,"fixture-spool");
const report=path.join(owned.root,"native-vitest.json");
const args=[path.join(repoRoot,"node_modules/vitest/vitest.mjs"),"run","--config",
 "tests/process-ssh-c2/vitest.config.mjs","--reporter=default","--reporter=json","--outputFile.json="+report];
const p=spawnSync(process.execPath,args,{cwd:repoRoot,env,stdio:"inherit",timeout:180000});
let result;try{result=JSON.parse(readFileSync(report,"utf8"))}catch{result=null}
writeFileSync(path.join(owned.root,"native-entry.json"),JSON.stringify({exit:p.status,error:p.error?.code??null,
 total:result?.numTotalTests,passing:result?.numPassedTests,failures:result?.numFailedTests,pending:result?.numPendingTests,
 sourceOnly:true,rootRetained:true,HOME_CODEX_unchanged:env.HOME===process.env.HOME&&env.CODEX_HOME===process.env.CODEX_HOME},null,2),{mode:0o600});
console.log("C2 native source evidence retained at "+owned.root);
process.exitCode=p.status??2;
