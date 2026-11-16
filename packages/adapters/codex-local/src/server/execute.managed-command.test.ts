import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
const seam=vi.hoisted(()=>({prepare:vi.fn(),ensure:vi.fn(),resolve:vi.fn(),run:vi.fn(),restore:vi.fn(),events:[] as string[]}));
vi.mock("@paperclipai/adapter-utils/execution-target",async(importOriginal)=>({
 ...(await importOriginal<Record<string,unknown>>()),
 prepareAdapterExecutionTargetRuntime:seam.prepare,
 ensureAdapterExecutionTargetCommandResolvable:seam.ensure,
 resolveAdapterExecutionTargetCommandForLogs:seam.resolve,
 runAdapterExecutionTargetProcess:seam.run,
 runAdapterExecutionTargetShellCommand:vi.fn(async()=>({exitCode:0,stdout:"",stderr:"",timedOut:false})),
 startAdapterExecutionTargetPaperclipBridge:vi.fn(async()=>({env:{},stop:async()=>{}})),
}));
import {execute} from "./execute.js";
const roots:string[]=[];
afterEach(async()=>{vi.restoreAllMocks();vi.clearAllMocks();seam.events.length=0;for(const r of roots.splice(0))await fs.rm(r,{recursive:true,force:true});});
it.each([false,true])("uses staged sandbox wrapper, missing asset fails closed=%s",async(missing)=>{
 const root=await fs.mkdtemp(path.join(os.tmpdir(),"wrapper-sandbox-test-"));roots.push(root);
 const project=path.join(root,"selected-project"),home=path.join(root,"home"),source=path.join(root,"operator");
 for(const p of [project,home,source])await fs.mkdir(p);
 await fs.writeFile(path.join(home,"auth.json"),"{}");
 const code="#!/usr/bin/env node\nconsole.log('wrapper fixture');\n";
 await fs.writeFile(path.join(source,"wrapper.mjs"),code);
 const wrapper="/workspace/.paperclip-runtime/codex/command/wrapper.mjs";
 let snapshot="",stagedHome="";
 seam.prepare.mockImplementation(async(input)=>{
  expect(input.workspaceLocalDir).toBe(project);
  expect(input.detectCommand).toBe("codex"); // baseline CLI detection, NOT proof wrapper exists
  seam.events.push("prepare");
  const command=input.assets.find((a:{key:string})=>a.key==="command");
  snapshot=command.localDir;stagedHome=input.assets.find((a:{key:string})=>a.key==="home").localDir;
  expect(await fs.readFile(path.join(snapshot,"wrapper.mjs"),"utf8")).toBe(code);
  return {workspaceRemoteDir:"/workspace",runtimeRootDir:"/workspace/.paperclip-runtime",assetDirs:{home:"/workspace/.paperclip-runtime/codex/home",...(missing?{}:{command:path.posix.dirname(wrapper)})},restoreWorkspace:seam.restore};
 });
 seam.ensure.mockImplementation(async(command,target,cwd)=>{seam.events.push("ensure");expect(command).toBe(wrapper);expect(target.remoteCwd).toBe("/workspace");expect(cwd).toBe("/workspace");});
 seam.resolve.mockImplementation(async(command,target,cwd)=>{seam.events.push("resolve");expect(command).toBe(wrapper);expect(target.remoteCwd).toBe("/workspace");expect(cwd).toBe("/workspace");return wrapper;});
 seam.run.mockImplementation(async(_run,target,command,_args,options)=>{seam.events.push("run");expect(command).toBe(wrapper);expect(target.remoteCwd).toBe("/workspace");expect(options.env.CODEX_HOME).toBe("/workspace/.paperclip-runtime/codex/home");return {exitCode:1,signal:null,timedOut:false,stdout:"",stderr:"fixture stop",pid:null,startedAt:new Date().toISOString()};});
 const action=execute({runId:"fixture-run",agent:{id:"fixture-agent",companyId:"fixture-company",name:"fixture",adapterType:"codex_local",adapterConfig:{}},runtime:{sessionId:null,sessionParams:null,sessionDisplayId:null,taskKey:null},config:{engine:"cli",command:"/workspace/scripts/missing.mjs",cwd:"/wrong-configured-project",managedCommand:{sourceDir:source,entrypoint:"wrapper.mjs",files:[{path:"wrapper.mjs",sha256:createHash("sha256").update(code).digest("hex")}]},env:{CODEX_HOME:home}},context:{paperclipWorkspace:{cwd:project,source:"project_primary"}},executionTarget:{kind:"remote",transport:"sandbox",remoteCwd:"/workspace",providerKey:"fixture",leaseId:"fixture",runner:{execute:vi.fn()}},onLog:async()=>{}} as Parameters<typeof execute>[0]);
 if(missing){await expect(action).rejects.toThrow("Managed command");expect(seam.run).not.toHaveBeenCalled();expect(seam.events).toEqual(["prepare"]);}else{await action;expect(seam.events).toEqual(["prepare","ensure","resolve","run"]);}
 expect(seam.restore).toHaveBeenCalledTimes(1);
 await expect(fs.access(snapshot)).rejects.toThrow();await expect(fs.access(stagedHome)).rejects.toThrow();
});

