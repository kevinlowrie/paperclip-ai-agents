import { randomUUID } from "node:crypto";
import { spawn,execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile,writeFile,cp,access,rename } from "node:fs/promises";
import path from "node:path";
import { beforeAll,afterAll,beforeEach,afterEach,it,expect } from "vitest";
import { eq,sql } from "drizzle-orm";
import { createDb,companies,agents,issues,projects,executionWorkspaces,heartbeatRuns,environments,environmentLeases,
 getEmbeddedPostgresTestSupport,startEmbeddedPostgresTestDatabase } from "@paperclipai/db";
import { secretService } from "../../server/src/services/secrets.js";
import { environmentService } from "../../server/src/services/environments.js";
import { environmentRuntimeService } from "../../server/src/services/environment-runtime.js";
import { resolveEnvironmentExecutionTarget } from "../../server/src/services/environment-execution-target.js";
import { remoteExecutionHasStopped } from "../../server/src/services/remote-execution-termination.js";
import { execute } from "../../server/src/adapters/process/execute.js";
import { runSshCommand,shellQuote } from "@paperclipai/adapter-utils/ssh";
import { createLoopbackFixture,waitForFile } from "../../server/src/__tests__/fixtures/process-ssh-target/loopback.js";
const run=promisify(execFile);
const parent=process.env.PAPERCLIP_PROCESS_SSH_TEST_ROOT!;
const helper=process.env.HOMIE_C2_FIXTURE_CLI!;
const baseline={HOME:process.env.HOME,CODEX_HOME:process.env.CODEX_HOME};
let database:any,db:any,runtime:any,ssh:Awaited<ReturnType<typeof createLoopbackFixture>>;
let native:any,fixture:any,root:string,owner:any,ownerClosed:Promise<number|null>|undefined;
const childEnv=()=>Object.fromEntries(Object.entries(process.env).filter(([k])=>["PATH","HOME","CODEX_HOME","USER","LANG"].includes(k))) as Record<string,string>;
async function exists(p:string){return access(p).then(()=>true,()=>false)}
async function saved(){return environmentService(db).getLeaseById(native.lease.id)}
beforeAll(async()=>{
 const support=await getEmbeddedPostgresTestSupport();
 if(!support.supported)throw new Error("INFRASTRUCTURE: installed embedded Postgres fixture unavailable; no fallback or skip");
 database=await startEmbeddedPostgresTestDatabase("c2-native");
 db=createDb(database.connectionString);runtime=environmentRuntimeService(db);
 ssh=await createLoopbackFixture(parent);
},90000);
afterAll(async()=>{
 if(ssh)await ssh.close();
 if(database)await database.cleanup();
 expect({HOME:process.env.HOME,CODEX_HOME:process.env.CODEX_HOME}).toEqual(baseline);
},30000);
beforeEach(async()=>{
 const companyId=randomUUID(),agentId=randomUUID(),taskId=randomUUID(),runId=randomUUID(),environmentId=randomUUID(),projectId=randomUUID(),workspaceId=randomUUID();
 await db.insert(companies).values({id:companyId,name:"Synthetic research company",issuePrefix:"FX"+companyId.replaceAll("-","").slice(0,8).toUpperCase(),status:"active"});
 await db.insert(agents).values({id:agentId,companyId,name:"Research fixture",role:"researcher",status:"active",
   adapterType:"process",adapterConfig:{},runtimeConfig:{},permissions:{}});
 await db.insert(projects).values({id:projectId,companyId,name:"Synthetic business project"});
 await db.insert(issues).values({id:taskId,companyId,projectId,title:"Research brief and video script",
   description:"Noncoding business fixture; no repository or patch",status:"in_progress",assigneeAgentId:agentId});
 await db.insert(executionWorkspaces).values({id:workspaceId,companyId,projectId,sourceIssueId:taskId,mode:"persistent",strategyType:"project_primary",name:"Synthetic business workspace",cwd:ssh.state.workspaceDir,providerType:"ssh"});
 await db.insert(heartbeatRuns).values({id:runId,companyId,agentId,invocationSource:"manual",status:"running"});
 const secrets=secretService(db),secret=await secrets.create(companyId,{name:"fixture-ssh-"+runId,
   provider:"local_encrypted",value:ssh.config.privateKey!});
 await secrets.createBinding({companyId,secretId:secret.id,targetType:"environment",targetId:environmentId,configPath:"privateKeySecretRef"});
 const config={...ssh.config,privateKey:null,privateKeySecretRef:{type:"secret_ref",secretId:secret.id,version:"latest"}};
 await db.insert(environments).values({id:environmentId,name:"fixture-"+environmentId,driver:"ssh",status:"active",config});
 const environment=(await db.select().from(environments).where(eq(environments.id,environmentId)))[0];
 const lease=await environmentService(db).acquireLease({companyId,environmentId,executionWorkspaceId:workspaceId,issueId:taskId,heartbeatRunId:runId,
   provider:"ssh",providerLeaseId:"ssh://fixture-owned/"+environmentId,leasePolicy:"ephemeral",expiresAt:new Date(Date.now()+300000),
   metadata:{driver:"ssh",agentId}});
 root=path.join(ssh.root,"hgl-"+runId.slice(0,8));const bindingFile=path.join(ssh.root,"binding-"+runId+".json");
 const binding={company_id:companyId,project_id:projectId,workspace_id:workspaceId,agent_id:agentId,task_id:taskId,run_id:runId,
   environment_id:environmentId,lease_id:lease.id,provider_lease_id:lease.providerLeaseId};
 await writeFile(bindingFile,JSON.stringify(binding),{mode:0o600});
 const prepareArgs=["-I","-B",helper,"--fixture-contract","c2-native-v1","prepare","--root",root,"--binding",bindingFile];
 if(/C2-01|C2-06/.test(expect.getState().currentTestName??""))prepareArgs.push("--business");
 const p=await run("/usr/bin/python3",prepareArgs,{env:childEnv(),timeout:5000});
 fixture=JSON.parse(p.stdout);
 const bound=JSON.parse(await readFile(fixture.binding_ref,"utf8"));
 await db.update(environmentLeases).set({metadata:{driver:"ssh",agentId,managedProcessHandoff:{
   schema:"homie.managed-control.v1",binding:bound,owner:null,cleanup_complete:false,
   config_ref:fixture.config_ref,binding_ref:fixture.binding_ref}}}).where(eq(environmentLeases.id,lease.id));
 native={companyId,agentId,taskId,runId,environment,lease:await environmentService(db).getLeaseById(lease.id),binding:bound};
 owner=null;ownerClosed=undefined;
});
afterEach(async()=>{
 if(owner){
  await writeFile(path.join(root,"test-stop"),"stop",{mode:0o600});
  expect(await ownerClosed,"fixture owner wrapper must join its own daemon").toBe(0);
  const teardown=JSON.parse(await readFile(path.join(root,"owner-teardown.json"),"utf8"));
  expect(teardown).toEqual({daemon_absent:true,children_absent:true,HOME_CODEX_unchanged:true,child_reserved_env_unchanged:true,grandchild_reserved_env_unchanged:true,owner_unknown:false});
 }
 expect({HOME:process.env.HOME,CODEX_HOME:process.env.CODEX_HOME}).toEqual(baseline);
});
async function startRealExistingOwner(enqueue=true){
 owner=spawn("/usr/bin/python3",["-I","-B",helper,"--fixture-contract","c2-native-v1","owner","--root",root],
   {env:childEnv(),stdio:["ignore","ignore","ignore"]});
 ownerClosed=new Promise((resolve,reject)=>{owner.once("error",reject);owner.once("close",resolve)});
 await waitForFile(path.join(root,"daemon.json"));
 if(!enqueue)return null;
 await cp(fixture.frame_ref,path.join(root,"inbox/invocation.json"));
 await waitForFile(path.join(root,"bundle/child.json"));
 const data=JSON.parse(await readFile(path.join(root,"bundle/child.json"),"utf8"));
 expect(await exists("/proc/"+data.pid+"/stat")).toBe(true);
 return data;
}
async function target(adapterType="process"){
 return resolveEnvironmentExecutionTarget({db,companyId:native.companyId,adapterType,
  environment:native.environment,leaseId:native.lease.id,leaseMetadata:native.lease.metadata,
  lease:native.lease,environmentRuntime:runtime});
}
it("C2-12/16 actual SSH release cannot release native lease while real HGL child is alive",async()=>{
 const child=await startRealExistingOwner();
 await runtime.releaseRunLeases(native.runId,"released");
 expect(await exists("/proc/"+child.pid+"/stat"),"bounded HGL child must still be alive during release probe").toBe(true);
 expect((await saved()).status,"current SSH driver prematurely marks unresolved work released").toBe("pending_cleanup");
 expect((await saved()).cleanupStatus).not.toBe("success");
 expect(await remoteExecutionHasStopped(db,native.companyId,native.runId)).toBe(false);
});
it("C2-13/16 cancellation with unknown owner cannot clear same selected lease",async()=>{
 await startRealExistingOwner();
 await runtime.releaseRunLeases(native.runId,"failed",undefined,undefined,true);
 expect((await saved()).status,"cancelActiveWork must not turn row release into remote stop").toBe("pending_cleanup");
 expect((await saved()).metadata.managedProcessHandoff.binding).toEqual(native.binding);
});
it("C2-14 foreign stopped receipt cannot authorize this active HGL lease",async()=>{
 await startRealExistingOwner();
 await db.update(environmentLeases).set({metadata:{...native.lease.metadata,remoteExecutionTermination:{
  schema:"paperclip.remote-termination.v1",companyId:native.companyId,runId:randomUUID(),leaseId:native.lease.id,
  provider:"ssh",providerLeaseId:native.lease.providerLeaseId,state:"stopped",confirmedAt:new Date().toISOString()}}}).where(eq(environmentLeases.id,native.lease.id));
 await runtime.releaseRunLeases(native.runId,"released");
 expect((await saved()).status).toBe("pending_cleanup");
 expect(await remoteExecutionHasStopped(db,native.companyId,native.runId)).toBe(false);
});
it("control: real existing known runner resolver preserves selected company and lease",async()=>{
 expect(await target("paperclip_runner")).toMatchObject({kind:"remote",transport:"ssh",
 environmentId:native.environment.id,leaseId:native.lease.id});
});
it("control: ordinary SSH lease without managed owner marker keeps existing release",async()=>{
 await db.update(environmentLeases).set({metadata:{driver:"ssh"}}).where(eq(environmentLeases.id,native.lease.id));
 await runtime.releaseRunLeases(native.runId,"released");
 expect((await saved()).status).toBe("released");
 expect(await remoteExecutionHasStopped(db,native.companyId,native.runId)).toBe(false);
});

it.each([
 ["missing tuple fields",{}],
 ["foreign operation with equal persisted owners",{instance_id:"1:0",operation_id:"foreign",generation:1,context_digest:"c".repeat(64),payload_digest:"d".repeat(64)}],
 ["malformed instance identity",{instance_id:"not-a-process",operation_id:null,generation:null,context_digest:null,payload_digest:null}],
])("lease receipt refuses %s even if owner and outcome owner are equal",async(_name,ownerValue)=>{
 const child=await startRealExistingOwner();
 const b=native.binding;
 const malformed={...ownerValue};
 const marker={schema:"homie.managed-control.v1",binding:b,owner:malformed,cleanup_complete:true,
  outcome:{schema:"homie.managed-control-result.v1",binding:b,owner:malformed,status:"succeeded",cleanup_complete:true}};
 await db.update(environmentLeases).set({metadata:{driver:"ssh",managedProcessHandoff:marker}}).where(eq(environmentLeases.id,native.lease.id));
 await runtime.releaseRunLeases(native.runId,"released");
 expect(await exists("/proc/"+child.pid+"/stat")).toBe(true);
 expect((await saved()).status).toBe("pending_cleanup");
 expect((await saved()).cleanupStatus).not.toBe("success");
 expect(await remoteExecutionHasStopped(db,native.companyId,native.runId)).toBe(false);
});
function deferred(){let resolve!:()=>void;const promise=new Promise<void>(done=>{resolve=done});return {resolve,promise}}
async function waitForLock(relation:string){
 const end=Date.now()+2000;
 while(Date.now()<end){
  const query=relation==="environment_leases"?"select count(*)::int as n from pg_locks where locktype='transactionid' and not granted":
   "select count(*)::int as n from pg_locks where relation='"+relation+"'::regclass and not granted";
  const rows=await db.execute(sql.raw(query));
  if(Number(rows[0]?.n)>0)return;
  await new Promise(resolve=>setTimeout(resolve,10));
 }
 throw new Error("INFRASTRUCTURE: real owned database release waiter did not reach lock");
}
it("stale ordinary input cannot release fresh selected unknown managed owner",async()=>{
 const child=await startRealExistingOwner();
 await db.update(environmentLeases).set({metadata:{driver:"ssh"}}).where(eq(environmentLeases.id,native.lease.id));
 const locked=deferred(),unblock=deferred();
 const transaction=db.transaction(async(tx:any)=>{
  await tx.execute(sql.raw("LOCK TABLE environments IN ACCESS EXCLUSIVE MODE"));
  locked.resolve();await unblock.promise;
 });
 let releasing:Promise<unknown>|undefined;
 try{
  await locked.promise;releasing=runtime.releaseRunLeases(native.runId,"released");
  await waitForLock("environments");
  await db.update(environmentLeases).set({metadata:native.lease.metadata}).where(eq(environmentLeases.id,native.lease.id));
 }finally{unblock.resolve();await transaction;if(releasing)await releasing}
 expect(await exists("/proc/"+child.pid+"/stat")).toBe(true);
 expect((await saved()).status).toBe("pending_cleanup");
 expect((await saved()).metadata.managedProcessHandoff.binding).toEqual(native.binding);
 expect(await remoteExecutionHasStopped(db,native.companyId,native.runId)).toBe(false);
});
it("ordinary release expected-absence CAS preserves a marker installed after fresh read",async()=>{
 const child=await startRealExistingOwner();
 await db.update(environmentLeases).set({metadata:{driver:"ssh"}}).where(eq(environmentLeases.id,native.lease.id));
 const locked=deferred(),unblock=deferred();
 const transaction=db.transaction(async(tx:any)=>{
  await tx.execute(sql.raw("SELECT id FROM environment_leases WHERE id='"+native.lease.id+"'::uuid FOR UPDATE"));
  locked.resolve();await unblock.promise;
  await tx.update(environmentLeases).set({metadata:native.lease.metadata}).where(eq(environmentLeases.id,native.lease.id));
 });
 let releasing:Promise<unknown>|undefined;
 try{
  await locked.promise;releasing=runtime.releaseRunLeases(native.runId,"released");
  await waitForLock("environment_leases");
 }finally{unblock.resolve();await transaction;if(releasing)await releasing}
 expect(await exists("/proc/"+child.pid+"/stat")).toBe(true);
 expect((await saved()).status).not.toBe("released");
 expect((await saved()).metadata.managedProcessHandoff.binding).toEqual(native.binding);
 expect((await saved()).metadata.managedProcessHandoff.cleanup_complete).toBe(false);
 expect(await remoteExecutionHasStopped(db,native.companyId,native.runId)).toBe(false);
});
