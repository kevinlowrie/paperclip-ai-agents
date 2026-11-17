import {createHash,randomUUID} from "node:crypto";
import {spawn,execFile} from "node:child_process";
import {promisify,isDeepStrictEqual} from "node:util";
import {readFile,writeFile,mkdir,chmod,access,unlink,symlink,link,rename} from "node:fs/promises";
import path from "node:path";
import {beforeAll,afterAll,beforeEach,afterEach,it,expect} from "vitest";
import {eq,sql} from "drizzle-orm";
import {createDb,companies,agents,issues,projects,executionWorkspaces,heartbeatRuns,environments,environmentLeases,
 authUsers,companyMemberships,getEmbeddedPostgresTestSupport,startEmbeddedPostgresTestDatabase} from "@paperclipai/db";
import {secretService} from "../../server/src/services/secrets.js";
import {environmentService} from "../../server/src/services/environments.js";
import {environmentRuntimeService} from "../../server/src/services/environment-runtime.js";
import {remoteExecutionHasStopped} from "../../server/src/services/remote-execution-termination.js";
import {environmentRunOrchestrator} from "../../server/src/services/environment-run-orchestrator.js";
import {authorizationService} from "../../server/src/services/authorization.js";
import {execute} from "../../server/src/adapters/process/execute.js";
import {parseAdapterExecutionTarget} from "@paperclipai/adapter-utils/execution-target";
import {resolvePaperclipInstanceRootForAdapter} from "@paperclipai/adapter-utils/server-utils";
import {createLoopbackFixture,waitForFile} from "../../server/src/__tests__/fixtures/process-ssh-target/loopback.js";
const exec=promisify(execFile);
const parent=process.env.PAPERCLIP_PROCESS_SSH_TEST_ROOT!;
const helper=process.env.HOMIE_C2_FIXTURE_CLI!;
const baseline={HOME:process.env.HOME,CODEX_HOME:process.env.CODEX_HOME};
const sha=(b:Buffer|string)=>createHash("sha256").update(b).digest("hex");
const exists=(p:string)=>access(p).then(()=>true,()=>false);
const sleep=(n:number)=>new Promise(resolve=>setTimeout(resolve,n));
const childEnv=()=>Object.fromEntries(Object.entries(process.env).filter(([k])=>["PATH","HOME","CODEX_HOME","USER","LANG"].includes(k))) as Record<string,string>;
let database:any,db:any,ssh:Awaited<ReturnType<typeof createLoopbackFixture>>;
let n:any,f:any,profile:any,profilePath:string,requestPath:string,hostRoot:string,remoteRoot:string;
let owner:any,ownerClosed:Promise<number|null>|undefined,ownerExit:number|null|undefined;
async function writePrivate(p:string,value:unknown){await writeFile(p,JSON.stringify(value),{mode:0o600});await chmod(p,0o600)}
async function saveProfile(){await writePrivate(profilePath,profile)}
async function update(table:any,values:Record<string,unknown>,id:string){await db.update(table).set(values).where(eq(table.id,id))}
async function assemble(adapterType="process"){
 // Existing production dispatcher input. No carrier or authority object is
 // supplied to the function under test; it must derive one from native state.
 return environmentRunOrchestrator(db).realizeForRun({
  environment:n.environment,lease:n.lease,adapterType,companyId:n.companyId,issueId:n.taskId,heartbeatRunId:n.runId,
  executionWorkspace:{baseCwd:ssh.state.workspaceDir,cwd:ssh.state.workspaceDir,source:"project_primary",
   projectId:n.projectId,workspaceId:n.workspaceId,repoUrl:null,repoRef:null,strategy:"project_primary",
   branchName:null,worktreePath:null,warnings:[],created:false,branchCreatedByRuntime:false},
  effectiveExecutionWorkspaceMode:"persistent",persistedExecutionWorkspace:n.workspace});
}
async function nativeDecision(){
 const current=(await db.select().from(heartbeatRuns).where(eq(heartbeatRuns.id,n.runId)))[0];
 return authorizationService(db).decide({
  actor:{type:"agent",agentId:n.agentId,companyId:n.companyId,runId:n.runId,
   onBehalfOfUserId:current.responsibleUserId,source:"agent_jwt"},
  action:"issue:mutate",resource:{type:"issue",companyId:n.companyId,issueId:n.taskId,
   projectId:n.projectId,assigneeAgentId:n.agentId,status:"in_progress"}});
}
beforeAll(async()=>{
 const support=await getEmbeddedPostgresTestSupport();
 if(!support.supported)throw new Error("INFRASTRUCTURE: owned embedded Postgres unavailable; no fallback/skip");
 database=await startEmbeddedPostgresTestDatabase("c2-assembly");db=createDb(database.connectionString);
 ssh=await createLoopbackFixture(parent);
},90000);
afterAll(async()=>{
 if(ssh)await ssh.close();
 if(database)await database.cleanup();
 expect({HOME:process.env.HOME,CODEX_HOME:process.env.CODEX_HOME}).toEqual(baseline);
},30000);
beforeEach(async()=>{
 const [companyId,agentId,taskId,runId,environmentId,projectId,workspaceId]=Array.from({length:7},()=>randomUUID());
 const userId="synthetic-native-"+randomUUID(),now=new Date();
 await db.insert(companies).values({id:companyId,name:"Synthetic business assembly",issuePrefix:"AS"+companyId.replaceAll("-","").slice(0,8).toUpperCase(),status:"active"});
 await db.insert(authUsers).values({id:userId,name:"Synthetic approved user",email:randomUUID()+"@example.invalid",emailVerified:true,createdAt:now,updatedAt:now});
 await db.insert(companyMemberships).values({companyId,principalType:"user",principalId:userId,status:"active",membershipRole:"owner"});
 await db.insert(agents).values({id:agentId,companyId,name:"Synthetic research actor",role:"researcher",status:"active",adapterType:"process",adapterConfig:{},runtimeConfig:{},permissions:{}});
 await db.insert(projects).values({id:projectId,companyId,name:"Research and video"});
 await db.insert(issues).values({id:taskId,companyId,projectId,title:"Prepare research evidence and video script",
  description:"Synthetic noncoding native business task; no GitHub repo or patch",status:"in_progress",assigneeAgentId:agentId});
 await db.insert(executionWorkspaces).values({id:workspaceId,companyId,projectId,sourceIssueId:taskId,mode:"persistent",
  strategyType:"project_primary",name:"Synthetic business workspace",cwd:ssh.state.workspaceDir,providerType:"ssh"});
 await db.insert(heartbeatRuns).values({id:runId,companyId,agentId,invocationSource:"manual",status:"running",
  runtimeMode:"native",nativeIssueId:taskId,responsibleUserId:userId});
 await update(issues,{executionRunId:runId},taskId);
 const secrets=secretService(db),key=await secrets.create(companyId,{name:"assembly-ssh-"+runId,provider:"local_encrypted",value:ssh.config.privateKey!});
 await secrets.createBinding({companyId,secretId:key.id,targetType:"environment",targetId:environmentId,configPath:"privateKeySecretRef"});
 await db.insert(environments).values({id:environmentId,name:"assembly-"+environmentId,driver:"ssh",status:"active",
  config:{...ssh.config,privateKey:null,privateKeySecretRef:{type:"secret_ref",secretId:key.id,version:"latest"}}});
 const environment=(await db.select().from(environments).where(eq(environments.id,environmentId)))[0];
 const lease=await environmentService(db).acquireLease({companyId,environmentId,executionWorkspaceId:workspaceId,
  issueId:taskId,heartbeatRunId:runId,provider:"ssh",providerLeaseId:"ssh://assembly-owned/"+environmentId,
  leasePolicy:"ephemeral",expiresAt:new Date(Date.now()+120000),metadata:{driver:"ssh",agentId}});
 remoteRoot=path.join(ssh.root,"hgl-"+runId.slice(0,8));
 const bindingFile=path.join(ssh.root,"native-binding-"+runId+".json");
 const binding={company_id:companyId,project_id:projectId,workspace_id:workspaceId,agent_id:agentId,task_id:taskId,run_id:runId,
  environment_id:environmentId,lease_id:lease.id,provider_lease_id:lease.providerLeaseId,deadline:lease.expiresAt.getTime()/1000};
 await writePrivate(bindingFile,binding);
 const prepared=await exec("/usr/bin/python3",["-I","-B",helper,"--fixture-contract","c2-native-v1","prepare",
  "--root",remoteRoot,"--binding",bindingFile,"--business"],{env:childEnv(),timeout:5000,maxBuffer:65536});
 f=JSON.parse(prepared.stdout);
 const request=await readFile(f.request_ref);
 hostRoot=path.join(resolvePaperclipInstanceRootForAdapter(),"managed-handoffs",runId);
 await mkdir(hostRoot,{recursive:true,mode:0o700});
 // Every controller-owned parent is private; do not alter HOME/CODEX_HOME.
 for(const dir of [path.dirname(path.dirname(hostRoot)),path.dirname(hostRoot),hostRoot])await chmod(dir,0o700);
 profilePath=path.join(hostRoot,"profile.json");requestPath=path.join(hostRoot,"submit.json");
 await writeFile(requestPath,request,{mode:0o600});
 const bound=JSON.parse(request.toString()).binding;
 profile={schema:"homie.managed-ssh-profile.v1",binding:bound,config_ref:f.config_ref,binding_ref:f.binding_ref,
  request_ref:{path:requestPath,sha256:sha(request),size_bytes:request.length,expected_uid:process.getuid!(),expected_mode:0o600},
  control_argv:["/usr/bin/python3","-B","-m","homie_gang_leader.cli"],
  control_env:{PYTHONPATH:path.join(remoteRoot,"guard")+path.delimiter+f.service}};
 await saveProfile();
 await update(environmentLeases,{metadata:{driver:"ssh",agentId,managedProcessHandoff:{
  schema:"homie.managed-control.v1",binding:bound,owner:null,cleanup_complete:false}}},lease.id);
 n={companyId,agentId,taskId,runId,environmentId,projectId,workspaceId,userId,environment,binding:bound,
  workspace:(await db.select().from(executionWorkspaces).where(eq(executionWorkspaces.id,workspaceId)))[0],
  lease:await environmentService(db).getLeaseById(lease.id)};
 owner=null;ownerClosed=undefined;ownerExit=undefined;
});
afterEach(async()=>{
 if(owner){
  await writePrivate(path.join(remoteRoot,"test-stop"),{stop:true});
  expect(await ownerClosed,"fixture supervisor must join its own exact daemon").toBe(0);
  const teardown=JSON.parse(await readFile(path.join(remoteRoot,"owner-teardown.json"),"utf8"));
  expect(teardown.daemon_absent).toBe(true);expect(teardown.children_absent).toBe(true);expect(teardown.owner_unknown).toBe(false);
 }
 expect({HOME:process.env.HOME,CODEX_HOME:process.env.CODEX_HOME}).toEqual(baseline);
});
async function rejectBeforeCarrier(){
 let error:unknown;
 try{await assemble()}catch(e){error=e}
 expect(error,"actual selected-target dispatcher must refuse invalid native/custody state; returning null permits local fallback").toBeInstanceOf(Error);
 if(error){
  expect(error,"denial must come from the actual target resolution boundary, not unrelated IO/setup").toMatchObject({code:"transport_resolution_failed"});
  expect(String(error)).not.toContain("PRIVATE_REQUEST_CANARY");
 }
}
async function startupOutcome(){
 owner=spawn("/usr/bin/python3",["-I","-B",helper,"--fixture-contract","c2-native-v1","owner","--root",remoteRoot],
  {env:childEnv(),stdio:["ignore","ignore","ignore"]});
 ownerClosed=new Promise((resolve,reject)=>{owner.once("error",reject);owner.once("close",(code:number|null)=>{ownerExit=code;resolve(code)})});
 await waitForFile(path.join(remoteRoot,"daemon.json"));
 const identity=JSON.parse(await readFile(path.join(remoteRoot,"daemon.json"),"utf8"));
 const request={schema:"homie.managed-control.v1",action:"status",binding:n.binding};
 const end=Date.now()+4000;
 while(Date.now()<end){
  let stdout="";
  try{
   // Actual installed source CLI outcome, not PID liveness. Only synthetic refs
   // go over stdin. No provider/auth source is imported or monkeypatched.
   const result=await new Promise<{code:number|null;out:string}>((resolve,reject)=>{
    const p=spawn("/usr/bin/python3",["-B","-m","homie_gang_leader.cli","--config",f.config_ref,"handoff","status"],
     {env:{...childEnv(),...profile.control_env},stdio:["pipe","pipe","ignore"]});
    let out="";p.stdout.on("data",b=>out+=b);
    const timer=setTimeout(()=>p.kill("SIGKILL"),900);
    p.once("error",reject);p.once("close",code=>{clearTimeout(timer);resolve({code,out})});
    p.stdin.end(JSON.stringify(request));
   });
   stdout=result.out;
   let body:any;try{body=JSON.parse(stdout)}catch{}
   if(body?.schema==="homie.managed-control-result.v1"&&isDeepStrictEqual(body.binding,n.binding)&&
    ["absent","accepted"].includes(body.custody_status)&&["waiting","accepted","running"].includes(body.status)&&
    body.owner?.instance_id===identity.pid+":"+identity.ticks){
    const current=await readFile("/proc/"+identity.pid+"/stat","utf8");
    const ticks=current.slice(current.lastIndexOf(") ")+2).split(/\s+/)[19];
    if(ticks!==identity.ticks)throw new Error("INFRASTRUCTURE: fixture daemon identity changed");
    return {stage:"ready",identity};
   }
  }catch(error){if(ownerExit===undefined)throw error}
  if(ownerExit!==undefined){
   const raw=await readFile(path.join(remoteRoot,"daemon.stderr"),"utf8");
   let body:any;try{body=JSON.parse(raw)}catch{}
   const stage=body?.error_code==="managed_configuration_invalid"?"config_rejected":"unexpected_terminal";
   await writePrivate(path.join(remoteRoot,"startup-outcome.json"),{stage,identity,wrapper_exit:ownerExit,readiness_proven:false});
   if(stage==="unexpected_terminal")throw new Error("INFRASTRUCTURE: unexpected owned daemon terminal outcome");
   return {stage,identity};
  }
  await sleep(20);
 }
 await writePrivate(path.join(remoteRoot,"startup-outcome.json"),{stage:"control_unavailable",identity,readiness_proven:false});
 return {stage:"control_unavailable",identity};
}
it("ASM-01 real dispatcher derives carrier from selected persisted native lease/profile",async()=>{
 expect(await nativeDecision()).toMatchObject({allowed:true});
 const result=await assemble();
 expect(result.executionTarget,"production factory currently returns null for selected process SSH").toMatchObject({
  kind:"remote",transport:"ssh",environmentId:n.environmentId,leaseId:n.lease.id,managedHandoff:profile});
});
it("ASM-02 existing target parser preserves actually assembled carrier",async()=>{
 const result=await assemble();
 expect(result.executionTarget,"assembly before parser is required").not.toBeNull();
 const parsed=parseAdapterExecutionTarget(result.executionTarget);
 expect(parsed).toMatchObject({managedHandoff:profile});
});
it("ASM-03 dispatcher to real adapter late business arrival uses no manually injected carrier",async()=>{
 const result=await assemble();
 expect(result.executionTarget,"no top-level ctx carrier may compensate for missing producer").not.toBeNull();
 const expected=path.join(remoteRoot,"producer-context.json"),pending=path.join(remoteRoot,"approved-late.json");
 await rename(expected,pending);
 const started=await startupOutcome();
 expect(started.stage,"actual bounded owner startup/control, never fixed timer").toBe("ready");
 const trap=path.join(hostRoot,"untrusted-local-command-ran");
 const meta:unknown[]=[],logs:string[]=[];
 await rename(pending,expected);
 const executed=await execute({runId:n.runId,
  agent:{id:n.agentId,companyId:n.companyId,name:"Synthetic researcher",adapterType:"process",adapterConfig:{}},
  runtime:{sessionId:null,sessionParams:null,sessionDisplayId:null,taskKey:n.taskId},
  context:{issueId:n.taskId,command:"untrusted",managedHandoff:{config_ref:"/untrusted/task.json"}},
  executionTarget:result.executionTarget,
  config:{command:process.execPath,args:["-e","require('fs').writeFileSync(process.argv[1],'wrong')",trap],cwd:ssh.state.workspaceDir,
   managedHandoff:{config_ref:"/untrusted/config.json"},env:{PAPERCLIP_API_KEY:"PRIVATE_REQUEST_CANARY"}},
  onLog:async(_stream,text)=>{logs.push(text)},onMeta:async value=>{meta.push(value)}});
 expect(await exists(trap),"task-selected command must never execute locally").toBe(false);
 expect(executed.errorCode).toBeUndefined();expect(executed.exitCode).toBe(0);
 await waitForFile(path.join(remoteRoot,"identities/current.json"));
 const current=JSON.parse(await readFile(path.join(remoteRoot,"identities/current.json"),"utf8"));
 expect(current.cleanup_complete).toBe(true);
 const events=(await readFile(path.join(remoteRoot,"bundle/events.jsonl"),"utf8")).trim().split("\n").map(l=>JSON.parse(l));
 expect(events.filter(e=>e.event==="launch")).toHaveLength(1);
 expect(events.find(e=>e.event==="launch"),"actual launch must be in the same validated daemon, not an inline CLI beside it").toMatchObject({
  caller_pid:started.identity.pid,caller_start_ticks:started.identity.ticks});
 expect(events.some(e=>e.event==="business_input_seen")).toBe(true);
 expect(events.some(e=>e.event==="business_output_written")).toBe(true);
 const stat=await readFile("/proc/"+started.identity.pid+"/stat","utf8");
 expect(stat.slice(stat.lastIndexOf(") ")+2).split(/\s+/)[19]).toBe(started.identity.ticks);
 expect(JSON.stringify({meta,logs,executed})).not.toContain("PRIVATE_REQUEST_CANARY");
 expect(JSON.stringify(meta)).not.toContain(profile.request_ref.path);
 const lease=await environmentService(db).getLeaseById(n.lease.id);
 expect(lease.metadata.managedProcessHandoff.cleanup_complete).toBe(true);
 const selected=result.executionTarget;
 if(selected?.kind!=="remote"||selected.transport!=="ssh"||!selected.recordManagedHandoffOutcome)throw new Error("missing real settlement hook");
 const receipt={schema:"homie.managed-control-result.v1" as const,action:"status" as const,
  binding:n.binding,custody_status:"accepted" as const,owner:lease.metadata.managedProcessHandoff.owner,
  status:"succeeded",cleanup_complete:true,error_code:null,result_ref:executed.resultJson!.result_ref};
 expect(receipt.owner.instance_id).toBe(started.identity.pid+":"+started.identity.ticks);
 await selected.recordManagedHandoffOutcome(receipt); // same verified outcome is idempotent
 await expect(selected.recordManagedHandoffOutcome({...receipt,owner:{...receipt.owner,instance_id:"1:0"}})).rejects.toMatchObject({code:"managed_handoff_invalid"});
 await expect(selected.recordManagedHandoffOutcome({...receipt,binding:{...n.binding,generation:2}})).rejects.toMatchObject({code:"managed_handoff_invalid"});
 await expect(selected.recordManagedHandoffOutcome({...receipt,status:"running",cleanup_complete:false,result_ref:null})).rejects.toMatchObject({code:"managed_handoff_invalid"});
 expect((await environmentService(db).getLeaseById(n.lease.id)).metadata).toEqual(lease.metadata);
 await environmentRuntimeService(db).releaseRunLeases(n.runId,"released");
 const released=await environmentService(db).getLeaseById(n.lease.id);
 expect(released.status).toBe("released");expect(released.cleanupStatus).toBe("success");
 expect(await remoteExecutionHasStopped(db,n.companyId,n.runId)).toBe(true);
});
it("ASM-04 controller does not open remote HGL config/binding paths locally",async()=>{
 profile.config_ref="/var/lib/homie/remote-fixture/"+n.runId+"/config.json";
 profile.binding_ref="/var/lib/homie/remote-fixture/"+n.runId+"/producer-binding.json";
 expect(await exists(profile.config_ref)).toBe(false);expect(await exists(profile.binding_ref)).toBe(false);
 await saveProfile();
 expect((await assemble()).executionTarget).toMatchObject({managedHandoff:profile});
});
it("ASM-05 actual C2 daemon startup is a reconciled control outcome, not process existence",async()=>{
 const result=await startupOutcome();
 expect(result.stage,"pinned Config.load rejects C2 profile; deeper daemon/dispatch remains NOT_REACHED").toBe("ready");
});
const invalidNative:Array<[string,()=>Promise<unknown>]>= [
 ["missing responsible native user",()=>update(heartbeatRuns,{responsibleUserId:null},n.runId)],
 ["membership with no native auth user",()=>db.delete(authUsers).where(eq(authUsers.id,n.userId))],
 ["membership belongs to another company",async()=>{
  const other=randomUUID();await db.insert(companies).values({id:other,name:"Other synthetic",issuePrefix:"OT"+other.replaceAll("-","").slice(0,8).toUpperCase()});
  await db.update(companyMemberships).set({companyId:other}).where(eq(companyMemberships.principalId,n.userId));
 }],
 ["revoked same-company membership",()=>db.update(companyMemberships).set({status:"inactive"}).where(eq(companyMemberships.principalId,n.userId))],
 ["viewer cannot mutate admitted task",()=>db.update(companyMemberships).set({membershipRole:"viewer"}).where(eq(companyMemberships.principalId,n.userId))],
 ["run is no longer running",()=>update(heartbeatRuns,{status:"cancelled"},n.runId)],
 ["legacy run is not native admission",()=>update(heartbeatRuns,{runtimeMode:"legacy"},n.runId)],
 ["native task binding changed",()=>update(heartbeatRuns,{nativeIssueId:randomUUID()},n.runId)],
 ["current issue checkout changed",async()=>{
  const next=randomUUID();await db.insert(heartbeatRuns).values({id:next,companyId:n.companyId,agentId:n.agentId,invocationSource:"manual",status:"running"});
  await update(issues,{executionRunId:next},n.taskId);
 }],
 ["assignee changed",()=>update(issues,{assigneeAgentId:null},n.taskId)],
 ["agent paused",()=>update(agents,{status:"paused"},n.agentId)],
 ["persisted lease pending cleanup despite detached active input",()=>update(environmentLeases,{status:"pending_cleanup"},n.lease.id)],
 ["persisted lease expired",()=>update(environmentLeases,{expiresAt:new Date(Date.now()-1000)},n.lease.id)],
 ["workspace closed",()=>update(executionWorkspaces,{status:"closed"},n.workspaceId)],
 ["persisted selected environment inactive",()=>update(environments,{status:"inactive"},n.environmentId)],
 ["persisted binding differs from detached input",()=>update(environmentLeases,{metadata:{driver:"ssh",managedProcessHandoff:{
   schema:"homie.managed-control.v1",binding:{...n.binding,operation_id:randomUUID()},owner:null,cleanup_complete:false}}},n.lease.id)],
];
it.each(invalidNative)("ASM-TRUST refuses %s at real dispatcher",async(_name,mutate)=>{
 await mutate();await rejectBeforeCarrier();
});
const invalidCustody:Array<[string,()=>Promise<unknown>]>= [
 ["missing protected producer profile",()=>unlink(profilePath)],
 ["public-readable producer profile",()=>chmod(profilePath,0o644)],
 ["linked producer profile",async()=>{const real=path.join(hostRoot,"actual.json");await rename(profilePath,real);await symlink(real,profilePath)}],
 ["aliased producer profile inode",()=>link(profilePath,path.join(hostRoot,"alias.json"))],
 ["request digest changed after profile freeze",()=>writePrivate(requestPath,{schema:"changed",canary:"PRIVATE_REQUEST_CANARY"})],
 ["request outside fixed private run root",async()=>{profile.request_ref.path=f.request_ref;await saveProfile()}],
 ["profile bound to another task",async()=>{profile.binding={...profile.binding,task_id:randomUUID()};await saveProfile()}],
 ["profile supplies credential values instead of references",async()=>{profile.extra_secret="PRIVATE_REQUEST_CANARY";await saveProfile()}],
];
it.each(invalidCustody)("ASM-CUSTODY refuses %s before transport",async(_name,mutate)=>{
 await mutate();await rejectBeforeCarrier();
});
it("ASM-TRUST shadow auth compatibility cannot authorize the credential producer",async()=>{
 await db.update(companyMemberships).set({status:"inactive"}).where(eq(companyMemberships.principalId,n.userId));
 process.env.PAPERCLIP_RESPONSIBLE_USER_AUTHZ_MODE="shadow";
 try{await rejectBeforeCarrier()}finally{delete process.env.PAPERCLIP_RESPONSIBLE_USER_AUTHZ_MODE}
});
it("ASM-TRUST adapter config cannot self-admit a profile without controller custody",async()=>{
 await unlink(profilePath);
 n.environment={...n.environment,config:{...n.environment.config,managedHandoff:profile}};
 await rejectBeforeCarrier();
});
it("ASM-TARGET selected raw SSH without opt-in cannot fall back to local execution",async()=>{
 await unlink(profilePath);
 await update(environmentLeases,{metadata:{driver:"ssh"}},n.lease.id);
 n.lease=await environmentService(db).getLeaseById(n.lease.id);
 await rejectBeforeCarrier();
});
it("control: existing native authorizer accepts synthetic responsible owner and current task",async()=>{
 expect(await nativeDecision()).toMatchObject({allowed:true});
});
it("control: existing native authorizer denies membership-only principal without authUsers",async()=>{
 await db.delete(authUsers).where(eq(authUsers.id,n.userId));
 expect(await nativeDecision()).toMatchObject({allowed:false,code:"RESPONSIBLE_USER_UNAVAILABLE"});
});
it("control: existing native authorizer denies revoked actual membership",async()=>{
 await db.update(companyMemberships).set({status:"inactive"}).where(eq(companyMemberships.principalId,n.userId));
 expect(await nativeDecision()).toMatchObject({allowed:false,code:"RESPONSIBLE_USER_UNAVAILABLE"});
});
it("control: existing known-runner selected SSH target stays compatible",async()=>{
 expect((await assemble("paperclip_runner")).executionTarget).toMatchObject({
  kind:"remote",transport:"ssh",environmentId:n.environmentId,leaseId:n.lease.id});
});
it("control: local process path remains local without managed profile",async()=>{
 const marker=path.join(hostRoot,"local-control");
 const result=await execute({runId:n.runId,
  agent:{id:n.agentId,companyId:n.companyId,name:"Local synthetic",adapterType:"process",adapterConfig:{}},
  runtime:{sessionId:null,sessionParams:null,sessionDisplayId:null,taskKey:n.taskId},context:{},
  executionTarget:{kind:"local"},config:{command:process.execPath,args:["-e","require('fs').writeFileSync(process.argv[1],'ok')",marker],cwd:ssh.state.workspaceDir},
  onLog:async()=>{}});
 expect(result.exitCode).toBe(0);expect(await readFile(marker,"utf8")).toBe("ok");
});


it("ASM-SETTLE actual recorder database failure holds selected lease after joined remote completion",async()=>{
 const selected=(await assemble()).executionTarget;
 expect(selected).toMatchObject({kind:"remote",transport:"ssh"});
 const started=await startupOutcome();expect(started.stage).toBe("ready");
 const suffix=n.lease.id.replaceAll("-","");
 const fn="fixture_fail_settlement_"+suffix;
 await db.execute(sql.raw("CREATE FUNCTION "+fn+"() RETURNS trigger AS $$ BEGIN IF NEW.id = '"+n.lease.id+
  "'::uuid AND NEW.metadata->'managedProcessHandoff'->>'cleanup_complete' = 'true' THEN RAISE EXCEPTION 'PRIVATE_SETTLEMENT_CANARY'; END IF; RETURN NEW; END; $$ LANGUAGE plpgsql"));
 await db.execute(sql.raw("CREATE TRIGGER "+fn+" BEFORE UPDATE ON environment_leases FOR EACH ROW EXECUTE FUNCTION "+fn+"()"));
 const meta:unknown[]=[],logs:string[]=[];
 const executed=await execute({runId:n.runId,
  agent:{id:n.agentId,companyId:n.companyId,name:"Synthetic research",adapterType:"process",adapterConfig:{}},
  runtime:{sessionId:null,sessionParams:null,sessionDisplayId:null,taskKey:n.taskId},context:{issueId:n.taskId},
  executionTarget:selected,config:{command:"/untrusted/command"},
  onLog:async(_stream,text)=>{logs.push(text)},onMeta:async value=>{meta.push(value)}});
 expect(executed.errorCode).toBe("process_managed_settlement_failed");
 expect(executed.resultJson).toMatchObject({cleanup_complete:false});
 const current=JSON.parse(await readFile(path.join(remoteRoot,"identities/current.json"),"utf8"));
 expect(current.cleanup_complete,"actual remote owner joined; database failure must not erase custody uncertainty").toBe(true);
 const events=(await readFile(path.join(remoteRoot,"bundle/events.jsonl"),"utf8")).trim().split("\n").map(l=>JSON.parse(l));
 expect(events.filter(e=>e.event==="launch")).toHaveLength(1);
 expect(events.find(e=>e.event==="launch")).toMatchObject({caller_pid:started.identity.pid,caller_start_ticks:started.identity.ticks});
 await environmentRuntimeService(db).releaseRunLeases(n.runId,"released");
 const lease=await environmentService(db).getLeaseById(n.lease.id);
 expect(lease.status).toBe("pending_cleanup");expect(lease.cleanupStatus).not.toBe("success");
 expect(lease.metadata.managedProcessHandoff.binding).toEqual(n.binding);
 expect(lease.metadata.managedProcessHandoff.owner.instance_id).toBe(started.identity.pid+":"+started.identity.ticks);
 expect(lease.metadata.managedProcessHandoff.cleanup_complete).toBe(false);
 expect(await remoteExecutionHasStopped(db,n.companyId,n.runId)).toBe(false);
 expect(JSON.stringify({executed,meta,logs})).not.toContain("PRIVATE_SETTLEMENT_CANARY");
 await db.execute(sql.raw("DROP TRIGGER "+fn+" ON environment_leases"));
 await db.execute(sql.raw("DROP FUNCTION "+fn+"()"));
});

it("ASM-SETTLE serialized profile cannot invent the native live settlement function",async()=>{
 const selected=(await assemble()).executionTarget;
 const jsonOnly=JSON.parse(JSON.stringify(selected));
 const trap=path.join(hostRoot,"serialized-profile-fallback");
 const executed=await execute({runId:n.runId,
  agent:{id:n.agentId,companyId:n.companyId,name:"Synthetic research",adapterType:"process",adapterConfig:{}},
  runtime:{sessionId:null,sessionParams:null,sessionDisplayId:null,taskKey:n.taskId},context:{},
  executionTarget:jsonOnly,config:{command:process.execPath,args:["-e","require('fs').writeFileSync(process.argv[1],'wrong')",trap]},
  onLog:async()=>{}});
 expect(executed.errorCode).toBe("process_ssh_owned_control_unavailable");
 expect(await exists(trap)).toBe(false);
 expect(await exists(path.join(remoteRoot,"bundle/events.jsonl"))).toBe(false);
});

it("ASM-READ actual native database read failure is unavailable, never an authorization denial",async()=>{
 await db.execute(sql.raw("ALTER TABLE environment_leases RENAME TO fixture_temporarily_unavailable_leases"));
 let error:any;
 try{await assemble()}catch(value){error=value}
 finally{await db.execute(sql.raw("ALTER TABLE fixture_temporarily_unavailable_leases RENAME TO environment_leases"))}
 expect(error).toMatchObject({code:"transport_resolution_failed",cause:{code:"managed_handoff_unavailable"}});
 expect(String(error)).toBe("EnvironmentRunError: Managed handoff unavailable.");
 expect(String(error.cause)).toBe("Error: Managed handoff unavailable.");
 expect(JSON.stringify(error)).not.toContain("environment_leases");
 expect(JSON.stringify(error)).not.toContain("select ");
});
