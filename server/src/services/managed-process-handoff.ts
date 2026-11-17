/** Admission consumer at the existing selected-target factory, never an issuer. */
import {and,eq,inArray,sql} from "drizzle-orm";
import {agents,authUsers,companyMemberships,environments,environmentLeases,executionWorkspaces,heartbeatRuns,issues,
 type Db} from "@paperclipai/db";
import {isDeepStrictEqual} from "node:util";
import {ManagedHandoffInvalid,ManagedHandoffUnavailable,readManagedSshProfile,parseManagedControlResult,validManagedHandoffOwner,type ManagedSshHandoff,type ManagedControlResult} from "@paperclipai/adapter-utils/managed-ssh-handoff";
import {authorizationService,responsibleUserAuthzShadowMode} from "./authorization.js";

export async function resolveManagedProcessHandoff(db:Db,companyId:string,environmentId:string,leaseId:string) {
 if (![companyId,environmentId,leaseId].every(v=>/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v))) throw new ManagedHandoffInvalid();
 try {
  const [lease] = await db.select().from(environmentLeases).where(eq(environmentLeases.id,leaseId));
  if (!lease || lease.companyId !== companyId || lease.environmentId !== environmentId ||
      lease.provider !== "ssh" || lease.status !== "active" || !lease.expiresAt ||
      lease.expiresAt.getTime() <= Date.now() || !lease.heartbeatRunId || !lease.issueId || !lease.executionWorkspaceId) throw new ManagedHandoffInvalid();
  const [run] = await db.select().from(heartbeatRuns).where(eq(heartbeatRuns.id,lease.heartbeatRunId));
  const [issue] = await db.select().from(issues).where(eq(issues.id,lease.issueId));
  const [workspace] = await db.select().from(executionWorkspaces).where(eq(executionWorkspaces.id,lease.executionWorkspaceId));
  const [environment] = await db.select().from(environments).where(eq(environments.id,environmentId));
  if (!run || !issue || !workspace || !environment || environment.status !== "active" || environment.driver !== "ssh" ||
      run.companyId !== companyId || run.runtimeMode !== "native" || run.status !== "running" ||
      !run.responsibleUserId || run.nativeIssueId !== issue.id || issue.companyId !== companyId ||
      issue.executionRunId !== run.id || issue.assigneeAgentId !== run.agentId || issue.status !== "in_progress" ||
      workspace.companyId !== companyId || workspace.projectId !== issue.projectId ||
      workspace.status !== "active" || responsibleUserAuthzShadowMode()) throw new ManagedHandoffInvalid();
  const [agent] = await db.select().from(agents).where(eq(agents.id,run.agentId));
  const [user] = await db.select().from(authUsers).where(eq(authUsers.id,run.responsibleUserId));
  const [member] = await db.select().from(companyMemberships).where(and(eq(companyMemberships.companyId,companyId),
    eq(companyMemberships.principalType,"user"),eq(companyMemberships.principalId,run.responsibleUserId),
    eq(companyMemberships.status,"active")));
  if (!agent || agent.companyId !== companyId || agent.adapterType !== "process" ||
      ["paused","terminated","pending_approval","error"].includes(agent.status) || !user || !member) throw new ManagedHandoffInvalid();
  const decision = await authorizationService(db).decide({
    actor:{type:"agent",agentId:agent.id,companyId,runId:run.id,onBehalfOfUserId:user.id,source:"agent_jwt"},
    action:"issue:mutate",resource:{type:"issue",companyId,issueId:issue.id,projectId:issue.projectId,
      assigneeAgentId:issue.assigneeAgentId,status:issue.status}});
  if (!decision.allowed) throw new ManagedHandoffInvalid();
  const profile = await readManagedSshProfile(run.id);
  const expected = {company_id:companyId,project_id:issue.projectId,workspace_id:workspace.id,agent_id:agent.id,
    task_id:issue.id,run_id:run.id,environment_id:environment.id,lease_id:lease.id,provider_lease_id:lease.providerLeaseId};
  for (const [key,value] of Object.entries(expected)) {
    if (!isDeepStrictEqual(profile.binding[key],value)) throw new ManagedHandoffInvalid();
  }
  const marker = lease.metadata?.managedProcessHandoff as Record<string,unknown>|undefined;
  if (!marker || marker.schema !== "homie.managed-control.v1" || !isDeepStrictEqual(marker.binding,profile.binding) ||
      Number(profile.binding.deadline)*1000 > lease.expiresAt.getTime()) throw new ManagedHandoffInvalid();
  return {profile,environment};
 } catch (error) {
   if (error instanceof ManagedHandoffInvalid) throw error;
   throw new ManagedHandoffUnavailable();
 }
}

/** Settlement only: this trusted closure cannot admit or mint work. */
export async function recordManagedProcessOutcome(
  db:Db,leaseId:string,profile:ManagedSshHandoff,result:ManagedControlResult,
):Promise<void> {
  const verified=parseManagedControlResult(result,profile,result.action);
  const [lease]=await db.select().from(environmentLeases).where(eq(environmentLeases.id,leaseId));
  let marker=lease?.metadata?.managedProcessHandoff as Record<string,unknown>|undefined;
  if(!lease||!marker||!isDeepStrictEqual(marker.binding,profile.binding)||
     lease.companyId!==profile.binding.company_id||lease.heartbeatRunId!==profile.binding.run_id||
     lease.providerLeaseId!==profile.binding.provider_lease_id||!["active","pending_cleanup"].includes(lease.status))throw new ManagedHandoffInvalid();
  if(marker.owner!=null&&verified.owner!=null&&!isDeepStrictEqual(marker.owner,verified.owner))throw new ManagedHandoffInvalid();
  const outcome={schema:verified.schema,binding:verified.binding,owner:verified.owner,status:verified.status,cleanup_complete:verified.cleanup_complete};
  if(marker.cleanup_complete===true){
    if(isDeepStrictEqual(marker.outcome,outcome))return;
    throw new ManagedHandoffInvalid(); // no late ACK/status can regress cleanup
  }
  const cas=async(previous:Record<string,unknown>,next:Record<string,unknown>)=>{
    const [updated]=await db.update(environmentLeases).set({
      metadata:sql`${environmentLeases.metadata} || ${JSON.stringify({managedProcessHandoff:next})}::jsonb`,updatedAt:new Date(),
    }).where(and(eq(environmentLeases.id,leaseId),eq(environmentLeases.heartbeatRunId,String(profile.binding.run_id)),
      inArray(environmentLeases.status,["active","pending_cleanup"]),
      sql`${environmentLeases.metadata}->'managedProcessHandoff' = ${JSON.stringify(previous)}::jsonb`)).returning();
    if(!updated)throw new ManagedHandoffInvalid();
  };
  if(verified.cleanup_complete&&marker.owner==null){
    // Reconciled terminal status can be the first response after a lost ACK.
    // Record its validated owner before settlement; a failed second write holds
    // the same owner with unknown cleanup, never a synthetic completed receipt.
    const claimed={...marker,owner:verified.owner,cleanup_complete:false};
    await cas(marker,claimed);marker=claimed;
  }
  const next={...marker,owner:verified.owner??marker.owner??null,cleanup_complete:verified.cleanup_complete,outcome};
  await cas(marker,next);
}

export function managedProcessLeaseSettled(lease:{id:string;companyId:string;heartbeatRunId:string|null;environmentId:string|null;
 providerLeaseId:string|null;executionWorkspaceId:string|null;issueId:string|null;metadata:Record<string,unknown>|null}):boolean {
 const marker=lease.metadata?.managedProcessHandoff as Record<string,unknown>|undefined;
 const b=marker?.binding as Record<string,unknown>|undefined;
 const outcome=marker?.outcome as Record<string,unknown>|undefined;
 return !!(marker&&b&&outcome&&marker.cleanup_complete===true&&validManagedHandoffOwner(marker.owner,b)&&
   b.company_id===lease.companyId&&b.run_id===lease.heartbeatRunId&&b.lease_id===lease.id&&
   b.environment_id===lease.environmentId&&b.provider_lease_id===lease.providerLeaseId&&
   b.workspace_id===lease.executionWorkspaceId&&b.task_id===lease.issueId&&
   outcome.schema==="homie.managed-control-result.v1"&&outcome.cleanup_complete===true&&
   ["succeeded","failed","cancelled"].includes(String(outcome.status))&&
   isDeepStrictEqual(outcome.binding,b)&&isDeepStrictEqual(outcome.owner,marker.owner));
}
