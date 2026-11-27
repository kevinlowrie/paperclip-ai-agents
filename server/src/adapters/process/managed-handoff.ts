/** Selected, privately admitted SSH -> existing HGL stdin control. No launcher here. */
import {isDeepStrictEqual} from "node:util";
import {readManagedSshProfile,readManagedSshRequest,managedOutputRef,parseManagedControlResult,type ManagedControlResult} from "@paperclipai/adapter-utils/managed-ssh-handoff";
import {runSshCommand,shellQuote} from "@paperclipai/adapter-utils/ssh";
import type {AdapterSshExecutionTarget} from "@paperclipai/adapter-utils/execution-target";
import type {AdapterExecutionContext,AdapterExecutionResult} from "../types.js";

export async function executeManagedHandoff(ctx:AdapterExecutionContext,target:AdapterSshExecutionTarget):Promise<AdapterExecutionResult> {
  const pending = (code:string):AdapterExecutionResult => ({
    exitCode:null,signal:null,timedOut:false,errorCode:code,
    errorMessage:"Managed SSH cleanup is unconfirmed.",
    resultJson:{status:"cleanup_pending",cleanup_complete:false,run_id:ctx.runId},
  });
  let cancellation:Promise<void>|undefined;
  let cancellationRequested=false;
  let cleanupDeadline:number|undefined;
  try {
    const profile=await readManagedSshProfile(ctx.runId);
    if (!isDeepStrictEqual(profile,target.managedHandoff) || !target.recordManagedHandoffOutcome ||
        profile.binding.run_id!==ctx.runId || profile.binding.agent_id!==ctx.agent.id ||
        profile.binding.company_id!==ctx.agent.companyId || profile.binding.lease_id!==target.leaseId ||
        profile.binding.environment_id!==target.environmentId) return pending("process_managed_handoff_invalid");
    const submit=await readManagedSshRequest(profile);
    const expectedOutput=managedOutputRef(submit);
    const request=JSON.parse(submit);
    const refs=request.frame.credential_refs;
    const leaseEnd=Math.min(Number(profile.binding.deadline),
      ...[refs.g,refs.model,...Object.values(refs.upstream)].map((r:any)=>Number(r.expires_at)))*1000;
    if (!Number.isFinite(leaseEnd) || leaseEnd<=Date.now()+15000) return pending("process_managed_handoff_invalid");
    const command=(action:string)=>[...profile.control_argv,"--config",profile.config_ref,"handoff",action].map(shellQuote).join(" ");
    const call=async(action:"submit"|"status"|"cancel",reason?:string):Promise<ManagedControlResult>=>{
      const input=action==="submit"?await readManagedSshRequest(profile):
        JSON.stringify({schema:"homie.managed-control.v1",action,binding:profile.binding,...(reason?{reason}:{})});
      const end=Math.min(leaseEnd,cleanupDeadline??leaseEnd,Date.now()+(action==="cancel"?1000:8000));
      if(end<=Date.now())throw new Error("Managed control deadline reached.");
      const result=await runSshCommand(target.spec,command(action),{
        inputMode:"private_v1",privateStdout:"trusted_protocol_v1",stdin:input,env:profile.control_env,
        deadlineEpochMs:Math.floor(end),timeoutMs:Math.max(1,end-Date.now()),maxBuffer:65536});
      // private_v1 proves transport custody only. Program output gains meaning
      // from the fixed trusted HGL CLI, independent protected binding, exact
      // protocol/owner checks and native settlement CAS.
      return parseManagedControlResult(JSON.parse(result.stdout),profile,action,expectedOutput);
    };
    const cancel=()=>{
      cancellationRequested=true;
      cleanupDeadline ??= Math.min(leaseEnd,Date.now()+15000);
      cancellation ??= (async()=>{
        try{const ack=await call("cancel","cancelled");await target.recordManagedHandoffOutcome!(ack)}catch{}
      })();
    };
    ctx.signal?.addEventListener("abort",cancel,{once:true});
    try {
      await ctx.onCancellationReady?.();
      if(ctx.signal?.aborted)return pending("process_cancelled");
      await ctx.onMeta?.({adapterType:"process",command:"managed-handoff"});
      // One submit attempt. Lost ACK reconciles the same operation via status,
      // never a new issuance or a second launch ID.
      ctx.onDispatch?.();
      let ack:ManagedControlResult|undefined;
      try { ack=await call("submit"); } catch { /* reconcile uncertain ACK without re-submit */ }
      if(ack){
        try{await target.recordManagedHandoffOutcome(ack)}
        catch{cancel();return pending("process_managed_settlement_failed")}
      }
      while(Date.now()<Math.min(leaseEnd,cleanupDeadline??leaseEnd)){
        if(ctx.signal?.aborted)cancel();
        if(Date.now()>=leaseEnd-15000)cancel();
        let state:ManagedControlResult|undefined;
        try{state=await call("status")}catch{}
        if(state){
          try{await target.recordManagedHandoffOutcome(state)}
          catch{cancel();return pending("process_managed_settlement_failed")}
        }
        if(state?.cleanup_complete && ["succeeded","failed","cancelled"].includes(state.status)){
          return {exitCode:state.status==="succeeded"?0:1,signal:null,timedOut:false,
            ...(state.status!=="succeeded"?{errorCode:cancellationRequested?"process_cancelled":"process_managed_run_failed"}:{}),
            resultJson:{status:state.status,cleanup_complete:true,run_id:ctx.runId,
              generation:profile.binding.generation,result_ref:state.result_ref}};
        }
        if(state?.status==="rejected")return pending("process_managed_control_rejected");
        await new Promise(resolve=>setTimeout(resolve,50));
      }
      cancel();
      return pending(cancellationRequested?"process_cancelled":"process_managed_cleanup_pending");
    } finally {
      ctx.signal?.removeEventListener("abort",cancel);
      await cancellation;
    }
  } catch { return pending("process_managed_handoff_invalid"); }
}
