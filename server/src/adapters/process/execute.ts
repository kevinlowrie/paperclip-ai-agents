import path from "node:path";
import type { AdapterExecutionContext, AdapterExecutionResult } from "../types.js";
import {
  adapterExecutionTargetFromRemoteExecution,
  parseAdapterExecutionTarget,
} from "@paperclipai/adapter-utils/execution-target";
import { signalRunningProcess } from "@paperclipai/adapter-utils/server-utils";
import {
  asString,
  asNumber,
  asStringArray,
  parseObject,
  buildPaperclipEnv,
  buildRuntimeToolsEnv,
  isForbiddenConfigEnvKey,
  isPaperclipRuntimeEnvKey,
  buildInvocationEnvForLogs,
  ensurePathInEnv,
  resolveCommandForLogs,
  runningProcesses,
  runChildProcess,
} from "../utils.js";

function bootstrapRefusal(code: string, message: string): AdapterExecutionResult {
  return {
    exitCode: null,
    signal: null,
    timedOut: false,
    errorCode: code,
    errorMessage: message,
    executionRecovery: { kind: "bootstrap", providerWorkStarted: false },
  };
}

function refuseUnownedTarget(ctx: AdapterExecutionContext): AdapterExecutionResult | null {
  const canonicalPresent = ctx.executionTarget != null;
  const legacy = ctx.executionTransport?.remoteExecution;
  const legacyPresent = legacy != null;
  const canonical = canonicalPresent ? parseAdapterExecutionTarget(ctx.executionTarget) : null;
  const legacyTarget = legacyPresent ? adapterExecutionTargetFromRemoteExecution(legacy) : null;
  if ((canonicalPresent && !canonical) || (legacyPresent && !legacyTarget)) {
    return bootstrapRefusal("process_execution_target_invalid", "Invalid selected process execution target.");
  }
  if (canonical && legacyTarget) {
    if (canonical.kind !== "remote" || canonical.transport !== "ssh" || legacyTarget.kind !== "remote" ||
        legacyTarget.transport !== "ssh" ||
        ["host", "port", "username", "remoteCwd", "privateKey", "knownHosts", "strictHostKeyChecking"]
          .some(key => canonical.spec[key as keyof typeof canonical.spec] !== legacyTarget.spec[key as keyof typeof legacyTarget.spec])) {
      return bootstrapRefusal("process_execution_target_conflict", "Selected process execution targets conflict.");
    }
  }
  const selected = canonical ?? legacyTarget;
  if (selected?.kind !== "remote") return null;
  if (!path.posix.isAbsolute(selected.remoteCwd)) {
    return bootstrapRefusal("process_execution_target_invalid", "Remote process working directory must be absolute.");
  }
  if (selected.transport !== "ssh") {
    return bootstrapRefusal("process_execution_target_unsupported", "Selected process transport is unsupported.");
  }
  // SSH client/process-group termination and lease release cannot certify remote
  // work teardown. Keep managed dispatch disabled until its real owner qualifies.
  return bootstrapRefusal("process_ssh_owned_control_unavailable", "Selected SSH target has no verified owned command control.");
}

export async function execute(ctx: AdapterExecutionContext): Promise<AdapterExecutionResult> {
  const { runId, agent, config, onLog, onMeta, authToken } = ctx;
  const targetRefusal = refuseUnownedTarget(ctx);
  if (targetRefusal) return targetRefusal;
  const command = asString(config.command, "");
  if (!command) throw new Error("Process adapter missing command");

  const args = asStringArray(config.args);
  const cwd = asString(config.cwd, process.cwd());
  const timeoutSec = asNumber(config.timeoutSec, 0);
  const graceSec = asNumber(config.graceSec, 15);
  let cancellationRequested = false;
  let stopTimer: ReturnType<typeof setTimeout> | undefined;
  let spawnBookkeepingFailed = false;
  let spawnForwarding: Promise<void> | undefined;
  let localOwnership: ReturnType<typeof runningProcesses.get>;
  const stopOwnedLocalProcess = () => {
    const owned = localOwnership;
    if (!owned || runningProcesses.get(runId) !== owned) return;
    signalRunningProcess(owned, "SIGTERM");
    if (!stopTimer) {
      stopTimer = setTimeout(() => {
        if (runningProcesses.get(runId) === owned) signalRunningProcess(owned, "SIGKILL");
      }, Math.max(0, graceSec) * 1000);
    }
  };
  const onAbort = () => {
    cancellationRequested = true;
    stopOwnedLocalProcess();
  };
  ctx.signal?.addEventListener("abort", onAbort, { once: true });
  try {
    await ctx.onCancellationReady?.();
    if (ctx.signal?.aborted) {
      return bootstrapRefusal("process_cancelled", "Process cancelled before dispatch.");
    }
    const envConfig = parseObject(config.env);
    const env: Record<string, string> = {
      ...buildPaperclipEnv(agent),
      ...buildRuntimeToolsEnv(ctx.runtimeTools),
    };
    for (const [k, v] of Object.entries(envConfig)) {
      if (typeof v !== "string") continue;
      if (isForbiddenConfigEnvKey(k)) continue;
      if (isPaperclipRuntimeEnvKey(k) && k in env) continue;
      env[k] = v;
    }
    env.PAPERCLIP_RUN_ID = runId;
    if (authToken) env.PAPERCLIP_API_KEY = authToken;
    // The local child keeps the existing inherited-Paperclip sanitization and
    // explicit runtime-token precedence in runChildProcess.
    const runtimeEnv = ensurePathInEnv({ ...process.env, ...env });
    const resolvedCommand = await resolveCommandForLogs(command, cwd, runtimeEnv);
    const loggedEnv = buildInvocationEnvForLogs(env, {
      runtimeEnv, includeRuntimeKeys: ["HOME"], resolvedCommand,
    });
    await onMeta?.({ adapterType: "process", command: resolvedCommand, cwd, commandArgs: args, env: loggedEnv });
    if (ctx.signal?.aborted) {
      return bootstrapRefusal("process_cancelled", "Process cancelled before dispatch.");
    }
    const proc = await runChildProcess(runId, command, args, {
      cwd, env, timeoutSec, graceSec, onLog,
      onSpawn: meta => {
        spawnForwarding = (async () => {
          // The shared helper publishes this exact child immediately after calling
          // onSpawn. Never signal another invocation merely sharing a runId.
          await Promise.resolve();
          const published = runningProcesses.get(runId);
          if (published?.child.pid === meta.pid) localOwnership = published;
          if (ctx.signal?.aborted) stopOwnedLocalProcess();
          try {
            ctx.onDispatch?.();
            await ctx.onSpawn?.(meta);
          } catch {
            spawnBookkeepingFailed = true;
          } finally {
            if (ctx.signal?.aborted || spawnBookkeepingFailed) stopOwnedLocalProcess();
          }
        })();
        return spawnForwarding;
      },
    });
    // Child close can precede asynchronous onSpawn persistence. Publication is
    // not complete until the exact forwarding obligation has settled.
    await spawnForwarding;
    if (spawnBookkeepingFailed || cancellationRequested || ctx.signal?.aborted) {
      return { exitCode: proc.exitCode, signal: proc.signal, timedOut: proc.timedOut,
        errorCode: spawnBookkeepingFailed ? "process_spawn_bookkeeping_failed" : "process_cancelled",
        errorMessage: spawnBookkeepingFailed ? "Process dispatch bookkeeping failed." : "Process execution cancelled.",
        resultJson: { stdout: proc.stdout, stderr: proc.stderr } };
    }
    if (proc.timedOut) {
      return { exitCode: proc.exitCode, signal: proc.signal, timedOut: true,
        errorMessage: `Timed out after ${timeoutSec}s` };
    }
    if ((proc.exitCode ?? 0) !== 0) {
      return { exitCode: proc.exitCode, signal: proc.signal, timedOut: false,
        errorMessage: `Process exited with code ${proc.exitCode ?? -1}`,
        resultJson: { stdout: proc.stdout, stderr: proc.stderr } };
    }
    return { exitCode: proc.exitCode, signal: proc.signal, timedOut: false,
      resultJson: { stdout: proc.stdout, stderr: proc.stderr } };
  } finally {
    ctx.signal?.removeEventListener("abort", onAbort);
    clearTimeout(stopTimer);
  }
}
