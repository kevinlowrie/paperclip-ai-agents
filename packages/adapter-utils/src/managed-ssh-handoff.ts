/** Run-private handoff custody. This consumes an admitted profile; it grants nothing. */
import fs, { constants } from "node:fs/promises";
import path from "node:path";
import {createHash} from "node:crypto";
import {isDeepStrictEqual} from "node:util";
import {resolvePaperclipInstanceRootForAdapter} from "./server-utils.js";

export interface PrivateHandoffRef {
  path: string; sha256: string; size_bytes: number; expected_uid: number; expected_mode: number;
}
export interface ManagedSshHandoff {
  schema: "homie.managed-ssh-profile.v1";
  binding: Record<string, unknown>;
  config_ref: string;
  binding_ref: string;
  request_ref: PrivateHandoffRef;
  control_argv: string[];
  control_env: Record<string, string>;
}
export class ManagedHandoffInvalid extends Error {
  readonly code = "managed_handoff_invalid";
  constructor() { super("Managed handoff unavailable."); }
}
export class ManagedHandoffUnavailable extends Error {
  readonly code = "managed_handoff_unavailable";
  constructor() { super("Managed handoff unavailable."); }
}
const invalid = (): never => { throw new ManagedHandoffInvalid(); };
const record = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const keys = (v: Record<string, unknown>, names: string[]) =>
  isDeepStrictEqual(Object.keys(v).sort(), [...names].sort());
const absolute = (v: unknown): v is string => typeof v === "string" && path.posix.isAbsolute(v) &&
  v !== "/" && !v.includes("\0") && !v.split("/").includes("..") && v.length <= 4096;
const uuid = (v: unknown): v is string => typeof v === "string" &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v);
export function managedHandoffRoot(runId: string): string {
  if (!uuid(runId)) return invalid();
  return path.join(resolvePaperclipInstanceRootForAdapter(), "managed-handoffs", runId);
}
export function parseManagedSshHandoff(value: unknown): ManagedSshHandoff | null {
  if (!record(value) || !keys(value, ["schema","binding","config_ref","binding_ref","request_ref","control_argv","control_env"]) ||
      value.schema !== "homie.managed-ssh-profile.v1" || !record(value.binding) ||
      !absolute(value.config_ref) || !absolute(value.binding_ref) ||
      value.config_ref === value.binding_ref || !record(value.request_ref) ||
      !keys(value.request_ref, ["path","sha256","size_bytes","expected_uid","expected_mode"]) ||
      !absolute(value.request_ref.path) || typeof value.request_ref.sha256 !== "string" ||
      !/^[a-f0-9]{64}$/.test(value.request_ref.sha256) || !Number.isSafeInteger(value.request_ref.size_bytes) ||
      Number(value.request_ref.size_bytes) < 1 || Number(value.request_ref.size_bytes) > 65536 ||
      value.request_ref.expected_uid !== process.getuid?.() || value.request_ref.expected_mode !== 0o600 ||
      !Array.isArray(value.control_argv) || value.control_argv.length !== 4 ||
      !absolute(value.control_argv[0]) || value.control_argv[1] !== "-B" ||
      value.control_argv[2] !== "-m" || value.control_argv[3] !== "homie_gang_leader.cli" ||
      !record(value.control_env) || Object.entries(value.control_env).some(([k,v]) =>
        !["PATH","PYTHONPATH","LANG","LC_ALL"].includes(k) || typeof v !== "string" ||
        v.length > 4096 || /[\0\r\n]/.test(v))) return null;
  return value as unknown as ManagedSshHandoff;
}
async function privateBytes(file: string, root: string): Promise<Buffer> {
  if (!absolute(file) || file === root || !file.startsWith(root + "/")) return invalid();
  const instance = resolvePaperclipInstanceRootForAdapter();
  const relative = path.relative(instance, path.dirname(file));
  if (relative.startsWith("..") || path.isAbsolute(relative)) return invalid();
  const dirs = [instance];
  for (const part of relative.split(path.sep).filter(Boolean)) dirs.push(path.join(dirs[dirs.length - 1]!, part));
  const snapshots = [];
  for (const dir of dirs) {
    const st = await fs.lstat(dir);
    if (!st.isDirectory() || st.isSymbolicLink() || st.uid !== process.getuid?.() || (st.mode & 0o777) !== 0o700) return invalid();
    snapshots.push(st);
  }
  const f = await fs.open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const st = await f.stat();
    if (!st.isFile() || st.nlink !== 1 || st.uid !== process.getuid?.() ||
        (st.mode & 0o777) !== 0o600 || st.size < 1 || st.size > 65536) return invalid();
    const buf = Buffer.alloc(st.size + 1);
    const {bytesRead} = await f.read(buf, 0, buf.length, 0);
    const after = await f.stat(), named = await fs.lstat(file);
    if (bytesRead !== st.size || after.size !== st.size || after.mtimeMs !== st.mtimeMs ||
        after.ctimeMs !== st.ctimeMs || named.dev !== st.dev || named.ino !== st.ino ||
        named.nlink !== 1 || named.uid !== st.uid || named.mode !== st.mode) return invalid();
    for (let i = 0; i < dirs.length; i++) {
      const current = await fs.lstat(dirs[i]!);
      const original = snapshots[i]!;
      if (current.dev !== original.dev || current.ino !== original.ino || current.mode !== original.mode ||
          current.uid !== original.uid || !current.isDirectory() || current.isSymbolicLink()) return invalid();
    }
    return buf.subarray(0, bytesRead);
  } finally { await f.close(); }
}
export async function readManagedSshProfile(runId: string): Promise<ManagedSshHandoff> {
  try {
    const root = managedHandoffRoot(runId);
    const parsed = parseManagedSshHandoff(JSON.parse((await privateBytes(path.join(root,"profile.json"),root)).toString("utf8")));
    if (!parsed || parsed.binding.run_id !== runId || !Number.isFinite(parsed.binding.deadline) ||
        Number(parsed.binding.deadline) * 1000 <= Date.now()) return invalid();
    await readManagedSshRequest(parsed);
    return parsed;
  } catch { return invalid(); }
}
export async function readManagedSshRequest(profile: ManagedSshHandoff): Promise<string> {
  try {
    const root = managedHandoffRoot(String(profile.binding.run_id));
    const raw = await privateBytes(profile.request_ref.path,root);
    if (raw.length !== profile.request_ref.size_bytes ||
        createHash("sha256").update(raw).digest("hex") !== profile.request_ref.sha256) return invalid();
    const request: unknown = JSON.parse(raw.toString("utf8"));
    if (!record(request) || !keys(request,["schema","action","binding","frame"]) ||
        request.schema !== "homie.managed-control.v1" || request.action !== "submit" ||
        !isDeepStrictEqual(request.binding,profile.binding) || !record(request.frame) ||
        !keys(request.frame,["admitted_context","credential_refs","untrusted_task"]) ||
        !record(request.frame.admitted_context) || !record(request.frame.credential_refs)) return invalid();
    const context = request.frame.admitted_context;
    for (const key of ["company_id","project_id","agent_id","task_id","run_id","workspace_id","generation","deadline"]) {
      if (!isDeepStrictEqual(context[key],profile.binding[key])) return invalid();
    }
    if (!record(context.launch_claim) || context.launch_claim.operation_id !== profile.binding.operation_id) return invalid();
    return raw.toString("utf8");
  } catch { return invalid(); }
}

export interface ManagedControlResult {
  schema: "homie.managed-control-result.v1";
  action: "submit" | "status" | "cancel";
  binding: Record<string,unknown>;
  custody_status: "absent" | "accepted" | "conflict" | "unknown";
  owner: {instance_id:string;operation_id:unknown;generation:unknown;context_digest:unknown;payload_digest:unknown} | null;
  status: string; cleanup_complete: boolean; error_code: unknown; result_ref: unknown;
}
export function managedOutputRef(request: string): {path:string; expected_uid:number} | null {
  try {
    const ref = JSON.parse(request)?.frame?.admitted_context?.business_command?.output_ref;
    if (!record(ref) || !keys(ref,["path","expected_uid","expected_mode"]) || !absolute(ref.path) ||
        path.posix.normalize(ref.path) !== ref.path || !Number.isSafeInteger(ref.expected_uid) ||
        Number(ref.expected_uid) < 0 || ref.expected_mode !== 0o700) return null;
    return {path:path.posix.join(ref.path,"manifest.json"),expected_uid:Number(ref.expected_uid)};
  } catch { return null; }
}
export function validManagedHandoffOwner(owner:unknown,binding:Record<string,unknown>): boolean {
  if (!record(owner) || !keys(owner,["instance_id","operation_id","generation","context_digest","payload_digest"]) ||
      typeof owner.instance_id!=="string" || !/^[1-9][0-9]*:[0-9]+$/.test(owner.instance_id) ||
      !Number.isSafeInteger(owner.generation) || Number(owner.generation)<1 ||
      typeof owner.operation_id!=="string" || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(owner.operation_id) ||
      !["context_digest","payload_digest"].every(k=>typeof owner[k]==="string" && /^[a-f0-9]{64}$/.test(owner[k] as string))) return false;
  return ["operation_id","generation","context_digest","payload_digest"].every(k=>isDeepStrictEqual(owner[k],binding[k]));
}
export function parseManagedControlResult(value: unknown, profile: ManagedSshHandoff, action: string,
  expected: {path:string; expected_uid:number} | null = null): ManagedControlResult {
  if (!record(value) || !keys(value,["schema","action","binding","custody_status","owner","status","cleanup_complete","error_code","result_ref"]) ||
      value.schema !== "homie.managed-control-result.v1" || value.action !== action ||
      !isDeepStrictEqual(value.binding,profile.binding) ||
      !["absent","accepted","conflict","unknown"].includes(String(value.custody_status)) ||
      !["waiting","accepted","running","succeeded","failed","cancelled","cleanup_pending","rejected"].includes(String(value.status)) ||
      typeof value.cleanup_complete !== "boolean") return invalid();
  if (value.owner !== null && !validManagedHandoffOwner(value.owner,profile.binding)) return invalid();
  if (value.cleanup_complete && (value.owner === null || value.custody_status !== "accepted" ||
      !["succeeded","failed","cancelled"].includes(String(value.status)))) return invalid();
  if (value.result_ref !== null) {
    const ref=value.result_ref;
    if (!expected || !record(ref) || !keys(ref,["path","sha256","size_bytes","media_type","expected_uid","expected_mode"]) ||
        ref.path !== expected.path || ref.expected_uid !== expected.expected_uid ||
        typeof ref.sha256!=="string" || !/^[a-f0-9]{64}$/.test(ref.sha256) ||
        !Number.isSafeInteger(ref.size_bytes) || Number(ref.size_bytes)<1 || Number(ref.size_bytes)>65536 ||
        ref.media_type!=="application/json" || ref.expected_mode!==0o600 ||
        value.status!=="succeeded" || value.cleanup_complete!==true) return invalid();
  }
  if (value.status==="succeeded" && (value.cleanup_complete!==true || value.error_code!==null || value.result_ref===null)) return invalid();
  return value as unknown as ManagedControlResult;
}
