import { createHash, randomUUID } from "node:crypto";
import { and, eq, inArray } from "drizzle-orm";
import {
  authSessions, authUsers, companies, companyMemberships, firebaseOperatorBindings,
  firebaseOperatorProvisionEvents, firebaseOperatorProvisionPackets,
  firebaseOperatorSessionAssurance, instanceUserRoles, principalPermissionGrants,
  type Db,
} from "@paperclipai/db";
import { authorizationService, type AuthorizationActor } from "../services/authorization.js";
import { grantsForHumanRole } from "../services/company-member-roles.js";
import { createProductionFirebaseOperatorIdentityDirectory, FirebaseOperatorVerificationError, type FirebaseOperatorIdentity } from "./firebase-operator-verifier.js";

const PROJECT_ID = "thl-pclipd-api" as const;
const PACKET_LIFETIME_MS = 5 * 60_000;
const MAX_IDENTITY_AGE_MS = 60_000;
const ROLES = new Set(["owner", "admin", "operator", "viewer"]);
type Role = "owner" | "admin" | "operator" | "viewer";
export type FirebaseOperatorActor = { type: "board"; source: "session" | "board_key"; userId: string };
export type FirebaseOperatorIntent = {
  projectId: typeof PROJECT_ID;
  firebaseUid: string;
  targetUserId: string;
  binding: { mode: "create" | "reassign" | "reenable"; expectedRevision: number | null; expectedUserId: string | null };
  companies: Array<{ companyId: string; role: Role }>;
};
type IdentityDirectory = { lookup(uid: string): Promise<unknown> };
type Options = { identityDirectory: IdentityDirectory; allowedCompanyIds: Set<string>; now?: () => number };

export class FirebaseOperatorProvisioningError extends Error {
  constructor(readonly status: 400 | 401 | 403 | 404 | 409 | 503, message: string) { super(message); this.name = "FirebaseOperatorProvisioningError"; }
}
function fail(status: FirebaseOperatorProvisioningError["status"], message: string): never { throw new FirebaseOperatorProvisioningError(status, message); }
function isRecord(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value); }
function canonical(value: unknown): string {
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (isRecord(value)) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}
function digest(value: unknown): string { return createHash("sha256").update(canonical(value)).digest("hex"); }
function reviewHash(actorUserId: string, intent: FirebaseOperatorIntent, expectedBindingState: unknown, expectedGrantStateHash: string, expiresAt: Date): string {
  return digest({ actorUserId, intent, expectedBindingState, expectedGrantStateHash, expiresAt });
}
function normalizedIntent(input: unknown, allowed: Set<string>): FirebaseOperatorIntent {
  if (!isRecord(input) || input.projectId !== PROJECT_ID || typeof input.firebaseUid !== "string" || !input.firebaseUid.trim() || input.firebaseUid.length > 128 ||
      typeof input.targetUserId !== "string" || !input.targetUserId || !isRecord(input.binding) ||
      !["create", "reassign", "reenable"].includes(String(input.binding.mode)) || !Array.isArray(input.companies) || input.companies.length === 0) fail(400, "Invalid provisioning intent");
  const mode = input.binding.mode as FirebaseOperatorIntent["binding"]["mode"];
  const revision = input.binding.expectedRevision;
  const priorUserId = input.binding.expectedUserId;
  if (mode === "create" ? revision !== null || priorUserId !== null : !Number.isSafeInteger(revision) || Number(revision) < 1 || typeof priorUserId !== "string" || !priorUserId || (mode === "reassign" && priorUserId === input.targetUserId)) fail(400, "Invalid expected binding state");
  if (input.firebaseUid.trim() !== input.firebaseUid) fail(400, "Invalid Firebase UID");
  const seen = new Set<string>();
  const normalizedCompanies = input.companies.map((entry) => {
    if (!isRecord(entry) || typeof entry.companyId !== "string" || !allowed.has(entry.companyId) || typeof entry.role !== "string" || !ROLES.has(entry.role) || seen.has(entry.companyId)) fail(400, "Invalid reviewed company scope");
    seen.add(entry.companyId);
    return { companyId: entry.companyId, role: entry.role as Role };
  }).sort((a, b) => a.companyId.localeCompare(b.companyId));
  return { projectId: PROJECT_ID, firebaseUid: input.firebaseUid, targetUserId: input.targetUserId, binding: { mode, expectedRevision: revision as number | null, expectedUserId: priorUserId as string | null }, companies: normalizedCompanies };
}
function trustedActor(input: unknown): FirebaseOperatorActor {
  if (!isRecord(input) || input.type !== "board" || !["session", "board_key"].includes(String(input.source)) || typeof input.userId !== "string" || input.userId.length === 0) fail(403, "Trusted board actor required");
  return { type: "board", source: input.source as "session" | "board_key", userId: input.userId };
}
function validIdentity(value: unknown, uid: string, now: number): FirebaseOperatorIdentity {
  if (!isRecord(value) || value.projectId !== PROJECT_ID || value.uid !== uid || !Number.isSafeInteger(value.checkedAtMs) || Number(value.checkedAtMs) > now || now - Number(value.checkedAtMs) > MAX_IDENTITY_AGE_MS) fail(401, "Firebase identity is not current and eligible");
  return { projectId: PROJECT_ID, uid, checkedAtMs: Number(value.checkedAtMs) };
}
function mapProviderError(error: unknown): never {
  if (error instanceof FirebaseOperatorVerificationError) fail(error.status, error.message);
  fail(503, "Firebase identity lookup is unavailable");
}
function isRetryableDatabaseError(error: unknown): boolean {
  let current: unknown = error;
  for (let depth = 0; depth < 5 && isRecord(current); depth += 1) {
    if (typeof current.code === "string" && ["40001", "40P01", "23505"].includes(current.code)) return true;
    current = current.cause;
  }
  return false;
}
function safeDatabaseFailure(error: unknown): never {
  if (isRetryableDatabaseError(error)) fail(409, "Provisioning state changed; create a new review packet");
  throw error;
}

async function lookup(directory: IdentityDirectory, uid: string, now: () => number): Promise<FirebaseOperatorIdentity> {
  let value: unknown;
  try { value = await directory.lookup(uid); } catch (error) { mapProviderError(error); }
  return validIdentity(value, uid, now());
}

async function lockAndAuthorize(tx: Db, actor: FirebaseOperatorActor, intent: FirebaseOperatorIntent, checkBinding = true, checkTargetScopes = true): Promise<void> {
  const actorRows = await tx.select({ id: authUsers.id }).from(authUsers).where(eq(authUsers.id, actor.userId)).for("update");
  const adminRows = await tx.select({ id: instanceUserRoles.id }).from(instanceUserRoles)
    .where(and(eq(instanceUserRoles.userId, actor.userId), eq(instanceUserRoles.role, "instance_admin"))).for("update");
  if (!actorRows.length || !adminRows.length) fail(403, "Current instance administrator required");
  const target = await tx.select({ id: authUsers.id }).from(authUsers).where(eq(authUsers.id, intent.targetUserId)).for("update");
  if (!target.length) fail(404, "Target Paperclip user does not exist");
  const targetAdmin = await tx.select({ id: instanceUserRoles.id }).from(instanceUserRoles)
    .where(and(eq(instanceUserRoles.userId, intent.targetUserId), eq(instanceUserRoles.role, "instance_admin"))).for("update");
  if (targetAdmin.length) fail(400, "Instance administrators cannot be Firebase binding targets");

  const existingBinding = await tx.select().from(firebaseOperatorBindings)
    .where(and(eq(firebaseOperatorBindings.projectId, PROJECT_ID), eq(firebaseOperatorBindings.firebaseUid, intent.firebaseUid))).for("update");
  const current = existingBinding[0];
  if (checkBinding && intent.binding.mode === "create") {
    if (current) fail(409, "Firebase UID is already bound");
  } else if (checkBinding && (!current || current.revision !== intent.binding.expectedRevision || current.userId !== intent.binding.expectedUserId ||
      (intent.binding.mode === "reassign" ? !current.enabled : current.enabled))) {
    fail(409, "Expected Firebase binding state no longer matches");
  }
  const enabledUserBinding = await tx.select({ id: firebaseOperatorBindings.id }).from(firebaseOperatorBindings)
    .where(and(eq(firebaseOperatorBindings.userId, intent.targetUserId), eq(firebaseOperatorBindings.enabled, true))).for("update");
  if (enabledUserBinding.some((row) => row.id !== current?.id)) fail(409, "Target user already has an enabled Firebase binding");

  const affected = new Set(intent.companies.map((scope) => scope.companyId));
  if (checkTargetScopes) {
    const targetMemberships = await tx.select({ companyId: companyMemberships.companyId }).from(companyMemberships)
      .where(and(eq(companyMemberships.principalType, "user"), eq(companyMemberships.principalId, intent.targetUserId), eq(companyMemberships.status, "active"))).for("update");
    for (const membership of targetMemberships) if (!affected.has(membership.companyId)) fail(400, "Review every active company scope for the target user");
  }
  if (current && (intent.binding.mode === "reassign" || intent.binding.mode === "reenable")) {
    const oldMemberships = await tx.select({ companyId: companyMemberships.companyId }).from(companyMemberships)
      .where(and(eq(companyMemberships.principalType, "user"), eq(companyMemberships.principalId, current.userId), eq(companyMemberships.status, "active"))).for("update");
    for (const membership of oldMemberships) if (!affected.has(membership.companyId)) fail(400, "Review every active company scope for the prior binding");
  }
  const companyIds = [...affected].sort();
  const companyRows = await tx.select({ id: companies.id, status: companies.status }).from(companies).where(inArray(companies.id, companyIds)).orderBy(companies.id).for("update");
  if (companyRows.length !== companyIds.length || companyRows.some((company) => company.status !== "active")) fail(409, "Every reviewed company must be active");
  const authz = authorizationService(tx);
  const authorizationActor: AuthorizationActor = { type: "board", source: actor.source, userId: actor.userId, ignoreInstanceAdmin: true };
  for (const companyId of companyIds) {
    const memberships = await tx.select({ membershipRole: companyMemberships.membershipRole }).from(companyMemberships)
      .where(and(eq(companyMemberships.companyId, companyId), eq(companyMemberships.principalType, "user"), eq(companyMemberships.principalId, actor.userId), eq(companyMemberships.status, "active"))).for("update");
    if (!memberships.length || memberships.some((membership) => membership.membershipRole === "viewer")) fail(403, "Active nonviewer company membership required");
    const grantRows = await tx.select({ id: principalPermissionGrants.id }).from(principalPermissionGrants)
      .where(and(eq(principalPermissionGrants.companyId, companyId), eq(principalPermissionGrants.principalType, "user"), eq(principalPermissionGrants.principalId, actor.userId))).for("update");
    void grantRows;
    const decision = await authz.decidePrincipalGrant({ companyId, principalType: "user", principalId: actor.userId, action: "users:manage_permissions", permissionKey: "users:manage_permissions" });
    if (!decision.allowed) fail(403, "Company permission to manage users is required");
  }
}

async function grantState(tx: Db, intent: FirebaseOperatorIntent): Promise<{ memberships: unknown[]; grants: unknown[]; hash: string }> {
  const companyIds = intent.companies.map((item) => item.companyId);
  const memberships = await tx.select().from(companyMemberships).where(and(inArray(companyMemberships.companyId, companyIds), eq(companyMemberships.principalType, "user"), eq(companyMemberships.principalId, intent.targetUserId))).orderBy(companyMemberships.companyId, companyMemberships.id).for("update");
  const grants = await tx.select().from(principalPermissionGrants).where(and(inArray(principalPermissionGrants.companyId, companyIds), eq(principalPermissionGrants.principalType, "user"), eq(principalPermissionGrants.principalId, intent.targetUserId))).orderBy(principalPermissionGrants.companyId, principalPermissionGrants.permissionKey, principalPermissionGrants.id).for("update");
  const state = { memberships, grants };
  return { ...state, hash: digest(state) };
}

function additions(state: { memberships: unknown[]; grants: unknown[] }, intent: FirebaseOperatorIntent): { membershipIds: string[]; grantValues: Array<{ companyId: string; permissionKey: string; scope: Record<string, unknown> | null }> } {
  const memberships = state.memberships as Array<typeof companyMemberships.$inferSelect>;
  const grants = state.grants as Array<typeof principalPermissionGrants.$inferSelect>;
  const membershipIds: string[] = [];
  const grantValues: Array<{ companyId: string; permissionKey: string; scope: Record<string, unknown> | null }> = [];
  for (const item of intent.companies) {
    const existing = memberships.filter((row) => row.companyId === item.companyId);
    if (existing.length > 1 || existing.some((row) => row.status !== "active" || row.membershipRole !== item.role)) fail(409, "Target has inactive or conflicting company membership");
    const existingGrants = grants.filter((row) => row.companyId === item.companyId);
    if (!existing.length && existingGrants.length) fail(409, "Orphan permission grants must be reconciled before provisioning");
    if (!existing.length) membershipIds.push(item.companyId);
    for (const defaultGrant of grantsForHumanRole(item.role)) {
      if (!existingGrants.some((row) => row.permissionKey === defaultGrant.permissionKey)) grantValues.push({ companyId: item.companyId, permissionKey: defaultGrant.permissionKey, scope: defaultGrant.scope ?? null });
    }
  }
  return { membershipIds, grantValues };
}

export function createFirebaseOperatorProvisioner(db: Db, options: Options) {
  const now = options.now ?? Date.now;
  async function transaction<T>(operation: (tx: Db) => Promise<T>): Promise<T> {
    try { return await db.transaction(async (tx) => operation(tx as unknown as Db), { isolationLevel: "serializable" }); }
    catch (error) { return safeDatabaseFailure(error); }
  }
  return {
    async dryRun(actorInput: unknown, intentInput: unknown) {
      const actor = trustedActor(actorInput);
      const intent = normalizedIntent(intentInput, options.allowedCompanyIds);
      const proof = await lookup(options.identityDirectory, intent.firebaseUid, now);
      return transaction(async (tx) => {
        await lockAndAuthorize(tx, actor, intent);
        if (now() - proof.checkedAtMs > MAX_IDENTITY_AGE_MS) fail(401, "Firebase identity lookup expired");
        const [binding] = await tx.select().from(firebaseOperatorBindings).where(and(eq(firebaseOperatorBindings.projectId, PROJECT_ID), eq(firebaseOperatorBindings.firebaseUid, intent.firebaseUid)));
        const state = await grantState(tx, intent);
        const plan = additions(state, intent);
        const packetId = randomUUID();
        const expiresAt = new Date(now() + PACKET_LIFETIME_MS);
        const expectedBindingState = binding ? { id: binding.id, userId: binding.userId, revision: binding.revision, enabled: binding.enabled } : null;
        const packetHash = reviewHash(actor.userId, intent, expectedBindingState, state.hash, expiresAt);
        await tx.insert(firebaseOperatorProvisionPackets).values({ id: packetId, actorUserId: actor.userId, intentHash: packetHash, intent, expectedBindingState, expectedGrantStateHash: state.hash, expiresAt, status: "pending" });
        await tx.insert(firebaseOperatorProvisionEvents).values({ packetId, actorUserId: actor.userId, action: "dry_run", outcome: "review_ready", details: { packetHash, bindingRevision: binding?.revision ?? null, addMembershipCount: plan.membershipIds.length, addGrantCount: plan.grantValues.length, identityCheckedAtMs: proof.checkedAtMs } });
        return { packetId, packetHash, expiresAt, bindingBefore: binding ? { userId: binding.userId, revision: binding.revision, enabled: binding.enabled } : null, plan: { companies: intent.companies, addMembershipCompanyIds: plan.membershipIds, addGrants: plan.grantValues.map(({ companyId, permissionKey }) => ({ companyId, permissionKey })) } };
      });
    },
    async apply(actorInput: unknown, input: { packetId: string; packetHash: string }) {
      const actor = trustedActor(actorInput);
      if (!isRecord(input) || typeof input.packetId !== "string" || typeof input.packetHash !== "string") fail(400, "Invalid review packet reference");
      const [preview] = await db.select().from(firebaseOperatorProvisionPackets).where(eq(firebaseOperatorProvisionPackets.id, input.packetId));
      if (!preview) fail(404, "Review packet not found");
      if (preview.actorUserId !== actor.userId) fail(403, "Review packet belongs to another actor");
      if (preview.status !== "pending" || preview.intentHash !== input.packetHash || preview.expiresAt.getTime() <= now()) fail(409, "Review packet is expired, changed, or already consumed");
      const intent = normalizedIntent(preview.intent, options.allowedCompanyIds);
      if (preview.intentHash !== reviewHash(preview.actorUserId, intent, preview.expectedBindingState, preview.expectedGrantStateHash, preview.expiresAt)) fail(409, "Review packet integrity check failed");
      const proof = await lookup(options.identityDirectory, intent.firebaseUid, now);
      return transaction(async (tx) => {
        await lockAndAuthorize(tx, actor, intent);
        const [packet] = await tx.select().from(firebaseOperatorProvisionPackets).where(eq(firebaseOperatorProvisionPackets.id, input.packetId)).for("update");
        if (!packet || packet.actorUserId !== actor.userId) fail(403, "Review packet belongs to another actor");
        if (packet.status !== "pending" || packet.intentHash !== input.packetHash || packet.intentHash !== reviewHash(packet.actorUserId, intent, packet.expectedBindingState, packet.expectedGrantStateHash, packet.expiresAt) || packet.expiresAt.getTime() <= now()) fail(409, "Review packet is expired, changed, or already consumed");
        if (now() - proof.checkedAtMs > MAX_IDENTITY_AGE_MS) fail(401, "Firebase identity lookup expired");
        const [current] = await tx.select().from(firebaseOperatorBindings).where(and(eq(firebaseOperatorBindings.projectId, PROJECT_ID), eq(firebaseOperatorBindings.firebaseUid, intent.firebaseUid))).for("update");
        const expected = packet.expectedBindingState as { id: string; userId: string; revision: number; enabled: boolean } | null;
        if (expected ? !current || current.id !== expected.id || current.userId !== expected.userId || current.revision !== expected.revision || current.enabled !== expected.enabled : Boolean(current)) fail(409, "Firebase binding changed after review");
        const state = await grantState(tx, intent);
        if (state.hash !== packet.expectedGrantStateHash) fail(409, "Target company grants changed after review");
        const toAdd = additions(state, intent);
        const priorUser = current?.userId;
        let bindingId: string;
        let revision: number;
        if (current) {
          bindingId = current.id; revision = current.revision + 1;
          const updated = await tx.update(firebaseOperatorBindings).set({ userId: intent.targetUserId, revision, enabled: true, updatedByUserId: actor.userId, updatedAt: new Date(now()) })
            .where(and(eq(firebaseOperatorBindings.id, current.id), eq(firebaseOperatorBindings.revision, current.revision))).returning({ id: firebaseOperatorBindings.id });
          if (!updated.length) fail(409, "Firebase binding revision changed during apply");
        } else {
          const [created] = await tx.insert(firebaseOperatorBindings).values({ projectId: PROJECT_ID, firebaseUid: intent.firebaseUid, userId: intent.targetUserId, revision: 1, enabled: true, createdByUserId: actor.userId, updatedByUserId: actor.userId, createdAt: new Date(now()), updatedAt: new Date(now()) }).returning({ id: firebaseOperatorBindings.id });
          bindingId = created.id; revision = 1;
        }
        const createdMembershipIds: string[] = [];
        for (const companyId of toAdd.membershipIds) {
          const role = intent.companies.find((item) => item.companyId === companyId)!.role;
          const [membership] = await tx.insert(companyMemberships).values({ companyId, principalType: "user", principalId: intent.targetUserId, status: "active", membershipRole: role }).returning({ id: companyMemberships.id });
          createdMembershipIds.push(membership.id);
        }
        const createdGrantIds: string[] = [];
        if (toAdd.grantValues.length) {
          const rows = await tx.insert(principalPermissionGrants).values(toAdd.grantValues.map((grant) => ({ ...grant, principalType: "user", principalId: intent.targetUserId, grantedByUserId: actor.userId }))).returning({ id: principalPermissionGrants.id });
          createdGrantIds.push(...rows.map((row) => row.id));
        }
        const affectedUsers = [...new Set([priorUser, intent.targetUserId].filter((userId): userId is string => Boolean(userId)))];
        const revoked = await tx.delete(authSessions).where(inArray(authSessions.userId, affectedUsers)).returning({ id: authSessions.id });
        const postState = await grantState(tx, intent);
        await tx.update(firebaseOperatorProvisionPackets).set({ status: "applied", appliedBindingId: bindingId, appliedBindingRevision: revision, createdMembershipIds, createdGrantIds, postGrantStateHash: postState.hash, updatedAt: new Date(now()) }).where(eq(firebaseOperatorProvisionPackets.id, packet.id));
        await tx.insert(firebaseOperatorProvisionEvents).values({ packetId: packet.id, actorUserId: actor.userId, action: "apply", outcome: "applied", details: { bindingId, bindingRevision: revision, createdMembershipIds, createdGrantIds, revokedSessionCount: revoked.length, identityCheckedAtMs: proof.checkedAtMs } });
        return { packetId: packet.id, bindingId, bindingRevision: revision, status: "applied" as const, createdMembershipIds, createdGrantIds, revokedSessionCount: revoked.length };
      });
    },
    async rollback(actorInput: unknown, input: { packetId: string; expectedBindingRevision: number }) {
      const actor = trustedActor(actorInput);
      const [preview] = await db.select().from(firebaseOperatorProvisionPackets).where(eq(firebaseOperatorProvisionPackets.id, input.packetId));
      if (!preview) fail(404, "Review packet not found");
      const intent = normalizedIntent(preview.intent, options.allowedCompanyIds);
      return transaction(async (tx) => {
        await lockAndAuthorize(tx, actor, intent, false, false);
        const [packet] = await tx.select().from(firebaseOperatorProvisionPackets).where(eq(firebaseOperatorProvisionPackets.id, input.packetId)).for("update");
        if (!packet || packet.actorUserId !== actor.userId) fail(403, "Review packet belongs to another actor");
        if (packet.status !== "applied" || !packet.appliedBindingId || packet.appliedBindingRevision !== input.expectedBindingRevision) fail(409, "Applied binding revision does not match");
        const [binding] = await tx.select().from(firebaseOperatorBindings).where(eq(firebaseOperatorBindings.id, packet.appliedBindingId)).for("update");
        if (!binding || !binding.enabled || binding.revision !== input.expectedBindingRevision) fail(409, "Current Firebase binding revision changed");
        const state = await grantState(tx, intent);
        const intact = state.hash === packet.postGrantStateHash;
        const nextRevision = binding.revision + 1;
        const disabled = await tx.update(firebaseOperatorBindings).set({ enabled: false, revision: nextRevision, updatedByUserId: actor.userId, updatedAt: new Date(now()) })
          .where(and(eq(firebaseOperatorBindings.id, binding.id), eq(firebaseOperatorBindings.revision, binding.revision))).returning({ id: firebaseOperatorBindings.id });
        if (!disabled.length) fail(409, "Firebase binding revision changed during rollback");
        const assurance = await tx.select({ sessionId: firebaseOperatorSessionAssurance.sessionId }).from(firebaseOperatorSessionAssurance)
          .where(and(eq(firebaseOperatorSessionAssurance.bindingId, binding.id), eq(firebaseOperatorSessionAssurance.bindingRevision, binding.revision))).for("update");
        let revokedSessionCount = 0;
        if (assurance.length) {
          const sessions = await tx.delete(authSessions).where(inArray(authSessions.id, assurance.map((row) => row.sessionId))).returning({ id: authSessions.id });
          revokedSessionCount = sessions.length;
        }
        let removedMembershipIds: string[] = [];
        let removedGrantIds: string[] = [];
        const conflicts: string[] = [];
        if (intact) {
          if (packet.createdGrantIds.length) {
            await tx.delete(principalPermissionGrants).where(inArray(principalPermissionGrants.id, packet.createdGrantIds));
            removedGrantIds = packet.createdGrantIds;
          }
          if (packet.createdMembershipIds.length) {
            await tx.delete(companyMemberships).where(inArray(companyMemberships.id, packet.createdMembershipIds));
            removedMembershipIds = packet.createdMembershipIds;
          }
        } else conflicts.push("target_company_grant_state_changed");
        const status = conflicts.length ? "partial" as const : "rolled_back" as const;
        await tx.update(firebaseOperatorProvisionPackets).set({ status, updatedAt: new Date(now()) }).where(eq(firebaseOperatorProvisionPackets.id, packet.id));
        await tx.insert(firebaseOperatorProvisionEvents).values({ packetId: packet.id, actorUserId: actor.userId, action: "rollback", outcome: status, details: { bindingDisabled: true, bindingRevision: nextRevision, revokedSessionCount, removedMembershipIds, removedGrantIds, conflicts } });
        return { packetId: packet.id, status, bindingDisabled: true, revokedSessionCount, conflicts, removedMembershipIds, removedGrantIds };
      });
    },
  };
}

export function createProductionFirebaseOperatorProvisioner(db: Db, options: { allowedCompanyIds: Set<string>; now?: () => number }) {
  return createFirebaseOperatorProvisioner(db, { ...options, identityDirectory: createProductionFirebaseOperatorIdentityDirectory() });
}
