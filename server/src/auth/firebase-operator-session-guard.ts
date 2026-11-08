import { createHash, randomUUID } from "node:crypto";
import { and, eq } from "drizzle-orm";
import { ROOT_CONTEXT, trace } from "@opentelemetry/api";
import {
  authSessions,
  authUsers,
  companyMemberships,
  companies,
  firebaseOperatorBindings,
  firebaseOperatorSessionAssurance,
  instanceUserRoles,
  type Db,
} from "@paperclipai/db";
import { FirebaseOperatorVerificationError, type FirebaseOperatorProof } from "./firebase-operator-verifier.js";
import { logger } from "../middleware/logger.js";

export type FirebaseOperatorGuardReason =
  | "unbound" | "allowed" | "assurance_missing" | "binding_invalid"
  | "session_expired" | "idle_expired" | "company_forbidden"
  | "instance_admin_forbidden" | "firebase_denied" | "dependency_unavailable";
export type FirebaseOperatorGuardDecision =
  | { kind: "unbound" }
  | { kind: "allowed"; checkedAtMs: number; bindingId: string; bindingRevision: number; absoluteExpiresAt: Date }
  | { kind: "denied"; status: 401 | 403 | 503; reason: Exclude<FirebaseOperatorGuardReason, "unbound" | "allowed"> };
export type FirebaseOperatorUserState =
  | { kind: "ordinary" }
  | { kind: "operator_state"; enabledBinding: { id: string; revision: number } | null }
  | { kind: "unavailable" };

const UNBOUND = { kind: "unbound" } as const;
const unavailable = (): FirebaseOperatorGuardDecision => ({ kind: "denied", status: 503, reason: "dependency_unavailable" });
const denied = (status: 401 | 403, reason: Exclude<FirebaseOperatorGuardReason, "unbound" | "allowed" | "dependency_unavailable">): FirebaseOperatorGuardDecision => ({ kind: "denied", status, reason });
const factorsHash = (factors: unknown) => {
  const normalized = Array.isArray(factors)
    ? factors.map((factor) => ({ factorId: (factor as { factorId?: unknown })?.factorId, uid: (factor as { uid?: unknown })?.uid }))
      .sort((left, right) => String(left.uid).localeCompare(String(right.uid)))
    : factors;
  return createHash("sha256").update(JSON.stringify(normalized)).digest("hex");
};

export function emitFirebaseOperatorGuardDenial(
  reason: Exclude<FirebaseOperatorGuardReason, "unbound" | "allowed">,
  status: 401 | 403 | 503,
  routeFamily: "http" | "better_auth" = "http",
): void {
  const correlationId = randomUUID();
  try { logger.warn({ event: "guard", outcome: "denied", reason, status, routeFamily, correlationId }, "Firebase operator session request denied"); } catch { /* audit cannot affect authorization */ }
  let span;
  try { span = trace.getTracer("paperclip.firebase-operator-session").startSpan("firebase.operator_session.guard", undefined, ROOT_CONTEXT); }
  catch { return; }
  try { span.setAttribute("firebase_operator.outcome", "denied"); } catch { /* best effort */ }
  try { span.setAttribute("firebase_operator.reason", reason); } catch { /* best effort */ }
  try { span.setAttribute("firebase_operator.status", status); } catch { /* best effort */ }
  try { span.setAttribute("firebase_operator.route_family", routeFamily); } catch { /* best effort */ }
  try { span.end(); } catch { /* best effort */ }
}

type Snapshot = {
  session: typeof authSessions.$inferSelect | undefined;
  assurance: typeof firebaseOperatorSessionAssurance.$inferSelect | undefined;
  binding: typeof firebaseOperatorBindings.$inferSelect | undefined;
  anyBinding: boolean;
  anyAssurance: boolean;
};

export function createFirebaseOperatorSessionGuard(deps: {
  db: Db;
  verifier: { checkUser(proof: FirebaseOperatorProof): Promise<FirebaseOperatorProof> };
  now?: () => number;
  maxPositiveCacheEntries?: number;
}) {
  const now = deps.now ?? Date.now;
  const cache = new Map<string, { checkedAtMs: number; deadline: number; bindingId: string; bindingRevision: number; absoluteExpiresAt: Date }>();
  const maxEntries = Math.max(1, Math.min(deps.maxPositiveCacheEntries ?? 256, 4096));

  async function readUserState(userId: string): Promise<FirebaseOperatorUserState> {
    try {
      const { bindings, assurances } = await deps.db.transaction(async (tx) => {
        await tx.select({ id: authUsers.id }).from(authUsers).where(eq(authUsers.id, userId)).for("update").limit(1);
        const bindings = await tx.select({ id: firebaseOperatorBindings.id, revision: firebaseOperatorBindings.revision, enabled: firebaseOperatorBindings.enabled })
          .from(firebaseOperatorBindings).where(eq(firebaseOperatorBindings.userId, userId));
        const assurances = await tx.select({ id: firebaseOperatorSessionAssurance.id }).from(firebaseOperatorSessionAssurance)
          .where(eq(firebaseOperatorSessionAssurance.userId, userId)).limit(1);
        return { bindings, assurances };
      }, { isolationLevel: "read committed" });
      if (!bindings.length && !assurances.length) return { kind: "ordinary" };
      const enabled = bindings.find((row) => row.enabled);
      return { kind: "operator_state", enabledBinding: enabled ? { id: enabled.id, revision: enabled.revision } : null };
    } catch {
      return { kind: "unavailable" };
    }
  }

  async function snapshot(sessionId: string, userId: string): Promise<Snapshot> {
    const [sessions, assurances, bindings, anyBindings, anyAssurances] = await Promise.all([
      deps.db.select().from(authSessions).where(eq(authSessions.id, sessionId)).limit(1),
      deps.db.select().from(firebaseOperatorSessionAssurance).where(eq(firebaseOperatorSessionAssurance.sessionId, sessionId)).limit(1),
      deps.db.select().from(firebaseOperatorBindings).where(eq(firebaseOperatorBindings.userId, userId)),
      deps.db.select({ id: firebaseOperatorBindings.id }).from(firebaseOperatorBindings).where(eq(firebaseOperatorBindings.userId, userId)).limit(1),
      deps.db.select({ id: firebaseOperatorSessionAssurance.id }).from(firebaseOperatorSessionAssurance).where(eq(firebaseOperatorSessionAssurance.userId, userId)).limit(1),
    ]);
    const assurance = assurances[0];
    const binding = assurance ? bindings.find((row) => row.id === assurance.bindingId) : bindings.find((row) => row.enabled);
    return { session: sessions[0], assurance, binding, anyBinding: anyBindings.length > 0, anyAssurance: anyAssurances.length > 0 };
  }

  async function removeOwned(sessionId: string, userId: string): Promise<void> {
    try {
      await deps.db.delete(authSessions).where(and(eq(authSessions.id, sessionId), eq(authSessions.userId, userId)));
    } catch { /* cleanup failure does not change the closed denial */ }
  }

  async function authorizeCurrent(input: { sessionId: string; userId: string; companyId?: string }, expected: Snapshot, checkedAtMs: number, persistCheck: boolean): Promise<FirebaseOperatorGuardDecision> {
    try {
      return await deps.db.transaction(async (tx) => {
        await tx.select({ id: authUsers.id }).from(authUsers).where(eq(authUsers.id, input.userId)).for("update").limit(1);
        await tx.select({ id: firebaseOperatorBindings.id }).from(firebaseOperatorBindings)
          .where(eq(firebaseOperatorBindings.userId, input.userId)).for("update");
        await tx.select({ id: firebaseOperatorSessionAssurance.id }).from(firebaseOperatorSessionAssurance)
          .where(eq(firebaseOperatorSessionAssurance.sessionId, input.sessionId)).for("update").limit(1);
        const sessionRows = await tx.select().from(authSessions).where(eq(authSessions.id, input.sessionId)).for("update").limit(1);
        const session = sessionRows[0];
        const assurance = (await tx.select().from(firebaseOperatorSessionAssurance).where(eq(firebaseOperatorSessionAssurance.sessionId, input.sessionId)).limit(1))[0];
        const binding = assurance
          ? (await tx.select().from(firebaseOperatorBindings).where(eq(firebaseOperatorBindings.id, assurance.bindingId)).for("update").limit(1))[0]
          : undefined;
        const currentNow = now();
        if (!session || session.userId !== input.userId) return denied(401, "assurance_missing");
        if (!assurance) return denied(401, "assurance_missing");
        if (!binding || !binding.enabled || assurance.userId !== input.userId || binding.userId !== input.userId
          || assurance.bindingId !== binding.id || assurance.bindingRevision !== binding.revision
          || expected.assurance?.id !== assurance.id || expected.binding?.id !== binding.id
          || expected.binding.revision !== binding.revision || assurance.projectId !== binding.projectId
          || assurance.firebaseUid !== binding.firebaseUid) return denied(401, "binding_invalid");
        if (session.expiresAt.getTime() <= currentNow || assurance.absoluteExpiresAt.getTime() <= currentNow
          || session.createdAt.getTime() + 8 * 60 * 60_000 <= currentNow) return denied(401, "session_expired");
        if (assurance.lastInteractiveAt.getTime() + 30 * 60_000 <= currentNow) return denied(401, "idle_expired");
        const [user, admins, memberships] = await Promise.all([
          tx.select({ id: authUsers.id }).from(authUsers).where(eq(authUsers.id, input.userId)).limit(1),
          tx.select({ id: instanceUserRoles.id }).from(instanceUserRoles)
            .where(and(eq(instanceUserRoles.userId, input.userId), eq(instanceUserRoles.role, "instance_admin"))).for("update").limit(1),
          tx.select({ id: companyMemberships.id, companyId: companyMemberships.companyId }).from(companyMemberships)
            .innerJoin(companies, eq(companies.id, companyMemberships.companyId))
            .where(and(eq(companyMemberships.principalType, "user"), eq(companyMemberships.principalId, input.userId), eq(companyMemberships.status, "active"), eq(companies.status, "active"))).for("update"),
        ]);
        if (!user.length) return denied(401, "binding_invalid");
        if (admins.length) return denied(403, "instance_admin_forbidden");
        if (!memberships.length || (input.companyId && !memberships.some((row) => row.companyId === input.companyId))) return denied(403, "company_forbidden");
        if (currentNow > checkedAtMs + 60_000) return unavailable();
        if (persistCheck) {
          await tx.update(firebaseOperatorSessionAssurance).set({ lastAuthoritativeCheckAt: new Date(checkedAtMs) })
            .where(eq(firebaseOperatorSessionAssurance.sessionId, input.sessionId));
        }
        const afterAwaitNow = now();
        if (afterAwaitNow > checkedAtMs + 60_000) return unavailable();
        if (session.expiresAt.getTime() <= afterAwaitNow || assurance.absoluteExpiresAt.getTime() <= afterAwaitNow
          || session.createdAt.getTime() + 8 * 60 * 60_000 <= afterAwaitNow) return denied(401, "session_expired");
        if (assurance.lastInteractiveAt.getTime() + 30 * 60_000 <= afterAwaitNow) return denied(401, "idle_expired");
        return { kind: "allowed", checkedAtMs, bindingId: binding.id, bindingRevision: binding.revision, absoluteExpiresAt: assurance.absoluteExpiresAt };
      }, { isolationLevel: "repeatable read" });
    } catch {
      return unavailable();
    }
  }

  async function checkInternal(input: { sessionId: string; userId: string; companyId?: string }): Promise<FirebaseOperatorGuardDecision> {
    let initial: Snapshot;
    try { initial = await snapshot(input.sessionId, input.userId); }
    catch { return unavailable(); }
    if (initial.session && initial.session.userId !== input.userId) return denied(401, "binding_invalid");
    if (!initial.anyBinding && !initial.anyAssurance) return UNBOUND;
    if (!initial.assurance) {
      await removeOwned(input.sessionId, input.userId);
      return denied(401, "assurance_missing");
    }
    if (!initial.binding || !initial.binding.enabled || initial.assurance.userId !== input.userId
      || initial.binding.userId !== input.userId || initial.assurance.bindingRevision !== initial.binding.revision
      || initial.assurance.projectId !== initial.binding.projectId || initial.assurance.firebaseUid !== initial.binding.firebaseUid) {
      await removeOwned(input.sessionId, input.userId);
      return denied(401, "binding_invalid");
    }
    const initialNow = now();
    if (!initial.session || initial.session.expiresAt.getTime() <= initialNow
      || initial.assurance.absoluteExpiresAt.getTime() <= initialNow
      || initial.session.createdAt.getTime() + 8 * 60 * 60_000 <= initialNow) {
      await removeOwned(input.sessionId, input.userId);
      return denied(401, "session_expired");
    }
    if (initial.assurance.lastInteractiveAt.getTime() + 30 * 60_000 <= initialNow) {
      await removeOwned(input.sessionId, input.userId);
      return denied(401, "idle_expired");
    }
    const assurance = initial.assurance;
    const key = [input.userId, input.sessionId, initial.binding.id, initial.binding.revision, assurance.authTimeSeconds, factorsHash(assurance.totpFactors)].join("|");
    const atStart = now();
    const cached = cache.get(key);
    let checkedAtMs: number;
    if (cached && atStart < cached.deadline) {
      checkedAtMs = cached.checkedAtMs;
      cache.delete(key); cache.set(key, cached);
    } else {
      if (cached) cache.delete(key);
      const proof: FirebaseOperatorProof = {
        projectId: assurance.projectId as FirebaseOperatorProof["projectId"], uid: assurance.firebaseUid,
        authTimeSeconds: assurance.authTimeSeconds, checkedAtMs: atStart, totpFactors: assurance.totpFactors,
      };
      let result: FirebaseOperatorProof;
      try { result = await deps.verifier.checkUser(proof); }
      catch (error) {
        if (error instanceof FirebaseOperatorVerificationError && error.status === 401) {
          await removeOwned(input.sessionId, input.userId);
          return denied(401, "firebase_denied");
        }
        return unavailable();
      }
      checkedAtMs = result.checkedAtMs;
      if (!Number.isSafeInteger(checkedAtMs) || checkedAtMs > now() || atStart > checkedAtMs + 60_000 || now() > atStart + 60_000
        || result.projectId !== assurance.projectId || result.uid !== assurance.firebaseUid
        || result.authTimeSeconds !== assurance.authTimeSeconds
        || factorsHash(result.totpFactors) !== factorsHash(assurance.totpFactors)) return unavailable();
    }
    const cacheHit = Boolean(cached && atStart < cached.deadline);
    let decision = await authorizeCurrent(input, initial, checkedAtMs, !cacheHit);
    if (decision.kind === "denied" && decision.status === 503) {
      try {
        const latest = await snapshot(input.sessionId, input.userId);
        if (!latest.assurance || !latest.binding || !latest.binding.enabled
          || latest.assurance.bindingId !== initial.assurance.bindingId
          || latest.assurance.bindingRevision !== initial.assurance.bindingRevision
          || latest.binding.id !== initial.binding.id
          || latest.binding.revision !== initial.binding.revision) {
          decision = denied(401, "binding_invalid");
        }
      } catch { /* retain closed unavailable decision */ }
    }
    if (decision.kind === "allowed") {
      try {
        const [completedSession] = await deps.db.select().from(authSessions).where(eq(authSessions.id, input.sessionId)).limit(1);
        const [completedAssurance] = await deps.db.select().from(firebaseOperatorSessionAssurance)
          .where(eq(firebaseOperatorSessionAssurance.sessionId, input.sessionId)).limit(1);
        const completedAt = now();
        if (!completedSession || completedSession.userId !== input.userId || !completedAssurance) {
          decision = denied(401, "session_expired");
        } else if (completedSession.expiresAt.getTime() <= completedAt || completedAssurance.absoluteExpiresAt.getTime() <= completedAt
          || completedSession.createdAt.getTime() + 8 * 60 * 60_000 <= completedAt) {
          decision = denied(401, "session_expired");
        } else if (completedAssurance.lastInteractiveAt.getTime() + 30 * 60_000 <= completedAt) {
          decision = denied(401, "idle_expired");
        } else if (completedAt > checkedAtMs + 60_000) {
          decision = unavailable();
        }
      } catch { decision = unavailable(); }
      if (decision.kind !== "allowed") {
        if (decision.kind === "denied" && decision.status === 401) await removeOwned(input.sessionId, input.userId);
        return decision;
      }
      const deadline = checkedAtMs + 60_000;
      if (now() > deadline) return unavailable();
      if (!cached || atStart >= cached.deadline) {
        cache.set(key, { checkedAtMs, deadline, bindingId: decision.bindingId, bindingRevision: decision.bindingRevision, absoluteExpiresAt: decision.absoluteExpiresAt });
        while (cache.size > maxEntries) cache.delete(cache.keys().next().value!);
      }
    } else if (decision.kind === "denied" && decision.status === 401) {
      await removeOwned(input.sessionId, input.userId);
    } else if (decision.kind === "denied" && decision.reason === "company_forbidden" && !input.companyId) {
      try {
        const [active] = await deps.db.select({ id: companyMemberships.id }).from(companyMemberships)
          .innerJoin(companies, eq(companies.id, companyMemberships.companyId))
          .where(and(eq(companyMemberships.principalType, "user"), eq(companyMemberships.principalId, input.userId), eq(companyMemberships.status, "active"), eq(companies.status, "active"))).limit(1);
        if (!active) await removeOwned(input.sessionId, input.userId);
      } catch { /* a membership query failure does not widen access */ }
    }
    return decision;
  }

  async function check(input: { sessionId: string; userId: string; companyId?: string }): Promise<FirebaseOperatorGuardDecision> {
    const decision = await checkInternal(input);
    if (decision.kind === "denied") emitFirebaseOperatorGuardDenial(decision.reason, decision.status);
    return decision;
  }

  return { check, readUserState };
}
