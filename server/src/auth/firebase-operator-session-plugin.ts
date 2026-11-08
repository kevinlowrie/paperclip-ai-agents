import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { and, eq, gt, isNull } from "drizzle-orm";
import { createAuthEndpoint } from "better-auth/api";
import { deleteSessionCookie, setSessionCookie } from "better-auth/cookies";
import type { BetterAuthOptions } from "better-auth";
import { ROOT_CONTEXT, trace } from "@opentelemetry/api";
import type { Db } from "@paperclipai/db";
import {
  authSessions, authUsers, companyMemberships, companies, firebaseOperatorBindings,
  firebaseOperatorLoginTransactions, firebaseOperatorSessionAssurance,
  instanceUserRoles,
} from "@paperclipai/db";
import { logger } from "../middleware/logger.js";
import { createProductionFirebaseOperatorVerifier, FirebaseOperatorVerificationError } from "./firebase-operator-verifier.js";
import { getFirebaseOperatorPreAuthContext } from "./firebase-operator-session-preflight.js";
import type { FirebaseOperatorProof } from "./firebase-operator-verifier.js";

const BEGIN_PATH = "/api/auth/firebase-session/begin" as const;
const EXCHANGE_PATH = "/api/auth/firebase-session/exchange" as const;
const BEGIN_ENDPOINT = "/firebase-session/begin" as const;
const EXCHANGE_ENDPOINT = "/firebase-session/exchange" as const;
const PROJECT_ID = "thl-pclipd-api";
const TRANSACTION_COOKIE = "firebase_operator_transaction";
const TRANSACTION_TTL_MS = 300_000;
const PROOF_MAX_AGE_MS = 300_000;
const CHECK_MAX_AGE_MS = 60_000;
const SESSION_TTL_MS = 8 * 60 * 60_000;
type Proof = FirebaseOperatorProof;
export type FirebaseOperatorAuditEvent = {
  event: "begin" | "exchange" | "better_auth_log_suppressed";
  outcome: "created" | "issued" | "cancelled" | "denied" | "suppressed";
  reason: "accepted" | "cancelled" | "bad_request" | "origin_denied" | "rate_limited" | "transaction_invalid" | "proof_denied" | "binding_denied" | "company_denied" | "session_failed" | "assurance_failed" | "deadline_expired" | "dependency_unavailable" | "internal_failure" | "sdk_message_suppressed";
  correlationId: string;
  sdkLevel?: "debug" | "info" | "warn" | "error";
};
export type FirebaseOperatorAuditSink = (event: FirebaseOperatorAuditEvent) => void;
const safeAuthLogCallbacks = new WeakSet<Function>();

function defaultAudit(event: FirebaseOperatorAuditEvent): void {
  const fields = { event: event.event, outcome: event.outcome, reason: event.reason, correlationId: event.correlationId, ...(event.sdkLevel ? { sdkLevel: event.sdkLevel } : {}) };
  if (event.outcome === "denied") logger.warn(fields, "Firebase operator session request denied");
  else if (event.outcome === "cancelled") logger.info(fields, "Firebase operator session request cancelled");
  else if (event.event === "better_auth_log_suppressed") logger.debug(fields, "Better Auth log suppressed");
  else logger.info(fields, "Firebase operator session request completed");
}

function emitAudit(sink: FirebaseOperatorAuditSink, event: FirebaseOperatorAuditEvent): void {
  try { sink(event); } catch { /* audit sinks cannot change authentication outcomes */ }
}

function startSafeSpan(route: "begin" | "exchange") {
  try { return trace.getTracer("paperclip.firebase-operator-session").startSpan(`firebase.operator_session.${route}`, { attributes: { "firebase_operator.route": route } }, ROOT_CONTEXT); }
  catch { return undefined; }
}

function finishSafeSpan(span: ReturnType<typeof startSafeSpan>, outcome: FirebaseOperatorAuditEvent["outcome"], reason: FirebaseOperatorAuditEvent["reason"]): void {
  try {
    span?.setAttribute("firebase_operator.outcome", outcome);
    span?.setAttribute("firebase_operator.reason", reason);
    span?.end();
  } catch { /* observability cannot change authentication outcomes */ }
}

export function firebaseOperatorSafeAuthOptions(options: BetterAuthOptions, audit: FirebaseOperatorAuditSink = defaultAudit): BetterAuthOptions {
  const callback = (level: "debug" | "info" | "warn" | "error") => {
    emitAudit(audit, { event: "better_auth_log_suppressed", outcome: "suppressed", reason: "sdk_message_suppressed", correlationId: randomUUID(), sdkLevel: level });
  };
  safeAuthLogCallbacks.add(callback);
  return {
    ...options,
    experimental: { ...options.experimental, instrumentation: { ...options.experimental?.instrumentation, enabled: false } },
    logger: { ...options.logger, disabled: false, log: callback },
  };
}

type Deps = { db: Db; verifier: { verify(token: string): Promise<Proof> }; trustedOrigins: ReadonlySet<string>; allowedCompanyIds: ReadonlySet<string>; now?: () => number; audit?: FirebaseOperatorAuditSink };
type EndpointContext = {
  body?: unknown;
  request: Request;
  headers: Headers;
  setHeader(name: string, value: string): void;
  setCookie(name: string, value: string, options: Record<string, unknown>): void;
  error(status: string, body?: Record<string, unknown>): unknown;
  context: {
    authCookies: { sessionToken: { name: string; attributes: Record<string, unknown> } };
    sessionConfig: { expiresIn: number };
    secret: string;
    createAuthCookie(name: string, options?: Record<string, unknown>): { name: string; attributes: Record<string, unknown> };
    internalAdapter: {
      findUserById(userId: string): Promise<any>;
      createSession(userId: string, dontRememberMe?: boolean, override?: Record<string, unknown>, overrideAll?: boolean): Promise<any>;
      deleteSession(token: string): Promise<void>;
    };
  };
};
type SafeStatus = "BAD_REQUEST" | "UNAUTHORIZED" | "FORBIDDEN" | "CONFLICT" | "PAYLOAD_TOO_LARGE" | "SERVICE_UNAVAILABLE" | "INTERNAL_SERVER_ERROR";
class FirebaseSessionResponseError extends Error { constructor(readonly status: SafeStatus) { super("Firebase session request rejected"); } }

function record(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value); }
function sha256(value: string): string { return createHash("sha256").update(value).digest("hex"); }
function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left); const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}
function validReturnPath(value: unknown): value is string {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//") || value.includes("\\") || /[\u0000-\u001f\u007f]/.test(value) || value.length > 2048) return false;
  try { const parsed = new URL(value, "https://paperclip.invalid"); return parsed.origin === "https://paperclip.invalid" && parsed.pathname.startsWith("/"); } catch { return false; }
}
function canonicalOrigins(origins: ReadonlySet<string>): Set<string> {
  if (!(origins instanceof Set) || origins.size === 0) throw new Error("Firebase session origins must be a finite nonempty set");
  const authorities = new Set<string>();
  for (const origin of origins) {
    let parsed: URL;
    try { parsed = new URL(origin); } catch { throw new Error("Invalid Firebase session origin"); }
    if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash || parsed.origin !== origin || authorities.has(parsed.host.toLowerCase())) {
      throw new Error("Firebase session origins must be canonical HTTPS origins with unique authorities");
    }
    authorities.add(parsed.host.toLowerCase());
  }
  return new Set(origins);
}
function nowValue(now: () => number): number {
  const value = now();
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("Invalid clock");
  return value;
}
function proofIsFresh(proof: Proof, at: number): boolean {
  if (!record(proof) || proof.projectId !== PROJECT_ID || typeof proof.uid !== "string" || !proof.uid || proof.uid.length > 128 ||
      !Number.isSafeInteger(proof.authTimeSeconds) || !Number.isSafeInteger(proof.checkedAtMs) || !Array.isArray(proof.totpFactors) || proof.totpFactors.length === 0) return false;
  const authAt = proof.authTimeSeconds * 1000;
  return authAt <= at && at - authAt <= PROOF_MAX_AGE_MS && proof.checkedAtMs <= at && at - proof.checkedAtMs <= CHECK_MAX_AGE_MS && authAt <= proof.checkedAtMs &&
    proof.totpFactors.every((factor) => record(factor) && factor.factorId === "totp" && typeof factor.uid === "string" && factor.uid.length > 0);
}
function failure(_ctx: EndpointContext, status: SafeStatus): never {
  throw new FirebaseSessionResponseError(status);
}
function reportEndpointFailure(ctx: EndpointContext, error: unknown): never {
  if (error instanceof FirebaseSessionResponseError) throw ctx.error(error.status, { message: "Firebase operator session request rejected" });
  throw ctx.error("INTERNAL_SERVER_ERROR", { message: "Firebase operator session request rejected" });
}
function exactBody(value: unknown, keys: string[]): value is Record<string, unknown> {
  return record(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}
function originFor(ctx: EndpointContext, origins: Set<string>, path: typeof BEGIN_PATH | typeof EXCHANGE_PATH): string {
  const privateContext = getFirebaseOperatorPreAuthContext(path);
  // The ALS capability validates the untouched Express request; request headers here are only a consistency check.
  if (!privateContext) failure(ctx, "FORBIDDEN");
  const origin = ctx.request.headers.get("origin");
  if (!origin || !origins.has(origin) || origin !== privateContext.origin) failure(ctx, "FORBIDDEN");
  return origin;
}
function cookieFor(ctx: EndpointContext) {
  const cookie = ctx.context.createAuthCookie(TRANSACTION_COOKIE, { maxAge: 300 });
  return { name: cookie.name, attributes: { ...cookie.attributes, domain: undefined, path: "/", secure: true, httpOnly: true, sameSite: "strict", maxAge: 300 } };
}
function requestCookie(ctx: EndpointContext, name: string): string | undefined {
  const header = ctx.request.headers.get("cookie");
  if (!header) return undefined;
  for (const entry of header.split(";")) {
    const split = entry.indexOf("=");
    if (split < 0 || entry.slice(0, split).trim() !== name) continue;
    try { return decodeURIComponent(entry.slice(split + 1).trim()); } catch { return undefined; }
  }
  return undefined;
}
function expireTransactionCookie(ctx: EndpointContext): void {
  const cookie = cookieFor(ctx);
  ctx.setCookie(cookie.name, "", { ...cookie.attributes, maxAge: 0, expires: new Date(0) });
}
function genericStatus(error: unknown): "UNAUTHORIZED" | "SERVICE_UNAVAILABLE" | "INTERNAL_SERVER_ERROR" {
  if (error instanceof FirebaseOperatorVerificationError) return error.status === 503 ? "SERVICE_UNAVAILABLE" : "UNAUTHORIZED";
  return "SERVICE_UNAVAILABLE";
}

function reasonForStatus(error: unknown): FirebaseOperatorAuditEvent["reason"] {
  if (error instanceof FirebaseSessionResponseError) {
    if (error.status === "BAD_REQUEST") return "bad_request";
    if (error.status === "FORBIDDEN") return "binding_denied";
    if (error.status === "SERVICE_UNAVAILABLE") return "dependency_unavailable";
    if (error.status === "INTERNAL_SERVER_ERROR") return "session_failed";
    return "transaction_invalid";
  }
  if (error instanceof FirebaseOperatorVerificationError) return error.status === 503 ? "dependency_unavailable" : "proof_denied";
  return "internal_failure";
}

export function firebaseOperatorSessionPlugin(dependencies: Deps) {
  const origins = canonicalOrigins(dependencies.trustedOrigins);
  if (!(dependencies.allowedCompanyIds instanceof Set) || dependencies.allowedCompanyIds.size === 0 || [...dependencies.allowedCompanyIds].some((id) => typeof id !== "string" || !id)) {
    throw new Error("Firebase session company IDs must be a finite nonempty set");
  }
  const allowedCompanies = new Set(dependencies.allowedCompanyIds);
  const now = dependencies.now ?? Date.now;
  nowValue(now);

  return {
    id: "paperclip-firebase-operator-session",
    init(ctx: { options?: { experimental?: { instrumentation?: { enabled?: boolean } }; logger?: { log?: Function } } }) {
      if (ctx.options?.experimental?.instrumentation?.enabled !== false || typeof ctx.options.logger?.log !== "function" || !safeAuthLogCallbacks.has(ctx.options.logger.log)) {
        throw new Error("Firebase operator sessions require firebaseOperatorSafeAuthOptions");
      }
    },
    endpoints: {
      beginFirebaseOperatorSession: createAuthEndpoint(BEGIN_ENDPOINT, { method: "POST", requireHeaders: true }, async (endpointContext) => {
        const ctx = endpointContext as unknown as EndpointContext;
        const correlationId = randomUUID();
        const span = startSafeSpan("begin");
        let auditReason: FirebaseOperatorAuditEvent["reason"] = "internal_failure";
        try {
        ctx.setHeader("Cache-Control", "no-store");
        ctx.setHeader("Referrer-Policy", "no-referrer");
        auditReason = "origin_denied";
        const origin = originFor(ctx, origins, BEGIN_PATH);
        auditReason = "bad_request";
        if (!exactBody(ctx.body, ["companyId", "returnPath"]) || typeof ctx.body.companyId !== "string" || !validReturnPath(ctx.body.returnPath)) failure(ctx, "BAD_REQUEST");
        auditReason = "company_denied";
        if (!allowedCompanies.has(ctx.body.companyId as string)) failure(ctx, "FORBIDDEN");
        const at = nowValue(now);
        const company = await dependencies.db.select({ id: companies.id }).from(companies)
          .where(and(eq(companies.id, ctx.body.companyId as string), eq(companies.status, "active"))).limit(1);
        if (company.length === 0) failure(ctx, "FORBIDDEN");
        const transactionId = randomUUID();
        const binding = randomBytes(32).toString("base64url");
        const state = randomBytes(32).toString("base64url");
        const expiresAt = new Date(at + TRANSACTION_TTL_MS);
        await dependencies.db.insert(firebaseOperatorLoginTransactions).values({
          id: transactionId, origin, companyId: ctx.body.companyId as string, returnPath: ctx.body.returnPath as string,
          browserBindingHash: sha256(binding), csrfStateHash: sha256(state), createdAt: new Date(at), expiresAt,
        });
        const remainingSeconds = Math.floor((expiresAt.getTime() - nowValue(now)) / 1000);
        if (remainingSeconds <= 0) { auditReason = "deadline_expired"; failure(ctx, "UNAUTHORIZED"); }
        const cookie = cookieFor(ctx);
        ctx.setCookie(cookie.name, binding, { ...cookie.attributes, maxAge: Math.min(300, remainingSeconds) });
        auditReason = "accepted";
        emitAudit(dependencies.audit ?? defaultAudit, { event: "begin", outcome: "created", reason: auditReason, correlationId });
        finishSafeSpan(span, "created", auditReason);
        return { transactionId, state, expiresAt: expiresAt.toISOString() };
        } catch (error) {
          const reason = error instanceof FirebaseSessionResponseError ? auditReason : reasonForStatus(error);
          emitAudit(dependencies.audit ?? defaultAudit, { event: "begin", outcome: "denied", reason, correlationId });
          finishSafeSpan(span, "denied", reason);
          return reportEndpointFailure(ctx, error);
        }
      }),
      exchangeFirebaseOperatorSession: createAuthEndpoint(EXCHANGE_ENDPOINT, { method: "POST", requireHeaders: true }, async (endpointContext) => {
        const ctx = endpointContext as unknown as EndpointContext;
        const correlationId = randomUUID();
        const span = startSafeSpan("exchange");
        let auditReason: FirebaseOperatorAuditEvent["reason"] = "internal_failure";
        let auditOutcome: FirebaseOperatorAuditEvent["outcome"] = "denied";
        try {
        ctx.setHeader("Cache-Control", "no-store");
        ctx.setHeader("Referrer-Policy", "no-referrer");
        let claimed = false;
        let sdkToken: string | undefined;
        let sessionId: string | undefined;
        let sessionCookieAttempted = false;
        auditReason = "origin_denied";
        const origin = originFor(ctx, origins, EXCHANGE_PATH);
        auditReason = "bad_request";
        if (!exactBody(ctx.body, ["transactionId", "state"]) || typeof ctx.body.transactionId !== "string" || !/^[0-9a-f-]{36}$/i.test(ctx.body.transactionId) || typeof ctx.body.state !== "string" || ctx.body.state.length < 32 || ctx.body.state.length > 256) failure(ctx, "BAD_REQUEST");
        auditReason = "transaction_invalid";
        const txId = ctx.body.transactionId as string;
        const rawState = ctx.body.state as string;
        const txCookie = cookieFor(ctx);
        const rawBinding = requestCookie(ctx, txCookie.name);
        const at = nowValue(now);
        const rows = await dependencies.db.select().from(firebaseOperatorLoginTransactions).where(and(eq(firebaseOperatorLoginTransactions.id, txId), eq(firebaseOperatorLoginTransactions.origin, origin), gt(firebaseOperatorLoginTransactions.expiresAt, new Date(at)), isNull(firebaseOperatorLoginTransactions.consumedAt))).limit(1);
        const transaction = rows[0];
        if (!transaction || !rawBinding || !safeEqual(transaction.browserBindingHash, sha256(rawBinding)) || !safeEqual(transaction.csrfStateHash, sha256(rawState))) failure(ctx, "UNAUTHORIZED");

        const claim = async () => {
          const claimAt = new Date(nowValue(now));
          const updated = await dependencies.db.update(firebaseOperatorLoginTransactions).set({ consumedAt: claimAt }).where(and(
            eq(firebaseOperatorLoginTransactions.id, txId), eq(firebaseOperatorLoginTransactions.origin, origin),
            eq(firebaseOperatorLoginTransactions.browserBindingHash, transaction.browserBindingHash),
            eq(firebaseOperatorLoginTransactions.csrfStateHash, transaction.csrfStateHash),
            gt(firebaseOperatorLoginTransactions.expiresAt, claimAt), isNull(firebaseOperatorLoginTransactions.consumedAt),
          )).returning({ id: firebaseOperatorLoginTransactions.id });
          if (updated.length !== 1) failure(ctx, "UNAUTHORIZED");
          claimed = true;
        };

        const authorization = ctx.request.headers.get("authorization");
        if (!authorization) {
          await claim();
          expireTransactionCookie(ctx);
          auditOutcome = "cancelled";
          auditReason = "cancelled";
          failure(ctx, "UNAUTHORIZED");
        }
        const bearer = /^Bearer ([A-Za-z0-9._~-]{1,8192})$/.exec(authorization);
        if (!bearer) failure(ctx, "UNAUTHORIZED");
        let proof: Proof;
        try { proof = await dependencies.verifier.verify(bearer[1]!); }
        catch (error) { auditReason = error instanceof FirebaseOperatorVerificationError && error.status === 503 ? "dependency_unavailable" : "proof_denied"; failure(ctx, genericStatus(error)); }
        const proofCheckedAt = nowValue(now);
        auditReason = "proof_denied";
        if (!proofIsFresh(proof!, proofCheckedAt)) failure(ctx, "UNAUTHORIZED");

        const preliminary = await dependencies.db.select({ binding: firebaseOperatorBindings, user: authUsers })
          .from(firebaseOperatorBindings).innerJoin(authUsers, eq(authUsers.id, firebaseOperatorBindings.userId))
          .where(and(eq(firebaseOperatorBindings.projectId, PROJECT_ID), eq(firebaseOperatorBindings.firebaseUid, proof!.uid), eq(firebaseOperatorBindings.enabled, true))).limit(1);
        const bound = preliminary[0];
        auditReason = "binding_denied";
        if (!bound) failure(ctx, "UNAUTHORIZED");
        const userId = bound.user.id;
        auditReason = "company_denied";
        if (await dependencies.db.select({ id: instanceUserRoles.id }).from(instanceUserRoles).where(and(eq(instanceUserRoles.userId, userId), eq(instanceUserRoles.role, "instance_admin"))).limit(1).then((result) => result.length)) failure(ctx, "FORBIDDEN");
        const activeMembership = await dependencies.db.select({ id: companyMemberships.id }).from(companyMemberships).innerJoin(companies, eq(companies.id, companyMemberships.companyId))
          .where(and(eq(companyMemberships.companyId, transaction.companyId), eq(companyMemberships.principalType, "user"), eq(companyMemberships.principalId, userId), eq(companyMemberships.status, "active"), eq(companies.status, "active"))).limit(1);
        if (activeMembership.length === 0) failure(ctx, "FORBIDDEN");

        await claim();
        auditReason = "session_failed";
        let cookiePrepared = false;
        try {
          sdkToken = randomBytes(32).toString("base64url");
          const issuedAt = new Date(nowValue(now));
          const expiresAt = new Date(issuedAt.getTime() + SESSION_TTL_MS);
          const session = await ctx.context.internalAdapter.createSession(userId, false, {
            token: sdkToken, createdAt: issuedAt, updatedAt: issuedAt, expiresAt,
          }, true);
          if (!session || typeof session.id !== "string" || session.token !== sdkToken) throw new Error("session creation failed");
          sessionId = session.id;
          let persistedSession: typeof authSessions.$inferSelect | undefined;
          auditReason = "assurance_failed";
          await dependencies.db.transaction(async (tx) => {
            const lockedBinding = await tx.select().from(firebaseOperatorBindings).where(and(eq(firebaseOperatorBindings.id, bound.binding.id), eq(firebaseOperatorBindings.enabled, true))).for("update").limit(1);
            const lockedUser = await tx.select({ id: authUsers.id }).from(authUsers).where(eq(authUsers.id, userId)).for("update").limit(1);
            const lockedAdmin = await tx.select({ id: instanceUserRoles.id }).from(instanceUserRoles).where(and(eq(instanceUserRoles.userId, userId), eq(instanceUserRoles.role, "instance_admin"))).for("update").limit(1);
            const lockedMembership = await tx.select({ id: companyMemberships.id }).from(companyMemberships).innerJoin(companies, eq(companies.id, companyMemberships.companyId))
              .where(and(eq(companyMemberships.companyId, transaction.companyId), eq(companyMemberships.principalType, "user"), eq(companyMemberships.principalId, userId), eq(companyMemberships.status, "active"), eq(companies.status, "active"))).for("update").limit(1);
            const lockedSessionRows = await tx.select().from(authSessions).where(eq(authSessions.id, session.id)).for("update").limit(1);
            const lockedSession = lockedSessionRows[0];
            const finalNow = nowValue(now);
            if (!lockedBinding[0] || lockedBinding[0].revision !== bound.binding.revision || lockedBinding[0].userId !== userId || !lockedUser.length || lockedAdmin.length || !lockedMembership.length || !lockedSession || lockedSession.id !== session.id || lockedSession.token !== sdkToken || lockedSession.userId !== userId || lockedSession.createdAt.getTime() !== issuedAt.getTime() || lockedSession.updatedAt.getTime() !== issuedAt.getTime() || lockedSession.expiresAt.getTime() !== expiresAt.getTime() || !proofIsFresh(proof!, finalNow) || transaction.expiresAt.getTime() <= finalNow) throw new Error("issuance state changed");
            persistedSession = lockedSession;
            await tx.insert(firebaseOperatorSessionAssurance).values({
              sessionId: session.id, bindingId: lockedBinding[0].id, userId, projectId: PROJECT_ID, firebaseUid: proof!.uid,
              bindingRevision: lockedBinding[0].revision, authTimeSeconds: proof!.authTimeSeconds, totpFactors: proof!.totpFactors,
              issuedAt, lastAuthoritativeCheckAt: new Date(proof!.checkedAtMs), lastInteractiveAt: issuedAt, absoluteExpiresAt: expiresAt,
            });
          }, { isolationLevel: "serializable" });
          auditReason = "deadline_expired";
          const freshnessValid = (at: number) => proofIsFresh(proof!, at) && transaction.expiresAt.getTime() > at && expiresAt.getTime() > at;
          if (!freshnessValid(nowValue(now))) throw new Error("issuance deadline expired");
          cookiePrepared = true;
          sessionCookieAttempted = true;
          const remainingSeconds = Math.floor((expiresAt.getTime() - nowValue(now)) / 1000);
          if (remainingSeconds <= 0) throw new Error("issuance deadline expired");
          if (!persistedSession) throw new Error("session creation failed");
          auditReason = "session_failed";
          await setSessionCookie(ctx as never, { session: persistedSession, user: bound.user }, false, {
            domain: undefined, path: "/", secure: true, httpOnly: true, sameSite: "lax", maxAge: remainingSeconds,
          });
          if (!freshnessValid(nowValue(now))) throw new Error("issuance deadline expired");
          expireTransactionCookie(ctx);
          auditOutcome = "issued";
          auditReason = "accepted";
          emitAudit(dependencies.audit ?? defaultAudit, { event: "exchange", outcome: auditOutcome, reason: auditReason, correlationId });
          finishSafeSpan(span, auditOutcome, auditReason);
          return { redirectTo: transaction.returnPath };
        } catch (error) {
          if (error instanceof Error && error.message === "issuance deadline expired") auditReason = "deadline_expired";
          if (sessionCookieAttempted || cookiePrepared) {
            try { await deleteSessionCookie(ctx as never); } catch { /* failed cookies are cleared below when possible */ }
          }
          try { expireTransactionCookie(ctx); } catch { /* response remains generic */ }
          if (sdkToken) {
            try { await ctx.context.internalAdapter.deleteSession(sdkToken); } catch { /* owned cleanup is best-effort after SDK failure */ }
          }
          failure(ctx, "INTERNAL_SERVER_ERROR");
        }
        } catch (error) {
          const reason = error instanceof FirebaseSessionResponseError ? auditReason : auditReason === "session_failed" ? "session_failed" : "dependency_unavailable";
          emitAudit(dependencies.audit ?? defaultAudit, { event: "exchange", outcome: auditOutcome, reason, correlationId });
          finishSafeSpan(span, auditOutcome, reason);
          return reportEndpointFailure(ctx, error);
        }
      }),
    },
  };
}

/** Explicit production composition; defining this wrapper does not activate the dormant route. */
export function createProductionFirebaseOperatorSessionPlugin(options: {
  db: Db;
  trustedOrigins: ReadonlySet<string>;
  allowedCompanyIds: ReadonlySet<string>;
  audit?: FirebaseOperatorAuditSink;
}) {
  return firebaseOperatorSessionPlugin({ ...options, verifier: createProductionFirebaseOperatorVerifier() });
}
