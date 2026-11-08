import express from "express";
import { and, eq, sql } from "drizzle-orm";
import { randomUUID } from "node:crypto";
import request from "supertest";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
  authSessions,
  authUsers,
  boardApiKeys,
  companies,
  companyMemberships,
  createDb,
  firebaseOperatorBindings,
  firebaseOperatorSessionAssurance,
  instanceUserRoles,
  principalPermissionGrants,
} from "@paperclipai/db";
import { actorMiddleware, resolveCloudTenantActor } from "../middleware/auth.js";
import { errorHandler } from "../middleware/error-handler.js";
import { assertCompanyAccess } from "../routes/authz.js";
import { logger } from "../middleware/logger.js";
import { authorizationService } from "../services/authorization.js";
import { accessService } from "../services/access.js";
import { hashBearerToken } from "../services/board-auth.js";
import { FirebaseOperatorVerificationError } from "../auth/firebase-operator-verifier.js";
import {
  getEmbeddedPostgresTestSupport,
  startEmbeddedPostgresTestDatabase,
} from "./helpers/embedded-postgres.js";

const postgresSupport = await getEmbeddedPostgresTestSupport();
if (!postgresSupport.supported) {
  throw new Error(`Firebase operator guard tests require embedded PostgreSQL: ${postgresSupport.reason ?? "unsupported host"}`);
}

const CLOUD_TOKEN = "firebase-guard-cloud-boundary-test-token";
const previousCloudToken = process.env.PAPERCLIP_CLOUD_TENANT_SERVER_TOKEN;
let database: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>>;
let db: ReturnType<typeof createDb>;

function deferred() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => { release = resolve; });
  return { promise, release };
}

describe("Firebase operator guard core and common HTTP boundary", () => {
  beforeAll(async () => {
    database = await startEmbeddedPostgresTestDatabase("paperclip-firebase-operator-guard-");
    db = createDb(database.connectionString);
    process.env.PAPERCLIP_CLOUD_TENANT_SERVER_TOKEN = CLOUD_TOKEN;
  }, 90_000);

  afterAll(async () => {
    await db?.$client.end();
    await database?.cleanup();
    if (previousCloudToken === undefined) delete process.env.PAPERCLIP_CLOUD_TENANT_SERVER_TOKEN;
    else process.env.PAPERCLIP_CLOUD_TENANT_SERVER_TOKEN = previousCloudToken;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  async function boundUser() {
    const id = `firebase-guard-${randomUUID()}`;
    const now = new Date();
    await db.insert(authUsers).values({
      id,
      name: "Guard test operator",
      email: `${id}@example.test`,
      emailVerified: true,
      createdAt: now,
      updatedAt: now,
    });
    await db.insert(firebaseOperatorBindings).values({
      firebaseUid: `uid-${id}`,
      userId: id,
      createdByUserId: id,
      updatedByUserId: id,
    });
    return id;
  }

  async function unrelatedOrdinarySession() {
    const id = `firebase-guard-unbound-${randomUUID()}`;
    const now = new Date();
    await db.insert(authUsers).values({
      id,
      name: "Unbound test user",
      email: `${id}@example.test`,
      emailVerified: true,
      createdAt: now,
      updatedAt: now,
    });
    const sessionId = randomUUID();
    await db.insert(authSessions).values({
      id: sessionId,
      userId: id,
      token: `test-token-${sessionId}`,
      expiresAt: new Date(now.getTime() + 60 * 60_000),
      createdAt: now,
      updatedAt: now,
    });
    return { id, sessionId };
  }

  async function assuredUser() {
    const userId = await boundUser();
    const [binding] = await db.select().from(firebaseOperatorBindings)
      .where(eq(firebaseOperatorBindings.userId, userId));
    const now = new Date();
    const sessionId = `firebase-guard-assured-session-${randomUUID()}`;
    const token = `firebase-guard-assured-token-${randomUUID()}`;
    const [company] = await db.insert(companies).values({
      name: `Guard assurance ${randomUUID()}`,
      issuePrefix: `G${randomUUID().replaceAll("-", "").slice(0, 8)}`,
    }).returning({ id: companies.id });
    await db.insert(companyMemberships).values({
      companyId: company!.id,
      principalType: "user",
      principalId: userId,
      status: "active",
      membershipRole: "owner",
    });
    await db.insert(authSessions).values({
      id: sessionId,
      userId,
      token,
      expiresAt: new Date(now.getTime() + 8 * 60 * 60_000),
      createdAt: now,
      updatedAt: now,
    });
    const authTimeSeconds = Math.floor(now.getTime() / 1000) - 301;
    await db.insert(firebaseOperatorSessionAssurance).values({
      sessionId,
      bindingId: binding.id,
      userId,
      firebaseUid: binding.firebaseUid,
      bindingRevision: binding.revision,
      authTimeSeconds,
      totpFactors: [{ factorId: "totp", uid: `factor-${userId}` }],
      issuedAt: now,
      lastAuthoritativeCheckAt: now,
      lastInteractiveAt: now,
      absoluteExpiresAt: new Date(now.getTime() + 8 * 60 * 60_000),
    });
    return {
      userId,
      bindingId: binding!.id,
      companyId: company!.id,
      authTimeSeconds,
      session: { id: sessionId, userId },
      user: { id: userId, name: "Guard test operator", email: `${userId}@example.test` },
    };
  }

  async function createGuard(options: { now?: () => number; checkUser?: (proof: Record<string, unknown>) => Promise<Record<string, unknown>> } = {}) {
    const moduleSpecifier = "../auth/firebase-operator-session-guard.js";
    let guardModule: Record<string, unknown> | undefined;
    try {
      guardModule = await import(moduleSpecifier);
    } catch (error) {
      expect.fail(`guard-core API is not implemented yet: ${error instanceof Error ? error.message : String(error)}`);
    }
    const factory = guardModule.createFirebaseOperatorSessionGuard as (input: Record<string, unknown>) => unknown;
    const now = options.now ?? Date.now;
    return factory({
      db,
      now,
      verifier: {
        checkUser: options.checkUser ?? (async (proof: Record<string, unknown>) => ({ ...proof, checkedAtMs: now() })),
      },
    });
  }

  function cloudHeaders(userId: string, stackId: string) {
    return {
      "x-paperclip-cloud-tenant-token": CLOUD_TOKEN,
      "x-paperclip-cloud-user-id": userId,
      "x-paperclip-cloud-user-email": `${userId}@example.test`,
      "x-paperclip-cloud-user-name": "Guarded Cloud owner",
      "x-paperclip-cloud-stack-id": stackId,
      "x-paperclip-cloud-stack-role": "owner",
    };
  }

  function cloudHeaderSource(userId: string, stackId: string, companyName?: string) {
    const headers: Record<string, string> = {
      "x-paperclip-cloud-tenant-token": CLOUD_TOKEN,
      "x-paperclip-cloud-user-id": userId,
      "x-paperclip-cloud-user-email": `${userId}@example.test`,
      "x-paperclip-cloud-user-name": "Guarded Cloud owner",
      "x-paperclip-cloud-stack-id": stackId,
      "x-paperclip-cloud-stack-role": "owner",
    };
    if (companyName) headers["x-paperclip-cloud-paperclip-company-name"] = companyName;
    return { header: (name: string) => headers[name.toLowerCase()] };
  }

  async function cloudBoundaryRequest(userId: string, resolveSession: () => Promise<unknown>, guard?: unknown) {
    const app = express();
    app.use(actorMiddleware(db, {
      deploymentMode: "authenticated",
      resolveSession: resolveSession as never,
      ...(guard ? { firebaseOperatorSessionGuard: guard } : {}),
    } as never));
    app.get("/actor", (req, res) => res.json(req.actor));
    app.use(errorHandler);
    const stackId = `stack-firebase-guard-${randomUUID()}`;
    return request(app).get("/actor").set(cloudHeaders(userId, stackId));
  }

  async function cloudSideEffects(userId: string) {
    const memberships = await db.select().from(companyMemberships)
      .where(and(eq(companyMemberships.principalType, "user"), eq(companyMemberships.principalId, userId)));
    const grants = await db.select().from(principalPermissionGrants)
      .where(and(eq(principalPermissionGrants.principalType, "user"), eq(principalPermissionGrants.principalId, userId)));
    return { memberships, grants };
  }

  async function waitForCloudSyncLock(controlDb: ReturnType<typeof createDb>, blockerPid: number) {
    const deadline = Date.now() + 10_000;
    let last: unknown;
    while (Date.now() < deadline) {
      const rows = await controlDb.execute(sql`
        select pid, state, wait_event_type, wait_event, query, pg_blocking_pids(pid) as blocking_pids
        from pg_stat_activity where datname = current_database()
      `) as unknown as Array<{
        pid: number;
        state: string;
        wait_event_type: string | null;
        wait_event: string | null;
        query: string;
        blocking_pids: number[];
      }>;
      last = rows.find((row) => row.blocking_pids.map(Number).includes(blockerPid));
      if (last && (last as { state: string }).state === "active"
        && (last as { wait_event_type: string | null }).wait_event_type === "Lock") return;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    throw new Error(`PostgreSQL Cloud-sync lock wait was not observed; last: ${JSON.stringify(last)}`);
  }

  it.each([
    { label: "no browser cookie", cookie: async () => null },
    {
      label: "an unrelated ordinary session cookie",
      cookie: async () => {
        const ordinary = await unrelatedOrdinarySession();
        return {
          session: { id: ordinary.sessionId, userId: ordinary.id },
          user: { id: ordinary.id, name: "Unbound test user", email: `${ordinary.id}@example.test` },
        };
      },
    },
  ])("denies a Cloud-bound operator principal with $label before tenant grant writes", async ({ cookie }) => {
    const userId = await boundUser();
    const before = await cloudSideEffects(userId);
    const response = await cloudBoundaryRequest(userId, cookie);

    expect.soft(response.status).toBe(401);
    expect.soft(await cloudSideEffects(userId)).toEqual(before);
  });

  it("keeps a closed idle denial when owned-session cleanup fails", async () => {
    const fixture = await assuredUser();
    let clock = Date.now();
    const realGuard = await createGuard({ now: () => clock }) as Record<string, any>;
    const wrappedGuard = {
      ...realGuard,
      check: async (input: { sessionId: string; userId: string }) => {
        const decision = await realGuard.check(input);
        clock += 30 * 60_000;
        return decision;
      },
      cleanupOwnedSession: vi.fn(async () => { throw new Error("cleanup unavailable"); }),
    };
    let routeCalls = 0;
    const app = express();
    app.use(actorMiddleware(db, {
      deploymentMode: "authenticated",
      resolveSession: async () => ({ session: fixture.session, user: fixture.user }),
      firebaseOperatorSessionGuard: wrappedGuard as never,
    } as never));
    app.get("/dispatch", (_req, res) => { routeCalls += 1; res.sendStatus(200); });
    app.use(errorHandler);

    const response = await request(app).get("/dispatch");
    expect.soft(response.status).toBe(401);
    expect.soft(routeCalls).toBe(0);
    expect.soft(wrappedGuard.cleanupOwnedSession).toHaveBeenCalledWith({ sessionId: fixture.session.id, userId: fixture.userId });
    await expect.soft(db.select().from(authSessions).where(eq(authSessions.id, fixture.session.id))).resolves.toHaveLength(1);
    await expect.soft(db.select().from(firebaseOperatorSessionAssurance)
      .where(eq(firebaseOperatorSessionAssurance.sessionId, fixture.session.id))).resolves.toHaveLength(1);
  });

  it("denies a Cloud principal that differs from an otherwise allowed assured cookie", async () => {
    const cloudUserId = await boundUser();
    const cookie = await assuredUser();
    const before = await cloudSideEffects(cloudUserId);
    const guard = await createGuard();
    const response = await cloudBoundaryRequest(cloudUserId, async () => cookie, guard);

    expect.soft(response.status).toBe(401);
    expect.soft(await cloudSideEffects(cloudUserId)).toEqual(before);
  });

  it("uses the same-user assured cookie actor without Cloud tenant grant repair", async () => {
    const cookie = await assuredUser();
    const before = await cloudSideEffects(cookie.userId);
    const guard = await createGuard();
    const response = await cloudBoundaryRequest(cookie.userId, async () => cookie, guard);

    expect.soft(response.status).toBe(200);
    expect.soft(response.body).toMatchObject({ type: "board", userId: cookie.userId, source: "session" });
    expect.soft(await cloudSideEffects(cookie.userId)).toEqual(before);
  });

  it("keeps a Firebase-bound cookie ahead of an unrelated ordinary Cloud principal", async () => {
    const cookie = await assuredUser();
    const cloudUser = await unrelatedOrdinarySession();
    const before = await cloudSideEffects(cloudUser.id);
    const guard = await createGuard();
    const response = await cloudBoundaryRequest(cloudUser.id, async () => cookie, guard);

    expect.soft(response.status).toBe(200);
    expect.soft(response.body).toMatchObject({ type: "board", userId: cookie.userId, source: "session" });
    expect.soft(await cloudSideEffects(cloudUser.id)).toEqual(before);
  });

  it("preserves ordinary Cloud actor sync for an unbound identity", async () => {
    const ordinary = await unrelatedOrdinarySession();
    const response = await cloudBoundaryRequest(ordinary.id, async () => null);
    const effects = await cloudSideEffects(ordinary.id);

    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({ type: "board", userId: ordinary.id, source: "cloud_tenant" });
    expect(effects.memberships.length).toBeGreaterThan(0);
    expect(effects.grants.length).toBeGreaterThan(0);
  });

  it("denies the exported Cloud actor resolver for a bound identity before tenant sync writes", async () => {
    const userId = await boundUser();
    const before = await cloudSideEffects(userId);
    const resolved = await resolveCloudTenantActor(db, cloudHeaderSource(userId, `stack-firebase-direct-${randomUUID()}`));

    expect(resolved).toBeNull();
    expect(await cloudSideEffects(userId)).toEqual(before);
  });

  it("rolls back a late Cloud grant-sync failure and retries after commit becomes possible", async () => {
    const userId = `guard-late-failure-${randomUUID()}`;
    const stackId = `stack-firebase-late-${randomUUID()}`;
    const companyName = `Guard Atomic ${randomUUID()}`;
    const source = cloudHeaderSource(userId, stackId, companyName);
    let failureTriggerInstalled = false;
    await db.execute(sql`
      create function paperclip_guard_red_fail_grant() returns trigger language plpgsql as $$
      begin
        if new.principal_id like 'guard-late-failure-%' then
          raise exception 'guard-core RED late grant failure';
        end if;
        return new;
      end
      $$
    `);
    await db.execute(sql`
      create trigger paperclip_guard_red_fail_grant
      before insert on principal_permission_grants
      for each row execute function paperclip_guard_red_fail_grant()
    `);
    failureTriggerInstalled = true;

    try {
      await expect(resolveCloudTenantActor(db, source)).rejects.toBeDefined();
      const [partialUser] = await db.select().from(authUsers).where(eq(authUsers.id, userId));
      const [partialCompany] = await db.select().from(companies).where(eq(companies.name, companyName));
      const effects = await cloudSideEffects(userId);
      expect.soft(partialUser).toBeUndefined();
      expect.soft(partialCompany).toBeUndefined();
      expect.soft(effects).toEqual({ memberships: [], grants: [] });

      await db.execute(sql`drop trigger paperclip_guard_red_fail_grant on principal_permission_grants`);
      await db.execute(sql`drop function paperclip_guard_red_fail_grant()`);
      failureTriggerInstalled = false;
      const retried = await resolveCloudTenantActor(db, source);
      expect(retried).toMatchObject({ type: "board", userId, source: "cloud_tenant" });
      const committed = await cloudSideEffects(userId);
      expect(committed.memberships.length).toBeGreaterThan(0);
      expect(committed.grants.length).toBeGreaterThan(0);
    } finally {
      if (failureTriggerInstalled) {
        await db.execute(sql`drop trigger if exists paperclip_guard_red_fail_grant on principal_permission_grants`);
        await db.execute(sql`drop function if exists paperclip_guard_red_fail_grant()`);
      }
    }
  });

  it("rechecks operator state after Cloud sync waits on the user row", async () => {
    const ordinary = await unrelatedOrdinarySession();
    const blockerDb = createDb(database.connectionString);
    const controlDb = createDb(database.connectionString);
    const blockerReleased = deferred();
    let signalBlocker!: (pid: number) => void;
    const blockerReady = new Promise<number>((resolve) => { signalBlocker = resolve; });
    const blockerTransaction = blockerDb.transaction(async (tx) => {
      const [{ pid }] = await tx.execute(sql`select pg_backend_pid()::int as pid`) as unknown as Array<{ pid: number }>;
      await tx.select({ id: authUsers.id }).from(authUsers)
        .where(eq(authUsers.id, ordinary.id)).for("update");
      signalBlocker(pid);
      await blockerReleased.promise;
      await tx.insert(firebaseOperatorBindings).values({
        firebaseUid: `uid-${ordinary.id}`,
        userId: ordinary.id,
        createdByUserId: ordinary.id,
        updatedByUserId: ordinary.id,
      });
    });

    let responsePromise: Promise<request.Response> | undefined;
    try {
      const pid = await blockerReady;
      responsePromise = cloudBoundaryRequest(ordinary.id, async () => null).then((response) => response);
      await waitForCloudSyncLock(controlDb, pid);
      blockerReleased.release();
      await blockerTransaction;
      const response = await responsePromise;

      expect.soft(response.status).toBe(401);
      expect.soft(await cloudSideEffects(ordinary.id)).toEqual({ memberships: [], grants: [] });
    } finally {
      blockerReleased.release();
      await blockerTransaction.catch(() => undefined);
      if (responsePromise) await responsePromise.catch(() => undefined);
      await blockerDb.$client.end();
      await controlDb.$client.end();
    }
  });

  it("rechecks operator state in the exported resolver after a real user-row lock wait", async () => {
    const ordinary = await unrelatedOrdinarySession();
    const blockerDb = createDb(database.connectionString);
    const controlDb = createDb(database.connectionString);
    const blockerReleased = deferred();
    let signalBlocker!: (pid: number) => void;
    const blockerReady = new Promise<number>((resolve) => { signalBlocker = resolve; });
    const blockerTransaction = blockerDb.transaction(async (tx) => {
      const [{ pid }] = await tx.execute(sql`select pg_backend_pid()::int as pid`) as unknown as Array<{ pid: number }>;
      await tx.select({ id: authUsers.id }).from(authUsers)
        .where(eq(authUsers.id, ordinary.id)).for("update");
      signalBlocker(pid);
      await blockerReleased.promise;
      await tx.insert(firebaseOperatorBindings).values({
        firebaseUid: `uid-${ordinary.id}`,
        userId: ordinary.id,
        createdByUserId: ordinary.id,
        updatedByUserId: ordinary.id,
      });
    });

    let resolverPromise: Promise<Awaited<ReturnType<typeof resolveCloudTenantActor>>> | undefined;
    try {
      const pid = await blockerReady;
      resolverPromise = resolveCloudTenantActor(db, cloudHeaderSource(ordinary.id, `stack-firebase-direct-race-${randomUUID()}`));
      await waitForCloudSyncLock(controlDb, pid);
      blockerReleased.release();
      await blockerTransaction;
      await expect(resolverPromise).resolves.toBeNull();
      await expect(cloudSideEffects(ordinary.id)).resolves.toEqual({ memberships: [], grants: [] });
      await expect(db.select().from(authUsers).where(eq(authUsers.id, ordinary.id))).resolves.toHaveLength(1);
    } finally {
      blockerReleased.release();
      await blockerTransaction.catch(() => undefined);
      if (resolverPromise) await resolverPromise.catch(() => undefined);
      await blockerDb.$client.end();
      await controlDb.$client.end();
    }
  });

  it("classifies disabled bindings as operator state instead of ordinary users", async () => {
    const ordinary = await unrelatedOrdinarySession();
    const guard = await createGuard() as {
      readUserState: (userId: string) => Promise<unknown>;
    };
    await expect(guard.readUserState(ordinary.id)).resolves.toEqual({ kind: "ordinary" });

    const userId = await boundUser();
    const [binding] = await db.select().from(firebaseOperatorBindings)
      .where(eq(firebaseOperatorBindings.userId, userId));
    await db.update(firebaseOperatorBindings).set({ enabled: false })
      .where(eq(firebaseOperatorBindings.id, binding!.id));

    await expect(guard.readUserState(userId)).resolves.toEqual({ kind: "operator_state", enabledBinding: null });
  });

  it("denies an enabled bound user's legacy session without assurance", async () => {
    const userId = await boundUser();
    const now = new Date();
    const sessionId = `firebase-guard-legacy-session-${randomUUID()}`;
    await db.insert(authSessions).values({
      id: sessionId,
      userId,
      token: `legacy-token-${sessionId}`,
      expiresAt: new Date(now.getTime() + 60 * 60_000),
      createdAt: now,
      updatedAt: now,
    });
    const guard = await createGuard() as {
      check: (input: { sessionId: string; userId: string }) => Promise<Record<string, unknown>>;
    };

    await expect(guard.check({ sessionId, userId })).resolves.toMatchObject({
      kind: "denied", status: 401, reason: "assurance_missing",
    });
    await expect(db.select().from(authSessions).where(eq(authSessions.id, sessionId))).resolves.toHaveLength(0);
  });

  it("keeps an assured session when a caller pairs it with a different user id", async () => {
    const fixture = await assuredUser();
    const unrelated = await unrelatedOrdinarySession();
    const guard = await createGuard() as {
      check: (input: { sessionId: string; userId: string }) => Promise<Record<string, unknown>>;
    };

    await expect(guard.check({ sessionId: fixture.session.id, userId: unrelated.id }))
      .resolves.toMatchObject({ kind: "denied" });
    await expect(db.select().from(authSessions).where(eq(authSessions.id, fixture.session.id)))
      .resolves.toHaveLength(1);
    await expect(db.select().from(firebaseOperatorSessionAssurance)
      .where(eq(firebaseOperatorSessionAssurance.sessionId, fixture.session.id))).resolves.toHaveLength(1);
    await expect(db.select().from(authSessions).where(eq(authSessions.id, unrelated.sessionId)))
      .resolves.toHaveLength(1);
  });

  it("allows lifecycle revalidation for a valid recorded proof older than the exchange freshness window", async () => {
    const fixture = await assuredUser();
    const guard = await createGuard() as {
      check: (input: { sessionId: string; userId: string }) => Promise<Record<string, unknown>>;
    };

    const decision = await guard.check({ sessionId: fixture.session.id, userId: fixture.userId });
    expect(fixture.authTimeSeconds * 1000).toBeLessThan(Date.now() - 300_000);
    expect(decision).toMatchObject({ kind: "allowed", bindingId: fixture.bindingId });
  });

  it("denies the selected company when another active membership remains", async () => {
    const fixture = await assuredUser();
    const unrelated = await assuredUser();
    const sameUserSessionId = `firebase-guard-same-user-session-${randomUUID()}`;
    const sameUserSessionNow = new Date();
    await db.insert(authSessions).values({
      id: sameUserSessionId,
      userId: fixture.userId,
      token: `firebase-guard-same-user-token-${randomUUID()}`,
      expiresAt: new Date(sameUserSessionNow.getTime() + 60 * 60_000),
      createdAt: sameUserSessionNow,
      updatedAt: sameUserSessionNow,
    });
    const [sameUserAssurance] = await db.select().from(firebaseOperatorSessionAssurance)
      .where(eq(firebaseOperatorSessionAssurance.sessionId, fixture.session.id));
    await db.insert(firebaseOperatorSessionAssurance).values({
      sessionId: sameUserSessionId,
      bindingId: sameUserAssurance!.bindingId,
      userId: fixture.userId,
      firebaseUid: sameUserAssurance!.firebaseUid,
      bindingRevision: sameUserAssurance!.bindingRevision,
      authTimeSeconds: sameUserAssurance!.authTimeSeconds,
      totpFactors: sameUserAssurance!.totpFactors,
      issuedAt: sameUserSessionNow,
      lastAuthoritativeCheckAt: sameUserSessionNow,
      lastInteractiveAt: sameUserSessionNow,
      absoluteExpiresAt: new Date(sameUserSessionNow.getTime() + 60 * 60_000),
    });
    const [otherCompany] = await db.insert(companies).values({
      name: `Guard second company ${randomUUID()}`,
      issuePrefix: `H${randomUUID().replaceAll("-", "").slice(0, 8)}`,
    }).returning({ id: companies.id });
    await db.insert(companyMemberships).values({
      companyId: otherCompany!.id,
      principalType: "user",
      principalId: fixture.userId,
      status: "active",
      membershipRole: "member",
    });
    const guard = await createGuard() as {
      check: (input: { sessionId: string; userId: string; companyId?: string }) => Promise<Record<string, unknown>>;
    };

    await expect(guard.check({ sessionId: fixture.session.id, userId: fixture.userId, companyId: otherCompany!.id }))
      .resolves.toMatchObject({ kind: "allowed" });
    await db.update(companyMemberships).set({ status: "inactive" })
      .where(and(eq(companyMemberships.principalId, fixture.userId), eq(companyMemberships.companyId, fixture.companyId)));
    const beforeDenied = await cloudSideEffects(fixture.userId);
    await expect(guard.check({ sessionId: fixture.session.id, userId: fixture.userId, companyId: fixture.companyId }))
      .resolves.toMatchObject({ kind: "denied", status: 403, reason: "company_forbidden" });
    await expect.soft(cloudSideEffects(fixture.userId)).resolves.toEqual(beforeDenied);
    await expect.soft(db.select().from(authSessions).where(eq(authSessions.id, fixture.session.id))).resolves.toHaveLength(0);
    await expect.soft(db.select().from(firebaseOperatorSessionAssurance)
      .where(eq(firebaseOperatorSessionAssurance.sessionId, fixture.session.id))).resolves.toHaveLength(0);
    await expect.soft(db.select().from(authSessions).where(eq(authSessions.id, unrelated.session.id))).resolves.toHaveLength(1);
    await expect.soft(db.select().from(firebaseOperatorSessionAssurance)
      .where(eq(firebaseOperatorSessionAssurance.sessionId, unrelated.session.id))).resolves.toHaveLength(1);
    await expect.soft(db.select().from(authSessions).where(eq(authSessions.id, sameUserSessionId))).resolves.toHaveLength(1);
    await expect.soft(db.select().from(firebaseOperatorSessionAssurance)
      .where(eq(firebaseOperatorSessionAssurance.sessionId, sameUserSessionId))).resolves.toHaveLength(1);
    await expect.soft(db.select().from(companyMemberships)
      .where(eq(companyMemberships.principalId, fixture.userId))).resolves.toHaveLength(2);
  });

  it("keeps a guarded Firebase actor inside the membership snapshot validated by the guard", async () => {
    const fixture = await assuredUser();
    const [inactiveCompany] = await db.insert(companies).values({
      name: `Guard inactive company ${randomUUID()}`,
      status: "inactive",
      issuePrefix: `I${randomUUID().replaceAll("-", "").slice(0, 8)}`,
    }).returning({ id: companies.id });
    await db.insert(companyMemberships).values({
      companyId: inactiveCompany!.id,
      principalType: "user",
      principalId: fixture.userId,
      status: "active",
      membershipRole: "member",
    });
    const guard = await createGuard() as {
      check: (input: { sessionId: string; userId: string; companyId?: string }) => Promise<Record<string, unknown>>;
      [key: string]: unknown;
    };
    await expect(guard.check({ sessionId: fixture.session.id, userId: fixture.userId, companyId: fixture.companyId }))
      .resolves.toMatchObject({ kind: "allowed" });
    const app = express();
    app.use(actorMiddleware(db, {
      deploymentMode: "authenticated",
      resolveSession: async () => ({ session: fixture.session, user: fixture.user }),
      firebaseOperatorSessionGuard: guard as never,
    } as never));
    app.get("/company/:companyId", (req, res) => {
      try {
        assertCompanyAccess(req, req.params.companyId!);
        res.status(200).json(req.actor);
      } catch {
        res.status(403).end();
      }
    });
    app.use(errorHandler);

    const allowed = await request(app).get(`/company/${fixture.companyId}`);
    const denied = await request(app).get(`/company/${inactiveCompany!.id}`);
    expect.soft(allowed.status).toBe(200);
    expect.soft(allowed.body.companyIds).toEqual([fixture.companyId]);
    expect.soft(denied.status).toBe(403);
  });

  it("does not accept an admin role committed after the guard snapshot", async () => {
    const fixture = await assuredUser();
    const [outsideCompany] = await db.insert(companies).values({
      name: `Guard outside company ${randomUUID()}`,
      issuePrefix: `O${randomUUID().replaceAll("-", "").slice(0, 8)}`,
    }).returning({ id: companies.id });
    const realGuard = await createGuard() as {
      check: (input: { sessionId: string; userId: string }) => Promise<Record<string, any>>;
      [key: string]: unknown;
    };
    const guarded = {
      ...realGuard,
      check: async (input: { sessionId: string; userId: string }) => {
        const result = await realGuard.check(input);
        await db.insert(instanceUserRoles).values({ userId: fixture.userId, role: "instance_admin" });
        return result;
      },
    };
    const app = express();
    app.use(actorMiddleware(db, {
      deploymentMode: "authenticated",
      resolveSession: async () => ({ session: fixture.session, user: fixture.user }),
      firebaseOperatorSessionGuard: guarded as never,
    } as never));
    app.get("/actor", (req, res) => res.json(req.actor));
    app.use(errorHandler);
    const response = await request(app).get("/actor");

    expect(response.status).toBe(200);
    expect.soft(response.body).toMatchObject({ source: "session", isInstanceAdmin: false });
    const assignment = await authorizationService(db).decide({
      actor: response.body,
      action: "tasks:assign",
      resource: { type: "issue", companyId: outsideCompany!.id },
    });
    expect.soft(assignment.reason).not.toBe("allow_instance_admin");
    await expect.soft(accessService(db).isInstanceAdmin(fixture.userId)).resolves.toBe(false);
    await expect.soft(accessService(db).canUser(outsideCompany!.id, fixture.userId, "tasks:assign"))
      .resolves.toBe(false);
  });

  it("excludes enabled-bound, disabled-bound, and assured users from DB-backed instance-admin eligibility", async () => {
    const enabledBound = await assuredUser();
    const disabledBound = await assuredUser();
    const assured = await assuredUser();
    const assuranceOnly = await unrelatedOrdinarySession();
    const unbound = await unrelatedOrdinarySession();
    const foreignBindingUserId = await boundUser();
    const [outsideCompany] = await db.insert(companies).values({
      name: `Guard admin policy target ${randomUUID()}`,
      issuePrefix: `P${randomUUID().replaceAll("-", "").slice(0, 8)}`,
    }).returning({ id: companies.id });
    const [foreignBinding] = await db.select().from(firebaseOperatorBindings)
      .where(eq(firebaseOperatorBindings.userId, foreignBindingUserId));
    const assuranceNow = new Date();
    await db.insert(firebaseOperatorSessionAssurance).values({
      sessionId: assuranceOnly.sessionId,
      bindingId: foreignBinding!.id,
      userId: assuranceOnly.id,
      firebaseUid: foreignBinding!.firebaseUid,
      bindingRevision: foreignBinding!.revision,
      authTimeSeconds: Math.floor(assuranceNow.getTime() / 1000),
      totpFactors: [{ factorId: "totp", uid: `factor-${assuranceOnly.id}` }],
      issuedAt: assuranceNow,
      lastAuthoritativeCheckAt: assuranceNow,
      lastInteractiveAt: assuranceNow,
      absoluteExpiresAt: new Date(assuranceNow.getTime() + 8 * 60 * 60_000),
    });
    for (const userId of [enabledBound.userId, disabledBound.userId, assured.userId, assuranceOnly.id, unbound.id]) {
      await db.insert(instanceUserRoles).values({ userId, role: "instance_admin" });
    }
    await db.update(firebaseOperatorBindings).set({ enabled: false })
      .where(eq(firebaseOperatorBindings.userId, disabledBound.userId));

    for (const userId of [enabledBound.userId, disabledBound.userId, assured.userId, assuranceOnly.id]) {
      await expect.soft(accessService(db).isInstanceAdmin(userId)).resolves.toBe(false);
      const decision = await authorizationService(db).decide({
        actor: { type: "board", userId, source: "session" },
        action: "tasks:assign",
        resource: { type: "issue", companyId: outsideCompany!.id },
      });
      expect.soft(decision.reason).not.toBe("allow_instance_admin");
      await expect.soft(accessService(db).canUser(outsideCompany!.id, userId, "tasks:assign"))
        .resolves.toBe(false);
    }
    await expect.soft(accessService(db).isInstanceAdmin(unbound.id)).resolves.toBe(true);
    const legacyAdmin = await authorizationService(db).decide({
      actor: { type: "board", userId: unbound.id, source: "session" },
      action: "tasks:assign",
      resource: { type: "issue", companyId: outsideCompany!.id },
    });
    expect.soft(legacyAdmin.reason).toBe("allow_instance_admin");
    await expect.soft(accessService(db).canUser(outsideCompany!.id, unbound.id, "tasks:assign"))
      .resolves.toBe(true);
    const nonadminId = `nonadmin-${randomUUID()}`;
    const [noGrantCompany] = await db.insert(companies).values({
      name: `Guard no-grant ${randomUUID()}`,
      issuePrefix: `N${randomUUID().replaceAll("-", "").slice(0, 8)}`,
    }).returning({ id: companies.id });
    await db.insert(companyMemberships).values({
      companyId: noGrantCompany!.id,
      principalType: "user",
      principalId: nonadminId,
      status: "active",
      membershipRole: "viewer",
    });
    await expect.soft(accessService(db).isInstanceAdmin(nonadminId)).resolves.toBe(false);
    await expect.soft(authorizationService(db).decide({
      actor: { type: "board", userId: nonadminId, source: "session", companyIds: [noGrantCompany!.id] },
      action: "tasks:assign",
      resource: { type: "issue", companyId: noGrantCompany!.id },
    })).resolves.toMatchObject({ allowed: false, reason: "deny_missing_grant" });
    await expect.soft(accessService(db).canUser(noGrantCompany!.id, nonadminId, "tasks:assign"))
      .resolves.toBe(false);
  });

  it("keeps failed instance-admin eligibility queries closed without a fallback", async () => {
    const failedDb: any = { select: vi.fn(() => { throw new Error("role lookup unavailable"); }) };
    await expect(accessService(failedDb).isInstanceAdmin(`failed-${randomUUID()}`)).rejects.toThrow("role lookup unavailable");
    await expect(authorizationService(failedDb).decide({
      actor: { type: "board", userId: `failed-${randomUUID()}`, source: "session" },
      action: "tasks:assign",
      resource: { type: "issue", companyId: `outside-${randomUUID()}` },
    })).rejects.toThrow("role lookup unavailable");
    expect(failedDb.select).toHaveBeenCalled();
  });

  it("does not slide a positive cache hit past its original 60-second deadline", async () => {
    const fixture = await assuredUser();
    const start = Date.now();
    let clock = start;
    let providerCalls = 0;
    const guard = await createGuard({
      now: () => clock,
      checkUser: async (proof) => {
        providerCalls += 1;
        if (providerCalls > 1) throw new FirebaseOperatorVerificationError(503);
        return { ...proof, checkedAtMs: clock };
      },
    }) as {
      check: (input: { sessionId: string; userId: string }) => Promise<Record<string, unknown>>;
    };

    await expect(guard.check({ sessionId: fixture.session.id, userId: fixture.userId }))
      .resolves.toMatchObject({ kind: "allowed" });
    clock = start + 59_000;
    await expect(guard.check({ sessionId: fixture.session.id, userId: fixture.userId }))
      .resolves.toMatchObject({ kind: "allowed" });
    expect(providerCalls).toBe(1);

    clock = start + 60_000;
    await expect(guard.check({ sessionId: fixture.session.id, userId: fixture.userId }))
      .resolves.toMatchObject({ kind: "denied", status: 503, reason: "dependency_unavailable" });
    expect(providerCalls).toBe(2);
  });

  it.each([
    { label: "provider evidence", advance: 60_000, expectedStatus: 503, cleanup: false },
    { label: "interactive idle authority", advance: 30 * 60_000, expectedStatus: 401, cleanup: true },
    { label: "absolute session authority", advance: 8 * 60 * 60_000, expectedStatus: 401, cleanup: true },
  ])("finalizes $label at dispatch after the real guard check returns", async ({ advance, expectedStatus, cleanup }) => {
    const fixture = await assuredUser();
    const unrelated = await assuredUser();
    let clock = Date.now();
    const realGuard = await createGuard({ now: () => clock }) as Record<string, any>;
    const wrappedGuard = {
      ...realGuard,
      check: async (input: { sessionId: string; userId: string }) => {
        const decision = await realGuard.check(input);
        clock += advance;
        return decision;
      },
    };
    let routeCalls = 0;
    const app = express();
    app.use(actorMiddleware(db, {
      deploymentMode: "authenticated",
      resolveSession: async () => ({ session: fixture.session, user: fixture.user }),
      firebaseOperatorSessionGuard: wrappedGuard as never,
    } as never));
    app.get("/dispatch", (_req, res) => { routeCalls += 1; res.sendStatus(200); });
    app.use(errorHandler);

    const response = await request(app).get("/dispatch");
    expect.soft(response.status).toBe(expectedStatus);
    expect.soft(routeCalls).toBe(0);
    if (cleanup) {
      await expect.soft(db.select().from(authSessions).where(eq(authSessions.id, fixture.session.id))).resolves.toHaveLength(0);
      await expect.soft(db.select().from(firebaseOperatorSessionAssurance)
        .where(eq(firebaseOperatorSessionAssurance.sessionId, fixture.session.id))).resolves.toHaveLength(0);
    } else {
      await expect.soft(db.select().from(authSessions).where(eq(authSessions.id, fixture.session.id))).resolves.toHaveLength(1);
      await expect.soft(db.select().from(firebaseOperatorSessionAssurance)
        .where(eq(firebaseOperatorSessionAssurance.sessionId, fixture.session.id))).resolves.toHaveLength(1);
    }
    await expect.soft(db.select().from(authSessions).where(eq(authSessions.id, unrelated.session.id))).resolves.toHaveLength(1);
    await expect.soft(db.select().from(firebaseOperatorSessionAssurance)
      .where(eq(firebaseOperatorSessionAssurance.sessionId, unrelated.session.id))).resolves.toHaveLength(1);
  });

  it.each([
    { label: "provider rejection", error: new FirebaseOperatorVerificationError(401), status: 401, reason: "firebase_denied", deleteOwnedSession: true },
    { label: "provider unavailability", error: new FirebaseOperatorVerificationError(503), status: 503, reason: "dependency_unavailable", deleteOwnedSession: false },
    { label: "an unexpected provider error", error: new Error("GUARD-PROVIDER-RAW-ERROR-SENTINEL"), status: 503, reason: "dependency_unavailable", deleteOwnedSession: false },
  ])("maps $label to a closed denial and only cleans up the owned session", async ({ error, status, reason, deleteOwnedSession }) => {
    const fixture = await assuredUser();
    const unrelated = await assuredUser();
    const spies = ["debug", "info", "warn", "error"].map((level) =>
      vi.spyOn(logger, level as "warn").mockImplementation(() => undefined as never));
    const guard = await createGuard({ checkUser: async () => { throw error; } }) as {
      check: (input: { sessionId: string; userId: string }) => Promise<Record<string, unknown>>;
    };

    const decision = await guard.check({ sessionId: fixture.session.id, userId: fixture.userId });
    expect(decision).toMatchObject({ kind: "denied", status, reason });
    const logCalls = spies.flatMap((spy) => spy.mock.calls);
    expect(JSON.stringify({ decision, logCalls })).not.toContain("GUARD-PROVIDER-RAW-ERROR-SENTINEL");
    if (deleteOwnedSession) {
      await expect(db.select().from(authSessions).where(eq(authSessions.id, fixture.session.id))).resolves.toHaveLength(0);
      await expect(db.select().from(firebaseOperatorSessionAssurance)
        .where(eq(firebaseOperatorSessionAssurance.sessionId, fixture.session.id))).resolves.toHaveLength(0);
    } else {
      await expect(db.select().from(authSessions).where(eq(authSessions.id, fixture.session.id))).resolves.toHaveLength(1);
      await expect(db.select().from(firebaseOperatorSessionAssurance)
        .where(eq(firebaseOperatorSessionAssurance.sessionId, fixture.session.id))).resolves.toHaveLength(1);
    }
    await expect(db.select().from(authSessions).where(eq(authSessions.id, unrelated.session.id))).resolves.toHaveLength(1);
    await expect(db.select().from(firebaseOperatorSessionAssurance)
      .where(eq(firebaseOperatorSessionAssurance.sessionId, unrelated.session.id))).resolves.toHaveLength(1);
  });

  it("does not allow a verifier result that returns after its lookup-start cache deadline", async () => {
    const fixture = await assuredUser();
    let clock = Date.now();
    const guard = await createGuard({
      now: () => clock,
      checkUser: async (proof) => {
        const checkedAtMs = clock;
        clock += 60_001;
        return { ...proof, checkedAtMs };
      },
    }) as {
      check: (input: { sessionId: string; userId: string }) => Promise<Record<string, unknown>>;
    };

    await expect(guard.check({ sessionId: fixture.session.id, userId: fixture.userId }))
      .resolves.toMatchObject({ kind: "denied" });
  });

  it("denies a direct guard check when provider evidence completes exactly at its fixed 60-second deadline", async () => {
    const fixture = await assuredUser();
    let clock = Date.now();
    let providerCheckedAtMs = 0;
    let signalProvider!: () => void;
    let releaseProvider!: (proof: Record<string, unknown>) => void;
    const providerStarted = new Promise<void>((resolve) => { signalProvider = resolve; });
    const providerResult = new Promise<Record<string, unknown>>((resolve) => { releaseProvider = resolve; });
    const guard = await createGuard({
      now: () => clock,
      checkUser: async (proof) => {
        providerCheckedAtMs = proof.checkedAtMs;
        signalProvider();
        return providerResult;
      },
    }) as {
      check: (input: { sessionId: string; userId: string }) => Promise<Record<string, unknown>>;
    };
    const pending = guard.check({ sessionId: fixture.session.id, userId: fixture.userId });
    await providerStarted;
    clock = providerCheckedAtMs + 60_000;
    releaseProvider({
      projectId: "thl-pclipd-api",
      userId: fixture.userId,
      uid: `uid-${fixture.userId}`,
      authTimeSeconds: fixture.authTimeSeconds,
      totpFactors: [{ factorId: "totp", uid: `factor-${fixture.userId}` }],
      checkedAtMs: providerCheckedAtMs,
    });

    await expect(pending).resolves.toMatchObject({
      kind: "denied", status: 503, reason: "dependency_unavailable",
    });
  });

  it.each([
    { label: "the auth-session expiration", reason: "session_expired", expire: async (fixture: Awaited<ReturnType<typeof assuredUser>>) => {
      await db.update(authSessions).set({ expiresAt: new Date(Date.now() - 1) })
        .where(eq(authSessions.id, fixture.session.id));
    } },
    { label: "the 30-minute interactive idle deadline", reason: "idle_expired", expire: async (fixture: Awaited<ReturnType<typeof assuredUser>>) => {
      await db.update(firebaseOperatorSessionAssurance).set({ lastInteractiveAt: new Date(Date.now() - 30 * 60_000) })
        .where(eq(firebaseOperatorSessionAssurance.sessionId, fixture.session.id));
    } },
    { label: "the 8-hour absolute deadline", reason: "session_expired", expire: async (fixture: Awaited<ReturnType<typeof assuredUser>>) => {
      await db.update(firebaseOperatorSessionAssurance).set({ absoluteExpiresAt: new Date(Date.now() - 1) })
        .where(eq(firebaseOperatorSessionAssurance.sessionId, fixture.session.id));
    } },
  ])("denies an assured session at $label", async ({ expire, reason }) => {
    const fixture = await assuredUser();
    await expire(fixture);
    const guard = await createGuard() as {
      check: (input: { sessionId: string; userId: string }) => Promise<Record<string, unknown>>;
    };

    await expect(guard.check({ sessionId: fixture.session.id, userId: fixture.userId }))
      .resolves.toMatchObject({ kind: "denied", status: 401, reason });
  });

  it("rechecks the idle deadline after a real PostgreSQL authorization lock wait", async () => {
    const fixture = await assuredUser();
    const unrelated = await assuredUser();
    let clock = Date.now();
    const issuedAt = new Date(clock - (30 * 60_000 - 1_000));
    const absoluteExpiresAt = new Date(issuedAt.getTime() + 8 * 60 * 60_000);
    await db.update(authSessions).set({
      createdAt: issuedAt,
      updatedAt: issuedAt,
      expiresAt: absoluteExpiresAt,
    }).where(eq(authSessions.id, fixture.session.id));
    await db.update(firebaseOperatorSessionAssurance).set({
      issuedAt,
      lastInteractiveAt: issuedAt,
      absoluteExpiresAt,
      authTimeSeconds: Math.floor(issuedAt.getTime() / 1000) - 1,
    }).where(eq(firebaseOperatorSessionAssurance.sessionId, fixture.session.id));

    const blockerDb = createDb(database.connectionString);
    const controlDb = createDb(database.connectionString);
    const membershipLockAcquired = deferred();
    const releaseMembershipLock = deferred();
    let blockerPid = 0;
    const blocker = blockerDb.transaction(async (tx) => {
      const [pid] = await tx.execute(sql`select pg_backend_pid() as pid`) as unknown as Array<{ pid: number }>;
      blockerPid = Number(pid?.pid);
      await tx.select({ id: companyMemberships.id }).from(companyMemberships)
        .where(and(
          eq(companyMemberships.companyId, fixture.companyId),
          eq(companyMemberships.principalType, "user"),
          eq(companyMemberships.principalId, fixture.userId),
          eq(companyMemberships.status, "active"),
        )).for("update").limit(1);
      membershipLockAcquired.release();
      await releaseMembershipLock.promise;
    }, { isolationLevel: "read committed" });

    try {
      await membershipLockAcquired.promise;
      const guard = await createGuard({
        now: () => clock,
        checkUser: async (proof) => ({ ...proof, checkedAtMs: clock }),
      }) as {
        check: (input: { sessionId: string; userId: string }) => Promise<Record<string, unknown>>;
      };
      const pending = guard.check({ sessionId: fixture.session.id, userId: fixture.userId });
      await waitForCloudSyncLock(controlDb, blockerPid);
      clock += 2_000;
      releaseMembershipLock.release();

      await expect(pending).resolves.toMatchObject({ kind: "denied", status: 401, reason: "idle_expired" });
      await expect(db.select().from(authSessions).where(eq(authSessions.id, fixture.session.id))).resolves.toHaveLength(0);
      await expect(db.select().from(firebaseOperatorSessionAssurance)
        .where(eq(firebaseOperatorSessionAssurance.sessionId, fixture.session.id))).resolves.toHaveLength(0);
      await expect(db.select().from(authSessions).where(eq(authSessions.id, unrelated.session.id))).resolves.toHaveLength(1);
      await expect(db.select().from(firebaseOperatorSessionAssurance)
        .where(eq(firebaseOperatorSessionAssurance.sessionId, unrelated.session.id))).resolves.toHaveLength(1);
    } finally {
      releaseMembershipLock.release();
      await blocker.catch(() => undefined);
      await blockerDb.$client.end();
      await controlDb.$client.end();
    }
  });

  it("rechecks current PostgreSQL authorization on a positive-cache hit", async () => {
    const fixture = await assuredUser();
    let providerCalls = 0;
    const guard = await createGuard({ checkUser: async (proof) => {
      providerCalls += 1;
      return { ...proof, checkedAtMs: Date.now() };
    } }) as {
      check: (input: { sessionId: string; userId: string }) => Promise<Record<string, unknown>>;
    };

    await expect(guard.check({ sessionId: fixture.session.id, userId: fixture.userId }))
      .resolves.toMatchObject({ kind: "allowed" });
    await db.update(companyMemberships).set({ status: "inactive" })
      .where(and(eq(companyMemberships.principalId, fixture.userId), eq(companyMemberships.companyId, fixture.companyId)));
    await expect(guard.check({ sessionId: fixture.session.id, userId: fixture.userId }))
      .resolves.toMatchObject({ kind: "denied", reason: "company_forbidden" });
    expect(providerCalls).toBe(1);
  });

  it.each([
    { label: "a disabled binding", deny: async (fixture: Awaited<ReturnType<typeof assuredUser>>) => {
      await db.update(firebaseOperatorBindings).set({ enabled: false })
        .where(eq(firebaseOperatorBindings.id, fixture.bindingId));
    }, reason: "binding_invalid" },
    { label: "an instance-admin role", deny: async (fixture: Awaited<ReturnType<typeof assuredUser>>) => {
      await db.insert(instanceUserRoles).values({ userId: fixture.userId, role: "instance_admin" });
    }, reason: "instance_admin_forbidden" },
    { label: "a removed active membership", deny: async (fixture: Awaited<ReturnType<typeof assuredUser>>) => {
      await db.update(companyMemberships).set({ status: "inactive" })
        .where(and(eq(companyMemberships.principalId, fixture.userId), eq(companyMemberships.companyId, fixture.companyId)));
    }, reason: "company_forbidden" },
  ])("denies an assured session after $label", async ({ deny, reason }) => {
    const fixture = await assuredUser();
    await deny(fixture);
    const guard = await createGuard() as {
      check: (input: { sessionId: string; userId: string }) => Promise<Record<string, unknown>>;
    };

    await expect(guard.check({ sessionId: fixture.session.id, userId: fixture.userId }))
      .resolves.toMatchObject({ kind: "denied", reason });
  });

  it("rechecks binding state after an in-flight provider lookup before allowing the same request", async () => {
    const fixture = await assuredUser();
    const unrelated = await assuredUser();
    let providerStarted!: () => void;
    let releaseProvider!: (proof: Record<string, unknown>) => void;
    const started = new Promise<void>((resolve) => { providerStarted = resolve; });
    const blocked = new Promise<Record<string, unknown>>((resolve) => { releaseProvider = resolve; });
    const guard = await createGuard({ checkUser: async (proof) => {
      providerStarted();
      return blocked;
    } }) as {
      check: (input: { sessionId: string; userId: string }) => Promise<Record<string, unknown>>;
    };
    const pending = guard.check({ sessionId: fixture.session.id, userId: fixture.userId });
    await started;
    await db.update(firebaseOperatorBindings).set({ revision: 2 })
      .where(eq(firebaseOperatorBindings.id, fixture.bindingId));
    releaseProvider({
      projectId: "thl-pclipd-api",
      uid: `uid-${fixture.userId}`,
      authTimeSeconds: fixture.authTimeSeconds,
      checkedAtMs: Date.now(),
      totpFactors: [{ factorId: "totp", uid: `factor-${fixture.userId}` }],
    });

    await expect(pending).resolves.toMatchObject({ kind: "denied" });
    await expect(db.select().from(authSessions).where(eq(authSessions.id, fixture.session.id)))
      .resolves.toHaveLength(0);
    await expect(db.select().from(authSessions).where(eq(authSessions.id, unrelated.session.id)))
      .resolves.toHaveLength(1);
    await expect(db.select().from(firebaseOperatorSessionAssurance)
      .where(eq(firebaseOperatorSessionAssurance.sessionId, unrelated.session.id))).resolves.toHaveLength(1);
  });

  it("denies a Firebase-bound human board API key before touching its last-used timestamp", async () => {
    const userId = await boundUser();
    const rawToken = `pcp_board_guard_${randomUUID().replaceAll("-", "")}`;
    const [key] = await db.insert(boardApiKeys).values({
      userId,
      name: "Guard test key",
      keyHash: hashBearerToken(rawToken),
    }).returning();
    const app = express();
    app.use(actorMiddleware(db, { deploymentMode: "authenticated" }));
    app.get("/actor", (req, res) => res.json(req.actor));
    app.use(errorHandler);

    const response = await request(app).get("/actor").set("Authorization", `Bearer ${rawToken}`);
    const [updatedKey] = await db.select().from(boardApiKeys).where(eq(boardApiKeys.id, key!.id));

    expect.soft(response.status).not.toBe(200);
    expect.soft(updatedKey?.lastUsedAt).toBeNull();
  });

  it("exposes the reusable Firebase operator guard factory", async () => {
    const moduleSpecifier = "../auth/firebase-operator-session-guard.js";
    let guardModule: Record<string, unknown> | undefined;
    try {
      guardModule = await import(moduleSpecifier);
    } catch (error) {
      expect.fail(`guard-core API is not implemented yet: ${error instanceof Error ? error.message : String(error)}`);
    }
    expect(guardModule.createFirebaseOperatorSessionGuard).toEqual(expect.any(Function));
  });
});
