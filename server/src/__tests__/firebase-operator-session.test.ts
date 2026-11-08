import { randomUUID } from "node:crypto";
import { Writable } from "node:stream";
import express from "express";
import request from "supertest";
import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { toNodeHandler } from "better-auth/node";
import pino from "pino";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { and, eq, sql } from "drizzle-orm";
import {
  authSessions,
  authUsers,
  companies,
  companyMemberships,
  createDb,
  firebaseOperatorBindings,
  firebaseOperatorSessionAssurance,
  firebaseOperatorLoginTransactions,
} from "@paperclipai/db";
import { startEmbeddedPostgresTestDatabase } from "./helpers/embedded-postgres.js";
import { firebaseOperatorSessionPlugin } from "../auth/firebase-operator-session-plugin.js";
import { firebaseOperatorPreAuthRequestHandler } from "../auth/firebase-operator-session-preflight.js";
import { FirebaseOperatorVerificationError, type FirebaseOperatorProof } from "../auth/firebase-operator-verifier.js";
import { createHttpLogger } from "../middleware/logger.js";

const PUBLIC = "https://paperclip.example.test";
const LAB = "https://paperclip.lab.example.test";
const NOW = Date.UTC(2026, 10, 8, 18, 0, 0);
const TOKEN_SENTINEL = "id-token-do-not-log-7cb289";
const SESSION_SENTINEL = "session-token-do-not-log-6b5c44";
const COMPANY_ID = "b0e62d4d-b4f9-4e27-9f62-2b95d1320717";

const proof = (overrides: Partial<FirebaseOperatorProof> = {}): FirebaseOperatorProof => ({
  projectId: "thl-pclipd-api",
  uid: "operator-uid-1",
  authTimeSeconds: Math.floor(NOW / 1000),
  checkedAtMs: NOW,
  totpFactors: [{ factorId: "totp", uid: "totp-factor-1" }],
  ...overrides,
} as FirebaseOperatorProof);

describe("Firebase operator browser session exchange (real PostgreSQL + Better Auth 1.7.18)", () => {
  let temporary: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>>;
  let db: ReturnType<typeof createDb>;
  let seq = 0;

  beforeAll(async () => {
    temporary = await startEmbeddedPostgresTestDatabase("paperclip-firebase-session-");
    db = createDb(temporary.connectionString);
  }, 90_000);

  afterAll(async () => {
    await db?.$client.end();
    await temporary?.cleanup();
  });

  async function fixture(options: { companyActive?: boolean; enabled?: boolean; admin?: boolean } = {}) {
    const suffix = `${++seq}-${randomUUID()}`;
    const userId = `firebase-session-user-${suffix}`;
    const creatorId = `firebase-session-creator-${suffix}`;
    const uid = `firebase-uid-${suffix}`;
    const bindingId = randomUUID();
    const companyId = COMPANY_ID;
    const timestamp = new Date(NOW);
    await db.insert(authUsers).values([
      { id: userId, name: "Operator", email: `${userId}@example.test`, emailVerified: true, createdAt: timestamp, updatedAt: timestamp },
      { id: creatorId, name: "Provisioner", email: `${creatorId}@example.test`, emailVerified: true, createdAt: timestamp, updatedAt: timestamp },
    ]);
    await db.insert(companies).values({ id: companyId, name: `Exchange ${suffix}`, issuePrefix: `X${seq}` }).onConflictDoNothing();
    await db.insert(companyMemberships).values({
      companyId, principalType: "user", principalId: userId,
      status: options.companyActive === false ? "inactive" : "active", membershipRole: "owner",
    });
    await db.insert(firebaseOperatorBindings).values({
      id: bindingId, projectId: "thl-pclipd-api", firebaseUid: uid, userId,
      revision: 4, enabled: options.enabled !== false, createdByUserId: creatorId, updatedByUserId: creatorId,
      createdAt: timestamp, updatedAt: timestamp,
    });
    if (options.admin) await db.execute(sql`insert into instance_user_roles (user_id, role) values (${userId}, 'instance_admin')`);
    return { userId, creatorId, uid, bindingId, companyId };
  }

  function appFor(f: Awaited<ReturnType<typeof fixture>>, options: {
    verify?: (token: string) => Promise<FirebaseOperatorProof>;
    now?: () => number;
    onLogger?: (entry: unknown) => void;
    hooks?: Record<string, unknown>;
    cookieDomain?: string;
    httpLogs?: string[];
  } = {}) {
    const auth = betterAuth({
      secret: "real-test-secret-for-better-auth-session-exchange",
      baseURL: PUBLIC,
      trustedOrigins: [PUBLIC, LAB],
      database: drizzleAdapter(db, { provider: "pg" }),
      emailAndPassword: { enabled: true },
      advanced: { crossSubDomainCookies: { enabled: Boolean(options.cookieDomain), domain: options.cookieDomain }, useSecureCookies: true },
      logger: { log: (level: string, message: string, ...args: unknown[]) => options.onLogger?.({ level, message, args }) } as never,
      databaseHooks: options.hooks as never,
      plugins: [firebaseOperatorSessionPlugin({
        db,
        verifier: { verify: options.verify ?? (async (token) => token === TOKEN_SENTINEL ? proof({ uid: f.uid }) : Promise.reject(new Error(`bad token ${token}`))) },
        trustedOrigins: new Set([PUBLIC, LAB]),
        allowedCompanyIds: new Set([f.companyId]),
        now: options.now ?? (() => NOW),
      })],
    });
    const app = express();
    if (options.httpLogs) {
      const stream = new Writable({ write(chunk, _encoding, callback) { options.httpLogs!.push(chunk.toString()); callback(); } });
      app.use(createHttpLogger(pino({ level: "trace" }, stream)));
    }
    app.use(firebaseOperatorPreAuthRequestHandler({ trustedOrigins: new Set([PUBLIC, LAB]) }));
    app.use(express.json());
    app.all("/api/auth/*splat", (req, res, next) => {
      void Promise.resolve(toNodeHandler(auth)(req, res)).catch(next);
    });
    app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
      res.status(500).json({ error: String(error) });
    });
    return { app, auth };
  }

  async function begin(app: express.Express, origin = PUBLIC, returnPath = "/companies/current") {
    return request(app).post("/api/auth/firebase-session/begin")
      .set("Origin", origin).set("Host", new URL(origin).host)
      .send({ companyId: COMPANY_ID, returnPath }).timeout({ response: 20_000 });
  }

  async function exchange(app: express.Express, transaction: request.Response, state: string, origin = PUBLIC, token: string | null = TOKEN_SENTINEL, cookieFrom = transaction) {
    const cookie = cookieFrom.headers["set-cookie"]?.[0];
    const call = request(app).post("/api/auth/firebase-session/exchange")
      .set("Origin", origin).set("Host", new URL(origin).host)
      .set("Cookie", cookie?.split(";")[0] ?? "")
      .send({ transactionId: transaction.body.transactionId, state });
    return (token === null ? call : call.set("Authorization", `Bearer ${token}`)).timeout({ response: 20_000 });
  }

  it("issues only the normal Better Auth cookie after durable assurance and returns safe metadata", async () => {
    const f = await fixture();
    const { app } = appFor(f, { cookieDomain: ".example.test" });
    const started = await begin(app);
    expect(started.status).toBe(200);
    expect(Object.keys(started.body).sort()).toEqual(["expiresAt", "state", "transactionId"]);
    expect(started.headers["set-cookie"]).toHaveLength(1);
    expect(started.headers["set-cookie"][0]).toMatch(/HttpOnly/i);
    expect(started.headers["set-cookie"][0]).toMatch(/Secure/i);
    expect(started.headers["set-cookie"][0]).toMatch(/SameSite=Strict/i);
    expect(started.headers["set-cookie"][0]).toMatch(/Path=\//i);
    expect(started.headers["set-cookie"][0]).not.toMatch(/Domain=/i);
    expect(started.headers["set-cookie"][0]).toMatch(/Max-Age=300/i);
    const rows = await db.select().from(firebaseOperatorLoginTransactions).where(eq(firebaseOperatorLoginTransactions.id, started.body.transactionId));
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ companyId: f.companyId, origin: PUBLIC, returnPath: "/companies/current" });
    expect(rows[0]?.browserBindingHash).toMatch(/^[0-9a-f]{64}$/);
    expect(rows[0]?.csrfStateHash).toMatch(/^[0-9a-f]{64}$/);
    expect(rows[0]?.csrfStateHash).not.toBe(started.body.state);
    const response = await exchange(app, started, started.body.state);
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ redirectTo: "/companies/current" });
    expect(response.headers["cache-control"]).toContain("no-store");
    expect(response.headers["referrer-policy"]).toBe("no-referrer");
    expect(response.headers["set-cookie"]).toHaveLength(2);
    const sessionCookie = response.headers["set-cookie"].find((value: string) => value.includes("session_token"));
    expect(sessionCookie).toMatch(/Secure/i);
    expect(sessionCookie).toMatch(/HttpOnly/i);
    expect(sessionCookie).toMatch(/SameSite=Lax/i);
    expect(sessionCookie).toMatch(/Path=\//i);
    expect(sessionCookie).not.toMatch(/Domain=/i);
    expect(await db.select().from(authSessions).where(eq(authSessions.userId, f.userId))).toHaveLength(1);
    const sessions = await db.select().from(authSessions).where(eq(authSessions.userId, f.userId));
    const assurances = await db.select().from(firebaseOperatorSessionAssurance).where(eq(firebaseOperatorSessionAssurance.userId, f.userId));
    expect(assurances).toHaveLength(1);
    expect(assurances[0]?.sessionId).toBe(sessions[0]?.id);
    expect(sessions[0]?.expiresAt.getTime()).toBe(NOW + 8 * 60 * 60_000);
    expect(Number(sessionCookie.match(/Max-Age=(\d+)/i)?.[1])).toBeLessThanOrEqual(8 * 60 * 60);
    expect(JSON.stringify(response.body)).not.toContain(SESSION_SENTINEL);
  });

  it.each([
    ["unapproved company", { companyId: randomUUID() }],
    ["extra begin field", { debug: true }],
    ["external return URL", { returnPath: "https://evil.example.test/" }],
    ["protocol relative return URL", { returnPath: "//evil.example.test/path" }],
  ])("rejects %s before issuing transaction state", async (_label, body) => {
    const f = await fixture(); const { app } = appFor(f);
    const response = await request(app).post("/api/auth/firebase-session/begin").set("Origin", PUBLIC).set("Host", new URL(PUBLIC).host).send({ companyId: f.companyId, returnPath: "/ok", ...body });
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(response.headers["set-cookie"] ?? []).toHaveLength(0);
  });

  it("maps authoritative Firebase verifier outages to 503 without issuing a session", async () => {
    const f = await fixture();
    const { app } = appFor(f, { verify: async () => { throw new FirebaseOperatorVerificationError(503); } });
    const started = await begin(app);
    const response = await exchange(app, started, started.body.state);
    expect(response.status).toBe(503);
    expect(response.headers["set-cookie"]?.join("\n") ?? "").not.toMatch(/session_token=[^;\s]+/);
    expect(await db.select().from(authSessions).where(eq(authSessions.userId, f.userId))).toHaveLength(0);
  });

  it("binds transaction to browser and exact configured origin, despite copied cookie and state", async () => {
    const f = await fixture(); const { app } = appFor(f);
    const started = await begin(app, PUBLIC);
    const mismatch = await exchange(app, started, started.body.state, LAB);
    expect(mismatch.status).toBeGreaterThanOrEqual(400);
    expect(mismatch.headers["set-cookie"] ?? []).toHaveLength(0);
    const wrongState = await exchange(app, started, `${started.body.state}x`, PUBLIC);
    expect(wrongState.status).toBeGreaterThanOrEqual(400);
    expect(await db.select().from(authSessions).where(eq(authSessions.userId, f.userId))).toHaveLength(0);
    const correct = await exchange(app, started, started.body.state, PUBLIC);
    expect(correct.status).toBe(200);
  });

  it("rejects extra exchange fields and any bearer token placed in the URL or body", async () => {
    const f = await fixture(); const { app } = appFor(f); const started = await begin(app);
    const cookie = started.headers["set-cookie"]?.[0]?.split(";")[0] ?? "";
    const extra = await request(app).post("/api/auth/firebase-session/exchange")
      .set("Origin", PUBLIC).set("Host", new URL(PUBLIC).host).set("Cookie", cookie)
      .set("Authorization", `Bearer ${TOKEN_SENTINEL}`)
      .send({ transactionId: started.body.transactionId, state: started.body.state, idToken: TOKEN_SENTINEL });
    expect(extra.status).toBeGreaterThanOrEqual(400);
    const query = await request(app).post(`/api/auth/firebase-session/exchange?token=${encodeURIComponent(TOKEN_SENTINEL)}`)
      .set("Origin", PUBLIC).set("Host", new URL(PUBLIC).host).set("Cookie", cookie)
      .set("Authorization", `Bearer ${TOKEN_SENTINEL}`)
      .send({ transactionId: started.body.transactionId, state: started.body.state });
    expect(query.status).toBeGreaterThanOrEqual(400);
    expect(await db.select().from(authSessions).where(eq(authSessions.userId, f.userId))).toHaveLength(0);
  });

  it.each([
    ["wrong project", { projectId: "attacker-project" }],
    ["stale authentication", { authTimeSeconds: Math.floor(NOW / 1000) - 301 }],
    ["future authentication", { authTimeSeconds: Math.floor(NOW / 1000) + 1 }],
    ["no TOTP", { totpFactors: [] }],
  ])("denies %s proof with a generic response and no session", async (_label, proofOverrides) => {
    const f = await fixture(); const { app } = appFor(f, { verify: async () => proof(proofOverrides) });
    const started = await begin(app);
    const response = await exchange(app, started, started.body.state);
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(JSON.stringify(response.body)).not.toContain("attacker-project");
    expect(response.headers["set-cookie"]?.join("\n") ?? "").not.toContain("session_token");
    expect(await db.select().from(authSessions).where(eq(authSessions.userId, f.userId))).toHaveLength(0);
  });

  it("rechecks auth_time freshness at final issuance after a PostgreSQL lock wait", async () => {
    const f = await fixture(); let clock = NOW; const { app } = appFor(f, { now: () => clock });
    const started = await begin(app);
    const blockerDb = createDb(temporary.connectionString);
    let unlock!: () => void;
    const blocked = new Promise<void>((resolve) => { unlock = resolve; });
    let pending: Promise<request.Response> | undefined;
    const holding = blockerDb.transaction(async (tx) => {
      await tx.execute(sql`select id from firebase_operator_bindings where id = ${f.bindingId} for update`);
      await blocked;
    });
    try {
      pending = exchange(app, started, started.body.state);
      const deadline = Date.now() + 10_000;
      let observedWait = false;
      while (Date.now() < deadline) {
        const waits = await db.execute(sql`
          select pid from pg_stat_activity
          where wait_event_type = 'Lock' and query ilike '%firebase_operator_bindings%'
        `) as unknown as Array<{ pid: number }>;
        if (waits.length > 0) { observedWait = true; break; }
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      expect(observedWait).toBe(true);
      clock = NOW + 301_000;
      unlock();
      const response = await pending;
      expect(response.status).toBeGreaterThanOrEqual(400);
      expect(response.headers["set-cookie"]?.join("\n") ?? "").not.toContain("session_token");
      expect(await db.select().from(authSessions).where(eq(authSessions.userId, f.userId))).toHaveLength(0);
    } finally {
      unlock();
      await pending?.catch(() => undefined);
      await holding;
      await blockerDb.$client.end();
    }
  });

  it("atomically permits one concurrent exchange, consumes failed claims, and rejects replay", async () => {
    const f = await fixture(); const { app } = appFor(f);
    const started = await begin(app);
    const pair = await Promise.all([
      exchange(app, started, started.body.state),
      exchange(app, started, started.body.state),
    ]);
    expect(pair.filter((response) => response.status === 200)).toHaveLength(1);
    expect(await db.select().from(authSessions).where(eq(authSessions.userId, f.userId))).toHaveLength(1);
    const replay = await exchange(app, started, started.body.state);
    expect(replay.status).toBeGreaterThanOrEqual(400);
    expect(await db.select().from(authSessions).where(eq(authSessions.userId, f.userId))).toHaveLength(1);
  });

  it("rejects an expired transaction without invoking the verifier or creating a session", async () => {
    const f = await fixture(); let clock = NOW;
    const verifier = vi.fn(async () => proof({ uid: f.uid }));
    const { app } = appFor(f, { now: () => clock, verify: verifier });
    const started = await begin(app);
    expect(new Date(started.body.expiresAt).getTime()).toBe(NOW + 300_000);
    clock += 300_001;
    const response = await exchange(app, started, started.body.state);
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(verifier).not.toHaveBeenCalled();
    expect(await db.select().from(authSessions).where(eq(authSessions.userId, f.userId))).toHaveLength(0);
  });

  it.each(["binding revision", "company membership"] as const)("rechecks %s after session creation begins", async (changedState) => {
    const f = await fixture();
    let entered!: () => void;
    let release!: () => void;
    const reachedCreate = new Promise<void>((resolve) => { entered = resolve; });
    const waitAtCreate = new Promise<void>((resolve) => { release = resolve; });
    const { app } = appFor(f, {
      hooks: { session: { create: { before: async () => { entered(); await waitAtCreate; } } } },
    });
    const started = await begin(app);
    const pending = exchange(app, started, started.body.state);
    try {
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([
          reachedCreate,
          new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("session create hook was not reached")), 10_000); }),
        ]);
      } finally {
        if (timer) clearTimeout(timer);
      }
      if (changedState === "binding revision") {
        await db.update(firebaseOperatorBindings).set({ revision: 5 }).where(eq(firebaseOperatorBindings.id, f.bindingId));
      } else {
        await db.update(companyMemberships).set({ status: "inactive" })
          .where(and(eq(companyMemberships.companyId, f.companyId), eq(companyMemberships.principalId, f.userId)));
      }
      release();
      const response = await pending;
      expect(response.status).toBeGreaterThanOrEqual(400);
      expect(response.headers["set-cookie"]?.join("\n") ?? "").not.toMatch(/session_token=[^;\s]+/);
      expect(await db.select().from(authSessions).where(eq(authSessions.userId, f.userId))).toHaveLength(0);
      expect(await db.select().from(firebaseOperatorSessionAssurance).where(eq(firebaseOperatorSessionAssurance.userId, f.userId))).toHaveLength(0);
    } finally {
      release();
      await pending.catch(() => undefined);
    }
  });

  it("supports same-origin cancellation only with this browser's cookie and state", async () => {
    const f = await fixture(); const { app } = appFor(f);
    const started = await begin(app);
    const other = await begin(app);
    const stolenCancel = await exchange(app, started, started.body.state, PUBLIC, null, other);
    expect(stolenCancel.status).toBeGreaterThanOrEqual(400);
    expect(await db.select().from(authSessions).where(eq(authSessions.userId, f.userId))).toHaveLength(0);
    const cancelled = await exchange(app, started, started.body.state, PUBLIC, null);
    expect(cancelled.status).toBe(401);
    expect(cancelled.headers["set-cookie"]?.join("\n") ?? "").not.toContain("session_token");
    const rows = await db.select().from(firebaseOperatorLoginTransactions).where(eq(firebaseOperatorLoginTransactions.id, started.body.transactionId));
    expect(rows[0]?.consumedAt).toBeInstanceOf(Date);
    expect((await exchange(app, other, other.body.state)).status).toBe(200);
  });

  it("cleans only its preallocated SDK session after assurance or cookie failure, and never replays", async () => {
    const f = await fixture();
    const { app } = appFor(f, { hooks: { session: { create: { after: () => { throw new Error(SESSION_SENTINEL); } } } } });
    const started = await begin(app);
    const failed = await exchange(app, started, started.body.state);
    expect(failed.status).toBeGreaterThanOrEqual(400);
    expect(failed.headers["set-cookie"]?.join("\n") ?? "").not.toContain("session_token");
    expect(failed.headers["set-cookie"]?.join("\n") ?? "").not.toContain(SESSION_SENTINEL);
    expect(await db.select().from(authSessions).where(eq(authSessions.userId, f.userId))).toHaveLength(0);
    expect((await exchange(app, started, started.body.state)).status).toBeGreaterThanOrEqual(400);
  });

  it("deletes the committed session and assurance if Better Auth cookie signing fails", async () => {
    const f = await fixture(); const { app, auth } = appFor(f); const started = await begin(app);
    const context = await auth.$context;
    const originalSecret = context.secret;
    try {
      // Corrupt only this test auth instance's real SDK signing context after begin.
      // This drives Better Auth's own setSignedCookie path to fail at issuance.
      context.secret = {} as string;
      const response = await exchange(app, started, started.body.state);
      expect(response.status).toBeGreaterThanOrEqual(400);
      const cookies = (response.headers["set-cookie"] ?? []) as string[];
      expect(cookies.some((cookie) => cookie.includes("session_token=") && !/Max-Age=0/i.test(cookie) && !/Expires=Thu, 01 Jan 1970/i.test(cookie))).toBe(false);
      expect(JSON.stringify(response.body)).not.toContain(SESSION_SENTINEL);
      expect(await db.select().from(authSessions).where(eq(authSessions.userId, f.userId))).toHaveLength(0);
      expect(await db.select().from(firebaseOperatorSessionAssurance).where(eq(firebaseOperatorSessionAssurance.userId, f.userId))).toHaveLength(0);
      const tx = await db.select().from(firebaseOperatorLoginTransactions).where(eq(firebaseOperatorLoginTransactions.id, started.body.transactionId));
      expect(tx[0]?.consumedAt).toBeInstanceOf(Date);
    } finally {
      context.secret = originalSecret;
    }
  });

  it("leaves no usable session when the real PostgreSQL assurance write fails after nonce claim", async () => {
    const f = await fixture(); const loggerEntries: unknown[] = []; const httpLogs: string[] = [];
    const { app } = appFor(f, { httpLogs, onLogger: (entry) => loggerEntries.push(entry) });
    const started = await begin(app);
    await db.execute(sql.raw(`
      create or replace function pclip_reject_test_assurance() returns trigger
      language plpgsql as $$ begin raise exception 'SQL-DETAIL-SENTINEL'; end $$
    `));
    await db.execute(sql.raw(`
      create trigger pclip_reject_test_assurance before insert on firebase_operator_session_assurance
      for each row execute function pclip_reject_test_assurance()
    `));
    try {
      const response = await exchange(app, started, started.body.state);
      expect(response.status).toBeGreaterThanOrEqual(400);
      expect(response.headers["set-cookie"]?.join("\n") ?? "").not.toMatch(/session_token=[^;\s]+/);
      expect(JSON.stringify(response.body)).not.toContain("SQL-DETAIL-SENTINEL");
      expect(JSON.stringify({ loggerEntries, httpLogs })).not.toContain("SQL-DETAIL-SENTINEL");
      expect(await db.select().from(authSessions).where(eq(authSessions.userId, f.userId))).toHaveLength(0);
      const transaction = await db.select().from(firebaseOperatorLoginTransactions)
        .where(eq(firebaseOperatorLoginTransactions.id, started.body.transactionId));
      expect(transaction[0]?.consumedAt).toBeInstanceOf(Date);
      const replay = await exchange(app, started, started.body.state);
      expect(replay.status).toBeGreaterThanOrEqual(400);
    } finally {
      await db.execute(sql.raw("drop trigger if exists pclip_reject_test_assurance on firebase_operator_session_assurance"));
      await db.execute(sql.raw("drop function if exists pclip_reject_test_assurance()"));
    }
  });

  it("does not exchange for inactive membership, disabled binding, or an instance administrator", async () => {
    for (const opts of [{ companyActive: false }, { enabled: false }, { admin: true }]) {
      const f = await fixture(opts); const { app } = appFor(f); const started = await begin(app);
      const response = await exchange(app, started, started.body.state);
      expect(response.status).toBeGreaterThanOrEqual(400);
      expect(response.headers["set-cookie"]?.join("\n") ?? "").not.toContain("session_token");
      expect(await db.select().from(authSessions).where(eq(authSessions.userId, f.userId))).toHaveLength(0);
    }
  });

  it("keeps token, state, verifier, SQL and session sentinels out of HTTP body and SDK logger", async () => {
    const f = await fixture(); const emitted: unknown[] = []; const httpLogs: string[] = [];
    const { app } = appFor(f, { httpLogs, onLogger: (entry) => emitted.push(entry), verify: async () => { throw new Error(`${TOKEN_SENTINEL} TOTP-SENTINEL SQL-DETAIL-SENTINEL`); } });
    const started = await begin(app);
    const response = await exchange(app, started, started.body.state);
    const surface = JSON.stringify({ body: response.body, logs: emitted, httpLogs, headers: response.headers });
    expect(surface).not.toContain(TOKEN_SENTINEL);
    expect(JSON.stringify({ emitted, httpLogs })).not.toContain(started.body.state);
    expect(surface).not.toContain(SESSION_SENTINEL);
  });
});
