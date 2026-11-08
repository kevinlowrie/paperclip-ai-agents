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
  authAccounts,
  authVerifications,
  companies,
  companyMemberships,
  createDb,
  firebaseOperatorBindings,
  firebaseOperatorSessionAssurance,
  firebaseOperatorLoginTransactions,
} from "@paperclipai/db";
import { startEmbeddedPostgresTestDatabase } from "./helpers/embedded-postgres.js";
import { firebaseOperatorSessionPlugin } from "../auth/firebase-operator-session-plugin.js";
import * as firebaseOperatorSessionModule from "../auth/firebase-operator-session-plugin.js";
import { firebaseOperatorPreAuthRequestHandler } from "../auth/firebase-operator-session-preflight.js";
import { FirebaseOperatorVerificationError, type FirebaseOperatorProof } from "../auth/firebase-operator-verifier.js";
import { createHttpLogger } from "../middleware/logger.js";
import { logger } from "../middleware/logger.js";
import { HTTP_LOG_REDACT_PATHS } from "../middleware/http-log-redaction.js";

const PUBLIC = "https://paperclip.example.test";
const LAB = "https://paperclip.lab.example.test";
const NOW = Date.now();
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

type CapturedSpan = {
  name: string;
  options: unknown;
  parent: unknown;
  attributes: Record<string, unknown>;
  exceptions: string[];
  statuses: Array<{ code: number; message?: string }>;
  ended: boolean;
};
type RecordingTelemetry = {
  spans: CapturedSpan[];
  api: Record<string, any>;
  deregisterResolutionHook(): void;
};
let recordingTelemetry: RecordingTelemetry | undefined;

async function installActualApiRecordingTracer(): Promise<RecordingTelemetry> {
  if (recordingTelemetry) return recordingTelemetry;
  const { createRequire, registerHooks } = await import("node:module");
  const { pathToFileURL } = await import("node:url");
  const apiPath = createRequire(import.meta.url).resolve("@opentelemetry/api");
  const resolutionHook = registerHooks({
    resolve(specifier, context, nextResolve) {
      if (specifier === "@opentelemetry/api") return nextResolve(pathToFileURL(apiPath).href, context);
      return nextResolve(specifier, context);
    },
  });
  const api = await import(pathToFileURL(apiPath).href) as Record<string, any>;
  const spans: CapturedSpan[] = [];
  const tracer = {
    startSpan(name: string, options?: unknown, parent?: unknown) {
      const captured: CapturedSpan = { name, options, parent, attributes: {}, exceptions: [], statuses: [], ended: false };
      spans.push(captured);
      return {
        setAttribute(key: string, value: unknown) { captured.attributes[key] = value; return this; },
        setAttributes(values: Record<string, unknown>) { Object.assign(captured.attributes, values); return this; },
        addEvent(name: string, attributes?: Record<string, unknown>) { captured.attributes[`event:${name}`] = attributes ?? {}; return this; },
        recordException(error: unknown) { captured.exceptions.push(error instanceof Error ? error.message : String(error)); },
        setStatus(status: { code: number; message?: string }) { captured.statuses.push(status); },
        updateName(name: string) { captured.name = name; return this; },
        end() { captured.ended = true; },
        isRecording() { return true; },
        spanContext() { return { traceId: "11111111111111111111111111111111", spanId: "2222222222222222", traceFlags: 1, traceState: undefined, isRemote: false }; },
      };
    },
    startActiveSpan(name: string, optionsOrCallback: unknown, contextOrCallback: unknown, callback?: (span: unknown) => unknown) {
      const span = this.startSpan(name, typeof optionsOrCallback === "function" ? undefined : optionsOrCallback);
      const run = typeof optionsOrCallback === "function" ? optionsOrCallback
        : typeof contextOrCallback === "function" ? contextOrCallback : callback;
      return typeof run === "function" ? run(span) : span;
    },
  };
  const provider = { getTracer: () => tracer };
  const registered = api.trace.setGlobalTracerProvider(provider);
  expect(registered).toBe(true);
  recordingTelemetry = { spans, api, deregisterResolutionHook: () => resolutionHook.deregister() };
  return recordingTelemetry;
}

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
    audit?: (event: unknown) => void;
    unsafeAuthOptions?: boolean;
  } = {}) {
    const pluginDependencies = {
      db,
      verifier: { verify: options.verify ?? (async (token: string) => token === TOKEN_SENTINEL ? proof({ uid: f.uid }) : Promise.reject(new Error(`bad token ${token}`))) },
      trustedOrigins: new Set([PUBLIC, LAB]),
      allowedCompanyIds: new Set([f.companyId]),
      now: options.now ?? (() => NOW),
      ...(options.audit ? { audit: options.audit } : {}),
    };
    const rawAuthOptions = {
      secret: "real-test-secret-for-better-auth-session-exchange",
      baseURL: PUBLIC,
      trustedOrigins: [PUBLIC, LAB],
      database: drizzleAdapter(db, {
        provider: "pg",
        schema: { user: authUsers, session: authSessions, account: authAccounts, verification: authVerifications },
      }),
      emailAndPassword: { enabled: true },
      advanced: { crossSubDomainCookies: { enabled: Boolean(options.cookieDomain), domain: options.cookieDomain }, useSecureCookies: true },
      logger: { log: (level: string, message: string, ...args: unknown[]) => options.onLogger?.({ level, message, args }) } as never,
      databaseHooks: options.hooks as never,
      plugins: [firebaseOperatorSessionPlugin(pluginDependencies)],
    };
    const safeOptionsFactory = (firebaseOperatorSessionModule as unknown as {
      firebaseOperatorSafeAuthOptions?: (input: Record<string, unknown>, audit?: (event: unknown) => void) => Record<string, unknown>;
    }).firebaseOperatorSafeAuthOptions;
    const authOptions = options.unsafeAuthOptions ? rawAuthOptions : safeOptionsFactory?.(rawAuthOptions, options.audit) ?? rawAuthOptions;
    const auth = betterAuth(authOptions as never);
    const app = express();
    if (options.httpLogs) {
      const stream = new Writable({ write(chunk, _encoding, callback) { options.httpLogs!.push(chunk.toString()); callback(); } });
      app.use(createHttpLogger(pino({ level: "trace", redact: [...HTTP_LOG_REDACT_PATHS] }, stream)));
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

  async function blockAssuranceInsert() {
    const lockKey = 7_351_921;
    await db.execute(sql.raw(`
      create or replace function pclip_block_test_assurance() returns trigger
      language plpgsql as $$ begin perform pg_advisory_xact_lock(${lockKey}); return new; end $$
    `));
    await db.execute(sql.raw(`
      create trigger pclip_block_test_assurance before insert on firebase_operator_session_assurance
      for each row execute function pclip_block_test_assurance()
    `));
    const blockerDb = createDb(temporary.connectionString);
    let releaseLock!: () => void;
    let signalLock!: () => void;
    const blocked = new Promise<void>((resolve) => { releaseLock = resolve; });
    const lockAcquired = new Promise<void>((resolve) => { signalLock = resolve; });
    const holding = blockerDb.transaction(async (tx) => {
      await tx.execute(sql`select pg_advisory_xact_lock(${lockKey})`);
      signalLock();
      await blocked;
    });
    let lockTimer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        lockAcquired,
        new Promise<never>((_, reject) => { lockTimer = setTimeout(() => reject(new Error("assurance advisory lock was not acquired")), 10_000); }),
      ]);
    } finally {
      if (lockTimer) clearTimeout(lockTimer);
    }
    let released = false;
    let cleaned = false;
    return {
      async waitForInsert() {
        const deadline = Date.now() + 10_000;
        while (Date.now() < deadline) {
          const waits = await db.execute(sql`
            select pid from pg_stat_activity
            where wait_event_type = 'Lock' and query ilike '%firebase_operator_session_assurance%'
          `) as unknown as Array<{ pid: number }>;
          if (waits.length > 0) return true;
          await new Promise((resolve) => setTimeout(resolve, 10));
        }
        return false;
      },
      async release() {
        if (released) return;
        released = true;
        releaseLock();
        await holding;
      },
      async cleanup() {
        if (cleaned) return;
        cleaned = true;
        await this.release();
        await blockerDb.$client.end();
        await db.execute(sql.raw("drop trigger if exists pclip_block_test_assurance on firebase_operator_session_assurance"));
        await db.execute(sql.raw("drop function if exists pclip_block_test_assurance()"));
      },
    };
  }

  async function blockTransactionInsert() {
    const lockKey = 7_351_923;
    await db.execute(sql.raw(`
      create or replace function pclip_block_test_login_transaction() returns trigger
      language plpgsql as $$ begin perform pg_advisory_xact_lock(${lockKey}); return new; end $$
    `));
    await db.execute(sql.raw(`
      create trigger pclip_block_test_login_transaction before insert on firebase_operator_login_transactions
      for each row execute function pclip_block_test_login_transaction()
    `));
    const blockerDb = createDb(temporary.connectionString);
    let releaseLock!: () => void;
    let signalLock!: () => void;
    const blocked = new Promise<void>((resolve) => { releaseLock = resolve; });
    const lockAcquired = new Promise<void>((resolve) => { signalLock = resolve; });
    const holding = blockerDb.transaction(async (tx) => {
      await tx.execute(sql`select pg_advisory_xact_lock(${lockKey})`);
      signalLock();
      await blocked;
    });
    await lockAcquired;
    let released = false;
    let cleaned = false;
    return {
      async waitForInsert() {
        const deadline = Date.now() + 10_000;
        while (Date.now() < deadline) {
          const waits = await db.execute(sql`
            select pid from pg_stat_activity
            where wait_event_type = 'Lock' and query ilike '%firebase_operator_login_transactions%'
          `) as unknown as Array<{ pid: number }>;
          if (waits.length > 0) return true;
          await new Promise((resolve) => setTimeout(resolve, 10));
        }
        return false;
      },
      async release() {
        if (released) return;
        released = true;
        releaseLock();
        await holding;
      },
      async cleanup() {
        if (cleaned) return;
        cleaned = true;
        await this.release();
        await blockerDb.$client.end();
        await db.execute(sql.raw("drop trigger if exists pclip_block_test_login_transaction on firebase_operator_login_transactions"));
        await db.execute(sql.raw("drop function if exists pclip_block_test_login_transaction()"));
      },
    };
  }

  it("records Better Auth 1.7.18's real post-create exception in a standalone unsafe SDK instance", async () => {
    const telemetry = await installActualApiRecordingTracer();
    telemetry.spans.length = 0;
    const f = await fixture();
    const sdkSentinel = "SDK-TRACE-ERROR-SENTINEL-REWORK1";
    const auth = betterAuth({
      secret: "standalone-unsafe-sdk-trace-control",
      baseURL: PUBLIC,
      trustedOrigins: [PUBLIC, LAB],
      experimental: { instrumentation: { enabled: true } },
      database: drizzleAdapter(db, {
        provider: "pg",
        schema: { user: authUsers, session: authSessions, account: authAccounts, verification: authVerifications },
      }),
      emailAndPassword: { enabled: true },
      databaseHooks: { session: { create: { after: async () => { throw new Error(sdkSentinel); } } } } as never,
    });
    const context = await auth.$context;
    let rejected = false;
    try {
      await context.internalAdapter.createSession(f.userId);
    } catch {
      rejected = true;
    }
    const sdkSpans = telemetry.spans.filter((span) => span.name.includes("session"));
    expect(rejected).toBe(true);
    expect(sdkSpans.some((span) => span.exceptions.includes(sdkSentinel))).toBe(true);
    expect(sdkSpans.some((span) => span.statuses.some((status) => status.message === sdkSentinel))).toBe(true);
  });

  it("builds safe Better Auth options, suppresses raw SDK arguments, and rejects unsafe plugin initialization", async () => {
    const factory = (firebaseOperatorSessionModule as unknown as {
      firebaseOperatorSafeAuthOptions?: (input: Record<string, unknown>, audit?: (event: unknown) => void) => Record<string, unknown>;
    }).firebaseOperatorSafeAuthOptions;
    expect(factory).toBeTypeOf("function");
    if (!factory) return;

    const events: unknown[] = [];
    const source = {
      secret: "safe-options-secret",
      baseURL: PUBLIC,
      trustedOrigins: [PUBLIC],
      experimental: { instrumentation: { enabled: true }, unrelatedFeature: { enabled: true } },
      logger: { level: "debug", disabled: false, log: () => undefined },
      emailAndPassword: { enabled: true },
    };
    const safe = factory(source, (event) => events.push(event));
    expect(safe).not.toBe(source);
    expect(safe.secret).toBe(source.secret);
    expect(safe.trustedOrigins).toEqual([PUBLIC]);
    expect((safe.experimental as Record<string, unknown>).unrelatedFeature).toEqual({ enabled: true });
    expect(((safe.experimental as Record<string, unknown>).instrumentation as Record<string, unknown>).enabled).toBe(false);
    const loggerOptions = safe.logger as { disabled?: boolean; log?: (...args: unknown[]) => void };
    expect(loggerOptions.disabled).not.toBe(true);
    expect(loggerOptions.log).toBeTypeOf("function");
    loggerOptions.log?.("error", "SDK-RAW-MESSAGE-SENTINEL", { state: "SDK-RAW-ARG-SENTINEL", token: TOKEN_SENTINEL });
    expect(events).toHaveLength(1);
    const event = events[0] as Record<string, unknown>;
    expect(event).toMatchObject({ event: "better_auth_log_suppressed", outcome: "suppressed", reason: "sdk_message_suppressed", sdkLevel: "error" });
    expect(Object.keys(event).sort()).toEqual(["correlationId", "event", "outcome", "reason", "sdkLevel"].sort());
    expect(event.correlationId).toEqual(expect.any(String));
    expect(JSON.stringify(events)).not.toContain("SDK-RAW-MESSAGE-SENTINEL");
    expect(JSON.stringify(events)).not.toContain("SDK-RAW-ARG-SENTINEL");
    expect(JSON.stringify(events)).not.toContain(TOKEN_SENTINEL);

    const f = await fixture();
    const unsafe = appFor(f, { unsafeAuthOptions: true }).auth;
    const unsafeRejected = await Promise.resolve(unsafe.$context).then(() => false, () => true);
    expect(unsafeRejected).toBe(true);
    const safeAuth = appFor(f).auth;
    const safeResolved = await Promise.resolve(safeAuth.$context).then(() => true, () => false);
    expect(safeResolved).toBe(true);
    const clonedCallback = { ...loggerOptions, log: (...args: unknown[]) => loggerOptions.log?.(...args) };
    const forged = { ...safe, logger: clonedCallback };
    const forgedAuth = betterAuth({ ...forged, plugins: [firebaseOperatorSessionPlugin({
      db, verifier: { verify: async () => proof() }, trustedOrigins: new Set([PUBLIC]), allowedCompanyIds: new Set([f.companyId]),
    })] } as never);
    const forgedRejected = await Promise.resolve(forgedAuth.$context).then(() => false, () => true);
    expect(forgedRejected).toBe(true);
  });

  it("fails plugin initialization when Better Auth retains ordinary tracing and logger configuration", async () => {
    const f = await fixture();
    const unsafe = appFor(f, { unsafeAuthOptions: true }).auth;
    const rejected = await Promise.resolve(unsafe.$context).then(() => false, () => true);
    expect(rejected).toBe(true);
  });

  it("keeps safe auth spans and audit while removing SDK exception telemetry", async () => {
    const telemetry = await installActualApiRecordingTracer();
    telemetry.spans.length = 0;
    const f = await fixture();
    const events: unknown[] = [];
    const sdkSentinel = "SAFE-TEST-SDK-TRACE-SENTINEL";
    const loggerEntries: unknown[] = [];
    const httpLogs: string[] = [];
    const pinoSpies = ["debug", "info", "warn", "error"].map((level) => vi.spyOn(logger, level as "debug").mockImplementation(() => undefined as never));
    const { app } = appFor(f, {
      audit: (event) => events.push(event),
      onLogger: (entry) => loggerEntries.push(entry),
      httpLogs,
      hooks: { session: { create: { after: async () => { throw new Error(`${sdkSentinel} ${TOKEN_SENTINEL} TOTP-SENTINEL SQL-DETAIL-SENTINEL ${SESSION_SENTINEL}`); } } } },
    });
    const started = await begin(app);
    const response = await exchange(app, started, started.body.state);
    try {
      const capturedSurfaces = [telemetry.spans, events, loggerEntries, httpLogs, response.body, response.headers].map((value) => JSON.stringify(value));
      expect(response.status).toBeGreaterThanOrEqual(400);
      for (const sentinel of [sdkSentinel, TOKEN_SENTINEL, "TOTP-SENTINEL", "SQL-DETAIL-SENTINEL", SESSION_SENTINEL]) {
        expect(capturedSurfaces.some((surface) => surface.includes(sentinel))).toBe(false);
      }
      expect(events.length).toBeGreaterThan(0);
      expect(telemetry.spans.some((span) => span.name.toLowerCase().includes("firebase") || span.name.toLowerCase().includes("operator"))).toBe(true);
      expect(telemetry.spans.some((span) => span.exceptions.length > 0 || span.statuses.some((status) => status.message !== undefined))).toBe(false);
      for (const span of telemetry.spans) {
        expect(Object.values(span.attributes).join(" ")).not.toContain(TOKEN_SENTINEL);
        expect(span.name).not.toContain(sdkSentinel);
      }
      const span = telemetry.spans.find((item) => item.name.toLowerCase().includes("firebase") || item.name.toLowerCase().includes("operator"));
      expect(span?.parent).toBe(telemetry.api.ROOT_CONTEXT);
      expect(response.headers["set-cookie"]?.join("\n") ?? "").not.toMatch(/session_token=[^;\s]+/);
    } finally {
      for (const spy of pinoSpies) spy.mockRestore();
    }
  });

  it("exposes reserved-route HTTP ignore policy and a live ordinary-span recorder control", async () => {
    const instrumentation = await import("../instrumentation.js") as unknown as {
      firebaseOperatorHttpInstrumentationOptions?: () => { ignoreIncomingRequestHook(req: { method?: string; url?: string }): boolean };
    };
    expect(instrumentation.firebaseOperatorHttpInstrumentationOptions).toBeTypeOf("function");
    if (!instrumentation.firebaseOperatorHttpInstrumentationOptions) return;
    const telemetry = await installActualApiRecordingTracer();
    telemetry.spans.length = 0;
    const hook = instrumentation.firebaseOperatorHttpInstrumentationOptions().ignoreIncomingRequestHook;
    const reserved = { method: "POST", url: `/api/auth/firebase-session/unknown?credential=${TOKEN_SENTINEL}&state=HTTP-STATE-SENTINEL` };
    expect(hook(reserved)).toBe(true);
    expect(hook({ method: "GET", url: "/api/auth/firebase-session/EXCHANGE/" })).toBe(true);
    expect(hook({ method: "POST", url: "/api/companies/current/issues?cursor=ordinary" })).toBe(false);

    const tracer = telemetry.api.trace.getTracer("paperclip.rework1.http-test");
    // The optional NodeSDK HTTP/PG instrumentation is not installed in this worktree;
    // this verifies the exact public policy and that the actual API recorder is live.
    tracer.startActiveSpan("http.request.ordinary", {}, (httpSpan: { end(): void }) => {
      tracer.startActiveSpan("pg.query.ordinary", {}, (databaseSpan: { end(): void }) => databaseSpan.end());
      tracer.startActiveSpan("business.handler.ordinary", {}, (businessSpan: { end(): void }) => businessSpan.end());
      httpSpan.end();
    });
    expect(telemetry.spans.map((span) => span.name)).toEqual([
      "http.request.ordinary", "pg.query.ordinary", "business.handler.ordinary",
    ]);
    expect(JSON.stringify(telemetry.spans)).not.toContain(TOKEN_SENTINEL);
    expect(JSON.stringify(telemetry.spans)).not.toContain("HTTP-STATE-SENTINEL");
  });

  it("emits closed audit events with fresh non-request correlation IDs for issuance and denial", async () => {
    const events: unknown[] = [];
    const f = await fixture();
    const { app } = appFor(f, { audit: (event) => events.push(event) });
    const started = await begin(app);
    const success = await exchange(app, started, started.body.state);
    const replay = await exchange(app, started, started.body.state);
    expect(success.status).toBe(200);
    expect(replay.status).toBeGreaterThanOrEqual(400);

    const deniedFixture = await fixture();
    const deniedApp = appFor(deniedFixture, {
      audit: (event) => events.push(event),
      verify: async () => { throw new FirebaseOperatorVerificationError(401); },
    }).app;
    const deniedStarted = await begin(deniedApp);
    const denied = await exchange(deniedApp, deniedStarted, deniedStarted.body.state);
    expect(denied.status).toBeGreaterThanOrEqual(400);

    const parsed = events as Array<Record<string, unknown>>;
    expect(parsed.some((event) => event.event === "begin" && event.outcome === "created" && event.reason === "accepted")).toBe(true);
    expect(parsed.some((event) => event.event === "exchange" && event.outcome === "issued" && event.reason === "accepted")).toBe(true);
    expect(parsed.some((event) => event.event === "exchange" && event.outcome === "denied" && event.reason === "proof_denied")).toBe(true);
    expect(parsed.every((event) => Object.keys(event).every((key) => ["event", "outcome", "reason", "correlationId", "sdkLevel"].includes(key)))).toBe(true);
    const correlations = parsed.map((event) => event.correlationId).filter((id) => typeof id === "string");
    expect(correlations.length).toBeGreaterThanOrEqual(5);
    expect(new Set(correlations).size).toBe(correlations.length);
    const surfaces = JSON.stringify({ events, state: started.body.state, transactionId: started.body.transactionId, uid: f.uid, token: TOKEN_SENTINEL });
    expect(surfaces).not.toContain(started.body.state);
    expect(surfaces).not.toContain(started.body.transactionId);
    expect(surfaces).not.toContain(f.uid);
    expect(surfaces).not.toContain(TOKEN_SENTINEL);
  });

  it("writes bounded default audit events through the repository Pino logger", async () => {
    const f = await fixture();
    const spies = ["debug", "info", "warn", "error"].map((level) => vi.spyOn(logger, level as "debug").mockImplementation(() => undefined as never));
    try {
      const { app } = appFor(f);
      const started = await begin(app);
      const response = await exchange(app, started, started.body.state);
      expect(response.status).toBe(200);
      const calls = spies.flatMap((spy) => spy.mock.calls);
      expect(calls.length).toBeGreaterThan(0);
      const serialized = JSON.stringify(calls);
      expect(serialized).toMatch(/begin|exchange/);
      expect(serialized).not.toContain(started.body.state);
      expect(serialized).not.toContain(started.body.transactionId);
      expect(serialized).not.toContain(f.uid);
      expect(serialized).not.toContain(TOKEN_SENTINEL);
    } finally {
      vi.restoreAllMocks();
    }
  });

  it("limits transaction-cookie lifetime to the remaining persisted begin deadline", async () => {
    const f = await fixture();
    let clock = NOW;
    const { app } = appFor(f, { now: () => clock });
    const beforeIds = new Set((await db.select({ id: firebaseOperatorLoginTransactions.id }).from(firebaseOperatorLoginTransactions)).map((row) => row.id));
    const transactionBlock = await blockTransactionInsert();
    let pending: Promise<request.Response> | undefined;
    try {
      pending = begin(app);
      expect(await transactionBlock.waitForInsert()).toBe(true);
      clock = NOW + 7_000;
      await transactionBlock.release();
      const started = await pending;
      expect(started.status).toBe(200);
      const row = await db.select().from(firebaseOperatorLoginTransactions)
        .where(eq(firebaseOperatorLoginTransactions.id, started.body.transactionId));
      expect(row[0]?.expiresAt.getTime()).toBe(NOW + 300_000);
      const maxAge = Number(started.headers["set-cookie"]?.[0]?.match(/Max-Age=(\d+)/i)?.[1]);
      expect(maxAge).toBeLessThanOrEqual(Math.floor((row[0]!.expiresAt.getTime() - clock) / 1000));
      expect(maxAge).toBeLessThan(300);
    } finally {
      await transactionBlock.release();
      await pending?.catch(() => undefined);
      await transactionBlock.cleanup();
    }
  });

  it("does not issue a new transaction cookie when begin persistence outlives the 300-second deadline", async () => {
    const f = await fixture();
    let clock = NOW;
    const { app } = appFor(f, { now: () => clock });
    const transactionBlock = await blockTransactionInsert();
    let pending: Promise<request.Response> | undefined;
    try {
      pending = begin(app);
      expect(await transactionBlock.waitForInsert()).toBe(true);
      clock = NOW + 300_001;
      await transactionBlock.release();
      const started = await pending;
      expect(started.status).toBeGreaterThanOrEqual(400);
      expect(started.headers["set-cookie"] ?? []).toHaveLength(0);
      const rows = await db.select().from(firebaseOperatorLoginTransactions)
        .where(eq(firebaseOperatorLoginTransactions.origin, PUBLIC));
      const justCreated = rows.find((row) => !beforeIds.has(row.id));
      expect(justCreated?.expiresAt.getTime()).toBe(NOW + 300_000);
    } finally {
      await transactionBlock.release();
      await pending?.catch(() => undefined);
      await transactionBlock.cleanup();
    }
  });

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

    const labStarted = await begin(app, LAB);
    expect(labStarted.status).toBe(200);
    const labExchange = await exchange(app, labStarted, labStarted.body.state, LAB);
    expect(labExchange.status).toBe(200);
    expect(labExchange.body).toEqual({ redirectTo: "/companies/current" });
  });

  it("rejects a persisted SDK session whose before-create hook changes its user, cleaning only that session", async () => {
    const f = await fixture();
    await db.execute(sql`insert into instance_user_roles (user_id, role) values (${f.creatorId}, 'instance_admin')`);
    const existing = {
      id: `unrelated-session-${randomUUID()}`,
      token: `unrelated-token-${randomUUID()}`,
      userId: f.creatorId,
      createdAt: new Date(NOW - 60_000),
      updatedAt: new Date(NOW - 60_000),
      expiresAt: new Date(NOW + 60 * 60_000),
    };
    await db.insert(authSessions).values(existing);
    const { app } = appFor(f, {
      hooks: { session: { create: { before: async () => ({ data: { userId: f.creatorId } }) } } },
    });
    const started = await begin(app);
    const response = await exchange(app, started, started.body.state);

    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(response.headers["set-cookie"]?.join("\n") ?? "").not.toMatch(/session_token=[^;\s]+/);
    const transaction = await db.select().from(firebaseOperatorLoginTransactions)
      .where(eq(firebaseOperatorLoginTransactions.id, started.body.transactionId));
    expect(transaction[0]?.consumedAt).toBeInstanceOf(Date);
    const creatorSessions = await db.select().from(authSessions).where(eq(authSessions.userId, f.creatorId));
    expect(creatorSessions).toHaveLength(1);
    expect(creatorSessions[0]).toMatchObject({ id: existing.id, token: existing.token });
    expect(await db.select().from(firebaseOperatorSessionAssurance)
      .where(eq(firebaseOperatorSessionAssurance.userId, f.userId))).toHaveLength(0);
  });

  it("rejects persisted SDK session timestamps changed by a before-create hook", async () => {
    const f = await fixture();
    const { app } = appFor(f, {
      hooks: { session: { create: { before: async () => ({ data: {
        createdAt: new Date(NOW - 60_000), expiresAt: new Date(NOW + 24 * 60 * 60_000),
      } }) } } },
    });
    const started = await begin(app);
    const response = await exchange(app, started, started.body.state);

    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(response.headers["set-cookie"]?.join("\n") ?? "").not.toMatch(/session_token=[^;\s]+/);
    const transaction = await db.select().from(firebaseOperatorLoginTransactions)
      .where(eq(firebaseOperatorLoginTransactions.id, started.body.transactionId));
    expect(transaction[0]?.consumedAt).toBeInstanceOf(Date);
    expect(await db.select().from(authSessions).where(eq(authSessions.userId, f.userId))).toHaveLength(0);
    expect(await db.select().from(firebaseOperatorSessionAssurance)
      .where(eq(firebaseOperatorSessionAssurance.userId, f.userId))).toHaveLength(0);
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

  it("requires private preflight provenance even when the same Better Auth plugin is mounted directly", async () => {
    const f = await fixture(); const { app, auth } = appFor(f);
    const started = await begin(app);
    const directMount = express();
    directMount.use(express.json());
    directMount.all("/api/auth/*splat", (req, res, next) => {
      void Promise.resolve(toNodeHandler(auth)(req, res)).catch(next);
    });
    const denied = await exchange(directMount, started, started.body.state);
    expect(denied.status).toBeGreaterThanOrEqual(400);
    expect(denied.headers["set-cookie"]?.join("\n") ?? "").not.toMatch(/session_token=[^;\s]+/);
    expect(await db.select().from(authSessions).where(eq(authSessions.userId, f.userId))).toHaveLength(0);
    const transactions = await db.select().from(firebaseOperatorLoginTransactions)
      .where(eq(firebaseOperatorLoginTransactions.id, started.body.transactionId));
    expect(transactions[0]?.consumedAt).toBeNull();
  });

  it("denies a whitespace-padded exchange parsed by an earlier 10 MB JSON middleware", async () => {
    const f = await fixture();
    const verifier = vi.fn(async () => proof({ uid: f.uid }));
    const { app, auth } = appFor(f, { verify: verifier });
    const started = await begin(app);
    const wrongOrder = express();
    wrongOrder.use(express.json({ limit: "10mb" }));
    wrongOrder.use(firebaseOperatorPreAuthRequestHandler({ trustedOrigins: new Set([PUBLIC, LAB]) }));
    wrongOrder.all("/api/auth/*splat", (req, res, next) => {
      void Promise.resolve(toNodeHandler(auth)(req, res)).catch(next);
    });
    wrongOrder.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
      res.status(500).json({ error: String(error) });
    });

    const cookie = started.headers["set-cookie"]?.[0]?.split(";")[0] ?? "";
    const valid = JSON.stringify({ transactionId: started.body.transactionId, state: started.body.state });
    const padded = `${valid}${" ".repeat(5000)}`;
    expect(Buffer.byteLength(padded)).toBeGreaterThan(4096);
    const response = await request(wrongOrder).post("/api/auth/firebase-session/exchange")
      .set("Origin", PUBLIC).set("Host", new URL(PUBLIC).host).set("Cookie", cookie)
      .set("Authorization", `Bearer ${TOKEN_SENTINEL}`).set("Content-Type", "application/json")
      .send(padded);

    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(response.headers["set-cookie"]?.join("\n") ?? "").not.toMatch(/session_token=[^;\s]+/);
    expect(verifier).not.toHaveBeenCalled();
    const transaction = await db.select().from(firebaseOperatorLoginTransactions)
      .where(eq(firebaseOperatorLoginTransactions.id, started.body.transactionId));
    expect(transaction[0]?.consumedAt).toBeNull();
  });

  it.each([
    ["wrong project", { projectId: "attacker-project" }],
    ["stale authentication", { authTimeSeconds: Math.floor(NOW / 1000) - 301 }],
    ["future authentication", { authTimeSeconds: Math.floor(NOW / 1000) + 1 }],
    ["no TOTP", { totpFactors: [] }],
  ])("denies %s proof with a generic response and no session", async (_label, proofOverrides) => {
    const f = await fixture(); const { app } = appFor(f, { verify: async () => proof({ ...proofOverrides, uid: f.uid } as Partial<FirebaseOperatorProof>) });
    const started = await begin(app);
    const response = await exchange(app, started, started.body.state);
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(JSON.stringify(response.body)).not.toContain("attacker-project");
    expect(response.headers["set-cookie"]?.join("\n") ?? "").not.toContain("session_token");
    expect(await db.select().from(authSessions).where(eq(authSessions.userId, f.userId))).toHaveLength(0);
  });

  it("rechecks auth_time freshness at final issuance after a PostgreSQL lock wait", async () => {
    const f = await fixture(); let clock = NOW;
    const authTimeSeconds = Math.floor(NOW / 1000) - 299;
    const verifier = vi.fn(async () => proof({ uid: f.uid, authTimeSeconds }));
    expect(NOW - authTimeSeconds * 1000).toBeLessThanOrEqual(300_000);
    const { app } = appFor(f, { now: () => clock, verify: verifier });
    const started = await begin(app);
    const blockerDb = createDb(temporary.connectionString);
    let unlock!: () => void;
    const blocked = new Promise<void>((resolve) => { unlock = resolve; });
    let signalLock!: () => void;
    const lockAcquired = new Promise<void>((resolve) => { signalLock = resolve; });
    let pending: Promise<request.Response> | undefined;
    const holding = blockerDb.transaction(async (tx) => {
      await tx.execute(sql`select id from firebase_operator_bindings where id = ${f.bindingId} for update`);
      signalLock();
      await blocked;
    });
    try {
      let lockTimer: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([
          lockAcquired,
          new Promise<never>((_, reject) => { lockTimer = setTimeout(() => reject(new Error("binding row lock was not acquired")), 10_000); }),
        ]);
      } finally {
        if (lockTimer) clearTimeout(lockTimer);
      }
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
      expect(verifier).toHaveBeenCalledOnce();
      clock = NOW + 2_000;
      expect(clock - authTimeSeconds * 1000).toBeGreaterThan(300_000);
      expect(clock - NOW).toBeLessThanOrEqual(60_000);
      expect(clock).toBeLessThan(new Date(started.body.expiresAt).getTime());
      unlock();
      const response = await pending;
      expect(response.status).toBeGreaterThanOrEqual(400);
      expect(response.headers["set-cookie"]?.join("\n") ?? "").not.toContain("session_token");
      expect(await db.select().from(authSessions).where(eq(authSessions.userId, f.userId))).toHaveLength(0);
      const transaction = await db.select().from(firebaseOperatorLoginTransactions)
        .where(eq(firebaseOperatorLoginTransactions.id, started.body.transactionId));
      expect(transaction[0]?.consumedAt).toBeInstanceOf(Date);
    } finally {
      unlock();
      await pending?.catch(() => undefined);
      await holding;
      await blockerDb.$client.end();
    }
  });

  it("rechecks auth_time after an actual PostgreSQL assurance INSERT wait", async () => {
    const f = await fixture();
    let clock = NOW;
    const authTimeSeconds = Math.floor(NOW / 1000) - 299;
    const verifier = vi.fn(async () => proof({ uid: f.uid, authTimeSeconds, checkedAtMs: NOW }));
    const { app } = appFor(f, { now: () => clock, verify: verifier });
    const started = await begin(app);
    const assuranceBlock = await blockAssuranceInsert();
    let pending: Promise<request.Response> | undefined;
    try {
      pending = exchange(app, started, started.body.state);
      expect(await assuranceBlock.waitForInsert()).toBe(true);
      expect(verifier).toHaveBeenCalledOnce();
      clock = NOW + 2_000;
      expect(clock - authTimeSeconds * 1000).toBeGreaterThan(300_000);
      expect(clock - NOW).toBeLessThanOrEqual(60_000);
      expect(clock).toBeLessThan(new Date(started.body.expiresAt).getTime());
      await assuranceBlock.release();
      const response = await pending;
      expect(response.status).toBeGreaterThanOrEqual(400);
      expect(response.headers["set-cookie"]?.join("\n") ?? "").not.toMatch(/session_token=[^;\s]+/);
      expect(await db.select().from(authSessions).where(eq(authSessions.userId, f.userId))).toHaveLength(0);
      expect(await db.select().from(firebaseOperatorSessionAssurance)
        .where(eq(firebaseOperatorSessionAssurance.userId, f.userId))).toHaveLength(0);
      const transaction = await db.select().from(firebaseOperatorLoginTransactions)
        .where(eq(firebaseOperatorLoginTransactions.id, started.body.transactionId));
      expect(transaction[0]?.consumedAt).toBeInstanceOf(Date);
    } finally {
      await assuranceBlock.release();
      await pending?.catch(() => undefined);
      await assuranceBlock.cleanup();
    }
  });

  it("rechecks the independent 60-second verifier freshness boundary after assurance INSERT waits", async () => {
    const f = await fixture();
    let clock = NOW;
    const verifier = vi.fn(async () => proof({ uid: f.uid, authTimeSeconds: Math.floor((NOW - 100_000) / 1000), checkedAtMs: NOW - 59_000 }));
    const { app } = appFor(f, { now: () => clock, verify: verifier });
    const started = await begin(app);
    const assuranceBlock = await blockAssuranceInsert();
    let pending: Promise<request.Response> | undefined;
    try {
      pending = exchange(app, started, started.body.state);
      expect(await assuranceBlock.waitForInsert()).toBe(true);
      clock = NOW + 2_000;
      expect(clock - (NOW - 59_000)).toBeGreaterThan(60_000);
      expect(clock - Math.floor((NOW - 100_000) / 1000) * 1000).toBeLessThanOrEqual(300_000);
      expect(clock).toBeLessThan(new Date(started.body.expiresAt).getTime());
      await assuranceBlock.release();
      const response = await pending;
      expect(response.status).toBeGreaterThanOrEqual(400);
      expect(response.headers["set-cookie"]?.join("\n") ?? "").not.toMatch(/session_token=[^;\s]+/);
      expect(await db.select().from(authSessions).where(eq(authSessions.userId, f.userId))).toHaveLength(0);
      expect(await db.select().from(firebaseOperatorSessionAssurance)
        .where(eq(firebaseOperatorSessionAssurance.userId, f.userId))).toHaveLength(0);
      const transaction = await db.select().from(firebaseOperatorLoginTransactions)
        .where(eq(firebaseOperatorLoginTransactions.id, started.body.transactionId));
      expect(transaction[0]?.consumedAt).toBeInstanceOf(Date);
    } finally {
      await assuranceBlock.release();
      await pending?.catch(() => undefined);
      await assuranceBlock.cleanup();
    }
  });

  it("rechecks the independent 300-second transaction expiry after assurance INSERT waits", async () => {
    const f = await fixture();
    let clock = NOW;
    const verifier = vi.fn(async () => {
      clock = NOW + 299_000;
      return proof({ uid: f.uid, authTimeSeconds: Math.floor(clock / 1000), checkedAtMs: clock });
    });
    const { app } = appFor(f, { now: () => clock, verify: verifier });
    const started = await begin(app);
    const assuranceBlock = await blockAssuranceInsert();
    let pending: Promise<request.Response> | undefined;
    try {
      pending = exchange(app, started, started.body.state);
      expect(await assuranceBlock.waitForInsert()).toBe(true);
      expect(clock).toBeLessThan(new Date(started.body.expiresAt).getTime());
      clock = NOW + 301_000;
      expect(clock).toBeGreaterThanOrEqual(new Date(started.body.expiresAt).getTime());
      expect(clock - Math.floor((NOW + 299_000) / 1000) * 1000).toBeLessThanOrEqual(60_000);
      expect(clock - Math.floor((NOW + 299_000) / 1000) * 1000).toBeLessThanOrEqual(300_000);
      await assuranceBlock.release();
      const response = await pending;
      expect(response.status).toBeGreaterThanOrEqual(400);
      expect(response.headers["set-cookie"]?.join("\n") ?? "").not.toMatch(/session_token=[^;\s]+/);
      expect(await db.select().from(authSessions).where(eq(authSessions.userId, f.userId))).toHaveLength(0);
      expect(await db.select().from(firebaseOperatorSessionAssurance)
        .where(eq(firebaseOperatorSessionAssurance.userId, f.userId))).toHaveLength(0);
      const transaction = await db.select().from(firebaseOperatorLoginTransactions)
        .where(eq(firebaseOperatorLoginTransactions.id, started.body.transactionId));
      expect(transaction[0]?.consumedAt).toBeInstanceOf(Date);
    } finally {
      await assuranceBlock.release();
      await pending?.catch(() => undefined);
      await assuranceBlock.cleanup();
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
    let observedSessionToken: string | undefined;
    const loggerEntries: unknown[] = []; const httpLogs: string[] = [];
    const { app } = appFor(f, {
      httpLogs,
      onLogger: (entry) => loggerEntries.push(entry),
      hooks: { session: { create: { after: (session: unknown) => {
        if (typeof session === "object" && session !== null && "token" in session && typeof session.token === "string") observedSessionToken = session.token;
        throw new Error(`${SESSION_SENTINEL} ${TOKEN_SENTINEL} TOTP-SENTINEL SQL-DETAIL-SENTINEL`);
      } } } },
    });
    const started = await begin(app);
    const failed = await exchange(app, started, started.body.state);
    expect(failed.status).toBeGreaterThanOrEqual(400);
    expect(failed.headers["set-cookie"]?.join("\n") ?? "").not.toContain("session_token");
    expect(failed.headers["set-cookie"]?.join("\n") ?? "").not.toContain(SESSION_SENTINEL);
    expect(observedSessionToken).toEqual(expect.any(String));
    expect(JSON.stringify({ body: failed.body, headers: failed.headers, loggerEntries, httpLogs })).not.toContain(observedSessionToken!);
    expect(JSON.stringify({ loggerEntries, httpLogs })).not.toContain(started.body.state);
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
