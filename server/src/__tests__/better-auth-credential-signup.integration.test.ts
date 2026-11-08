/**
 * End-to-end coverage for the credential sign-up and sign-in that a
 * self-hosted install depends on, driven through the real Better Auth mount
 * against the real Drizzle schema and a migrated Postgres.
 *
 * The other Better Auth suites mount either a stub handler or the in-memory
 * adapter, so neither notices when Better Auth's `account` model grows a field
 * the Drizzle table does not have. The Drizzle adapter validates the model
 * against the schema on every write and throws
 * `The field "<name>" does not exist in the "account" Drizzle schema`, which
 * the mount turns into a 500 with an empty body — a fresh install cannot
 * create its first user at all. This suite is the one that fails when that
 * happens.
 */

import express from "express";
import { createHash, randomUUID } from "node:crypto";
import { eq } from "drizzle-orm";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { authAccounts, authSessions, createDb, firebaseOperatorBindings } from "@paperclipai/db";
import {
  getEmbeddedPostgresTestSupport,
  startEmbeddedPostgresTestDatabase,
} from "./helpers/embedded-postgres.js";
import { createBetterAuthHandler, createBetterAuthInstance } from "../auth/better-auth.js";
import type { Config } from "../config.js";

const ORIGIN = "http://127.0.0.1:41999";
const EMAIL = "founder@example.com";
const PASSWORD = "correct-horse-battery-staple";

const embeddedPostgresSupport = await getEmbeddedPostgresTestSupport();
const describeEmbeddedPostgres = embeddedPostgresSupport.supported ? describe : describe.skip;

function testConfig(): Config {
  // Only the auth-relevant fields are read by `createBetterAuthInstance`; the
  // rest of `Config` describes storage, backups, and scheduling that the Better
  // Auth instance never looks at.
  return {
    deploymentMode: "authenticated",
    deploymentExposure: "private",
    authBaseUrlMode: "explicit",
    authPublicBaseUrl: ORIGIN,
    authDisableSignUp: false,
    allowedHostnames: ["127.0.0.1"],
    port: 41999,
  } as unknown as Config;
}

function sessionCookies(response: request.Response): string[] {
  const raw = response.headers["set-cookie"];
  const cookies = Array.isArray(raw) ? raw : raw ? [raw] : [];
  return cookies.filter((cookie) => cookie.includes("session_token"));
}

function sha256(value: string) {
  return createHash("sha256").update(value).digest("hex");
}

describeEmbeddedPostgres("Better Auth credential sign-up against the real schema", () => {
  let database: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>> | null = null;
  let db!: ReturnType<typeof createDb>;
  let app!: express.Express;
  const originalEnv = {
    secret: process.env.BETTER_AUTH_SECRET,
    rateLimit: process.env.PAPERCLIP_AUTH_RATE_LIMIT_ENABLED,
  };

  beforeAll(async () => {
    process.env.BETTER_AUTH_SECRET = "better-auth-secret-for-credential-signup-tests";
    // The rate limiter is on by default in `authenticated` mode and would score
    // the sign-up and sign-in this suite issues back to back.
    process.env.PAPERCLIP_AUTH_RATE_LIMIT_ENABLED = "false";

    database = await startEmbeddedPostgresTestDatabase("paperclip-better-auth-signup-");
    db = createDb(database.connectionString);

    const auth = createBetterAuthInstance(db, testConfig(), [ORIGIN]);
    app = express();
    // Mounted exactly as `createApp` mounts it, and with no body parser in
    // front of it: Better Auth reads the raw request body itself.
    app.all("/api/auth/{*authPath}", createBetterAuthHandler(auth));
  }, 30_000);

  afterAll(async () => {
    await database?.cleanup();
    if (originalEnv.secret === undefined) delete process.env.BETTER_AUTH_SECRET;
    else process.env.BETTER_AUTH_SECRET = originalEnv.secret;
    if (originalEnv.rateLimit === undefined) delete process.env.PAPERCLIP_AUTH_RATE_LIMIT_ENABLED;
    else process.env.PAPERCLIP_AUTH_RATE_LIMIT_ENABLED = originalEnv.rateLimit;
  });

  it("creates the user and its credential account, then signs that user in", async () => {
    const signUp = await request(app)
      .post("/api/auth/sign-up/email")
      .set("origin", ORIGIN)
      .send({ email: EMAIL, password: PASSWORD, name: "Founder" });

    // A missing `account` column fails here with a 500 and an empty body.
    expect(signUp.status).toBe(200);
    expect(signUp.body?.user?.email).toBe(EMAIL);

    // Sign-up has to leave a usable account row behind. A half-created user —
    // a `user` row with no `account` — cannot sign in, cannot sign up again,
    // and cannot reset its password.
    const accounts = await db.select().from(authAccounts);
    expect(accounts).toHaveLength(1);
    expect(accounts[0]).toMatchObject({
      providerId: "credential",
    });
    // New Better Auth credential accounts are keyed by provider_id/account_id;
    // issuer is retained only for legacy rows and is nullable in the current DB.
    expect(accounts[0]?.issuer).toBeNull();
    expect(accounts[0]?.password).toBeTruthy();

    const signIn = await request(app)
      .post("/api/auth/sign-in/email")
      .set("origin", ORIGIN)
      .send({ email: EMAIL, password: PASSWORD });

    expect(signIn.status).toBe(200);
    expect(signIn.body?.user?.email).toBe(EMAIL);
    expect(sessionCookies(signIn).length).toBeGreaterThan(0);
  });

  it("keeps a legacy issuer credential usable after upgrading the account key", async () => {
    const signUp = await request(app)
      .post("/api/auth/sign-up/email")
      .set("origin", ORIGIN)
      .send({ email: "legacy@example.com", password: PASSWORD, name: "Legacy" });
    expect(signUp.status).toBe(200);

    // Model a row written by Better Auth 1.7.2 before issuer became optional.
    await db
      .update(authAccounts)
      .set({ issuer: "local:credential" })
      .where(eq(authAccounts.userId, signUp.body.user.id));

    const signIn = await request(app)
      .post("/api/auth/sign-in/email")
      .set("origin", ORIGIN)
      .send({ email: "legacy@example.com", password: PASSWORD });

    expect(signIn.status).toBe(200);
    expect(signIn.body?.user?.email).toBe("legacy@example.com");
    expect(sessionCookies(signIn).length).toBeGreaterThan(0);
  });

  it("does not issue an ordinary credential session after the user is Firebase-bound", async () => {
    const signUp = await request(app)
      .post("/api/auth/sign-up/email")
      .set("origin", ORIGIN)
      .send({ email: "bound-credential@example.com", password: PASSWORD, name: "Bound User" });
    expect(signUp.status).toBe(200);

    const userId = signUp.body.user.id as string;
    await db.insert(firebaseOperatorBindings).values({
      firebaseUid: `bound-credential-${userId}`,
      userId,
      createdByUserId: userId,
      updatedByUserId: userId,
    });
    const sessionsBefore = await db.select().from(authSessions);

    const signIn = await request(app)
      .post("/api/auth/sign-in/email")
      .set("origin", ORIGIN)
      .send({ email: "bound-credential@example.com", password: PASSWORD });

    // The browser must not receive a normal session for an operator identity;
    // checking both the HTTP cookie and persisted rows proves the real SDK hook.
    expect.soft(signIn.status).toBe(401);
    expect.soft(sessionCookies(signIn)).toHaveLength(0);
    expect.soft(await db.select().from(authSessions)).toHaveLength(sessionsBefore.length);
  });

  async function makeBoundUser(label: string) {
    const email = `${label}-${randomUUID()}@example.test`;
    const signUp = await request(app)
      .post("/api/auth/sign-up/email")
      .set("origin", ORIGIN)
      .send({ email, password: PASSWORD, name: label });
    expect(signUp.status).toBe(200);
    const userId = signUp.body.user.id as string;
    const [binding] = await db.insert(firebaseOperatorBindings).values({
      firebaseUid: `bound-${userId}`,
      userId,
      createdByUserId: userId,
      updatedByUserId: userId,
    }).returning();
    return { userId, bindingId: binding!.id, bindingRevision: binding!.revision };
  }

  async function loadIssuanceCapability() {
    const moduleSpecifier = "../auth/firebase-operator-session-issuance.js";
    let capability: {
      withFirebaseOperatorSessionIssuance<T>(input: {
        userId: string;
        bindingId: string;
        bindingRevision: number;
        sessionTokenHash: string;
      }, operation: () => Promise<T>): Promise<T>;
    } | undefined;
    try {
      capability = await import(moduleSpecifier) as never;
    } catch (error) {
      expect.fail(`session issuance capability is not implemented yet: ${error instanceof Error ? error.message : String(error)}`);
    }
    return capability.withFirebaseOperatorSessionIssuance;
  }

  async function sessionAdapterFor() {
    const auth = createBetterAuthInstance(db, testConfig(), [ORIGIN]);
    const context = await (auth as unknown as { $context: Promise<{
      internalAdapter: {
        createSession(userId: string, dontRememberMe?: boolean, override?: Record<string, unknown>, overrideAll?: boolean): Promise<unknown>;
      };
    }> }).$context;
    return context.internalAdapter;
  }

  it("allows the actual SDK token only through a matching one-shot issuance capability", async () => {
    const bound = await makeBoundUser("capability-positive");
    const capability = await loadIssuanceCapability();
    const adapter = await sessionAdapterFor();
    const token = `preallocated-${randomUUID()}`;
    const created = await capability({ ...bound, sessionTokenHash: sha256(token) }, () =>
      adapter.createSession(bound.userId, false, { token }, true));

    expect(created).toMatchObject({ userId: bound.userId, token });
    expect(await db.select().from(authSessions).where(eq(authSessions.userId, bound.userId)))
      .toHaveLength(2);
  });

  it("denies a capability whose preallocated token does not match actual SDK data.token", async () => {
    const bound = await makeBoundUser("capability-wrong-token");
    const capability = await loadIssuanceCapability();
    const adapter = await sessionAdapterFor();
    const before = await db.select().from(authSessions).where(eq(authSessions.userId, bound.userId));
    const reserved = `reserved-${randomUUID()}`;
    const actual = `actual-${randomUUID()}`;

    await expect(capability({ ...bound, sessionTokenHash: sha256(reserved) }, () =>
      adapter.createSession(bound.userId, false, { token: actual }, true))).rejects.toBeDefined();
    await expect(db.select().from(authSessions).where(eq(authSessions.userId, bound.userId)))
      .resolves.toHaveLength(before.length);
  });

  it("denies using another bound user's capability on an actual SDK session", async () => {
    const issuer = await makeBoundUser("capability-wrong-user-issuer");
    const target = await makeBoundUser("capability-wrong-user-target");
    const capability = await loadIssuanceCapability();
    const adapter = await sessionAdapterFor();
    const token = `wrong-user-${randomUUID()}`;
    const before = await db.select().from(authSessions).where(eq(authSessions.userId, target.userId));

    await expect(capability({ ...issuer, sessionTokenHash: sha256(token) }, () =>
      adapter.createSession(target.userId, false, { token }, true))).rejects.toBeDefined();
    await expect(db.select().from(authSessions).where(eq(authSessions.userId, target.userId)))
      .resolves.toHaveLength(before.length);
  });

  it("denies stale binding revisions and replayed capability consumption", async () => {
    const stale = await makeBoundUser("capability-stale-revision");
    const capability = await loadIssuanceCapability();
    const staleAdapter = await sessionAdapterFor();
    const staleToken = `stale-${randomUUID()}`;
    await db.update(firebaseOperatorBindings).set({ revision: stale.bindingRevision + 1 })
      .where(eq(firebaseOperatorBindings.id, stale.bindingId));
    await expect(capability({ ...stale, sessionTokenHash: sha256(staleToken) }, () =>
      staleAdapter.createSession(stale.userId, false, { token: staleToken }, true))).rejects.toBeDefined();

    const replay = await makeBoundUser("capability-replay");
    const replayAdapter = await sessionAdapterFor();
    const firstToken = `first-${randomUUID()}`;
    const replayToken = `replay-${randomUUID()}`;
    const created = await capability({ ...replay, sessionTokenHash: sha256(firstToken) }, async () => {
      const first = await replayAdapter.createSession(replay.userId, false, { token: firstToken }, true);
      await expect(replayAdapter.createSession(replay.userId, false, { token: replayToken }, true))
        .rejects.toBeDefined();
      return first;
    });
    expect(created).toMatchObject({ userId: replay.userId, token: firstToken });
  });
});
