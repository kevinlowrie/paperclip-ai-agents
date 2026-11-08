import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { eq } from "drizzle-orm";
import {
  authSessions,
  authUsers,
  companies,
  companyMemberships,
  createDb,
  instanceUserRoles,
  principalPermissionGrants,
} from "@paperclipai/db";
import {
  getEmbeddedPostgresTestSupport,
  startEmbeddedPostgresTestDatabase,
} from "./helpers/embedded-postgres.js";
import { createFirebaseOperatorProvisioner } from "../auth/firebase-operator-provisioning.js";

const postgresSupport = await getEmbeddedPostgresTestSupport();
if (!postgresSupport.supported) {
  throw new Error(`Firebase operator provisioning tests require embedded PostgreSQL: ${postgresSupport.reason ?? "unsupported host"}`);
}

const NOW = Date.UTC(2026, 10, 8, 12, 0, 0);
const ACTOR_ID = "firebase-provisioning-actor";
const TARGET_ID = "firebase-provisioning-target";
const COMPANY_ID = "af61edaa-51b0-4e45-87c1-1a230a432a55";

describe("Firebase operator provisioning", () => {
  let database: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>>;
  let db: ReturnType<typeof createDb>;

  beforeAll(async () => {
    database = await startEmbeddedPostgresTestDatabase("paperclip-firebase-operator-provisioning-");
    db = createDb(database.connectionString);
  }, 20_000);

  afterEach(async () => {
    await db.delete(authSessions);
    await db.delete(principalPermissionGrants);
    await db.delete(companyMemberships);
    await db.delete(companies);
    await db.delete(instanceUserRoles);
    await db.delete(authUsers);
  });

  afterAll(async () => {
    await db?.$client.end();
    await database?.cleanup();
  });

  async function seedAuthorizedActor() {
    const timestamp = new Date(NOW);
    await db.insert(authUsers).values([
      { id: ACTOR_ID, name: "Board operator", email: "actor@example.test", emailVerified: true, createdAt: timestamp, updatedAt: timestamp },
      { id: TARGET_ID, name: "Existing user", email: "target@example.test", emailVerified: true, createdAt: timestamp, updatedAt: timestamp },
    ]);
    await db.insert(instanceUserRoles).values({ userId: ACTOR_ID, role: "instance_admin" });
    await db.insert(companies).values({ id: COMPANY_ID, name: "Reviewed company", issuePrefix: "FOP" });
    await db.insert(companyMemberships).values({
      companyId: COMPANY_ID,
      principalType: "user",
      principalId: ACTOR_ID,
      status: "active",
      membershipRole: "owner",
    });
    await db.insert(principalPermissionGrants).values({
      companyId: COMPANY_ID,
      principalType: "user",
      principalId: ACTOR_ID,
      permissionKey: "users:manage_permissions",
      scope: null,
      grantedByUserId: ACTOR_ID,
    });
  }

  function makeProvisioner() {
    return createFirebaseOperatorProvisioner(db, {
      identityDirectory: {
        lookup: async (uid: string) => ({ projectId: "thl-pclipd-api", uid, checkedAtMs: NOW }),
      },
      allowedCompanyIds: new Set([COMPANY_ID]),
      now: () => NOW,
    });
  }

  const actor = { type: "board" as const, source: "session" as const, userId: ACTOR_ID };
  const intent = {
    projectId: "thl-pclipd-api" as const,
    firebaseUid: "operator-firebase-uid",
    targetUserId: TARGET_ID,
    binding: { mode: "create" as const, expectedRevision: null, expectedUserId: null },
    companies: [{ companyId: COMPANY_ID, role: "operator" as const }],
  };

  it("requires a current database instance-admin row and separately granted company authority", async () => {
    await seedAuthorizedActor();
    await db.delete(instanceUserRoles).where(eq(instanceUserRoles.userId, ACTOR_ID));
    await expect(makeProvisioner().dryRun({ ...actor, isInstanceAdmin: true }, intent)).rejects.toMatchObject({ status: 403 });

    await db.insert(instanceUserRoles).values({ userId: ACTOR_ID, role: "instance_admin" });
    await db.delete(principalPermissionGrants).where(eq(principalPermissionGrants.principalId, ACTOR_ID));
    await expect(makeProvisioner().dryRun(actor, intent)).rejects.toMatchObject({ status: 403 });
  });

  it("persists an expiring review packet without changing users, bindings, memberships, grants, or sessions", async () => {
    await seedAuthorizedActor();
    await db.insert(authSessions).values({
      id: "target-prebinding-session",
      userId: TARGET_ID,
      token: "synthetic-session-token",
      expiresAt: new Date(NOW + 60_000),
      createdAt: new Date(NOW),
      updatedAt: new Date(NOW),
    });
    const before = {
      users: await db.select().from(authUsers),
      roles: await db.select().from(instanceUserRoles),
      memberships: await db.select().from(companyMemberships),
      grants: await db.select().from(principalPermissionGrants),
      sessions: await db.select().from(authSessions),
    };

    const packet = await makeProvisioner().dryRun(actor, intent);

    expect(packet).toMatchObject({
      packetId: expect.any(String),
      packetHash: expect.any(String),
      expiresAt: expect.any(Date),
      bindingBefore: null,
      plan: expect.any(Object),
    });
    expect(JSON.stringify(packet)).not.toContain("operator@example.test");
    expect(JSON.stringify(packet)).not.toContain("synthetic-session-token");
    await expect(db.select().from(authUsers)).resolves.toEqual(before.users);
    await expect(db.select().from(instanceUserRoles)).resolves.toEqual(before.roles);
    await expect(db.select().from(companyMemberships)).resolves.toEqual(before.memberships);
    await expect(db.select().from(principalPermissionGrants)).resolves.toEqual(before.grants);
    await expect(db.select().from(authSessions)).resolves.toEqual(before.sessions);
  });

  it("applies one exact reviewed packet once, adds only its company scope, and revokes target prebinding sessions", async () => {
    await seedAuthorizedActor();
    await db.insert(authSessions).values([
      { id: "target-before-bind", userId: TARGET_ID, token: "target-session", expiresAt: new Date(NOW + 60_000), createdAt: new Date(NOW), updatedAt: new Date(NOW) },
      { id: "actor-unrelated-session", userId: ACTOR_ID, token: "actor-session", expiresAt: new Date(NOW + 60_000), createdAt: new Date(NOW), updatedAt: new Date(NOW) },
    ]);
    const provisioner = makeProvisioner();
    const packet = await provisioner.dryRun(actor, intent);
    const applied = await provisioner.apply(actor, { packetId: packet.packetId, packetHash: packet.packetHash });

    expect(applied).toMatchObject({
      packetId: packet.packetId,
      bindingId: expect.any(String),
      bindingRevision: 1,
      status: "applied",
      revokedSessionCount: 1,
    });
    expect(await db.select().from(authUsers)).toHaveLength(2);
    expect(await db.select().from(instanceUserRoles).where(eq(instanceUserRoles.userId, TARGET_ID))).toHaveLength(0);
    expect(await db.select().from(companyMemberships).where(eq(companyMemberships.principalId, TARGET_ID))).toMatchObject([
      { companyId: COMPANY_ID, principalType: "user", principalId: TARGET_ID, status: "active", membershipRole: "operator" },
    ]);
    expect(await db.select().from(authSessions).then((rows) => rows.map((row) => row.id).sort())).toEqual(["actor-unrelated-session"]);
    await expect(provisioner.apply(actor, { packetId: packet.packetId, packetHash: packet.packetHash }))
      .rejects.toMatchObject({ status: 409 });
    expect(await db.select().from(companyMemberships).where(eq(companyMemberships.principalId, TARGET_ID))).toHaveLength(1);
  });

  it("fails closed when company authorization changes after review", async () => {
    await seedAuthorizedActor();
    await db.insert(authSessions).values({
      id: "target-before-stale-apply", userId: TARGET_ID, token: "target-session",
      expiresAt: new Date(NOW + 60_000), createdAt: new Date(NOW), updatedAt: new Date(NOW),
    });
    const provisioner = makeProvisioner();
    const packet = await provisioner.dryRun(actor, intent);
    await db.delete(principalPermissionGrants).where(eq(principalPermissionGrants.principalId, ACTOR_ID));

    await expect(provisioner.apply(actor, { packetId: packet.packetId, packetHash: packet.packetHash }))
      .rejects.toMatchObject({ status: 403 });
    expect(await db.select().from(companyMemberships).where(eq(companyMemberships.principalId, TARGET_ID))).toHaveLength(0);
    expect(await db.select().from(authSessions).where(eq(authSessions.userId, TARGET_ID))).toHaveLength(1);
  });

  it("allows exactly one winner when the same reviewed packet is applied concurrently", async () => {
    await seedAuthorizedActor();
    const provisioner = makeProvisioner();
    const packet = await provisioner.dryRun(actor, intent);
    const attempts = await Promise.allSettled([
      provisioner.apply(actor, { packetId: packet.packetId, packetHash: packet.packetHash }),
      provisioner.apply(actor, { packetId: packet.packetId, packetHash: packet.packetHash }),
    ]);

    expect(attempts.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(attempts.filter((result) => result.status === "rejected")).toHaveLength(1);
    const rejection = attempts.find((result) => result.status === "rejected");
    expect(rejection).toMatchObject({ reason: { status: 409 } });
    expect(await db.select().from(companyMemberships).where(eq(companyMemberships.principalId, TARGET_ID))).toHaveLength(1);
  });

  it("rejects untrusted actor classes and never treats caller-supplied admin flags as proof", async () => {
    await seedAuthorizedActor();
    const provisioner = makeProvisioner();
    await expect(provisioner.dryRun({ type: "agent", userId: ACTOR_ID } as never, intent)).rejects.toMatchObject({ status: 403 });
    await expect(provisioner.dryRun({ ...actor, isInstanceAdmin: false }, intent)).rejects.toMatchObject({ status: 403 });
  });
});
