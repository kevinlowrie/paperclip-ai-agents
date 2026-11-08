import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { and, eq, sql } from "drizzle-orm";
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
const PROJECT = "thl-pclipd-api" as const;
let testCounter = 0;

describe("Firebase operator provisioning", () => {
  let database: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>>;
  let db: ReturnType<typeof createDb>;

  beforeAll(async () => {
    database = await startEmbeddedPostgresTestDatabase("paperclip-firebase-operator-provisioning-");
    db = createDb(database.connectionString);
  }, 90_000);

  afterAll(async () => {
    await db?.$client.end();
    await database?.cleanup();
  });

  async function fixture() {
    const n = ++testCounter;
    const suffix = `${n}-${randomUUID()}`;
    const value = {
      actorId: `firebase-actor-${suffix}`,
      targetId: `firebase-target-${suffix}`,
      companyId: randomUUID(),
      actorSessionId: `actor-session-${suffix}`,
      targetSessionId: `target-session-${suffix}`,
      firebaseUid: `operator-uid-${suffix}`,
      now: NOW,
    };
    const timestamp = new Date(NOW);
    await db.insert(authUsers).values([
      { id: value.actorId, name: "Board operator", email: `${value.actorId}@example.test`, emailVerified: true, createdAt: timestamp, updatedAt: timestamp },
      { id: value.targetId, name: "Existing user", email: `${value.targetId}@example.test`, emailVerified: true, createdAt: timestamp, updatedAt: timestamp },
    ]);
    await db.insert(instanceUserRoles).values({ userId: value.actorId, role: "instance_admin" });
    await db.insert(companies).values({ id: value.companyId, name: `Reviewed ${suffix}`, issuePrefix: `F${n}` });
    await db.insert(companyMemberships).values({
      companyId: value.companyId, principalType: "user", principalId: value.actorId,
      status: "active", membershipRole: "owner",
    });
    await db.insert(principalPermissionGrants).values({
      companyId: value.companyId, principalType: "user", principalId: value.actorId,
      permissionKey: "users:manage_permissions", scope: null, grantedByUserId: value.actorId,
    });
    return value;
  }

  function actor(f: Awaited<ReturnType<typeof fixture>>) {
    return { type: "board" as const, source: "session" as const, userId: f.actorId };
  }

  function intent(f: Awaited<ReturnType<typeof fixture>>, overrides: Record<string, unknown> = {}) {
    return {
      projectId: PROJECT,
      firebaseUid: f.firebaseUid,
      targetUserId: f.targetId,
      binding: { mode: "create", expectedRevision: null, expectedUserId: null },
      companies: [{ companyId: f.companyId, role: "operator" }],
      ...overrides,
    };
  }

  function makeProvisioner(f: Awaited<ReturnType<typeof fixture>>, options: {
    lookup?: (uid: string) => Promise<unknown>;
    allowedCompanyIds?: Set<string>;
  } = {}) {
    return createFirebaseOperatorProvisioner(db, {
      identityDirectory: {
        lookup: options.lookup ?? (async (uid: string) => ({ projectId: PROJECT, uid, checkedAtMs: f.now })),
      },
      allowedCompanyIds: options.allowedCompanyIds ?? new Set([f.companyId]),
      now: () => f.now,
    });
  }

  async function addSession(id: string, userId: string) {
    const timestamp = new Date(NOW);
    await db.insert(authSessions).values({
      id, userId, token: `synthetic-${id}`, expiresAt: new Date(NOW + 60_000),
      createdAt: timestamp, updatedAt: timestamp,
    });
  }

  it("requires an existing actor row and current instance-admin role, ignoring a false request flag", async () => {
    const f = await fixture();
    const p = makeProvisioner(f);
    await expect(p.dryRun({ ...actor(f), isInstanceAdmin: false }, intent(f))).resolves.toMatchObject({ packetId: expect.any(String) });
    await db.delete(instanceUserRoles).where(eq(instanceUserRoles.userId, f.actorId));
    await expect(p.dryRun({ ...actor(f), isInstanceAdmin: true }, intent(f))).rejects.toMatchObject({ status: 403 });
  });

  it.each(["agent", "cloud", "local_implicit"] as const)("denies untrusted %s actor context", async (type) => {
    const f = await fixture();
    const p = makeProvisioner(f);
    await expect(p.dryRun({ type, userId: f.actorId } as never, intent(f))).rejects.toMatchObject({ status: 403 });
  });

  it("requires a separate active nonviewer membership and users:manage_permissions grant", async () => {
    const f = await fixture();
    const p = makeProvisioner(f);
    await db.delete(principalPermissionGrants).where(eq(principalPermissionGrants.principalId, f.actorId));
    await expect(p.dryRun(actor(f), intent(f))).rejects.toMatchObject({ status: 403 });
    await db.insert(principalPermissionGrants).values({
      companyId: f.companyId, principalType: "user", principalId: f.actorId,
      permissionKey: "users:manage_permissions", scope: null, grantedByUserId: f.actorId,
    });
    await db.update(companyMemberships).set({ membershipRole: "viewer" })
      .where(and(eq(companyMemberships.companyId, f.companyId), eq(companyMemberships.principalId, f.actorId)));
    await expect(p.dryRun(actor(f), intent(f))).rejects.toMatchObject({ status: 403 });
  });

  it("accepts only the fixed project, configured company, and unique supported roles", async () => {
    const f = await fixture();
    const p = makeProvisioner(f);
    await expect(p.dryRun(actor(f), intent(f, { projectId: "other-project" }))).rejects.toMatchObject({ status: 400 });
    await expect(p.dryRun(actor(f), intent(f, { companies: [{ companyId: randomUUID(), role: "operator" }] }))).rejects.toMatchObject({ status: 400 });
    await expect(p.dryRun(actor(f), intent(f, { companies: [{ companyId: f.companyId, role: "root" }] }))).rejects.toMatchObject({ status: 400 });
    await expect(p.dryRun(actor(f), intent(f, { companies: [
      { companyId: f.companyId, role: "operator" }, { companyId: f.companyId, role: "viewer" },
    ] }))).rejects.toMatchObject({ status: 400 });
  });

  it("rejects missing and instance-admin targets without creating or promoting users", async () => {
    const f = await fixture();
    const p = makeProvisioner(f);
    await expect(p.dryRun(actor(f), intent(f, { targetUserId: "missing-target" }))).rejects.toMatchObject({ status: 404 });
    await db.insert(instanceUserRoles).values({ userId: f.targetId, role: "instance_admin" });
    await expect(p.dryRun(actor(f), intent(f))).rejects.toMatchObject({ status: 400 });
    expect(await db.select().from(authUsers)).toHaveLength(2);
  });

  it("stores only an opaque expiring packet during dry run and leaves all authority state unchanged", async () => {
    const f = await fixture();
    await addSession(f.targetSessionId, f.targetId);
    const p = makeProvisioner(f);
    const before = {
      users: await db.select().from(authUsers), roles: await db.select().from(instanceUserRoles),
      memberships: await db.select().from(companyMemberships), grants: await db.select().from(principalPermissionGrants),
      sessions: await db.select().from(authSessions),
      bindings: await db.execute(sql`select * from firebase_operator_bindings where firebase_uid = ${f.firebaseUid}`),
    };
    const packet = await p.dryRun(actor(f), intent(f));
    expect(packet).toMatchObject({ packetId: expect.any(String), packetHash: expect.any(String), expiresAt: expect.any(Date), bindingBefore: null, plan: expect.any(Object) });
    expect(JSON.stringify(packet)).not.toContain("target@example.test");
    expect(JSON.stringify(packet)).not.toContain("synthetic-");
    await expect(db.select().from(authUsers)).resolves.toEqual(before.users);
    await expect(db.select().from(instanceUserRoles)).resolves.toEqual(before.roles);
    await expect(db.select().from(companyMemberships)).resolves.toEqual(before.memberships);
    await expect(db.select().from(principalPermissionGrants)).resolves.toEqual(before.grants);
    await expect(db.select().from(authSessions)).resolves.toEqual(before.sessions);
    await expect(db.execute(sql`select * from firebase_operator_bindings where firebase_uid = ${f.firebaseUid}`)).resolves.toEqual(before.bindings);
  });

  it("rejects wrong packet hash, wrong actor, and an expired review packet", async () => {
    const f = await fixture();
    const p = makeProvisioner(f);
    const packet = await p.dryRun(actor(f), intent(f));
    await expect(p.apply(actor(f), { packetId: packet.packetId, packetHash: "0".repeat(64) })).rejects.toMatchObject({ status: 409 });
    await expect(p.apply({ ...actor(f), userId: "another-actor" }, { packetId: packet.packetId, packetHash: packet.packetHash })).rejects.toMatchObject({ status: 403 });
    f.now = NOW + 301_000;
    await expect(p.apply(actor(f), { packetId: packet.packetId, packetHash: packet.packetHash })).rejects.toMatchObject({ status: 409 });
  });

  it("uses a fresh current UID lookup at apply and maps directory outage to 503 without state change", async () => {
    const f = await fixture();
    const p = makeProvisioner(f, { lookup: async () => { throw new Error("provider-secret-detail"); } });
    const packet = await p.dryRun(actor(f), intent(f));
    await expect(p.apply(actor(f), { packetId: packet.packetId, packetHash: packet.packetHash })).rejects.toMatchObject({ status: 503 });
    expect(await db.select().from(companyMemberships).where(eq(companyMemberships.principalId, f.targetId))).toHaveLength(0);
    expect(await db.select().from(authUsers)).toHaveLength(2);
  });

  it("applies once, adds reviewed memberships and defaults, preserves unrelated sessions, and never promotes the target", async () => {
    const f = await fixture();
    await addSession(f.targetSessionId, f.targetId);
    await addSession(f.actorSessionId, f.actorId);
    const p = makeProvisioner(f);
    const packet = await p.dryRun(actor(f), intent(f));
    const applied = await p.apply(actor(f), { packetId: packet.packetId, packetHash: packet.packetHash });
    expect(applied).toMatchObject({ packetId: packet.packetId, bindingId: expect.any(String), bindingRevision: 1, status: "applied", revokedSessionCount: 1 });
    expect(await db.select().from(companyMemberships).where(eq(companyMemberships.principalId, f.targetId))).toMatchObject([
      { companyId: f.companyId, principalType: "user", principalId: f.targetId, status: "active", membershipRole: "operator" },
    ]);
    expect(await db.select().from(principalPermissionGrants).where(eq(principalPermissionGrants.principalId, f.targetId))).toHaveLength(applied.createdGrantIds.length);
    expect(await db.select().from(instanceUserRoles).where(eq(instanceUserRoles.userId, f.targetId))).toHaveLength(0);
    expect(await db.select().from(authSessions).then((rows) => rows.map((row) => row.id))).toEqual([f.actorSessionId]);
    await expect(p.apply(actor(f), { packetId: packet.packetId, packetHash: packet.packetHash })).rejects.toMatchObject({ status: 409 });
  });

  it("preserves a matching active target membership and existing custom grant", async () => {
    const f = await fixture();
    await db.insert(companyMemberships).values({ companyId: f.companyId, principalType: "user", principalId: f.targetId, status: "active", membershipRole: "operator" });
    await db.insert(principalPermissionGrants).values({ companyId: f.companyId, principalType: "user", principalId: f.targetId, permissionKey: "custom:kept", scope: { marker: "preexisting" }, grantedByUserId: f.actorId });
    const before = await db.select().from(principalPermissionGrants).where(eq(principalPermissionGrants.principalId, f.targetId));
    const p = makeProvisioner(f);
    const packet = await p.dryRun(actor(f), intent(f));
    const applied = await p.apply(actor(f), { packetId: packet.packetId, packetHash: packet.packetHash });
    expect(applied.createdMembershipIds).toHaveLength(0);
    expect(await db.select().from(principalPermissionGrants).where(eq(principalPermissionGrants.principalId, f.targetId))).toEqual(before);
  });

  it.each(["inactive", "viewer"] as const)("rejects %s target membership instead of silently changing it", async (state) => {
    const f = await fixture();
    await db.insert(companyMemberships).values({ companyId: f.companyId, principalType: "user", principalId: f.targetId, status: state === "inactive" ? "inactive" : "active", membershipRole: state === "viewer" ? "viewer" : "operator" });
    const p = makeProvisioner(f);
    await expect(p.dryRun(actor(f), intent(f))).rejects.toMatchObject({ status: 409 });
  });

  it("detects target membership and grant-state changes between review and apply", async () => {
    const f = await fixture();
    const p = makeProvisioner(f);
    const packet = await p.dryRun(actor(f), intent(f));
    await db.insert(principalPermissionGrants).values({ companyId: f.companyId, principalType: "user", principalId: f.targetId, permissionKey: "custom:concurrent", scope: null, grantedByUserId: f.actorId });
    await expect(p.apply(actor(f), { packetId: packet.packetId, packetHash: packet.packetHash })).rejects.toMatchObject({ status: 409 });
    expect(await db.select().from(principalPermissionGrants).where(eq(principalPermissionGrants.principalId, f.targetId))).toHaveLength(1);
  });

  it("rechecks actor and company permission after dry run and leaves sessions untouched on denial", async () => {
    const f = await fixture();
    await addSession(f.targetSessionId, f.targetId);
    const p = makeProvisioner(f);
    const packet = await p.dryRun(actor(f), intent(f));
    await db.delete(principalPermissionGrants).where(eq(principalPermissionGrants.principalId, f.actorId));
    await expect(p.apply(actor(f), { packetId: packet.packetId, packetHash: packet.packetHash })).rejects.toMatchObject({ status: 403 });
    expect(await db.select().from(companyMemberships).where(eq(companyMemberships.principalId, f.targetId))).toHaveLength(0);
    expect(await db.select().from(authSessions).where(eq(authSessions.userId, f.targetId))).toHaveLength(1);
  });

  it("allows exactly one winner when the same packet is applied concurrently", async () => {
    const f = await fixture();
    const p = makeProvisioner(f);
    const packet = await p.dryRun(actor(f), intent(f));
    const attempts = await Promise.allSettled([
      p.apply(actor(f), { packetId: packet.packetId, packetHash: packet.packetHash }),
      p.apply(actor(f), { packetId: packet.packetId, packetHash: packet.packetHash }),
    ]);
    expect(attempts.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(attempts.filter((result) => result.status === "rejected")).toHaveLength(1);
    expect(attempts.find((result) => result.status === "rejected")).toMatchObject({ reason: { status: 409 } });
    expect(await db.select().from(companyMemberships).where(eq(companyMemberships.principalId, f.targetId))).toHaveLength(1);
  });

  it("rolls back only rows owned by its applied packet and disables the expected binding revision", async () => {
    const f = await fixture();
    await addSession(f.targetSessionId, f.targetId);
    const p = makeProvisioner(f);
    const packet = await p.dryRun(actor(f), intent(f));
    const applied = await p.apply(actor(f), { packetId: packet.packetId, packetHash: packet.packetHash });
    await addSession("unassured-unrelated-session", f.targetId);
    const rolledBack = await p.rollback(actor(f), { packetId: packet.packetId, expectedBindingRevision: applied.bindingRevision });
    expect(rolledBack).toMatchObject({ status: "rolled_back", bindingDisabled: true, removedMembershipIds: applied.createdMembershipIds, removedGrantIds: applied.createdGrantIds });
    expect(await db.select().from(companyMemberships).where(eq(companyMemberships.principalId, f.targetId))).toHaveLength(0);
    expect(await db.select().from(authSessions).where(eq(authSessions.id, "unassured-unrelated-session"))).toHaveLength(1);
  });

  it("rejects stale rollback revision and preserves concurrent target grants as a partial result", async () => {
    const f = await fixture();
    const p = makeProvisioner(f);
    const packet = await p.dryRun(actor(f), intent(f));
    const applied = await p.apply(actor(f), { packetId: packet.packetId, packetHash: packet.packetHash });
    await expect(p.rollback(actor(f), { packetId: packet.packetId, expectedBindingRevision: applied.bindingRevision + 1 })).rejects.toMatchObject({ status: 409 });
    await db.insert(principalPermissionGrants).values({ companyId: f.companyId, principalType: "user", principalId: f.targetId, permissionKey: "custom:concurrent", scope: null, grantedByUserId: f.actorId });
    const result = await p.rollback(actor(f), { packetId: packet.packetId, expectedBindingRevision: applied.bindingRevision });
    expect(result).toMatchObject({ status: "partial", bindingDisabled: true });
    expect(await db.select().from(principalPermissionGrants).where(eq(principalPermissionGrants.permissionKey, "custom:concurrent"))).toHaveLength(1);
  });

  it("requires explicit expected UID and revision for reassignment and increments the binding revision", async () => {
    const f = await fixture();
    const p = makeProvisioner(f);
    const firstPacket = await p.dryRun(actor(f), intent(f));
    const first = await p.apply(actor(f), { packetId: firstPacket.packetId, packetHash: firstPacket.packetHash });
    const secondTarget = `firebase-new-target-${randomUUID()}`;
    const timestamp = new Date(NOW);
    await db.insert(authUsers).values({ id: secondTarget, name: "Replacement", email: `${secondTarget}@example.test`, emailVerified: true, createdAt: timestamp, updatedAt: timestamp });
    const reassignment = intent(f, { targetUserId: secondTarget, binding: { mode: "reassign", expectedRevision: first.bindingRevision, expectedUserId: f.targetId } });
    const packet = await p.dryRun(actor(f), reassignment);
    await expect(p.apply(actor(f), { packetId: packet.packetId, packetHash: packet.packetHash })).resolves.toMatchObject({ bindingRevision: first.bindingRevision + 1, status: "applied" });
    await expect(p.dryRun(actor(f), intent(f, { targetUserId: "wrong", binding: { mode: "reassign", expectedRevision: first.bindingRevision, expectedUserId: "wrong" } }))).rejects.toMatchObject({ status: 409 });
  });

  it("reassignment revokes the old and new target prebinding sessions", async () => {
    const f = await fixture();
    await addSession(f.targetSessionId, f.targetId);
    const p = makeProvisioner(f);
    const firstPacket = await p.dryRun(actor(f), intent(f));
    const first = await p.apply(actor(f), { packetId: firstPacket.packetId, packetHash: firstPacket.packetHash });
    const secondTarget = `firebase-new-target-${randomUUID()}`;
    const timestamp = new Date(NOW);
    await db.insert(authUsers).values({ id: secondTarget, name: "Replacement", email: `${secondTarget}@example.test`, emailVerified: true, createdAt: timestamp, updatedAt: timestamp });
    await addSession("second-target-prebinding", secondTarget);
    const nextIntent = intent(f, { targetUserId: secondTarget, binding: { mode: "reassign", expectedRevision: first.bindingRevision, expectedUserId: f.targetId } });
    const packet = await p.dryRun(actor(f), nextIntent);
    const result = await p.apply(actor(f), { packetId: packet.packetId, packetHash: packet.packetHash });
    expect(result.revokedSessionCount).toBe(2);
    expect(await db.select().from(authSessions).where(eq(authSessions.userId, f.targetId))).toHaveLength(0);
    expect(await db.select().from(authSessions).where(eq(authSessions.userId, secondTarget))).toHaveLength(0);
  });

  it("records append-only bounded audit events without token or provider error details", async () => {
    const f = await fixture();
    const p = makeProvisioner(f, { lookup: async () => { throw new Error("private-provider-detail"); } });
    const packet = await p.dryRun(actor(f), intent(f));
    await expect(p.apply(actor(f), { packetId: packet.packetId, packetHash: packet.packetHash })).rejects.toMatchObject({ status: 503 });
    const rows = await db.execute(sql`select id, packet_id, actor_user_id, action, outcome, details::text as details, created_at from firebase_operator_provision_events where packet_id = ${packet.packetId}`);
    const eventText = JSON.stringify(rows);
    expect(eventText).not.toContain("private-provider-detail");
    expect(eventText).not.toContain("synthetic-");
    await expect(db.execute(sql`update firebase_operator_provision_events set outcome = 'changed' where packet_id = ${packet.packetId}`))
      .rejects.toMatchObject({ code: "42501" });
    await expect(db.execute(sql`delete from firebase_operator_provision_events where packet_id = ${packet.packetId}`))
      .rejects.toMatchObject({ code: "42501" });
    await expect(db.execute(sql`truncate firebase_operator_provision_events`)).rejects.toMatchObject({ code: "42501" });
  });
});
