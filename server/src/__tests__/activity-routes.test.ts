import express from "express";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mockActivityService = vi.hoisted(() => ({
  list: vi.fn(),
  forIssue: vi.fn(),
  runsForIssue: vi.fn(),
  finalResponseForIssueRun: vi.fn(),
  issuesForRun: vi.fn(),
  create: vi.fn(),
}));

const mockHeartbeatService = vi.hoisted(() => ({
  getRun: vi.fn(),
}));

const mockIssueService = vi.hoisted(() => ({
  getById: vi.fn(),
  getByIdentifier: vi.fn(),
}));

const mockAccessService = vi.hoisted(() => ({
  decide: vi.fn(),
  canUser: vi.fn(),
}));

const mockAgentActionAuditService = vi.hoisted(() => ({
  list: vi.fn(),
}));
const mockRunRedaction = vi.hoisted(() => vi.fn());
vi.mock("../services/run-secret-redaction.js", () => ({
  createRunSecretRedactionRegistry: () => ({ redactForRun: mockRunRedaction }),
}));
vi.mock("../services/instance-settings.js", () => ({
  instanceSettingsService: () => ({ getGeneral: async () => ({ censorUsernameInLogs: false }) }),
}));

vi.mock("../services/activity.js", () => ({
  activityService: () => mockActivityService,
  normalizeActivityLimit: (limit: number | undefined) => {
    if (!Number.isFinite(limit)) return 100;
    return Math.max(1, Math.min(500, Math.floor(limit ?? 100)));
  },
}));

vi.mock("../services/index.js", () => ({
  accessService: () => mockAccessService,
  issueService: () => mockIssueService,
  heartbeatService: () => mockHeartbeatService,
}));

vi.mock("../services/agent-action-audit.js", () => ({
  agentActionAuditService: () => mockAgentActionAuditService,
}));

async function createApp(
  actor: Record<string, unknown> = {
    type: "board",
    userId: "user-1",
    companyIds: ["company-1"],
    source: "session",
    isInstanceAdmin: false,
  },
) {
  vi.resetModules();
  const [{ errorHandler }, { activityRoutes }] = await Promise.all([
    import("../middleware/index.js") as Promise<typeof import("../middleware/index.js")>,
    import("../routes/activity.js") as Promise<typeof import("../routes/activity.js")>,
  ]);
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    (req as any).actor = {
      ...actor,
      companyIds: Array.isArray(actor.companyIds) ? [...actor.companyIds] : actor.companyIds,
    };
    next();
  });
  app.use("/api", activityRoutes({} as any));
  app.use(errorHandler);
  return app;
}

async function requestApp(
  app: express.Express,
  buildRequest: (baseUrl: string) => request.Test,
) {
  const { createServer } = await vi.importActual<typeof import("node:http")>("node:http");
  const server = createServer(app);
  try {
    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("Expected HTTP server to listen on a TCP port");
    }
    return await buildRequest(`http://127.0.0.1:${address.port}`);
  } finally {
    if (server.listening) {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) reject(error);
          else resolve();
        });
      });
    }
  }
}

describe.sequential("activity routes", () => {
  beforeEach(() => {
    for (const mock of Object.values(mockActivityService)) mock.mockReset();
    for (const mock of Object.values(mockHeartbeatService)) mock.mockReset();
    for (const mock of Object.values(mockIssueService)) mock.mockReset();
    mockAccessService.decide.mockReset();
    mockAccessService.canUser.mockReset();
    mockAgentActionAuditService.list.mockReset();
    mockRunRedaction.mockReset();
    mockRunRedaction.mockImplementation(async (_company, _run, value) => value);
    mockAccessService.decide.mockResolvedValue({
      allowed: true,
      action: "company_scope:read",
      reason: "allow_test",
      explanation: "Allowed by test mock.",
    });
    mockAccessService.canUser.mockResolvedValue(false);
  });

  const responseRun = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const responseIssue = { id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", companyId: "company-1", projectId: null,
    parentId: null, assigneeAgentId: "agent-1", assigneeUserId: null, status: "done" };

  it("reads only the authorized issue response and applies run redaction", async () => {
    mockIssueService.getById.mockResolvedValue(responseIssue);
    mockActivityService.finalResponseForIssueRun.mockResolvedValue({
      companyId: "company-1", issueId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", runId: responseRun, text: "private-value",
    });
    mockRunRedaction.mockImplementation(async (_company, _run, value) => ({ ...value, text: "[REDACTED]" }));
    const app = await createApp({ type: "agent", agentId: "agent-1", companyId: "company-1",
      source: "agent_key", keyId: "key-1", keyScope: { kind: "task_bridge", parentIssueId: "parent-1" } });
    const res = await requestApp(app, base => request(base).get(`/api/issues/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/runs/${responseRun}/final-response`));
    expect(res.status).toBe(200);
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(res.body.text).toBe("[REDACTED]");
    expect(mockAccessService.decide).toHaveBeenCalledWith(expect.objectContaining({
      action: "issue:read", resource: expect.objectContaining({ companyId: "company-1", issueId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" }),
    }));
    expect(mockActivityService.finalResponseForIssueRun).toHaveBeenCalledWith("company-1", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", responseRun);
    expect(mockRunRedaction).toHaveBeenCalledWith("company-1", responseRun, expect.any(Object));
  });

  it.each(["foreign", "denied", "missing"])("hides %s issue responses before reading run data", async mode => {
    mockIssueService.getById.mockResolvedValue(mode === "missing" ? null : {
      ...responseIssue, companyId: mode === "foreign" ? "company-2" : "company-1",
    });
    if (mode === "denied") mockAccessService.decide.mockResolvedValue({ allowed: false });
    const app = await createApp();
    const res = await requestApp(app, base => request(base).get(`/api/issues/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/runs/${responseRun}/final-response`));
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: "Issue not found" });
    expect(mockActivityService.finalResponseForIssueRun).not.toHaveBeenCalled();
    expect(mockRunRedaction).not.toHaveBeenCalled();
  });

  it("rejects anonymous response reads before looking up the issue", async () => {
    const app = await createApp({ type: "none", source: "none" });
    const res = await requestApp(app, base => request(base).get(`/api/issues/${responseIssue.id}/runs/${responseRun}/final-response`));
    expect(res.status).toBe(401);
    expect(mockIssueService.getById).not.toHaveBeenCalled();
    expect(mockActivityService.finalResponseForIssueRun).not.toHaveBeenCalled();
    expect(mockRunRedaction).not.toHaveBeenCalled();
  });

  it("does not return the response when secret redaction fails", async () => {
    mockIssueService.getById.mockResolvedValue(responseIssue);
    mockActivityService.finalResponseForIssueRun.mockResolvedValue({ text: "private-response-marker" });
    mockRunRedaction.mockRejectedValue(new Error("Redaction provider unavailable"));
    const app = await createApp();
    const res = await requestApp(app, base => request(base).get(`/api/issues/${responseIssue.id}/runs/${responseRun}/final-response`));
    expect(res.status).toBe(500);
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(JSON.stringify(res.body)).not.toContain("private-response-marker");
  });

  it("returns 404 for an unbound run and refuses malformed run IDs", async () => {
    mockIssueService.getById.mockResolvedValue(responseIssue);
    mockActivityService.finalResponseForIssueRun.mockResolvedValue(null);
    const app = await createApp();
    const absent = await requestApp(app, base => request(base).get(`/api/issues/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/runs/${responseRun}/final-response`));
    expect(absent.status).toBe(404);
    const malformed = await requestApp(app, base => request(base).get("/api/issues/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/runs/not-uuid/final-response"));
    expect(malformed.status).toBe(400);
    expect(mockActivityService.finalResponseForIssueRun).toHaveBeenCalledTimes(1);
  });

  it("returns redacted all-actors rows to a basic company reader", async () => {
    mockAgentActionAuditService.list.mockResolvedValue({
      items: [{
        id: "activity-1",
        companyId: "company-1",
        actorType: "plugin",
        actorId: "plugin-1",
        action: "plugin.synced",
        entityType: "company",
        entityId: "company-1",
        agentId: "agent-1",
        runId: "run-1",
        responsibleUserId: "user-2",
        details: { privateAttribution: true },
        createdAt: "2026-08-04T00:00:00.000Z",
        entity: { issue: null, comment: null, document: null },
      }],
      nextCursor: null,
    });

    const app = await createApp();
    const res = await request(app)
      .get("/api/companies/company-1/audit/agent-actions?actorScope=all");

    expect(res.status).toBe(200);
    expect(mockAgentActionAuditService.list).toHaveBeenCalledWith({
      companyId: "company-1",
      actorScope: "all",
      limit: 50,
    });
    expect(res.body.items[0]).toMatchObject({
      actorType: "plugin",
      actorId: "plugin-1",
      action: "plugin.synced",
      entityType: "company",
      entityId: "company-1",
      createdAt: "2026-08-04T00:00:00.000Z",
      agentId: null,
      runId: null,
      responsibleUserId: null,
      details: null,
    });
    expect(res.body.accessTier).toBe("basic");
  });

  it("rejects attribution filters for a basic all-actors reader", async () => {
    const app = await createApp();
    const res = await request(app)
      .get("/api/companies/company-1/audit/agent-actions?actorScope=all&runId=00000000-0000-4000-8000-000000000001");

    expect(res.status).toBe(403);
    expect(res.body.error).toContain("audit:view_agent_actions");
    expect(mockAgentActionAuditService.list).not.toHaveBeenCalled();
  });

  it("keeps attribution for a permitted all-actors reader", async () => {
    mockAccessService.canUser.mockResolvedValue(true);
    mockAgentActionAuditService.list.mockResolvedValue({
      items: [{
        id: "activity-1",
        agentId: "agent-1",
        runId: "run-1",
        responsibleUserId: "user-2",
        details: { attribution: true },
      }],
      nextCursor: null,
    });

    const app = await createApp();
    const res = await request(app)
      .get("/api/companies/company-1/audit/agent-actions?actorScope=all&actorType=system");

    expect(res.status).toBe(200);
    expect(mockAgentActionAuditService.list).toHaveBeenCalledWith({
      companyId: "company-1",
      actorScope: "all",
      actorType: "system",
      limit: 50,
    });
    expect(res.body.items[0]).toMatchObject({
      agentId: "agent-1",
      runId: "run-1",
      responsibleUserId: "user-2",
      details: { attribution: true },
    });
    expect(res.body.accessTier).toBe("full");
  });

  it("limits company activity lists by default", async () => {
    mockActivityService.list.mockResolvedValue([]);

    const app = await createApp();
    const res = await requestApp(app, (baseUrl) => request(baseUrl).get("/api/companies/company-1/activity"));

    expect(res.status).toBe(200);
    expect(mockActivityService.list).toHaveBeenCalledWith({
      companyId: "company-1",
      agentId: undefined,
      entityType: undefined,
      entityId: undefined,
      limit: 100,
    });
  });

  it("caps requested company activity list limits", async () => {
    mockActivityService.list.mockResolvedValue([]);

    const app = await createApp();
    const res = await requestApp(app, (baseUrl) =>
      request(baseUrl).get("/api/companies/company-1/activity?limit=5000&entityType=issue"),
    );

    expect(res.status).toBe(200);
    expect(mockActivityService.list).toHaveBeenCalledWith({
      companyId: "company-1",
      agentId: undefined,
      entityType: "issue",
      entityId: undefined,
      limit: 500,
    });
  });

  it("resolves alphanumeric issue identifiers before loading runs", async () => {
    mockIssueService.getByIdentifier.mockResolvedValue({
      id: "issue-uuid-1",
      companyId: "company-1",
    });
    mockActivityService.runsForIssue.mockResolvedValue([
      {
        runId: "run-1",
        adapterType: "codex_local",
      },
    ]);

    const app = await createApp();
    const res = await requestApp(app, (baseUrl) => request(baseUrl).get("/api/issues/pc1a2-475/runs"));

    expect(res.status).toBe(200);
    expect(mockIssueService.getByIdentifier).toHaveBeenCalledWith("PC1A2-475");
    expect(mockIssueService.getById).not.toHaveBeenCalled();
    expect(mockActivityService.runsForIssue).toHaveBeenCalledWith("company-1", "issue-uuid-1");
    expect(res.body).toEqual([{ runId: "run-1", adapterType: "codex_local" }]);
  });

  it("requires company access before creating activity events", async () => {
    const app = await createApp();
    const res = await requestApp(app, (baseUrl) => request(baseUrl)
      .post("/api/companies/company-2/activity")
      .send({
        actorId: "user-1",
        action: "test.event",
        entityType: "issue",
        entityId: "issue-1",
      }));

    expect(res.status).toBe(403);
    expect(mockActivityService.create).not.toHaveBeenCalled();
  });

  it("returns 200 [] (not 404) when listing issues for another company's run, preserving API contract and the cross-tenant oracle", async () => {
    mockHeartbeatService.getRun.mockResolvedValue({
      id: "run-2",
      companyId: "company-2",
    });

    const app = await createApp();
    const res = await requestApp(app, (baseUrl) => request(baseUrl).get("/api/heartbeat-runs/run-2/issues"));

    expect(res.status).toBe(200);
    expect(res.body).toEqual([]);
    expect(mockActivityService.issuesForRun).not.toHaveBeenCalled();
  });

  it("returns 200 [] (not 404) for a non-existent heartbeat run, matching the cross-tenant response", async () => {
    mockHeartbeatService.getRun.mockResolvedValue(null);

    const app = await createApp();
    const res = await requestApp(app, (baseUrl) => request(baseUrl).get("/api/heartbeat-runs/missing-run/issues"));

    expect(res.status).toBe(200);
    expect(res.body).toEqual([]);
    expect(mockActivityService.issuesForRun).not.toHaveBeenCalled();
  });

  it("rejects anonymous heartbeat run issue lookups before run existence checks", async () => {
    const app = await createApp({ type: "none", source: "none" });
    const res = await requestApp(app, (baseUrl) => request(baseUrl).get("/api/heartbeat-runs/missing-run/issues"));

    expect(res.status).toBe(401);
    expect(mockHeartbeatService.getRun).not.toHaveBeenCalled();
    expect(mockActivityService.issuesForRun).not.toHaveBeenCalled();
  });
});
