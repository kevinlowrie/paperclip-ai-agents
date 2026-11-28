import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import { stripTypeScriptTypes } from "node:module";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@paperclipai/adapter-utils/server-utils", () => ({
  resolvePaperclipInstanceRootForAdapter: () => { throw new Error("No host credential access"); },
}));
vi.mock("../../../packages/adapters/codex-local/src/server/codex-auth-cache.js", () => ({
  isCodexAuthCachePath: () => false,
  readSubscriptionAccountId: () => null,
}));
import { stageCodexHomeForSync, writeManagedCodexMcpConfig } from "../../../packages/adapters/codex-local/src/server/codex-home.js";
import { HttpError, forbidden, conflict, notFound, unauthorized, unprocessable } from "../errors.js";

// Source-seam harness: execute the exact producer, actual call argument,
// route handler, and validator with an in-memory query boundary. No DB,
// token signing, provider, model, or network operation runs in this suite.
const heartbeat = fs.readFileSync(new URL("../services/heartbeat.ts", import.meta.url), "utf8");
const intents = fs.readFileSync(new URL("../services/connection-intents.ts", import.meta.url), "utf8");
const routes = fs.readFileSync(new URL("../routes/connection-intents.ts", import.meta.url), "utf8");
function actualFunction(source: string, name: string, bindings: Record<string, unknown>) {
  const code = stripTypeScriptTypes(source, {mode: "transform"});
  const declaration = new RegExp("^( *)(?:export )?(?:async )?function " + name + "\\(", "m").exec(code);
  if (!declaration) throw new Error("Expected production function was not found: " + name);
  const close = code.indexOf("\n" + declaration[1] + "}", declaration.index + declaration[0].length);
  if (close < 0) throw new Error("Expected production function boundary was not found: " + name);
  const actual = code.slice(declaration.index, close + declaration[1].length + 2).replace(/^( *)export /, "$1");
  return new Function(...Object.keys(bindings), actual + "\nreturn " + name)(...Object.values(bindings));
}
async function actualProducerCall(db: unknown, agent: unknown, run: unknown, producer: unknown) {
  const declaration = /^( *)const runtimeTools = (?:await )?createAdapterRuntimeToolAccess\(\{/m.exec(heartbeat);
  if (!declaration) throw new Error("Expected production callsite was not found");
  const start = declaration.index;
  const close = heartbeat.indexOf("\n" + declaration[1] + "});", start);
  if (close < 0) throw new Error("Expected production callsite boundary was not found");
  const statement = heartbeat.slice(start, close + declaration[1].length + 4);
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  let immediate: unknown;
  await new AsyncFunction("db", "agent", "run", "createAdapterRuntimeToolAccess", "consume",
    statement + "\nconsume(runtimeTools);")(db, agent, run, producer, (value: unknown) => { immediate = value; });
  // Do not return the value directly: AsyncFunction would hide a missing await
  // by assimilating the Promise before the test could observe the consumer.
  return { immediate };
}
const text = (value: unknown) => typeof value === "string" && value.trim() ? value.trim() : null;
const origin = "https://runtime.example:8443";
function table(name: string, fields: string[]) {
  return Object.fromEntries([["__name", name], ...fields.map(field => [field, { field }])]);
}
const tables = {
  heartbeatRuns: table("run", ["id", "companyId", "agentId", "status", "errorCode",
    "responsibleUserId", "activeIdentityContextId", "contextSnapshot", "nativeIssueId"]),
  issues: table("issue", ["id", "companyId", "status", "assigneeAgentId"]),
  agents: table("agent", ["id", "companyId", "name"]),
  companyMemberships: table("membership", ["companyId", "principalType", "principalId", "status", "membershipRole"]),
};
type Row = Record<string, any>;
function fixture() {
  const run: Row = { id: "fixture-run", companyId: "fixture-company", agentId: "fixture-agent",
    status: "running", responsibleUserId: "fixture-user", activeIdentityContextId: null,
    contextSnapshot: {}, nativeIssueId: null };
  const claims = { sub: run.agentId, company_id: run.companyId, run_id: run.id,
    responsible_user_id: run.responsibleUserId };
  const issue: Row = { id: "fixture-issue", companyId: run.companyId,
    status: "in_progress", assigneeAgentId: run.agentId };
  const agent: Row = { id: run.agentId, companyId: run.companyId, name: "Fixture" };
  const membership: Row = { companyId: run.companyId, principalType: "user",
    principalId: run.responsibleUserId, status: "active", membershipRole: "owner" };
  const rows: Record<string, Row> = { run, issue, agent, membership };
  const db = { select: () => ({ from: (t: Row) => ({
    where: (predicate: (row: Row) => boolean) => Promise.resolve(
      predicate(rows[t.__name]) ? [rows[t.__name]] : []),
  }) }) };
  const counters = { minted: 0, validated: 0, identityReads: 0, consumerSawPromise: false };
  const validate = actualFunction(intents, "loadRunContext", {
    db, ...tables, text,
    record: (value: unknown) => value && typeof value === "object" && !Array.isArray(value) ? value : null,
    eq: (column: {field: string}, value: unknown) => (row: Row) => row[column.field] === value,
    and: (...predicates: ((row: Row) => boolean)[]) => (row: Row) => predicates.every(p => p(row)),
    forbidden, conflict, notFound, unprocessable,
    isAiAuthenticationFailure: () => false,
    captureRunIdentity: async () => { counters.identityReads++; return { run }; },
  }) as (claims: Row) => Promise<unknown>;
  let failure: unknown;
  const service = { validate: async (input: Row) => {
    counters.validated++;
    if (failure) throw failure;
    return validate(input);
  } };
  const producer = actualFunction(heartbeat, "createAdapterRuntimeToolAccess", {
    HttpError, connectionIntentService: () => service,
    createRuntimeToolsToken: () => { counters.minted++; return {
      token: "fixture-runtime-token", expiresAt: "2099-01-01T00:00:00.000Z" }; },
    configuredPaperclipApiBaseUrl: () => origin,
    readNonEmptyString: text,
    CONNECTION_INTENT_AGENT_GUIDANCE: "Fixture connection guidance",
    CONNECTION_RUNTIME_TOOL_NAMES: ["connections_search", "connection_request"],
  });
  async function produce() {
    const { immediate } = await actualProducerCall(db, agent, run, producer);
    counters.consumerSawPromise = immediate instanceof Promise;
    return immediate;
  }
  const handlers = new Map<string, Function>();
  const router = { get: () => router, post: (route: string, handler: Function) => {
    handlers.set(route, handler); return router;
  } };
  const bearer = actualFunction(routes, "bearer", {});
  const runtimeClaims = actualFunction(routes, "runtimeClaims", {
    bearer, verifyRuntimeToolsToken: (token: string) => token === "fixture-runtime-token" ? claims : null,
    unauthorized,
  });
  actualFunction(routes, "runtimeConnectionIntentRoutes", {
    Router: () => router, connectionIntentService: () => service, runtimeClaims,
    RUNTIME_CONNECTION_TOOL_DEFINITIONS: [{name: "connections_search"}, {name: "connection_request"}],
  })(db);
  async function invoke(message: unknown, token = "fixture-runtime-token") {
    const result: {status: number; body?: any} = { status: 200 };
    const response = {
      status(code: number) { result.status = code; return response; },
      json(body: unknown) { result.body = body; return response; },
      end() { return response; },
    };
    try {
      await handlers.get("/mcp/runtime-tools")!({
        body: message, header: () => "Bearer " + token,
      }, response);
    } catch (error) {
      if (!(error instanceof HttpError)) throw error;
      result.status = error.status; result.body = { error: error.message };
    }
    return result;
  }
  return { run, issue, agent, membership, claims, counters, produce, invoke,
    failWith: (error: unknown) => { failure = error; } };
}
function actualNativeMcpDelivery(runtimeTools: unknown, assigned: unknown[]) {
  const start = heartbeat.indexOf("            const runtimeToolDelivery =");
  const end = heartbeat.indexOf("            if (authToken", start);
  if (start < 0 || end < 0) throw new Error("Expected native MCP delivery branch was not found");
  const code = stripTypeScriptTypes(heartbeat.slice(start, end));
  return new Function("runtimeTools", "adapter", "runtimeMcpServers",
    code + "\nreturn runtimeMcpServers")(runtimeTools, {runtimeToolDelivery: "native_mcp"}, [...assigned]);
}
const fixtureRoots: string[] = [];
afterEach(async () => {
  await Promise.all(fixtureRoots.splice(0).map(root => fsp.rm(root, {recursive: true, force: true})));
});
const initialize = { jsonrpc: "2.0", id: 1, method: "initialize",
  params: { protocolVersion: "2025-06-18", capabilities: {},
    clientInfo: {name: "codex-mcp-client", version: "0.164.0"} } };

describe("persisted runtime-tools availability before required MCP initialization", () => {
  it("omits connection capability and token issuance for the actual issue-less timer shape", async () => {
    const f = fixture();
    expect(await f.produce()).toBeUndefined();
    expect(f.counters.minted).toBe(0);
  });

  for (const binding of ["issueId", "taskId", "nativeIssueId"]) {
    it("preserves " + binding + " task binding through actual callsite, producer, initialize and list", async () => {
      const f = fixture();
      if (binding === "nativeIssueId") f.run.nativeIssueId = f.issue.id;
      else f.run.contextSnapshot[binding] = f.issue.id;
      const capability = await f.produce();
      expect(capability.mcpEndpoint).toBe(origin + "/mcp/runtime-tools");
      expect(f.counters.minted).toBe(1);
      expect(await f.invoke(initialize)).toMatchObject({status: 200,
        body: {jsonrpc: "2.0", id: 1, result: {protocolVersion: "2025-03-26"}}});
      expect(await f.invoke({jsonrpc: "2.0", id: 2, method: "tools/list"}))
        .toMatchObject({status: 200, body: {result: {tools: [{name: "connections_search"}, {name: "connection_request"}]}}});
    });
  }

  it("reproduces initialize 422 for an explicit request with no persisted task", async () => {
    const f = fixture();
    expect(await f.invoke(initialize)).toEqual({status: 422,
      body: {error: "Connection requests require a task-bound heartbeat run"}});
  });

  for (const invalid of ["ended", "wrong-agent", "wrong-company", "wrong-user", "revoked-membership", "foreign-task", "wrong-assignee", "closed-task"]) {
    it("does not issue a capability for " + invalid + " persisted authorization", async () => {
      const f = fixture(); f.run.contextSnapshot.issueId = f.issue.id;
      if (invalid === "ended") f.run.status = "failed";
      if (invalid === "wrong-agent") f.run.agentId = "other-agent";
      if (invalid === "wrong-company") f.run.companyId = "other-company";
      if (invalid === "wrong-user") f.run.responsibleUserId = "other-user";
      if (invalid === "revoked-membership") f.membership.status = "revoked";
      if (invalid === "foreign-task") f.issue.companyId = "other-company";
      if (invalid === "wrong-assignee") f.issue.assigneeAgentId = "other-agent";
      if (invalid === "closed-task") f.issue.status = "done";
      // Claim boundary is the existing agent and run identity, not a supplied actor alias.
      expect(await f.produce()).toBeUndefined();
      expect(f.counters.minted).toBe(0);
    });
  }

  it("propagates unexpected database and arbitrary status-bearing errors before mint", async () => {
    for (const error of [new Error("fixture database unavailable"), new HttpError(500, "fixture typed server failure"), Object.assign(new Error("fixture database status"), {status: 422}), {status: 422, message: "not a typed eligibility denial"}]) {
      const f = fixture(); f.run.contextSnapshot.issueId = f.issue.id; f.failWith(error);
      await expect(f.produce()).rejects.toBe(error);
      expect(f.counters.minted).toBe(0);
    }
  });

  it("awaits the original producer call statement before the immediate delivery consumer", async () => {
    const f = fixture(); f.run.contextSnapshot.issueId = f.issue.id;
    expect(await f.produce()).toBeDefined();
    expect(f.counters.consumerSawPromise).toBe(false);
  });

  it("keeps handler validation after admission if the run ends before initialize/list/call", async () => {
    const f = fixture(); f.run.contextSnapshot.issueId = f.issue.id;
    expect(await f.produce()).toBeDefined();
    f.run.status = "failed";
    for (const method of ["initialize", "tools/list", "tools/call"]) {
      expect((await f.invoke({...initialize, method})).status).toBe(403);
    }
  });

  it("clears stale connections from actual delivery/materialization/staging while retaining the assigned gateway", async () => {
    const f = fixture();
    const assigned = [{name: "paperclip-assigned", url: origin + "/mcp/gateways/gw_fixturea1", token: "fixture-assigned-current"}];
    const capability = await f.produce();
    const advertised = actualNativeMcpDelivery(capability, assigned);
    expect(advertised).toEqual(assigned);
    const home = await fsp.mkdtemp(path.join(os.tmpdir(), "runtime-tools-staging-"));
    fixtureRoots.push(home);
    await writeManagedCodexMcpConfig({codexHome: home, apiBaseUrl: origin, gateways: [
      {name: "paperclip-connections", endpointPath: origin + "/mcp/runtime-tools", bearerToken: "fixture-stale-connection"},
    ]});
    await writeManagedCodexMcpConfig({codexHome: home, apiBaseUrl: origin,
      gateways: advertised.map((server: any) => ({name: server.name, endpointPath: server.url, bearerToken: server.token}))});
    const staged = await stageCodexHomeForSync(home, {runId: "fixture-unbound-timer"});
    fixtureRoots.push(staged);
    const config = await fsp.readFile(path.join(staged, "config.toml"), "utf8");
    expect(config).toContain('url = "' + origin + '/mcp/gateways/gw_fixturea1"');
    expect(config).toContain("fixture-assigned-current");
    expect(config).not.toContain("paperclip-connections");
    expect(config).not.toContain("fixture-stale-connection");
  });

  it("retains the connection server beside assigned MCP for an authorized task-bound run", async () => {
    const f = fixture(); f.run.nativeIssueId = f.issue.id;
    const assigned = [{name: "paperclip-assigned", url: origin + "/mcp/gateways/gw_fixturea1", token: "fixture-assigned-current"}];
    const advertised = actualNativeMcpDelivery(await f.produce(), assigned);
    expect(advertised.map((server: any) => server.name)).toEqual(["Paperclip connections", "paperclip-assigned"]);
    expect(advertised[1]).toEqual(assigned[0]);
  });

  it("retains active identity validation before mint and on each request", async () => {
    const f = fixture(); f.run.nativeIssueId = f.issue.id; f.run.activeIdentityContextId = "fixture-identity";
    expect(await f.produce()).toBeDefined();
    expect(f.counters.identityReads).toBe(1);
    expect((await f.invoke(initialize)).status).toBe(200);
    expect(f.counters.identityReads).toBe(2);
  });

});
