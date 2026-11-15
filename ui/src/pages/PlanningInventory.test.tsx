import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, it, expect, vi } from "vitest";
const mocks = vi.hoisted(() => ({ company: "c1", identity: { userId: "u1", settled: true, failed: false }, loading: false, companies: [{ id: "c1" }], query: {} as any, options: {} as any, projects: [] as any[], issues: [] as any[] }));
vi.mock("@tanstack/react-query", () => ({ useQuery: (options: any) => { mocks.options = options; return mocks.query; } }));
vi.mock("../context/CompanyContext", () => ({ useCompany: () => ({ selectedCompanyId: mocks.company, companies: mocks.companies, loading: mocks.loading, error: null }) }));
vi.mock("../api/companies-query", () => ({ useAccountIdentity: () => mocks.identity }));
vi.mock("../api/client", () => ({ requestResponse: vi.fn(async (path: string) => new Response(JSON.stringify(path.endsWith("/projects") ? mocks.projects : mocks.issues))) }));
import { PlanningInventory } from "./PlanningInventory";
function render() { return renderToStaticMarkup(<PlanningInventory />); }
describe("native planning inventory source", () => {
  it("requires selected company", () => { mocks.company = ""; expect(render()).toContain("Select an authorized company"); });
  it("shows honest unscheduled partial coverage", () => {
    mocks.company = "c1"; mocks.query = { dataUpdatedAt: 1, data: { projects: [], issues: [{ id: "i1", title: "Task", status: "blocked", projectId: null }] } };
    const html = render(); expect(html).toContain("Task"); expect(html).toContain("Unassigned"); expect(html).toContain("not the full backlog"); expect(html).toContain("Schedule: unavailable");
  });
  it("hides previous response during refresh and errors", () => {
    mocks.query.isFetching = true; expect(render()).not.toContain("<h3"); mocks.query.isFetching = false; mocks.query.isError = true; expect(render()).not.toContain("<h3");
  });
  it("uses company-scoped bounded cancellable no-store native reads", async () => {
    mocks.query = {}; mocks.projects = []; mocks.issues = []; render();
    const controller = new AbortController(); await mocks.options.queryFn({ signal: controller.signal });
    const { requestResponse } = await import("../api/client");
    expect(requestResponse).toHaveBeenCalledWith("/companies/c1/projects", { signal: controller.signal, cache: "no-store", redirect: "error" });
    expect(requestResponse).toHaveBeenCalledWith("/companies/c1/issues?limit=100&sortField=id&sortDir=asc", { signal: controller.signal, cache: "no-store", redirect: "error" });
  });
  it("gates unresolved membership and failed identity", () => {
    mocks.loading = true; expect(render()).toContain("No inventory is shown"); mocks.loading = false;
    mocks.identity.failed = true; expect(render()).toContain("No inventory is shown"); mocks.identity.failed = false;
    mocks.companies = []; expect(render()).toContain("Select an authorized company"); mocks.companies = [{ id: "c1" }];
  });
  it("separates account query caches even for same company", () => {
    mocks.identity.userId = "u1"; render(); expect(mocks.options.queryKey).toEqual(["planning-inventory", "u1", "c1"]);
    mocks.identity.userId = "u2"; render(); expect(mocks.options.queryKey).toEqual(["planning-inventory", "u2", "c1"]);
  });
  it("rejects foreign company rows and duplicate IDs", async () => {
    mocks.projects = [{ id: "p1", companyId: "other", name: "Hidden" }]; render();
    await expect(mocks.options.queryFn({ signal: new AbortController().signal })).rejects.toThrow();
    mocks.projects = []; mocks.issues = [1,2].map(() => ({ id: "i1", companyId: "c1", title: "Task", status: "todo", projectId: null }));
    await expect(mocks.options.queryFn({ signal: new AbortController().signal })).rejects.toThrow();
  });
});
