import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import type { Project, Issue } from "@paperclipai/shared";
import { requestResponse } from "../api/client";
import { readApiJson } from "../api/response";
import { useAccountIdentity } from "../api/companies-query";
import { useCompany } from "../context/CompanyContext";

export function PlanningInventory() {
  const { selectedCompanyId, companies, loading, error } = useCompany();
  const identity = useAccountIdentity();
  if (!identity.settled || identity.failed || !identity.userId || loading || error)
    return <p role="status">Verifying current account and company membership. No inventory is shown.</p>;
  return selectedCompanyId && companies.some(company => company.id === selectedCompanyId) ?
    <CompanyInventory key={identity.userId + ":" + selectedCompanyId} userId={identity.userId} companyId={selectedCompanyId} /> :
    <p role="status">Select an authorized company to view planning inventory.</p>;
}
function CompanyInventory({ companyId, userId }: { companyId: string; userId: string }) {
  const [project, setProject] = useState("");
  const [blocked, setBlocked] = useState(false);
  const query = useQuery({
    queryKey: ["planning-inventory", userId, companyId],
    queryFn: async ({ signal }) => {
      const [projects, issues] = await Promise.all([
        requestResponse("/companies/" + encodeURIComponent(companyId) + "/projects", { signal, cache: "no-store", redirect: "error" }).then(readApiJson<Project[]>),
        requestResponse("/companies/" + encodeURIComponent(companyId) + "/issues?limit=100&sortField=id&sortDir=asc", { signal, cache: "no-store", redirect: "error" }).then(readApiJson<Issue[]>),
      ]);
      if (!Array.isArray(projects) || !Array.isArray(issues) || projects.length > 5000 || issues.length > 100 ||
          new Set(projects.map(p => p?.id)).size !== projects.length || new Set(issues.map(i => i?.id)).size !== issues.length ||
          projects.some(p => !p || p.companyId !== companyId || typeof p.id !== "string" || typeof p.name !== "string") ||
          issues.some(i => !i || i.companyId !== companyId || typeof i.id !== "string" || typeof i.title !== "string" || typeof i.status !== "string" || !(i.projectId === null || typeof i.projectId === "string")))
        throw new Error("Invalid authorized inventory");
      return { projects, issues };
    },
    staleTime: 0,
    gcTime: 0,
    retry: false,
    refetchOnMount: "always",
    refetchOnWindowFocus: "always",
  });
  // Never present cached/background-failed responses as current work.
  const data = !query.isFetching && !query.isError ? query.data : undefined;
  const rows = data?.issues.filter(i => (!project || (project === "unassigned" ? i.projectId === null : i.projectId === project)) &&
    (!blocked || i.status === "blocked")) ?? [];
  return <section className="space-y-4 p-4" aria-label="Planning inventory">
    <h1 className="text-2xl font-semibold">Planning inventory</h1>
    <p>Read-only native company inventory. First authorized page only, up to 100 issue rows. This is not the full backlog.</p>
    <p>All tasks below are unscheduled in this view: approved start/end dates, sprints and dependency edges are not connected. No delivery forecast or worker completion is inferred.</p>
    <button className="border rounded px-3 py-2" disabled={query.isFetching} onClick={() => void query.refetch()}>Refresh inventory</button>
    {query.isFetching && <p role="status">Loading current authorized inventory…</p>}
    {query.isError && <p role="alert">Inventory unavailable. No current snapshot is shown. Refresh to retry.</p>}
    {data && <>
      <p role="status">Fetched {new Date(query.dataUpdatedAt).toLocaleString()}. Point-in-time API observation, not execution proof. Coverage may be partial even when fewer than 100 rows appear.</p>
      <div className="flex flex-wrap gap-4">
        <label>Project <select className="border rounded p-2" value={project} onChange={e => setProject(e.target.value)}>
          <option value="">All visible projects</option><option value="unassigned">Unassigned</option>
          {data.projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select></label>
        <label><input type="checkbox" checked={blocked} onChange={e => setBlocked(e.target.checked)} /> Blocked only</label>
      </div>
      <h2 className="text-xl">Unscheduled · {rows.length} visible</h2>
      {!rows.length && <p>No matching rows in this page. This does not prove the backlog is empty.</p>}
      <div className="grid gap-3 sm:grid-cols-2">{rows.map(i => <article className="border rounded p-3 break-words" key={i.id}>
        <h3 className="font-semibold">{i.title}</h3><p>Status: {i.status}</p>
        <p>Project: {i.projectId === null ? "Unassigned" : data.projects.find(p => p.id === i.projectId)?.name ?? "Not in visible project list"}</p>
        <p>Schedule: unavailable</p><small>{i.id}</small>
      </article>)}</div>
    </>}
  </section>;
}
