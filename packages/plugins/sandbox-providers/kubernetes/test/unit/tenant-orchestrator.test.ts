import { describe, it, expect, vi } from "vitest";
import { ensureTenant } from "../../src/tenant-orchestrator.js";
import { buildCiliumNetworkPolicyManifest } from "../../src/cilium-network-policy.js";

function makeMockClients() {
  const calls: { kind: string; name: string; namespace?: string; body?: unknown }[] = [];
  function track(kind: string) {
    return vi.fn(async (...args: unknown[]) => {
      const arg = (args[0] ?? {}) as { name?: string; namespace?: string; body?: unknown };
      calls.push({ kind, name: arg.name ?? "", namespace: arg.namespace, body: arg.body });
      return { body: arg.body };
    });
  }
  return {
    calls,
    core: {
      createNamespace: track("Namespace"),
      readNamespacedServiceAccount: vi.fn().mockRejectedValue({ code: 404 }),
      createNamespacedServiceAccount: track("ServiceAccount"),
      readNamespacedResourceQuota: vi.fn().mockRejectedValue({ code: 404 }),
      createNamespacedResourceQuota: track("ResourceQuota"),
      readNamespacedLimitRange: vi.fn().mockRejectedValue({ code: 404 }),
      createNamespacedLimitRange: track("LimitRange"),
      readNamespace: vi.fn().mockRejectedValue({ code: 404 }),
    },
    rbac: {
      readNamespacedRole: vi.fn().mockRejectedValue({ code: 404 }),
      createNamespacedRole: track("Role"),
      readNamespacedRoleBinding: vi.fn().mockRejectedValue({ code: 404 }),
      createNamespacedRoleBinding: track("RoleBinding"),
    },
    networking: {
      readNamespacedNetworkPolicy: vi.fn().mockRejectedValue({ code: 404 }),
      createNamespacedNetworkPolicy: track("NetworkPolicy"),
    },
    custom: {
      getNamespacedCustomObject: vi.fn().mockRejectedValue({ code: 404 }),
      createNamespacedCustomObject: track("CiliumNetworkPolicy"),
    },
  };
}

describe("ensureTenant", () => {
  const baseInput = {
    namespace: "paperclip-acme",
    companyId: "11111111-1111-1111-1111-111111111111",
    paperclipServerNamespace: "paperclip",
    serviceAccountAnnotations: {},
    egressMode: "standard" as const,
    egressAllowFqdns: ["api.anthropic.com"],
    egressAllowCidrs: [] as string[],
    resourceQuota: { pods: "20", requestsCpu: "5", requestsMemory: "20Gi", limitsCpu: "20", limitsMemory: "80Gi" },
  };

  it("creates all required resources in the correct order on a fresh tenant", async () => {
    const clients = makeMockClients();
    await ensureTenant(clients as never, baseInput);
    const order = clients.calls.map((c) => c.kind);
    expect(order).toEqual([
      "Namespace",
      "ServiceAccount",
      "Role",
      "RoleBinding",
      "ResourceQuota",
      "LimitRange",
      "NetworkPolicy",
      "NetworkPolicy",
    ]);
  });

  it("creates a CiliumNetworkPolicy instead of standard egress when egressMode=cilium", async () => {
    const clients = makeMockClients();
    await ensureTenant(clients as never, { ...baseInput, egressMode: "cilium" });
    const cnpCall = clients.calls.find((c) => c.kind === "CiliumNetworkPolicy");
    expect(cnpCall).toBeDefined();
    const npCalls = clients.calls.filter((c) => c.kind === "NetworkPolicy");
    expect(npCalls).toHaveLength(1);
    expect((npCalls[0].body as { metadata: { name: string } }).metadata.name).toBe("paperclip-deny-all");
  });

  it("fails closed on an existing wildcard Cilium DNS policy before lease provisioning", async () => {
    const clients = makeMockClients();
    clients.custom.getNamespacedCustomObject.mockResolvedValue({ body: { spec: { egress: [{ toPorts: [{ rules: { dns: [{ matchPattern: "*" }] } }] }] } } });
    await expect(ensureTenant(clients as never, { ...baseInput, egressMode: "cilium", dnsQueryAllowFqdns: ["api.example.invalid"] })).rejects.toThrow(/DNS/i);
    expect(clients.custom.createNamespacedCustomObject).not.toHaveBeenCalled();
  });

  it("accepts an existing exact provider DNS query policy", async () => {
    const clients = makeMockClients();
    const exact = buildCiliumNetworkPolicyManifest({
      namespace: baseInput.namespace,
      paperclipServerNamespace: baseInput.paperclipServerNamespace,
      egressAllowFqdns: baseInput.egressAllowFqdns,
      egressAllowCidrs: [],
      dnsQueryAllowFqdns: ["api.example.invalid"],
    });
    clients.custom.getNamespacedCustomObject.mockResolvedValue({ body: exact });
    await expect(ensureTenant(clients as never, { ...baseInput, egressMode: "cilium", dnsQueryAllowFqdns: ["api.example.invalid"] })).resolves.toBeUndefined();
    expect(clients.custom.createNamespacedCustomObject).not.toHaveBeenCalled();
  });

  it.each([
    ["separate unrestricted kube-dns L4 rule", (policy: any) => policy.spec.egress.push({ toEndpoints: [{ matchLabels: { "k8s:io.kubernetes.pod.namespace": "kube-system", "k8s-app": "kube-dns" } }], toPorts: [{ ports: [{ port: "53", protocol: "UDP" }, { port: "53", protocol: "TCP" }] }] })],
    ["DNS rule on a different endpoint", (policy: any) => { policy.spec.egress[0].toEndpoints[0].matchLabels["k8s:io.kubernetes.pod.namespace"] = "other"; }],
    ["portless grant", (policy: any) => { policy.spec.egress.push({ toEndpoints: [{ matchLabels: { "k8s:io.kubernetes.pod.namespace": "kube-system", "k8s-app": "kube-dns" } }] }); }],
    ["wildcard endpoint selector", (policy: any) => { policy.spec.egress[0].toEndpoints[0].matchLabels = {}; }],
    ["extra wildcard DNS name", (policy: any) => { policy.spec.egress[0].toPorts[0].rules.dns.push({ matchPattern: "*" }); }],
    ["empty port list", (policy: any) => { policy.spec.egress[0].toPorts[0].ports = []; }],
    ["named port", (policy: any) => { policy.spec.egress[0].toPorts[0].ports = [{ port: "dns", protocol: "UDP" }]; }],
    ["port range covering DNS", (policy: any) => { policy.spec.egress[0].toPorts[0].ports = [{ port: "1", endPort: 53, protocol: "UDP" }]; }],
    ["unrestricted unknown selector grant", (policy: any) => { policy.spec.egress.push({ toEndpoints: [{}] }); }],
    ["portless world entity grant", (policy: any) => { policy.spec.egress.push({ toEntities: ["world"] }); }],
    ["endpoint selector expressions", (policy: any) => { policy.spec.egress[0].toEndpoints[0].matchExpressions = []; }],
    ["unconfigured FQDN", (policy: any) => { policy.spec.egress.find((rule: any) => rule.toFQDNs).toFQDNs.push({ matchName: "extra.example.invalid" }); }],
    ["duplicate FQDN", (policy: any) => { const rule = policy.spec.egress.find((item: any) => item.toFQDNs); rule.toFQDNs.push({ ...rule.toFQDNs[0] }); }],
    ["missing configured FQDN", (policy: any) => { policy.spec.egress = policy.spec.egress.filter((rule: any) => !rule.toFQDNs); }],
  ])("rejects %s in strict Cilium mode", async (_label, mutate) => {
    const clients = makeMockClients();
    const policy = buildCiliumNetworkPolicyManifest({
      namespace: baseInput.namespace,
      paperclipServerNamespace: baseInput.paperclipServerNamespace,
      egressAllowFqdns: baseInput.egressAllowFqdns,
      egressAllowCidrs: [],
      dnsQueryAllowFqdns: ["api.example.invalid"],
    });
    mutate(policy);
    clients.custom.getNamespacedCustomObject.mockResolvedValue({ body: policy });
    await expect(ensureTenant(clients as never, { ...baseInput, egressMode: "cilium", dnsQueryAllowFqdns: ["api.example.invalid"] })).rejects.toThrow(/DNS/i);
    expect(clients.custom.createNamespacedCustomObject).not.toHaveBeenCalled();
  });

  it("rejects any FQDN policy rule when none is configured", async () => {
    const clients = makeMockClients();
    const policy = buildCiliumNetworkPolicyManifest({
      namespace: baseInput.namespace,
      paperclipServerNamespace: baseInput.paperclipServerNamespace,
      egressAllowFqdns: [],
      egressAllowCidrs: [],
      dnsQueryAllowFqdns: ["api.example.invalid"],
    });
    policy.spec.egress.push({
      toFQDNs: [{ matchName: "extra.example.invalid" }],
      toPorts: [{ ports: [{ port: "443", protocol: "TCP" }] }],
    });
    clients.custom.getNamespacedCustomObject.mockResolvedValue({ body: policy });
    await expect(ensureTenant(clients as never, {
      ...baseInput,
      egressMode: "cilium",
      egressAllowFqdns: [],
      dnsQueryAllowFqdns: ["api.example.invalid"],
    })).rejects.toThrow(/DNS/i);
  });

  it("applies serviceAccountAnnotations to the ServiceAccount", async () => {
    const clients = makeMockClients();
    await ensureTenant(clients as never, {
      ...baseInput,
      serviceAccountAnnotations: { "eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/paperclip" },
    });
    const saCall = clients.calls.find((c) => c.kind === "ServiceAccount");
    const sa = saCall!.body as { metadata: { annotations: Record<string, string> } };
    expect(sa.metadata.annotations["eks.amazonaws.com/role-arn"]).toBe("arn:aws:iam::123:role/paperclip");
  });

  it("skips creates that already exist (idempotency)", async () => {
    const clients = makeMockClients();
    clients.core.readNamespace.mockResolvedValue({ body: { metadata: { name: baseInput.namespace } } });
    await ensureTenant(clients as never, baseInput);
    expect(clients.core.createNamespace).not.toHaveBeenCalled();
  });

  it("tolerates a 409 AlreadyExists from a concurrent ensure for the same tenant", async () => {
    const clients = makeMockClients();
    // Both racers saw the 404 read; the loser's create returns 409, which means
    // the desired state exists and must not fail the lease acquisition.
    clients.core.createNamespace.mockRejectedValue({ statusCode: 409 });
    clients.core.createNamespacedServiceAccount.mockRejectedValue({ code: 409 });
    await expect(ensureTenant(clients as never, baseInput)).resolves.not.toThrow();
  });
});
