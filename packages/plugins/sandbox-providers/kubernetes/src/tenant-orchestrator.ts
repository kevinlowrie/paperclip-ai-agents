import type { KubeClients } from "./kube-client.js";
import { buildNetworkPolicyManifests } from "./network-policy.js";
import { buildCiliumNetworkPolicyManifest } from "./cilium-network-policy.js";

export interface EnsureTenantInput {
  namespace: string;
  companyId: string;
  paperclipServerNamespace: string;
  serviceAccountAnnotations: Record<string, string>;
  egressMode: "standard" | "cilium";
  egressAllowFqdns: string[];
  dnsQueryAllowFqdns?: string[];
  egressAllowCidrs: string[];
  resourceQuota: {
    pods: string;
    requestsCpu: string;
    requestsMemory: string;
    limitsCpu: string;
    limitsMemory: string;
  };
}

const SERVICE_ACCOUNT_NAME = "paperclip-tenant-sa";
const ROLE_NAME = "paperclip-tenant-role";
const ROLE_BINDING_NAME = "paperclip-tenant-rb";
const RESOURCE_QUOTA_NAME = "paperclip-quota";
const LIMIT_RANGE_NAME = "paperclip-limits";

/**
 * Lazy, first-write-wins tenant provisioning. Each helper checks if the named
 * resource exists and creates it only on 404; if it already exists, it is
 * left as-is — config-driven values (quota limits, RBAC permissions, network
 * policies, egress allow-list) are FROZEN at first provisioning time.
 *
 * V1 limitation: changing KubernetesProviderConfig after a tenant namespace
 * is provisioned does NOT update the in-cluster resources. To apply config
 * changes, an operator must delete the per-tenant resources manually (or
 * the namespace itself). A future iteration should add strategic-merge
 * reconciliation here.
 *
 * Particular gotcha: switching egressMode "standard" → "cilium" leaves the
 * old paperclip-egress-allow NetworkPolicy in place alongside the new
 * CiliumNetworkPolicy. Both apply; the effective egress is the intersection.
 */
export async function ensureTenant(clients: KubeClients, input: EnsureTenantInput): Promise<void> {
  await ensureNamespace(clients, input);
  await ensureServiceAccount(clients, input);
  await ensureRole(clients, input);
  await ensureRoleBinding(clients, input);
  await ensureResourceQuota(clients, input);
  await ensureLimitRange(clients, input);
  await ensureNetworkPolicies(clients, input);
}

async function ensureNamespace(clients: KubeClients, input: EnsureTenantInput): Promise<void> {
  try {
    await clients.core.readNamespace({ name: input.namespace });
    return;
  } catch (err) {
    if (!isNotFound(err)) throw err;
  }
  await createIgnoringAlreadyExists(
    clients.core.createNamespace({
        body: {
          apiVersion: "v1",
          kind: "Namespace",
          metadata: {
            name: input.namespace,
            labels: {
              "paperclip.io/company-id": input.companyId,
              "paperclip.io/managed-by": "paperclip-k8s-plugin",
              "pod-security.kubernetes.io/enforce": "restricted",
              "pod-security.kubernetes.io/audit": "restricted",
              "pod-security.kubernetes.io/warn": "restricted",
            },
          },
        },
      }),
  );
}

async function ensureServiceAccount(clients: KubeClients, input: EnsureTenantInput): Promise<void> {
  try {
    await clients.core.readNamespacedServiceAccount({ name: SERVICE_ACCOUNT_NAME, namespace: input.namespace });
    return;
  } catch (err) {
    if (!isNotFound(err)) throw err;
  }
  await createIgnoringAlreadyExists(
    clients.core.createNamespacedServiceAccount({
        namespace: input.namespace,
        body: {
          apiVersion: "v1",
          kind: "ServiceAccount",
          metadata: {
            name: SERVICE_ACCOUNT_NAME,
            namespace: input.namespace,
            annotations: input.serviceAccountAnnotations,
            labels: { "paperclip.io/managed-by": "paperclip-k8s-plugin" },
          },
        },
      }),
  );
}

async function ensureRole(clients: KubeClients, input: EnsureTenantInput): Promise<void> {
  try {
    await clients.rbac.readNamespacedRole({ name: ROLE_NAME, namespace: input.namespace });
    return;
  } catch (err) {
    if (!isNotFound(err)) throw err;
  }
  await createIgnoringAlreadyExists(
    clients.rbac.createNamespacedRole({
        namespace: input.namespace,
        body: {
          apiVersion: "rbac.authorization.k8s.io/v1",
          kind: "Role",
          metadata: { name: ROLE_NAME, namespace: input.namespace },
          rules: [
            { apiGroups: [""], resources: ["pods/log"], verbs: ["get"] },
          ],
        },
      }),
  );
}

async function ensureRoleBinding(clients: KubeClients, input: EnsureTenantInput): Promise<void> {
  try {
    await clients.rbac.readNamespacedRoleBinding({ name: ROLE_BINDING_NAME, namespace: input.namespace });
    return;
  } catch (err) {
    if (!isNotFound(err)) throw err;
  }
  await createIgnoringAlreadyExists(
    clients.rbac.createNamespacedRoleBinding({
        namespace: input.namespace,
        body: {
          apiVersion: "rbac.authorization.k8s.io/v1",
          kind: "RoleBinding",
          metadata: { name: ROLE_BINDING_NAME, namespace: input.namespace },
          roleRef: { apiGroup: "rbac.authorization.k8s.io", kind: "Role", name: ROLE_NAME },
          subjects: [{ kind: "ServiceAccount", name: SERVICE_ACCOUNT_NAME, namespace: input.namespace }],
        },
      }),
  );
}

async function ensureResourceQuota(clients: KubeClients, input: EnsureTenantInput): Promise<void> {
  try {
    await clients.core.readNamespacedResourceQuota({ name: RESOURCE_QUOTA_NAME, namespace: input.namespace });
    return;
  } catch (err) {
    if (!isNotFound(err)) throw err;
  }
  await createIgnoringAlreadyExists(
    clients.core.createNamespacedResourceQuota({
        namespace: input.namespace,
        body: {
          apiVersion: "v1",
          kind: "ResourceQuota",
          metadata: { name: RESOURCE_QUOTA_NAME, namespace: input.namespace },
          spec: {
            hard: {
              pods: input.resourceQuota.pods,
              "requests.cpu": input.resourceQuota.requestsCpu,
              "requests.memory": input.resourceQuota.requestsMemory,
              "limits.cpu": input.resourceQuota.limitsCpu,
              "limits.memory": input.resourceQuota.limitsMemory,
            },
          },
        },
      }),
  );
}

async function ensureLimitRange(clients: KubeClients, input: EnsureTenantInput): Promise<void> {
  try {
    await clients.core.readNamespacedLimitRange({ name: LIMIT_RANGE_NAME, namespace: input.namespace });
    return;
  } catch (err) {
    if (!isNotFound(err)) throw err;
  }
  await createIgnoringAlreadyExists(
    clients.core.createNamespacedLimitRange({
        namespace: input.namespace,
        body: {
          apiVersion: "v1",
          kind: "LimitRange",
          metadata: { name: LIMIT_RANGE_NAME, namespace: input.namespace },
          spec: {
            limits: [
              {
                type: "Container",
                max: { cpu: "4", memory: "8Gi" },
                min: { cpu: "100m", memory: "128Mi" },
                // The k8s client-node type names this `_default` but the actual
                // Kubernetes API field is `default`. We produce a JSON-shape
                // manifest so the cast is safe.
                default: { cpu: "1", memory: "2Gi" },
                defaultRequest: { cpu: "250m", memory: "512Mi" },
              },
            ],
          },
        } as never,
      }),
  );
}

async function ensureNetworkPolicies(clients: KubeClients, input: EnsureTenantInput): Promise<void> {
  const [denyAll, egressStd] = buildNetworkPolicyManifests({
    namespace: input.namespace,
    paperclipServerNamespace: input.paperclipServerNamespace,
    egressAllowCidrs: input.egressAllowCidrs,
    egressAllowFqdns: input.egressAllowFqdns,
  });

  await ensureNetworkPolicy(clients, input.namespace, denyAll);

  if (input.egressMode === "cilium") {
    const cnp = buildCiliumNetworkPolicyManifest({
      namespace: input.namespace,
      paperclipServerNamespace: input.paperclipServerNamespace,
      egressAllowFqdns: input.egressAllowFqdns,
      dnsQueryAllowFqdns: input.dnsQueryAllowFqdns,
      egressAllowCidrs: input.egressAllowCidrs,
    });
    await ensureCiliumNetworkPolicy(clients, input.namespace, cnp);
    if (input.dnsQueryAllowFqdns !== undefined) {
      await assertCiliumDnsQueries(
        clients, input.namespace, input.paperclipServerNamespace, input.dnsQueryAllowFqdns,
      );
    }
  } else {
    await ensureNetworkPolicy(clients, input.namespace, egressStd);
  }
}

async function ensureNetworkPolicy(
  clients: KubeClients,
  namespace: string,
  manifest: Record<string, unknown>,
): Promise<void> {
  const name = (manifest.metadata as { name: string }).name;
  try {
    await clients.networking.readNamespacedNetworkPolicy({ name, namespace });
    return;
  } catch (err) {
    if (!isNotFound(err)) throw err;
  }
  await createIgnoringAlreadyExists(
    clients.networking.createNamespacedNetworkPolicy({ namespace, body: manifest as never }),
  );
}

async function assertCiliumDnsQueries(
  clients: KubeClients,
  namespace: string,
  paperclipServerNamespace: string,
  expectedNames: string[],
): Promise<void> {
  const result = await clients.custom.getNamespacedCustomObject({
    group: "cilium.io",
    version: "v2",
    namespace,
    plural: "ciliumnetworkpolicies",
    name: "paperclip-egress-fqdn",
  });
  type Policy = { body?: { spec?: { egress?: unknown } }; spec?: { egress?: unknown } };
  const response = result as Policy;
  const egress = (response.body ?? response).spec?.egress;
  if (!Array.isArray(egress)) throw dnsPolicyMismatch();

  let dnsRuleCount = 0;
  for (const candidate of egress) {
    const rule = asRecord(candidate);
    if (!rule) throw dnsPolicyMismatch();
    if (isExactKubeDnsRule(rule, expectedNames)) {
      dnsRuleCount += 1;
      continue;
    }
    if (isExactPaperclipServerRule(rule, paperclipServerNamespace) || isExactFqdn443Rule(rule)) continue;
    // Only the known generated rule forms are accepted. Any broader or
    // unfamiliar selector/port shape could reach a DNS resolver without the
    // exact L7 name restriction, so strict mode fails closed.
    throw dnsPolicyMismatch();
  }
  if (dnsRuleCount !== 1) throw dnsPolicyMismatch();
}

function isExactKubeDnsRule(rule: Record<string, unknown>, expectedNames: string[]): boolean {
  if (!hasOnlyKeys(rule, ["toEndpoints", "toPorts"])) return false;
  const endpoints = rule.toEndpoints;
  if (!Array.isArray(endpoints) || endpoints.length !== 1) return false;
  const endpoint = asRecord(endpoints[0]);
  const labels = endpoint && hasOnlyKeys(endpoint, ["matchLabels"]) ? asRecord(endpoint.matchLabels) : undefined;
  if (!labels || !hasExactEntries(labels, {
    "k8s:io.kubernetes.pod.namespace": "kube-system",
    "k8s-app": "kube-dns",
  })) return false;

  const ports = rule.toPorts;
  if (!Array.isArray(ports) || ports.length !== 1) return false;
  const port = asRecord(ports[0]);
  if (!port || !hasOnlyKeys(port, ["ports", "rules"])) return false;
  if (!isExactDnsRules(port.rules, expectedNames)) return false;
  const allowedPorts = port.ports;
  if (!Array.isArray(allowedPorts) || allowedPorts.length !== 2) return false;
  const normalizedPorts = allowedPorts.map((item) => asRecord(item));
  if (normalizedPorts.some((item) => !item || !hasOnlyKeys(item, ["port", "protocol"]))) return false;
  const pairs = normalizedPorts.map((item) => `${item!.port}/${item!.protocol}`).sort();
  return pairs[0] === "53/TCP" && pairs[1] === "53/UDP";
}

function isExactDnsRules(value: unknown, expectedNames: string[]): boolean {
  const rules = asRecord(value);
  if (!rules || !hasOnlyKeys(rules, ["dns"]) || !Array.isArray(rules.dns)) return false;
  const names = rules.dns.map((item) => {
    const entry = asRecord(item);
    return entry && hasOnlyKeys(entry, ["matchName"]) && typeof entry.matchName === "string"
      ? entry.matchName
      : undefined;
  });
  if (names.some((name) => name === undefined) || names.length !== expectedNames.length) return false;
  const expected = [...expectedNames].sort();
  return [...names].sort().every((name, index) => name === expected[index]);
}

function isExactPaperclipServerRule(
  rule: Record<string, unknown>,
  paperclipServerNamespace: string,
): boolean {
  if (!hasOnlyKeys(rule, ["toEndpoints", "toPorts"])) return false;
  const endpoints = rule.toEndpoints;
  const ports = rule.toPorts;
  if (!Array.isArray(endpoints) || endpoints.length !== 1 || !Array.isArray(ports) || ports.length !== 1) return false;
  const endpoint = asRecord(endpoints[0]);
  const labels = endpoint && hasOnlyKeys(endpoint, ["matchLabels"]) ? asRecord(endpoint.matchLabels) : undefined;
  const port = asRecord(ports[0]);
  if (!labels || !hasExactEntries(labels, {
    "k8s:io.kubernetes.pod.namespace": paperclipServerNamespace,
    app: "paperclip-server",
  }) || !port || !hasOnlyKeys(port, ["ports"])) return false;
  return hasExactPortList(port.ports, [{ port: "3100", protocol: "TCP" }]);
}

function isExactFqdn443Rule(rule: Record<string, unknown>): boolean {
  if (!hasOnlyKeys(rule, ["toFQDNs", "toPorts"])) return false;
  const names = rule.toFQDNs;
  const ports = rule.toPorts;
  if (!Array.isArray(names) || names.length === 0 || !Array.isArray(ports) || ports.length !== 1) return false;
  if (names.some((item) => {
    const name = asRecord(item);
    return !name || !hasOnlyKeys(name, ["matchName"]) || typeof name.matchName !== "string";
  })) return false;
  const port = asRecord(ports[0]);
  return !!port && hasOnlyKeys(port, ["ports"]) && hasExactPortList(port.ports, [{ port: "443", protocol: "TCP" }]);
}

function hasExactPortList(value: unknown, expected: Array<{ port: string; protocol: string }>): boolean {
  if (!Array.isArray(value) || value.length !== expected.length) return false;
  const ports = value.map(asRecord);
  if (ports.some((port) => !port || !hasOnlyKeys(port, ["port", "protocol"]))) return false;
  const actual = ports.map((port) => `${port!.port}/${port!.protocol}`).sort();
  const wanted = expected.map((item) => `${item.port}/${item.protocol}`).sort();
  return actual.every((pair, index) => pair === wanted[index]);
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: string[]): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function hasExactEntries(value: Record<string, unknown>, expected: Record<string, unknown>): boolean {
  return Object.keys(value).length === Object.keys(expected).length &&
    Object.entries(expected).every(([key, expectedValue]) => JSON.stringify(value[key]) === JSON.stringify(expectedValue));
}

function dnsPolicyMismatch(): Error {
  return new Error("CiliumNetworkPolicy DNS rules do not match dnsQueryAllowFqdns; operator migration is required");
}

async function ensureCiliumNetworkPolicy(
  clients: KubeClients,
  namespace: string,
  manifest: Record<string, unknown>,
): Promise<void> {
  const name = (manifest.metadata as { name: string }).name;
  try {
    await clients.custom.getNamespacedCustomObject({
      group: "cilium.io",
      version: "v2",
      namespace,
      plural: "ciliumnetworkpolicies",
      name,
    });
    return;
  } catch (err) {
    if (!isNotFound(err)) throw err;
  }
  await createIgnoringAlreadyExists(
    clients.custom.createNamespacedCustomObject({
        group: "cilium.io",
        version: "v2",
        namespace,
        plural: "ciliumnetworkpolicies",
        body: manifest,
      }),
  );
}

function isNotFound(err: unknown): boolean {
  if (typeof err !== "object" || err === null) return false;
  const e = err as { code?: number; statusCode?: number };
  return e.code === 404 || e.statusCode === 404;
}

function isAlreadyExists(err: unknown): boolean {
  if (typeof err !== "object" || err === null) return false;
  const e = err as { code?: number; statusCode?: number };
  return e.code === 409 || e.statusCode === 409;
}

// Two concurrent lease acquisitions for a brand-new tenant can both observe
// the 404 read and race the create; a 409 AlreadyExists from the loser means
// the desired state already exists, which is exactly what ensure* wants.
async function createIgnoringAlreadyExists(create: Promise<unknown>): Promise<void> {
  try {
    await create;
  } catch (err) {
    if (!isAlreadyExists(err)) throw err;
  }
}
