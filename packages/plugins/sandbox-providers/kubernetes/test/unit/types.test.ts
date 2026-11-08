import { describe, it, expect } from "vitest";
import { kubernetesProviderConfigSchema, parseKubernetesProviderConfig } from "../../src/types.js";

describe("kubernetesProviderConfigSchema", () => {
  it("accepts inCluster=true with no kubeconfig", () => {
    const parsed = parseKubernetesProviderConfig({ inCluster: true });
    expect(parsed.inCluster).toBe(true);
    expect(parsed.namespacePrefix).toBe("paperclip-");
    expect(parsed.imageAllowList).toEqual([]);
    expect(parsed.egressMode).toBe("standard");
    expect(parsed.jobTtlSecondsAfterFinished).toBe(900);
  });

  it("accepts inline kubeconfig", () => {
    const parsed = parseKubernetesProviderConfig({
      inCluster: false,
      kubeconfig: "apiVersion: v1\nkind: Config\n",
    });
    expect(parsed.kubeconfig).toContain("apiVersion");
  });

  it("rejects when neither inCluster nor any kubeconfig source is set", () => {
    expect(() => parseKubernetesProviderConfig({ inCluster: false })).toThrow(
      /requires one of `inCluster` or `kubeconfig`/,
    );
  });

  it("rejects invalid companySlug", () => {
    expect(() =>
      parseKubernetesProviderConfig({ inCluster: true, companySlug: "INVALID UPPER" }),
    ).toThrow();
  });

  it("accepts a bounded canonical DNS query allow-list and preserves absence", () => {
    const absent = parseKubernetesProviderConfig({ inCluster: true });
    expect(absent).not.toHaveProperty("dnsQueryAllowFqdns");
    const strict = parseKubernetesProviderConfig({
      inCluster: true,
      egressMode: "cilium",
      dnsQueryAllowFqdns: ["api.example.invalid", "svc.namespace.svc"],
    });
    expect(strict.dnsQueryAllowFqdns).toEqual(["api.example.invalid", "svc.namespace.svc"]);
  });

  it("rejects CIDR grants when exact DNS query restrictions are configured", () => {
    expect(() => parseKubernetesProviderConfig({
      inCluster: true,
      egressMode: "cilium",
      dnsQueryAllowFqdns: ["api.example.invalid"],
      egressAllowCidrs: ["192.0.2.0/24"],
    })).toThrow(/egressAllowCidrs/);
  });

  it("requires Cilium mode for DNS query restrictions", () => {
    expect(() =>
      parseKubernetesProviderConfig({ inCluster: true, dnsQueryAllowFqdns: ["api.example.invalid"] }),
    ).toThrow(/egressMode=cilium/);
  });

  it.each([
    [[]],
    [["*.example.invalid"]],
    [["https://example.invalid"]],
    [["192.0.2.1"]],
    [["127.1"]],
    [["127.0.1"]],
    [["0x7f.0x1"]],
    [["api.example.invalid."]],
    [["Api.example.invalid"]],
    [["a.example.invalid:443"]],
    [["localhost"]],
    [["api.example.invalid", "api.example.invalid"]],
    [Array(17).fill("a.example.invalid")],
  ])("rejects invalid strict DNS list %j", (dnsQueryAllowFqdns) => {
    expect(() => parseKubernetesProviderConfig({ inCluster: true, dnsQueryAllowFqdns })).toThrow();
  });

  it("rejects egressAllowCidrs entries that are not valid CIDR", () => {
    expect(() =>
      parseKubernetesProviderConfig({ inCluster: true, egressAllowCidrs: ["not-a-cidr"] }),
    ).toThrow(/CIDR/i);
  });
});
