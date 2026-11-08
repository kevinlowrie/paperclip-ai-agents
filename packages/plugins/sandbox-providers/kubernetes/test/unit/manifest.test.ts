import { describe, expect, it } from "vitest";
import manifest from "../../src/manifest.js";

describe("Kubernetes provider manifest", () => {
  it("publishes the bounded exact DNS query capability", () => {
    const configSchema = manifest.environmentDrivers?.[0].configSchema as {
      properties?: Record<string, { minItems?: number; maxItems?: number; uniqueItems?: boolean }>;
    };
    const property = configSchema.properties?.dnsQueryAllowFqdns as {
      minItems?: number;
      maxItems?: number;
      uniqueItems?: boolean;
      items?: { pattern?: string };
    };
    expect(property).toMatchObject({ minItems: 1, maxItems: 16, uniqueItems: true });
    const pattern = new RegExp(property.items?.pattern);
    for (const ipLikeName of ["192.0.2.1", "127.1", "127.0.1", "0x7f.0x1"]) {
      expect(pattern.test(ipLikeName)).toBe(false);
    }
  });
});
