import { describe, expect, it } from "vitest";
import manifest from "../../src/manifest.js";

describe("Kubernetes provider manifest", () => {
  it("publishes the bounded exact DNS query capability", () => {
    const configSchema = manifest.environmentDrivers?.[0].configSchema as {
      properties?: Record<string, { minItems?: number; maxItems?: number; uniqueItems?: boolean }>;
    };
    expect(configSchema.properties?.dnsQueryAllowFqdns).toMatchObject({
      minItems: 1,
      maxItems: 16,
      uniqueItems: true,
    });
  });
});
