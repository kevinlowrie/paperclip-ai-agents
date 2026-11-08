import { describe, expect, it } from "vitest";
import {
  getOperatorInstanceConfig,
  getRuntimeInstancePolicy,
  isOperatorManagedInstance,
  OPERATOR_CONFIG_ENV_KEY,
  parseOperatorConfigEnv,
} from "./operator-config.js";

const validOperatorDocument = {
  v: 1,
  mode: "operator",
  catalogVersion: "2026.720.0",
  features: { enablePipelines: true },
  plugins: { autoInstall: ["kubernetes"] },
  environments: [{ name: "Sandbox", provider: "kubernetes", config: { image: "runner:v1" } }],
};

const envWith = (raw: string | undefined) => ({
  ...(raw === undefined ? {} : { [OPERATOR_CONFIG_ENV_KEY]: raw }),
});

describe("parseOperatorConfigEnv", () => {
  it("parses the complete v1 operator document without exposing credential values", () => {
    expect(parseOperatorConfigEnv(envWith(JSON.stringify(validOperatorDocument)))).toMatchObject({
      v: 1,
      mode: "operator",
      catalogVersion: "2026.720.0",
      features: { enablePipelines: true },
      plugins: { autoInstall: ["kubernetes"] },
      environments: [{ name: "Sandbox", provider: "kubernetes", config: { image: "runner:v1" } }],
    });
  });

  it("returns null only when the operator variable is absent", () => {
    expect(parseOperatorConfigEnv({})).toBeNull();
    expect(() => parseOperatorConfigEnv(envWith("  "))).toThrow(/blank/i);
  });

  it.each([
    ["malformed JSON", "{"],
    ["wrong mode", JSON.stringify({ ...validOperatorDocument, mode: "cloud" })],
    ["unsupported version", JSON.stringify({ ...validOperatorDocument, v: 2 })],
    ["missing features", JSON.stringify(Object.fromEntries(Object.entries(validOperatorDocument).filter(([k]) => k !== "features")))],
    ["missing plugins", JSON.stringify(Object.fromEntries(Object.entries(validOperatorDocument).filter(([k]) => k !== "plugins")))],
    ["unknown top-level key", JSON.stringify({ ...validOperatorDocument, cloud: true })],
    ["unknown feature key", JSON.stringify({ ...validOperatorDocument, features: { allowEverything: true } })],
    ["secret in environment config", JSON.stringify({ ...validOperatorDocument, environments: [{ name: "Sandbox", provider: "kubernetes", config: { nested: { apiToken: "do-not-echo" } } }] })],
    ["secret in environment config nested inside arrays", JSON.stringify({ ...validOperatorDocument, environments: [{ name: "Sandbox", provider: "kubernetes", config: { nested: [[{ apiToken: "do-not-echo" }]] } }] })],
    ["unprovisioned environment provider", JSON.stringify({ ...validOperatorDocument, environments: [{ name: "Sandbox", provider: "daytona" }] })],
  ])("rejects %s", (_label, raw) => {
    expect(() => parseOperatorConfigEnv(envWith(raw as string))).toThrow();
  });
});

describe("operator policy identity", () => {
  it("caches parsed values and identifies operator instances without claiming Cloud", () => {
    const env = envWith(JSON.stringify(validOperatorDocument));
    const first = getOperatorInstanceConfig(env);
    expect(getOperatorInstanceConfig(env)).toBe(first);
    expect(isOperatorManagedInstance(env)).toBe(true);
    expect(getRuntimeInstancePolicy(env)).toMatchObject({ mode: "operator" });
    expect(isOperatorManagedInstance({})).toBe(false);
  });

  it("rejects operator policy combined with Cloud config or a Cloud tenant token", () => {
    const operator = JSON.stringify(validOperatorDocument);
    expect(() => getRuntimeInstancePolicy({
      PAPERCLIP_OPERATOR_CONFIG: operator,
      PAPERCLIP_MANAGED_CONFIG: JSON.stringify({ ...validOperatorDocument, mode: "cloud" }),
    })).toThrow(/ambiguous|operator.*cloud|cloud.*operator/i);
    expect(() => getRuntimeInstancePolicy({
      PAPERCLIP_OPERATOR_CONFIG: operator,
      PAPERCLIP_CLOUD_TENANT_SERVER_TOKEN: "cloud-token",
    })).toThrow(/ambiguous|operator.*cloud|cloud.*operator/i);
  });

  it("rejects Cloud ambiguity in direct parser calls and after an operator config cache hit", () => {
    const operator = JSON.stringify(validOperatorDocument);
    const cloud = JSON.stringify({ ...validOperatorDocument, mode: "cloud" });
    expect(() => parseOperatorConfigEnv({
      PAPERCLIP_OPERATOR_CONFIG: operator,
      PAPERCLIP_MANAGED_CONFIG: cloud,
    })).toThrow(/ambiguous|operator.*cloud|cloud.*operator/i);
    expect(() => parseOperatorConfigEnv({
      PAPERCLIP_OPERATOR_CONFIG: operator,
      PAPERCLIP_CLOUD_TENANT_SERVER_TOKEN: "cloud-token",
    })).toThrow(/ambiguous|operator.*cloud|cloud.*operator/i);

    const cachedEnv: Record<string, string | undefined> = { PAPERCLIP_OPERATOR_CONFIG: operator };
    expect(getOperatorInstanceConfig(cachedEnv)?.mode).toBe("operator");
    cachedEnv.PAPERCLIP_CLOUD_TENANT_SERVER_TOKEN = "cloud-token";
    expect(() => getOperatorInstanceConfig(cachedEnv)).toThrow(/ambiguous|operator.*cloud|cloud.*operator/i);
  });
});
