/** Self-host operator policy, deliberately distinct from Cloud tenant identity. */
import { MANAGED_CONFIG_ENV_KEY, parseManagedConfigEnv, type ManagedConfigEnv, type ManagedInstanceConfig } from "./managed-config.js";
export { SECRET_LIKE_CONFIG_KEY_PATTERN } from "./managed-config.js";

export const OPERATOR_CONFIG_ENV_KEY = "PAPERCLIP_OPERATOR_CONFIG";
export type OperatorInstanceConfig = Omit<ManagedInstanceConfig, "mode"> & { mode: "operator" };
export type RuntimeInstancePolicy = ManagedInstanceConfig | OperatorInstanceConfig;

let cache: { raw: string | undefined; config: OperatorInstanceConfig | null } | null = null;

export function parseOperatorConfigEnv(env: ManagedConfigEnv): OperatorInstanceConfig | null {
  assertNoAmbiguousCloud(env);
  const raw = env[OPERATOR_CONFIG_ENV_KEY];
  if (raw === undefined) return null;
  if (!raw.trim()) throw new Error(`${OPERATOR_CONFIG_ENV_KEY} is set but blank`);
  let input: unknown;
  try { input = JSON.parse(raw); } catch { throw new Error(`${OPERATOR_CONFIG_ENV_KEY} is not valid JSON`); }
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error(`${OPERATOR_CONFIG_ENV_KEY} must be a JSON object`);
  const doc = input as Record<string, unknown>;
  if (doc.mode !== "operator") throw new Error(`${OPERATOR_CONFIG_ENV_KEY} has invalid mode; expected operator`);
  // Reuse the strict, shared v1 schema/catalog/secret-key checks. Do not expose
  // parser detail here because malformed values can themselves be credentials.
  try {
    const normalized = { ...doc, mode: "cloud" };
    const parsed = parseManagedConfigEnv({ [MANAGED_CONFIG_ENV_KEY]: JSON.stringify(normalized) });
    if (!parsed) throw new Error("missing config");
    return Object.freeze({ ...parsed, mode: "operator" }) as OperatorInstanceConfig;
  } catch (error) {
    if (error instanceof Error && /secret-bearing|looks secret/i.test(error.message)) {
      throw new Error(`${OPERATOR_CONFIG_ENV_KEY} contains a secret-bearing environment config key`);
    }
    throw new Error(`${OPERATOR_CONFIG_ENV_KEY} is invalid; check the v1 operator schema`);
  }
}

function assertNoAmbiguousCloud(env: ManagedConfigEnv): void {
  if (env[OPERATOR_CONFIG_ENV_KEY] !== undefined &&
      (env[MANAGED_CONFIG_ENV_KEY] !== undefined || Boolean(env.PAPERCLIP_CLOUD_TENANT_SERVER_TOKEN?.trim()))) {
    throw new Error("ambiguous operator and Cloud runtime configuration");
  }
}

export function getOperatorInstanceConfig(env: ManagedConfigEnv = process.env): OperatorInstanceConfig | null {
  assertNoAmbiguousCloud(env);
  const raw = env[OPERATOR_CONFIG_ENV_KEY];
  if (cache && cache.raw === raw) return cache.config;
  const config = parseOperatorConfigEnv(env);
  cache = { raw, config };
  return config;
}

export function isOperatorManagedInstance(env: ManagedConfigEnv = process.env): boolean {
  return getOperatorInstanceConfig(env) !== null;
}

export function getRuntimeInstancePolicy(env: ManagedConfigEnv = process.env): RuntimeInstancePolicy | null {
  const operator = getOperatorInstanceConfig(env);
  if (operator) return operator;
  return parseManagedConfigEnv(env);
}
