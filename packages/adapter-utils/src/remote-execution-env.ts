const REMOTE_EXECUTION_ENV_INHERITED_PASSTHROUGH_KEYS = new Set([
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "TERM",
  "COLORTERM",
]);

function hasInheritedEnvValueCaseInsensitive(
  env: NodeJS.ProcessEnv,
  key: string,
  value: string,
): boolean {
  const upper = key.toUpperCase();
  for (const [candidateKey, candidateValue] of Object.entries(env)) {
    if (
      candidateKey.toUpperCase() === upper &&
      typeof candidateValue === "string" &&
      candidateValue === value
    ) {
      return true;
    }
  }
  return false;
}

export function sanitizeRemoteExecutionEnv(
  env: Record<string, string>,
  inheritedEnv: NodeJS.ProcessEnv = process.env,
): Record<string, string> {
  const sanitized: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    const normalizedKey = key.toUpperCase();
    if (
      hasInheritedEnvValueCaseInsensitive(inheritedEnv, key, value) &&
      !REMOTE_EXECUTION_ENV_INHERITED_PASSTHROUGH_KEYS.has(normalizedKey)
    ) {
      continue;
    }
    sanitized[key] = value;
  }
  return sanitized;
}
