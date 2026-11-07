import fs from "node:fs/promises";
import { X509Certificate } from "node:crypto";
import os from "node:os";
import path from "node:path";
import { asBoolean } from "@paperclipai/adapter-utils/server-utils";

type PreparedOpenCodeRuntimeConfig = {
  env: Record<string, string>;
  credentialEnv?: Record<string, string>;
  trustedCaRelativePath?: string;
  notes: string[];
  cleanup: () => Promise<void>;
};

const REMOTE_TRUST_MAX_BYTES = 64 * 1024;
const REMOTE_TRUST_MAX_CERTIFICATES = 8;
const REMOTE_TRUST_CONFLICTING_ENV = [
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
  "REQUESTS_CA_BUNDLE",
  "CURL_CA_BUNDLE",
  "NODE_OPTIONS",
  "NODE_TLS_REJECT_UNAUTHORIZED",
  "OPENSSL_CONF",
  "OPENSSL_MODULES",
  "SSLKEYLOGFILE",
  "NODE_EXTRA_CA_CERTS",
];

export function validateOpenCodeRemoteTrustedCaPem(value: unknown, now = new Date()): string {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") === 0) {
    throw new Error("Remote OpenCode trusted CA bundle must be a non-empty PEM string.");
  }
  if (Buffer.byteLength(value, "utf8") > REMOTE_TRUST_MAX_BYTES) {
    throw new Error("Remote OpenCode trusted CA bundle exceeds size limit.");
  }
  const matches = [...value.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)];
  if (matches.length === 0 || matches.length > REMOTE_TRUST_MAX_CERTIFICATES) {
    throw new Error("Remote OpenCode trusted CA bundle exceeds certificate limit or has no certificates.");
  }
  const remainder = value.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g, "");
  if (remainder.trim().length > 0) {
    throw new Error("Remote OpenCode trusted CA bundle must contain only CA PEM certificate blocks and whitespace.");
  }
  for (const match of matches) {
    let certificate: X509Certificate;
    try {
      certificate = new X509Certificate(match[0]);
    } catch {
      throw new Error("Remote OpenCode trusted CA bundle contains an invalid certificate.");
    }
    if (!certificate.ca) {
      throw new Error("Remote OpenCode trusted CA bundle contains a certificate that is not a CA.");
    }
    const validFrom = Date.parse(certificate.validFrom);
    const validTo = Date.parse(certificate.validTo);
    const timestamp = now.getTime();
    if (timestamp < validFrom) throw new Error("Remote OpenCode trusted CA certificate is not yet valid.");
    if (timestamp > validTo) throw new Error("Remote OpenCode trusted CA certificate has expired.");
  }
  return value.endsWith("\n") ? value : `${value}\n`;
}

/** Apply a staged remote CA using Node's additive system-root trust behavior. */
export function configureOpenCodeRemoteTrustedCa(input: {
  env: Record<string, string>;
  relativePath?: string;
  stagedXdgConfigHome?: string;
}): void {
  if (!input.relativePath) return;
  if (!input.stagedXdgConfigHome) {
    throw new Error("Remote OpenCode trust asset was not staged.");
  }
  for (const name of REMOTE_TRUST_CONFLICTING_ENV) delete input.env[name];
  input.env.NODE_EXTRA_CA_CERTS = path.posix.join(input.stagedXdgConfigHome, input.relativePath);
}

function resolveXdgConfigHome(env: Record<string, string>): string {
  return (
    (typeof env.XDG_CONFIG_HOME === "string" && env.XDG_CONFIG_HOME.trim()) ||
    (typeof process.env.XDG_CONFIG_HOME === "string" && process.env.XDG_CONFIG_HOME.trim()) ||
    path.join(os.homedir(), ".config")
  );
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function containsCredential(value: unknown, expected: string): boolean {
  if (typeof value === "string") {
    return value.includes(expected);
  }
  if (Array.isArray(value)) return value.some((entry) => containsCredential(entry, expected));
  if (isPlainObject(value)) return Object.values(value).some((entry) => containsCredential(entry, expected));
  return false;
}

// Recursively replace {env:VAR} placeholders with the resolved value. Used to bake
// gateway provider secrets (e.g. the LLM-gateway virtual key) into opencode.json
// SERVER-SIDE, where the value is reliably present. OpenCode's own {env:...}
// resolution happens inside the (possibly sandboxed) run process, whose env
// plumbing is not guaranteed to carry the key to OpenCode's spawned server -- so
// we resolve it here. Unresolvable placeholders are left intact for OpenCode to try.
function expandEnvPlaceholders<T>(value: T, resolve: (name: string) => string | undefined): T {
  if (typeof value === "string") {
    return value.replace(/\{env:([A-Za-z_][A-Za-z0-9_]*)\}/g, (match, name: string) => {
      const resolved = resolve(name);
      return resolved !== undefined && resolved.length > 0 ? resolved : match;
    }) as unknown as T;
  }
  if (Array.isArray(value)) {
    return value.map((entry) => expandEnvPlaceholders(entry, resolve)) as unknown as T;
  }
  if (isPlainObject(value)) {
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) {
      out[key] = expandEnvPlaceholders(entry, resolve);
    }
    return out as unknown as T;
  }
  return value;
}

function parseProviderConfig(
  raw: unknown,
  resolveEnv: (name: string) => string | undefined,
  notes: string[],
): Record<string, unknown> | null {
  if (typeof raw !== "string" || raw.trim().length === 0) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // Surface the misconfiguration instead of silently dropping the provider
    // block; an unparseable value would otherwise be undiagnosable.
    notes.push("PAPERCLIP_OPENCODE_PROVIDERS contains invalid JSON; custom providers ignored.");
    return null;
  }
  if (!isPlainObject(parsed)) {
    notes.push(
      "PAPERCLIP_OPENCODE_PROVIDERS is set but is not a JSON object; custom providers ignored.",
    );
    return null;
  }
  // Only keep provider entries that are themselves objects; surface the ones
  // we drop so a malformed entry is just as diagnosable as malformed JSON.
  const providers: Record<string, unknown> = {};
  const skipped: string[] = [];
  for (const [key, value] of Object.entries(parsed)) {
    if (isPlainObject(value)) providers[key] = expandEnvPlaceholders(value, resolveEnv);
    else skipped.push(key);
  }
  if (skipped.length > 0) {
    notes.push(
      `PAPERCLIP_OPENCODE_PROVIDERS: skipped provider(s) with non-object values: ${skipped.join(", ")}.`,
    );
  }
  return Object.keys(providers).length > 0 ? providers : null;
}

function parseConfiguredModelRef(raw: unknown): { provider: string; model: string } | null {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  const slash = trimmed.indexOf("/");
  if (slash <= 0 || slash === trimmed.length - 1) return null;
  return { provider: trimmed.slice(0, slash), model: trimmed.slice(slash + 1) };
}

async function readJsonObject(filepath: string): Promise<Record<string, unknown>> {
  try {
    const raw = await fs.readFile(filepath, "utf8");
    const parsed = JSON.parse(raw);
    return isPlainObject(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

export async function prepareOpenCodeRuntimeConfig(input: {
  env: Record<string, string>;
  config: Record<string, unknown>;
  targetIsRemote?: boolean;
}): Promise<PreparedOpenCodeRuntimeConfig> {
  const skipPermissions = asBoolean(input.config.dangerouslySkipPermissions, true);
  // Remote execution must only use the run's declared provider profile. Never
  // inherit the server's OpenCode profile or ambient provider settings.
  const providerConfig = input.env.PAPERCLIP_OPENCODE_PROVIDERS ??
    (input.targetIsRemote ? undefined : process.env.PAPERCLIP_OPENCODE_PROVIDERS);
  if (!input.targetIsRemote && !skipPermissions && !providerConfig?.trim()) {
    return {
      env: input.env,
      notes: [],
      cleanup: async () => {},
    };
  }

  if (input.targetIsRemote) {
    return prepareRemoteOpenCodeRuntimeConfig(input, providerConfig, skipPermissions);
  }

  const sourceConfigDir = path.join(resolveXdgConfigHome(input.env), "opencode");
  const runtimeConfigHome = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-opencode-config-"));
  const runtimeConfigDir = path.join(runtimeConfigHome, "opencode");
  const runtimeConfigPath = path.join(runtimeConfigDir, "opencode.json");

  await fs.mkdir(runtimeConfigDir, { recursive: true });
  try {
    await fs.cp(sourceConfigDir, runtimeConfigDir, {
      recursive: true,
      force: true,
      errorOnExist: false,
      dereference: false,
    });
  } catch (err) {
    if ((err as NodeJS.ErrnoException | null)?.code !== "ENOENT") {
      throw err;
    }
  }

  const existingConfig = await readJsonObject(runtimeConfigPath);
  const notes = [
    skipPermissions
      ? "Injected runtime OpenCode config with permission=allow for all tools and connections."
      : "Injected runtime OpenCode provider config without changing tool permissions.",
  ];

  // Merge gateway/custom provider definitions supplied via PAPERCLIP_OPENCODE_PROVIDERS
  // (a JSON object in OpenCode's `provider` shape). OpenCode resolves a `--model
  // provider/model` only when that model exists in a provider's `models` map, and
  // OPENCODE_ALLOW_ALL_MODELS does NOT bypass its internal getModel(). So routing a
  // gateway model (e.g. an EU LLM gateway exposing OpenAI-compatible /v1) requires a
  // custom provider with an explicit models map. We accept it as config (not
  // hard-coded) so the gateway URL, key env, and model list stay declarative.
  const resolveEnv = (name: string): string | undefined => input.env[name] ?? process.env[name];
  const gatewayProviders = parseProviderConfig(
    providerConfig,
    resolveEnv,
    notes,
  );
  const existingProvider = isPlainObject(existingConfig.provider) ? existingConfig.provider : {};
  let nextProvider = gatewayProviders
    ? { ...existingProvider, ...gatewayProviders }
    : existingProvider;
  if (gatewayProviders) {
    notes.push(
      `Injected ${Object.keys(gatewayProviders).length} custom OpenCode provider(s) from PAPERCLIP_OPENCODE_PROVIDERS: ${Object.keys(gatewayProviders).join(", ")}.`,
    );
  }

  // Register the configured model on its provider's models map. OpenCode resolves
  // `--model provider/model` only when the model id exists in that map, so ids the
  // models.dev catalog does not carry — OpenRouter routing variants such as
  // `openai/gpt-oss-120b:nitro`, or models newer than the bundled catalog — are
  // otherwise rejected with "Model not found" even though the provider serves them.
  // An empty entry deep-merges with catalog metadata, so this is a no-op for models
  // the catalog already knows, and we never clobber an explicit definition from the
  // user config or PAPERCLIP_OPENCODE_PROVIDERS.
  const configuredModel = parseConfiguredModelRef(input.config.model);
  if (configuredModel) {
    const providerEntry = isPlainObject(nextProvider[configuredModel.provider])
      ? { ...(nextProvider[configuredModel.provider] as Record<string, unknown>) }
      : {};
    const providerModels = isPlainObject(providerEntry.models)
      ? { ...(providerEntry.models as Record<string, unknown>) }
      : {};
    if (!isPlainObject(providerModels[configuredModel.model])) {
      providerModels[configuredModel.model] = {};
      providerEntry.models = providerModels;
      nextProvider = { ...nextProvider, [configuredModel.provider]: providerEntry };
      notes.push(
        `Registered configured model ${configuredModel.provider}/${configuredModel.model} in the runtime OpenCode config.`,
      );
    }
  }

  const nextConfig: Record<string, unknown> = {
    ...existingConfig,
    ...(skipPermissions ? { permission: "allow" } : {}),
  };
  if (Object.keys(nextProvider).length > 0) {
    nextConfig.provider = nextProvider;
  }

  // Pin OpenCode's auxiliary "small" model (used for session-title generation and
  // other helper tasks) via PAPERCLIP_OPENCODE_SMALL_MODEL. OpenCode otherwise
  // defaults the small model to a built-in provider default (e.g. a claude-* model
  // for the anthropic provider); when that provider is repointed at a gateway that
  // does not serve that exact model, the title-gen call fails and aborts the run.
  // Setting small_model to a gateway-served model keeps every call on supported models.
  const smallModel = (input.env.PAPERCLIP_OPENCODE_SMALL_MODEL ?? process.env.PAPERCLIP_OPENCODE_SMALL_MODEL)?.trim();
  if (smallModel) {
    nextConfig.small_model = smallModel;
    notes.push(`Pinned OpenCode small_model to ${smallModel}.`);
  }
  await fs.writeFile(runtimeConfigPath, `${JSON.stringify(nextConfig, null, 2)}\n`, "utf8");

  return {
    env: {
      ...input.env,
      XDG_CONFIG_HOME: runtimeConfigHome,
    },
    notes,
    cleanup: async () => {
      await fs.rm(runtimeConfigHome, { recursive: true, force: true });
    },
  };
}

async function prepareRemoteOpenCodeRuntimeConfig(
  input: { env: Record<string, string>; config: Record<string, unknown> },
  providerConfig: string | undefined,
  skipPermissions: boolean,
): Promise<PreparedOpenCodeRuntimeConfig> {
  const configuredModel = parseConfiguredModelRef(input.config.model);
  if (!configuredModel) {
    throw new Error("Remote OpenCode requires an explicit provider/model selection.");
  }
  if (!providerConfig?.trim()) {
    throw new Error("Remote OpenCode requires an explicit provider profile.");
  }
  const notes: string[] = [];
  const trustedCaConfigured = Object.prototype.hasOwnProperty.call(input.config, "trustedCaPem");
  const trustedCaPem = trustedCaConfigured
    ? validateOpenCodeRemoteTrustedCaPem(input.config.trustedCaPem)
    : undefined;
  const providers = parseProviderConfig(providerConfig, () => undefined, notes);
  const configuredSmallModel = input.env.PAPERCLIP_OPENCODE_SMALL_MODEL?.trim();
  const smallModelRef = configuredSmallModel
    ? parseConfiguredModelRef(configuredSmallModel)
    : configuredModel;
  if (!smallModelRef) {
    throw new Error("Remote OpenCode small_model must use an explicit provider/model reference.");
  }
  const requestedModels = [configuredModel, smallModelRef];
  const minimalProviders: Record<string, Record<string, unknown>> = {};
  const credentialEnv: Record<string, string> = {};
  for (const modelRef of requestedModels) {
    const declaredProvider = providers?.[modelRef.provider];
    if (!isPlainObject(declaredProvider)) {
      throw new Error(`Remote OpenCode provider profile is missing ${modelRef.provider}.`);
    }
    const options = isPlainObject(declaredProvider.options) ? declaredProvider.options : {};
    const keyReference = options.apiKey;
    const keyMatch = typeof keyReference === "string"
      ? /^\{env:([A-Za-z_][A-Za-z0-9_]*)\}$/.exec(keyReference)
      : null;
    if (!keyMatch) {
      throw new Error(`Remote OpenCode provider ${modelRef.provider} must bind apiKey to an explicit environment variable.`);
    }
    const keyValue = input.env[keyMatch[1]];
    if (typeof keyValue !== "string" || keyValue.trim().length === 0) {
      throw new Error(`Remote OpenCode credential binding ${keyMatch[1]} is missing or empty.`);
    }
    credentialEnv[keyMatch[1]] = keyValue;
    const providerModels = isPlainObject(declaredProvider.models) ? declaredProvider.models : {};
    const existing = minimalProviders[modelRef.provider];
    const minimalProvider: Record<string, unknown> = existing ?? {
      ...declaredProvider,
      options: { ...options, apiKey: keyReference },
      models: {},
    };
    const minimalModels = minimalProvider.models as Record<string, unknown>;
    minimalModels[modelRef.model] = isPlainObject(providerModels[modelRef.model])
      ? providerModels[modelRef.model]
      : {};
    minimalProviders[modelRef.provider] = minimalProvider;
  }
  const nextConfig: Record<string, unknown> = {
    ...(skipPermissions ? { permission: "allow" } : {}),
    provider: minimalProviders,
  };
  nextConfig.small_model = configuredSmallModel || `${configuredModel.provider}/${configuredModel.model}`;
  for (const [name, value] of Object.entries(credentialEnv)) {
    if (containsCredential(nextConfig, value)) {
      throw new Error(`Remote OpenCode profile embeds credential ${name} instead of keeping it in the runtime environment.`);
    }
  }
  const runtimeConfigHome = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-opencode-remote-config-"));
  const runtimeConfigDir = path.join(runtimeConfigHome, "opencode");
  try {
    await fs.mkdir(runtimeConfigDir, { recursive: true });
    await fs.writeFile(path.join(runtimeConfigDir, "opencode.json"), `${JSON.stringify(nextConfig, null, 2)}\n`, "utf8");
    if (trustedCaPem) {
      const trustDir = path.join(runtimeConfigHome, "trust");
      await fs.mkdir(trustDir, { recursive: true });
      await fs.writeFile(path.join(trustDir, "ca.pem"), trustedCaPem, { encoding: "utf8", mode: 0o600 });
    }
  } catch (err) {
    await fs.rm(runtimeConfigHome, { recursive: true, force: true }).catch(() => {});
    throw err;
  }
  const runtimeEnv = { ...input.env };
  delete runtimeEnv.PAPERCLIP_OPENCODE_PROVIDERS;
  delete runtimeEnv.PAPERCLIP_OPENCODE_SMALL_MODEL;
  if (trustedCaPem) {
    for (const name of REMOTE_TRUST_CONFLICTING_ENV) delete runtimeEnv[name];
  }
  for (const name of Object.keys(credentialEnv)) delete runtimeEnv[name];
  return {
    env: { ...runtimeEnv, XDG_CONFIG_HOME: runtimeConfigHome },
    credentialEnv,
    ...(trustedCaPem ? { trustedCaRelativePath: "trust/ca.pem" } : {}),
    notes: ["Created an isolated remote OpenCode config from the selected run provider/model."],
    cleanup: async () => fs.rm(runtimeConfigHome, { recursive: true, force: true }),
  };
}

/** Every remote run gets a fresh HOME/XDG profile to prevent retained auth fallback. */
export function prepareOpenCodeRemoteHomes(input: {
  env: Record<string, string>;
  runtimeRootDir: string | null | undefined;
  runId: string;
  configDir?: string;
}): void {
  if (!input.runtimeRootDir) throw new Error("Remote OpenCode requires an isolated runtime directory.");
  const home = path.posix.join(input.runtimeRootDir, "home", input.runId);
  const configHome = input.configDir ?? path.posix.join(home, "config");
  Object.assign(input.env, {
    HOME: home,
    XDG_CONFIG_HOME: configHome,
    XDG_DATA_HOME: path.posix.join(home, "data"),
    XDG_CACHE_HOME: path.posix.join(home, "cache"),
    XDG_STATE_HOME: path.posix.join(home, "state"),
    XDG_RUNTIME_DIR: path.posix.join(home, "runtime"),
    OPENCODE_CONFIG: path.posix.join(configHome, "opencode", "opencode.json"),
  });
  delete input.env.OPENCODE_CONFIG_DIR;
}
