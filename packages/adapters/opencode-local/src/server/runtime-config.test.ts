import fs from "node:fs/promises";
import { X509Certificate } from "node:crypto";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  configureOpenCodeRemoteTrustedCa,
  prepareOpenCodeRuntimeConfig,
  validateOpenCodeRemoteTrustedCaPem,
} from "./runtime-config.js";

const TEST_CA_PEM = `-----BEGIN CERTIFICATE-----
MIICFDCCAX2gAwIBAgIUbAcXH/gLdZYHDyCg5uD9QkoU6dIwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQT3BlbkNvZGUgdGVzdCBDQTAgFw0yNjExMDcyMTUzNDla
GA8yMTI2MTAxNDIxNTM0OVowGzEZMBcGA1UEAwwQT3BlbkNvZGUgdGVzdCBDQTCB
nzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAt6JhKkjqhmQqsAVduWHKAjedHpgq
mq9V64pHCUqCAQY1+iwLuk8y7Z7vVvEtYmwylbRX9fHpb1dvcd6bdvotPiCGErxQ
C5FcoQZcOp4NX/CfMzHhrV4T5Gun5UDENjiF5JMTeASEOB2fXO9xIi2SQz88lLH6
Zu2dah78veBx4pMCAwEAAaNTMFEwHQYDVR0OBBYEFMA2LZmKGJhTf6LFANr/inEa
gZs5MB8GA1UdIwQYMBaAFMA2LZmKGJhTf6LFANr/inEagZs5MA8GA1UdEwEB/wQF
MAMBAf8wDQYJKoZIhvcNAQELBQADgYEAs+N7JG+Sj0YZllh7Qb1vKxTb1WBxz6VW
pj3iscD8veHT1r5Q9Qhh9fU+n2NrcOh6HxXrmRDoj18iVNxvRXxMmJ19ovzhXfxg
SGOiW1iUdiPtY5hNAiORBB4f+Fo7ReTP2S8JyFqy6U682uE1YxyjwElrotZjKXWv
nvUmXExeOTA=
-----END CERTIFICATE-----
`;

const TEST_LEAF_PEM = `-----BEGIN CERTIFICATE-----
MIICFTCCAX6gAwIBAgIUfH5kBzQV9n4YHNd1SfngcCwfl1UwDQYJKoZIhvcNAQEL
BQAwHTEbMBkGA1UEAwwST3BlbkNvZGUgdGVzdCBsZWFmMCAXDTI2MTEwNzIxNTM1
NVoYDzIxMjYxMDE0MjE1MzU1WjAdMRswGQYDVQQDDBJPcGVuQ29kZSB0ZXN0IGxl
YWYwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANHAdcvHoIpNdSuhbJ+6TXQr
UpcXa99TskHueb0E1qG2fbNKDDgse1W2elxan+4sF5nHKVym57TpTFbpd1W83qdu
IoqKyZis5bpfpo200DACTUaSTnPFpTLJfyq3ggo2P7PIDgHBHLq8CnKw5sTmBgqJ
xeMAf3f/XumMZsfFCGb7AgMBAAGjUDBOMB0GA1UdDgQWBBQKhEWowUpj0ab3VodR
XEcN7A/4OzAfBgNVHSMEGDAWgBQKhEWowUpj0ab3VodRXEcN7A/4OzAMBgNVHRMB
Af8EAjAAMA0GCSqGSIb3DQEBCwUAA4GBAJmwpwOajazfOqnGHVhKPJUtYtAAcIfA
xBe0M5hiFqv5UXjVZKAG69k+GBYdwKySoinH6NQlXYM5ABjC95vDL94X/fVxp1kh
SzSxDzcV3ktir26Fj+ibGaoDOIrzOmDNUyS1M0ZcMCvKjcgYlO58gTL9q1idVKhi
0Ne4H9KNXnFt
-----END CERTIFICATE-----
`;

const cleanupPaths = new Set<string>();

afterEach(async () => {
  await Promise.all(
    [...cleanupPaths].map(async (filepath) => {
      await fs.rm(filepath, { recursive: true, force: true });
      cleanupPaths.delete(filepath);
    }),
  );
});

async function makeConfigHome(initialConfig?: Record<string, unknown>) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-opencode-test-"));
  cleanupPaths.add(root);
  const configDir = path.join(root, "opencode");
  await fs.mkdir(configDir, { recursive: true });
  if (initialConfig) {
    await fs.writeFile(
      path.join(configDir, "opencode.json"),
      `${JSON.stringify(initialConfig, null, 2)}\n`,
      "utf8",
    );
  }
  return root;
}

describe("prepareOpenCodeRuntimeConfig", () => {
  it("stages only the public CA asset in an isolated remote config and adds its path to Node trust", async () => {
    const prepared = await prepareOpenCodeRuntimeConfig({
      env: {
        PAPERCLIP_OPENCODE_PROVIDERS: JSON.stringify({
          gateway: { options: { apiKey: "{env:SCOPED_KEY}" }, models: { model: {} } },
        }),
        SCOPED_KEY: "fixture-scoped-key",
        SSL_CERT_FILE: "/host/replace-roots.pem",
        SSL_CERT_DIR: "/host/cert-dir",
        REQUESTS_CA_BUNDLE: "/host/request-roots.pem",
        CURL_CA_BUNDLE: "/host/curl-roots.pem",
        NODE_OPTIONS: "--use-openssl-ca --require /host/preload.js",
        NODE_TLS_REJECT_UNAUTHORIZED: "0",
        OPENSSL_CONF: "/host/openssl.cnf",
        OPENSSL_MODULES: "/host/openssl-modules",
        SSLKEYLOGFILE: "/host/tls.keys",
      },
      config: { model: "gateway/model", trustedCaPem: TEST_CA_PEM },
      targetIsRemote: true,
    });
    cleanupPaths.add(prepared.env.XDG_CONFIG_HOME);

    expect(prepared.trustedCaRelativePath).toBe("trust/ca.pem");
    expect(await fs.readFile(path.join(prepared.env.XDG_CONFIG_HOME, "trust", "ca.pem"), "utf8")).toBe(TEST_CA_PEM);
    expect(prepared.env.NODE_EXTRA_CA_CERTS).toBeUndefined();
    for (const name of [
      "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
      "NODE_OPTIONS", "NODE_TLS_REJECT_UNAUTHORIZED", "OPENSSL_CONF", "OPENSSL_MODULES", "SSLKEYLOGFILE",
    ]) {
      expect(prepared.env[name]).toBeUndefined();
    }
    expect(prepared.credentialEnv?.SCOPED_KEY).toBe("fixture-scoped-key");
    expect(await fs.readFile(path.join(prepared.env.XDG_CONFIG_HOME, "opencode", "opencode.json"), "utf8"))
      .not.toContain("fixture-scoped-key");

    const childEnv = { ...prepared.env };
    configureOpenCodeRemoteTrustedCa({
      env: childEnv,
      relativePath: prepared.trustedCaRelativePath,
      stagedXdgConfigHome: "/remote/runtime/xdgConfig",
    });
    expect(childEnv.NODE_EXTRA_CA_CERTS).toBe("/remote/runtime/xdgConfig/trust/ca.pem");
    expect(childEnv.SSL_CERT_FILE).toBeUndefined();
    await prepared.cleanup();
    cleanupPaths.delete(prepared.env.XDG_CONFIG_HOME);
  });

  it.each([
    ["private key blocks", `${TEST_CA_PEM}-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----`],
    ["non-CA certificates", TEST_LEAF_PEM],
    ["extra text", `untrusted prefix\n${TEST_CA_PEM}`],
    ["malformed certificates", "-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----"],
    ["malformed data inside a certificate", TEST_CA_PEM.replace("MIICFD", "MIICFDjunk")],
    ["DER data after a certificate", TEST_CA_PEM.replace("-----END CERTIFICATE-----", "AAAA-----END CERTIFICATE-----")],
  ])("rejects remote trusted CA material containing %s", async (_label, trustedCaPem) => {
    await expect(prepareOpenCodeRuntimeConfig({
      env: { PAPERCLIP_OPENCODE_PROVIDERS: JSON.stringify({ gateway: { options: { apiKey: "{env:KEY}" }, models: { model: {} } } }), KEY: "fixture" },
      config: { model: "gateway/model", trustedCaPem },
      targetIsRemote: true,
    })).rejects.toThrow(/trusted CA|certificate|PEM/i);
  });

  it("canonicalizes certificate bytes from the parsed X509 certificate", () => {
    const canonicalPem = new X509Certificate(TEST_CA_PEM).toString();
    expect(validateOpenCodeRemoteTrustedCaPem(`\n${TEST_CA_PEM.trim()}\n\n`)).toBe(`${canonicalPem.trimEnd()}\n`);
  });

  it("rejects expired, not-yet-valid, oversized, and excessive remote CA bundles", () => {
    expect(() => validateOpenCodeRemoteTrustedCaPem(TEST_CA_PEM, new Date("2200-01-01T00:00:00Z")))
      .toThrow(/expired|validity/i);
    expect(() => validateOpenCodeRemoteTrustedCaPem(TEST_CA_PEM, new Date("2000-01-01T00:00:00Z")))
      .toThrow(/not yet valid|validity/i);
    expect(() => validateOpenCodeRemoteTrustedCaPem(TEST_CA_PEM.repeat(800)))
      .toThrow(/size limit/i);
    expect(() => validateOpenCodeRemoteTrustedCaPem(Array(10).fill(TEST_CA_PEM).join("\n")))
      .toThrow(/certificate limit/i);
  });

  it("requires the staged remote trust asset and leaves local profile behavior unchanged", async () => {
    const env = { SSL_CERT_FILE: "/local/roots.pem", NODE_OPTIONS: "--trace-warnings" };
    expect(() => configureOpenCodeRemoteTrustedCa({ env, relativePath: "trust/ca.pem" }))
      .toThrow(/trust asset.*not staged/i);
    expect(env).toEqual({ SSL_CERT_FILE: "/local/roots.pem", NODE_OPTIONS: "--trace-warnings" });

    const configHome = await makeConfigHome({ theme: "local-profile" });
    const prepared = await prepareOpenCodeRuntimeConfig({
      env: { XDG_CONFIG_HOME: configHome, SSL_CERT_FILE: "/local/roots.pem", NODE_OPTIONS: "--trace-warnings" },
      config: { trustedCaPem: TEST_CA_PEM },
    });
    cleanupPaths.add(prepared.env.XDG_CONFIG_HOME);
    expect(prepared.env.SSL_CERT_FILE).toBe("/local/roots.pem");
    expect(prepared.env.NODE_OPTIONS).toBe("--trace-warnings");
    await expect(fs.access(path.join(prepared.env.XDG_CONFIG_HOME, "trust", "ca.pem"))).rejects.toThrow();
    await prepared.cleanup();
  });

  it("builds a minimal remote profile from run declarations and keeps the scoped key as an env reference", async () => {
    const hostConfig = await makeConfigHome({
      theme: "host-only-sentinel",
      provider: { hostOnly: { options: { apiKey: "host-file-key-sentinel" } } },
      small_model: "host-file-small-model",
    });
    const providers = {
      gateway: {
        npm: "@ai-sdk/openai-compatible",
        name: "Gateway",
        options: { baseURL: "https://gateway.invalid/v1", apiKey: "{env:SCOPED_KEY}" },
        models: {
          "selected-model": { name: "Selected" },
          "title-model": { name: "Title" },
          "unselected-model": {},
        },
      },
      unrelated: { options: { apiKey: "raw-unselected-key" }, models: { other: {} } },
    };
    const oldProviders = process.env.PAPERCLIP_OPENCODE_PROVIDERS;
    const oldSmallModel = process.env.PAPERCLIP_OPENCODE_SMALL_MODEL;
    const oldScopedKey = process.env.SCOPED_KEY;
    process.env.PAPERCLIP_OPENCODE_PROVIDERS = JSON.stringify({ ambient: { options: { apiKey: "{env:SCOPED_KEY}" } } });
    process.env.PAPERCLIP_OPENCODE_SMALL_MODEL = "ambient/host-model";
    process.env.SCOPED_KEY = "ambient-host-key";
    try {
      const prepared = await prepareOpenCodeRuntimeConfig({
        env: {
          XDG_CONFIG_HOME: hostConfig,
          PAPERCLIP_OPENCODE_PROVIDERS: JSON.stringify(providers),
          PAPERCLIP_OPENCODE_SMALL_MODEL: "gateway/title-model",
          SCOPED_KEY: "explicit-scoped-key",
        },
        config: { model: "gateway/selected-model" },
        targetIsRemote: true,
      });
      cleanupPaths.add(prepared.env.XDG_CONFIG_HOME);
      const runtimeConfig = JSON.parse(
        await fs.readFile(path.join(prepared.env.XDG_CONFIG_HOME, "opencode", "opencode.json"), "utf8"),
      ) as {
        provider?: Record<string, { options?: { apiKey?: unknown }; models?: Record<string, unknown> }>;
        small_model?: string;
      };
      expect(runtimeConfig).toMatchObject({
        provider: {
          gateway: {
            options: { apiKey: "{env:SCOPED_KEY}" },
            models: {
              "selected-model": { name: "Selected" },
              "title-model": { name: "Title" },
            },
          },
        },
        small_model: "gateway/title-model",
      });
      expect(runtimeConfig.provider?.unrelated).toBeUndefined();
      expect(JSON.stringify(runtimeConfig)).not.toMatch(/host-only-sentinel|host-file-key-sentinel|host-file-small-model|raw-unselected-key|explicit-scoped-key|ambient-host-key|host-model/);
      expect(prepared.env.SCOPED_KEY).toBeUndefined();
      expect(prepared.credentialEnv?.SCOPED_KEY).toBe("explicit-scoped-key");
      expect(prepared.env.PAPERCLIP_OPENCODE_PROVIDERS).toBeUndefined();
      expect(prepared.env.PAPERCLIP_OPENCODE_SMALL_MODEL).toBeUndefined();
      await prepared.cleanup();
      cleanupPaths.delete(prepared.env.XDG_CONFIG_HOME);
    } finally {
      if (oldProviders === undefined) delete process.env.PAPERCLIP_OPENCODE_PROVIDERS;
      else process.env.PAPERCLIP_OPENCODE_PROVIDERS = oldProviders;
      if (oldSmallModel === undefined) delete process.env.PAPERCLIP_OPENCODE_SMALL_MODEL;
      else process.env.PAPERCLIP_OPENCODE_SMALL_MODEL = oldSmallModel;
      if (oldScopedKey === undefined) delete process.env.SCOPED_KEY;
      else process.env.SCOPED_KEY = oldScopedKey;
    }
  });

  it("rejects an ambient-only remote credential binding", async () => {
    const oldScopedKey = process.env.SCOPED_KEY;
    process.env.SCOPED_KEY = "ambient-host-key";
    try {
      await expect(prepareOpenCodeRuntimeConfig({
        env: {
          PAPERCLIP_OPENCODE_PROVIDERS: JSON.stringify({
            gateway: { options: { apiKey: "{env:SCOPED_KEY}" }, models: { model: {} } },
          }),
        },
        config: { model: "gateway/model" },
        targetIsRemote: true,
      })).rejects.toThrow("SCOPED_KEY is missing or empty");
    } finally {
      if (oldScopedKey === undefined) delete process.env.SCOPED_KEY;
      else process.env.SCOPED_KEY = oldScopedKey;
    }
  });

  it("rejects an empty selected remote credential", async () => {
    await expect(prepareOpenCodeRuntimeConfig({
      env: {
        PAPERCLIP_OPENCODE_PROVIDERS: JSON.stringify({
          gateway: { options: { apiKey: "{env:SCOPED_KEY}" }, models: { model: {} } },
        }),
        SCOPED_KEY: "  ",
      },
      config: { model: "gateway/model" },
      targetIsRemote: true,
    })).rejects.toThrow("SCOPED_KEY is missing or empty");
  });

  it("rejects a literal selected credential instead of an env binding", async () => {
    await expect(prepareOpenCodeRuntimeConfig({
      env: {
        PAPERCLIP_OPENCODE_PROVIDERS: JSON.stringify({
          gateway: { options: { apiKey: "literal-secret-fixture" }, models: { model: {} } },
        }),
        SCOPED_KEY: "literal-secret-fixture",
      },
      config: { model: "gateway/model" },
      targetIsRemote: true,
    })).rejects.toThrow("must bind apiKey to an explicit environment variable");
  });

  it("rejects a selected credential copied into model metadata", async () => {
    await expect(prepareOpenCodeRuntimeConfig({
      env: {
        PAPERCLIP_OPENCODE_PROVIDERS: JSON.stringify({
          gateway: {
            options: { apiKey: "{env:SCOPED_KEY}" },
            models: { model: { description: "untrusted metadata contains fixture-model-key-value exactly" } },
          },
        }),
        SCOPED_KEY: "fixture-model-key-value",
      },
      config: { model: "gateway/model" },
      targetIsRemote: true,
    })).rejects.toThrow("Remote OpenCode profile embeds credential SCOPED_KEY");
  });

  it("allows all tools and connected tools by default", async () => {
    const configHome = await makeConfigHome({
      permission: {
        read: "allow",
        bash: "ask",
        "mcp__example__write": "deny",
      },
      theme: "system",
    });

    const prepared = await prepareOpenCodeRuntimeConfig({
      env: { XDG_CONFIG_HOME: configHome },
      config: {},
    });
    cleanupPaths.add(prepared.env.XDG_CONFIG_HOME);

    expect(prepared.env.XDG_CONFIG_HOME).not.toBe(configHome);
    const runtimeConfig = JSON.parse(
      await fs.readFile(
        path.join(prepared.env.XDG_CONFIG_HOME, "opencode", "opencode.json"),
        "utf8",
      ),
    ) as Record<string, unknown>;
    expect(runtimeConfig).toMatchObject({
      theme: "system",
      permission: "allow",
    });

    await prepared.cleanup();
    cleanupPaths.delete(prepared.env.XDG_CONFIG_HOME);
    await expect(fs.access(prepared.env.XDG_CONFIG_HOME)).rejects.toThrow();
  });

  it("merges custom providers from PAPERCLIP_OPENCODE_PROVIDERS into the config", async () => {
    const configHome = await makeConfigHome({ permission: { read: "allow" } });
    const providers = {
      bifrost: {
        npm: "@ai-sdk/openai-compatible",
        name: "Bifrost EU",
        options: {
          baseURL: "http://gateway.example.svc.cluster.local:8080/v1",
          apiKey: "{env:ANTHROPIC_API_KEY}",
        },
        models: { "example/model-a": { name: "Model A" } },
      },
    };

    const prepared = await prepareOpenCodeRuntimeConfig({
      env: {
        XDG_CONFIG_HOME: configHome,
        PAPERCLIP_OPENCODE_PROVIDERS: JSON.stringify(providers),
      },
      config: {},
    });
    cleanupPaths.add(prepared.env.XDG_CONFIG_HOME);

    const runtimeConfig = JSON.parse(
      await fs.readFile(path.join(prepared.env.XDG_CONFIG_HOME, "opencode", "opencode.json"), "utf8"),
    ) as Record<string, unknown>;
    expect(runtimeConfig).toMatchObject({
      permission: "allow",
      provider: providers,
    });
    expect(prepared.notes.some((n) => n.includes("bifrost"))).toBe(true);
    await prepared.cleanup();
  });

  it("reads PAPERCLIP_OPENCODE_PROVIDERS from process.env when absent from the run env", async () => {
    const configHome = await makeConfigHome({ permission: { read: "allow" } });
    const providers = { bifrost: { npm: "@ai-sdk/openai-compatible", models: { "example/model-a": {} } } };
    process.env.PAPERCLIP_OPENCODE_PROVIDERS = JSON.stringify(providers);
    try {
      const prepared = await prepareOpenCodeRuntimeConfig({
        env: { XDG_CONFIG_HOME: configHome },
        config: {},
      });
      cleanupPaths.add(prepared.env.XDG_CONFIG_HOME);
      const runtimeConfig = JSON.parse(
        await fs.readFile(path.join(prepared.env.XDG_CONFIG_HOME, "opencode", "opencode.json"), "utf8"),
      ) as Record<string, unknown>;
      expect(runtimeConfig).toMatchObject({ provider: providers });
      await prepared.cleanup();
    } finally {
      delete process.env.PAPERCLIP_OPENCODE_PROVIDERS;
    }
  });

  it("expands {env:VAR} placeholders in custom providers using the run/process env (bakes the literal vk)", async () => {
    const configHome = await makeConfigHome({ permission: { read: "allow" } });
    const providers = {
      bifrost: {
        npm: "@ai-sdk/openai-compatible",
        options: { baseURL: "http://bifrost/v1", apiKey: "{env:ANTHROPIC_API_KEY}" },
        models: { "example/model-a": {} },
      },
    };
    const prepared = await prepareOpenCodeRuntimeConfig({
      env: { XDG_CONFIG_HOME: configHome, PAPERCLIP_OPENCODE_PROVIDERS: JSON.stringify(providers), ANTHROPIC_API_KEY: "sk-bf-REALVK" },
      config: {},
    });
    cleanupPaths.add(prepared.env.XDG_CONFIG_HOME);
    const runtimeConfig = JSON.parse(
      await fs.readFile(path.join(prepared.env.XDG_CONFIG_HOME, "opencode", "opencode.json"), "utf8"),
    ) as { provider: { bifrost: { options: { apiKey: string } } } };
    // The {env:...} placeholder must be replaced with the literal value, so OpenCode
    // does not depend on its sandboxed process env carrying the key.
    expect(runtimeConfig.provider.bifrost.options.apiKey).toBe("sk-bf-REALVK");
    await prepared.cleanup();
  });

  it("leaves an unresolvable {env:VAR} placeholder intact", async () => {
    const configHome = await makeConfigHome({ permission: { read: "allow" } });
    const providers = { bifrost: { options: { apiKey: "{env:DEFINITELY_UNSET_VAR_XYZ}" }, models: { "x/y": {} } } };
    const prepared = await prepareOpenCodeRuntimeConfig({
      env: { XDG_CONFIG_HOME: configHome, PAPERCLIP_OPENCODE_PROVIDERS: JSON.stringify(providers) },
      config: {},
    });
    cleanupPaths.add(prepared.env.XDG_CONFIG_HOME);
    const runtimeConfig = JSON.parse(
      await fs.readFile(path.join(prepared.env.XDG_CONFIG_HOME, "opencode", "opencode.json"), "utf8"),
    ) as { provider: { bifrost: { options: { apiKey: string } } } };
    expect(runtimeConfig.provider.bifrost.options.apiKey).toBe("{env:DEFINITELY_UNSET_VAR_XYZ}");
    await prepared.cleanup();
  });

  it("pins small_model from PAPERCLIP_OPENCODE_SMALL_MODEL", async () => {
    const configHome = await makeConfigHome({ permission: { read: "allow" } });
    const prepared = await prepareOpenCodeRuntimeConfig({
      env: { XDG_CONFIG_HOME: configHome, PAPERCLIP_OPENCODE_SMALL_MODEL: "example/model-a" },
      config: {},
    });
    cleanupPaths.add(prepared.env.XDG_CONFIG_HOME);
    const runtimeConfig = JSON.parse(
      await fs.readFile(path.join(prepared.env.XDG_CONFIG_HOME, "opencode", "opencode.json"), "utf8"),
    ) as { small_model?: string };
    expect(runtimeConfig.small_model).toBe("example/model-a");
    await prepared.cleanup();
  });

  it("ignores malformed PAPERCLIP_OPENCODE_PROVIDERS without writing a provider block and surfaces a note", async () => {
    const configHome = await makeConfigHome({ permission: { read: "allow" } });
    const prepared = await prepareOpenCodeRuntimeConfig({
      env: { XDG_CONFIG_HOME: configHome, PAPERCLIP_OPENCODE_PROVIDERS: "not json" },
      config: {},
    });
    cleanupPaths.add(prepared.env.XDG_CONFIG_HOME);
    const runtimeConfig = JSON.parse(
      await fs.readFile(path.join(prepared.env.XDG_CONFIG_HOME, "opencode", "opencode.json"), "utf8"),
    ) as Record<string, unknown>;
    expect(runtimeConfig.provider).toBeUndefined();
    expect(prepared.notes).toContain(
      "PAPERCLIP_OPENCODE_PROVIDERS contains invalid JSON; custom providers ignored.",
    );
    await prepared.cleanup();
  });

  it("surfaces a note when PAPERCLIP_OPENCODE_PROVIDERS is valid JSON but not an object", async () => {
    const configHome = await makeConfigHome({ permission: { read: "allow" } });
    const prepared = await prepareOpenCodeRuntimeConfig({
      env: { XDG_CONFIG_HOME: configHome, PAPERCLIP_OPENCODE_PROVIDERS: "[1,2,3]" },
      config: {},
    });
    cleanupPaths.add(prepared.env.XDG_CONFIG_HOME);
    const runtimeConfig = JSON.parse(
      await fs.readFile(path.join(prepared.env.XDG_CONFIG_HOME, "opencode", "opencode.json"), "utf8"),
    ) as Record<string, unknown>;
    expect(runtimeConfig.provider).toBeUndefined();
    expect(prepared.notes).toContain(
      "PAPERCLIP_OPENCODE_PROVIDERS is set but is not a JSON object; custom providers ignored.",
    );
    await prepared.cleanup();
  });

  it("surfaces skipped provider entries with non-object values and keeps the usable ones", async () => {
    const configHome = await makeConfigHome({ permission: { read: "allow" } });
    const prepared = await prepareOpenCodeRuntimeConfig({
      env: {
        XDG_CONFIG_HOME: configHome,
        PAPERCLIP_OPENCODE_PROVIDERS: JSON.stringify({
          bifrost: "http://gateway.example/v1",
          usable: { options: { baseURL: "http://gateway.example/v1" } },
        }),
      },
      config: {},
    });
    cleanupPaths.add(prepared.env.XDG_CONFIG_HOME);
    const runtimeConfig = JSON.parse(
      await fs.readFile(path.join(prepared.env.XDG_CONFIG_HOME, "opencode", "opencode.json"), "utf8"),
    ) as { provider?: Record<string, unknown> };
    expect(runtimeConfig.provider?.usable).toBeDefined();
    expect(runtimeConfig.provider?.bifrost).toBeUndefined();
    expect(prepared.notes).toContain(
      "PAPERCLIP_OPENCODE_PROVIDERS: skipped provider(s) with non-object values: bifrost.",
    );
    await prepared.cleanup();
  });

  it("surfaces skipped provider entries when no usable entries remain", async () => {
    const configHome = await makeConfigHome({ permission: { read: "allow" } });
    const prepared = await prepareOpenCodeRuntimeConfig({
      env: {
        XDG_CONFIG_HOME: configHome,
        PAPERCLIP_OPENCODE_PROVIDERS: JSON.stringify({ bifrost: "http://gateway.example/v1" }),
      },
      config: {},
    });
    cleanupPaths.add(prepared.env.XDG_CONFIG_HOME);
    const runtimeConfig = JSON.parse(
      await fs.readFile(path.join(prepared.env.XDG_CONFIG_HOME, "opencode", "opencode.json"), "utf8"),
    ) as Record<string, unknown>;
    expect(runtimeConfig.provider).toBeUndefined();
    expect(prepared.notes).toContain(
      "PAPERCLIP_OPENCODE_PROVIDERS: skipped provider(s) with non-object values: bifrost.",
    );
    await prepared.cleanup();
  });

  it("registers a configured model missing from the catalog on its provider", async () => {
    const configHome = await makeConfigHome({ permission: { read: "allow" } });
    const prepared = await prepareOpenCodeRuntimeConfig({
      env: { XDG_CONFIG_HOME: configHome },
      config: { model: "openrouter/openai/gpt-oss-120b:nitro" },
    });
    cleanupPaths.add(prepared.env.XDG_CONFIG_HOME);
    const runtimeConfig = JSON.parse(
      await fs.readFile(path.join(prepared.env.XDG_CONFIG_HOME, "opencode", "opencode.json"), "utf8"),
    ) as { provider?: Record<string, { models?: Record<string, unknown> }> };
    expect(runtimeConfig.provider?.openrouter?.models).toEqual({
      "openai/gpt-oss-120b:nitro": {},
    });
    expect(prepared.notes).toContain(
      "Registered configured model openrouter/openai/gpt-oss-120b:nitro in the runtime OpenCode config.",
    );
    await prepared.cleanup();
  });

  it("does not clobber an explicit model definition when registering the configured model", async () => {
    const configHome = await makeConfigHome({ permission: { read: "allow" } });
    const providers = {
      openrouter: {
        models: {
          "openai/gpt-oss-120b:nitro": { name: "GPT-OSS 120B (nitro)" },
          "example/other": {},
        },
      },
    };
    const prepared = await prepareOpenCodeRuntimeConfig({
      env: {
        XDG_CONFIG_HOME: configHome,
        PAPERCLIP_OPENCODE_PROVIDERS: JSON.stringify(providers),
      },
      config: { model: "openrouter/openai/gpt-oss-120b:nitro" },
    });
    cleanupPaths.add(prepared.env.XDG_CONFIG_HOME);
    const runtimeConfig = JSON.parse(
      await fs.readFile(path.join(prepared.env.XDG_CONFIG_HOME, "opencode", "opencode.json"), "utf8"),
    ) as { provider?: Record<string, { models?: Record<string, unknown> }> };
    expect(runtimeConfig.provider?.openrouter?.models).toEqual(providers.openrouter.models);
    expect(
      prepared.notes.some((note) => note.startsWith("Registered configured model")),
    ).toBe(false);
    await prepared.cleanup();
  });

  it("skips model registration when the configured model is not provider/model shaped", async () => {
    const configHome = await makeConfigHome({ permission: { read: "allow" } });
    const prepared = await prepareOpenCodeRuntimeConfig({
      env: { XDG_CONFIG_HOME: configHome },
      config: { model: "not-a-provider-model" },
    });
    cleanupPaths.add(prepared.env.XDG_CONFIG_HOME);
    const runtimeConfig = JSON.parse(
      await fs.readFile(path.join(prepared.env.XDG_CONFIG_HOME, "opencode", "opencode.json"), "utf8"),
    ) as Record<string, unknown>;
    expect(runtimeConfig.provider).toBeUndefined();
    await prepared.cleanup();
  });

  it("injects gateway credentials without enabling permission skipping", async () => {
    const permission = { read: "allow", bash: "ask", edit: "deny" };
    const configHome = await makeConfigHome({ permission });
    const keyName = "PAPERCLIP_TEST_GATEWAY_KEY";
    process.env[keyName] = "fixture-gateway-marker";
    const providers = {
      litellm: {
        npm: "@ai-sdk/openai-compatible",
        options: { baseURL: "http://gateway.test/v1", apiKey: `{env:${keyName}}` },
        models: { "luna-6": {} },
      },
    };
    try {
      const prepared = await prepareOpenCodeRuntimeConfig({
        env: { XDG_CONFIG_HOME: configHome, PAPERCLIP_OPENCODE_PROVIDERS: JSON.stringify(providers) },
        config: { dangerouslySkipPermissions: false, model: "litellm/luna-6" },
      });
      cleanupPaths.add(prepared.env.XDG_CONFIG_HOME);
      const runtimeConfig = JSON.parse(await fs.readFile(
        path.join(prepared.env.XDG_CONFIG_HOME, "opencode", "opencode.json"), "utf8",
      ));
      expect(runtimeConfig.permission).toEqual(permission);
      expect(runtimeConfig.provider.litellm.options.apiKey).toBe("fixture-gateway-marker");
      expect(prepared.env[keyName]).toBeUndefined();
      expect(prepared.notes.some((n) => n.includes("permission=allow"))).toBe(false);
      await prepared.cleanup();
    } finally {
      delete process.env[keyName];
    }
  });

  it("respects explicit opt-out", async () => {
    const configHome = await makeConfigHome();
    const prepared = await prepareOpenCodeRuntimeConfig({
      env: { XDG_CONFIG_HOME: configHome },
      config: { dangerouslySkipPermissions: false },
    });

    expect(prepared.env).toEqual({ XDG_CONFIG_HOME: configHome });
    expect(prepared.notes).toEqual([]);
    await prepared.cleanup();
  });
});
