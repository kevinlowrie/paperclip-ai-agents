import { describe, expect, it } from "vitest";
import { sanitizeRemoteExecutionEnv } from "./remote-execution-env.js";

describe("sanitizeRemoteExecutionEnv", () => {
  it("omits unchanged inherited server values across arbitrary secret names", () => {
    const inherited = {
      DATABASE_URL: "server-database-url",
      SERVER_SEALING_KEY: "server-sealing-key",
      PROVIDER_TOKEN: "server-provider-token",
      x_CUSTOM_SECRET: "server-custom-secret",
      LANG: "en_US.UTF-8",
      TERM: "xterm-256color",
    };

    expect(
      sanitizeRemoteExecutionEnv(
        {
          DATABASE_URL: inherited.DATABASE_URL,
          SERVER_SEALING_KEY: inherited.SERVER_SEALING_KEY,
          PROVIDER_TOKEN: inherited.PROVIDER_TOKEN,
          X_CUSTOM_SECRET: inherited.x_CUSTOM_SECRET,
          LANG: inherited.LANG,
          TERM: inherited.TERM,
        },
        inherited,
      ),
    ).toEqual({ LANG: "en_US.UTF-8", TERM: "xterm-256color" });
  });

  it("matches inherited names case-insensitively", () => {
    expect(
      sanitizeRemoteExecutionEnv(
        { database_url: "inherited-database-url", pRoViDeR_tOkEn: "inherited-token" },
        { DATABASE_URL: "inherited-database-url", PROVIDER_TOKEN: "inherited-token" },
      ),
    ).toEqual({});
  });

  it("omits a value matching any inherited case-folded duplicate key", () => {
    expect(
      sanitizeRemoteExecutionEnv(
        { DATABASE_URL: "ambient-secret" },
        { DATABASE_URL: "different-value", database_url: "ambient-secret" },
      ),
    ).toEqual({});
  });

  it("preserves missing and intentionally different remote values", () => {
    expect(
      sanitizeRemoteExecutionEnv(
        {
          REMOTE_ONLY_SETTING: "remote-only",
          DATABASE_URL: "tenant-database-url",
          PAPERCLIP_API_TOKEN: "scoped-per-run-token",
          SSL_CERT_FILE: "/remote/pki/ca-bundle.crt",
          NODE_PATH: "/remote/runtime/node_modules",
        },
        {
          DATABASE_URL: "server-database-url",
          PAPERCLIP_API_TOKEN: "server-global-token",
          SSL_CERT_FILE: "/etc/ssl/certs/ca-certificates.crt",
          NODE_PATH: "/usr/local/lib/node_modules",
        },
      ),
    ).toEqual({
      REMOTE_ONLY_SETTING: "remote-only",
      DATABASE_URL: "tenant-database-url",
      PAPERCLIP_API_TOKEN: "scoped-per-run-token",
      SSL_CERT_FILE: "/remote/pki/ca-bundle.crt",
      NODE_PATH: "/remote/runtime/node_modules",
    });
  });

  it("keeps existing remote identity omission behavior", () => {
    expect(
      sanitizeRemoteExecutionEnv(
        {
          PATH: "/server/bin",
          HOME: "/remote/home",
          USER: "remote-agent",
          PWD: "/remote/workspace",
        },
        { PATH: "/server/bin", HOME: "/server/home", USER: "server-user" },
      ),
    ).toEqual({
      HOME: "/remote/home",
      USER: "remote-agent",
      PWD: "/remote/workspace",
    });
  });
});
