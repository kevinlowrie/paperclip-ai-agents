import { afterEach, describe, expect, it, vi } from "vitest";
import { createProductionFirebaseOperatorIdentityDirectory } from "./firebase-operator-verifier.js";

const firebaseAdminMocks = vi.hoisted(() => {
  const auth = { getUser: vi.fn() };
  return {
    auth,
    getApps: vi.fn(() => []),
    initializeApp: vi.fn((_options?: Record<string, unknown>, _name?: string) => ({
      name: "synthetic-paperclip-app",
      options: { projectId: "thl-pclipd-api" },
    })),
    getAuth: vi.fn(() => auth),
    applicationDefault: vi.fn(() => ({ credentialMarker: "inert-adc" })),
    cert: vi.fn(() => { throw new Error("service account credentials must not be read"); }),
  };
});

vi.mock("firebase-admin/app", () => ({
  getApps: firebaseAdminMocks.getApps,
  initializeApp: firebaseAdminMocks.initializeApp,
  applicationDefault: firebaseAdminMocks.applicationDefault,
  cert: firebaseAdminMocks.cert,
}));
vi.mock("firebase-admin/auth", () => ({ getAuth: firebaseAdminMocks.getAuth }));

const NOW = Date.UTC(2026, 10, 8, 12, 0, 0);

function eligibleUser(overrides: Record<string, unknown> = {}) {
  return {
    uid: "operator-uid",
    disabled: false,
    emailVerified: true,
    tenantId: undefined,
    tokensValidAfterTime: new Date(NOW - 10_000).toUTCString(),
    providerData: [{ providerId: "google.com", uid: "google-subject" }],
    multiFactor: { enrolledFactors: [{ factorId: "totp", uid: "totp-factor" }] },
    ...overrides,
  };
}

afterEach(() => {
  vi.useRealTimers();
  vi.setSystemTime();
  firebaseAdminMocks.getApps.mockReset().mockReturnValue([]);
  firebaseAdminMocks.initializeApp.mockReset().mockReturnValue({
    name: "synthetic-paperclip-app",
    options: { projectId: "thl-pclipd-api" },
  });
  firebaseAdminMocks.getAuth.mockReset().mockReturnValue(firebaseAdminMocks.auth);
  firebaseAdminMocks.applicationDefault.mockClear();
  firebaseAdminMocks.cert.mockClear();
  firebaseAdminMocks.auth.getUser.mockReset();
});

describe("production Firebase operator identity directory", () => {
  it("uses only the fixed project and returns a minimal current UID lookup", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
    firebaseAdminMocks.auth.getUser.mockResolvedValue(eligibleUser());

    const directory = createProductionFirebaseOperatorIdentityDirectory();
    await expect(directory.lookup("operator-uid")).resolves.toEqual({
      projectId: "thl-pclipd-api",
      uid: "operator-uid",
      checkedAtMs: NOW,
    });

    expect(firebaseAdminMocks.initializeApp).toHaveBeenCalledExactlyOnceWith(
      { credential: { credentialMarker: "inert-adc" }, projectId: "thl-pclipd-api" },
      expect.any(String),
    );
    expect(firebaseAdminMocks.auth.getUser).toHaveBeenCalledExactlyOnceWith("operator-uid");
    expect(firebaseAdminMocks.cert).not.toHaveBeenCalled();
  });

  it.each([
    ["UID mismatch", { uid: "different-uid" }],
    ["disabled user", { disabled: true }],
    ["unverified email", { emailVerified: false }],
    ["tenant namespace", { tenantId: "tenant-a" }],
    ["missing Google provider", { providerData: [] }],
    ["missing TOTP enrollment", { multiFactor: { enrolledFactors: [] } }],
  ])("rejects a non-current or ineligible directory record: %s", async (_label, overrides) => {
    firebaseAdminMocks.auth.getUser.mockResolvedValue(eligibleUser(overrides));
    const directory = createProductionFirebaseOperatorIdentityDirectory();
    await expect(directory.lookup("operator-uid")).rejects.toMatchObject({ status: 401 });
  });

  it("maps a provider outage to a safe unavailable error", async () => {
    firebaseAdminMocks.auth.getUser.mockRejectedValue(new Error("provider-secret-detail"));
    const directory = createProductionFirebaseOperatorIdentityDirectory();
    let caught: unknown;
    try {
      await directory.lookup("operator-uid");
    } catch (error) {
      caught = error;
    }
    expect(caught).toMatchObject({ status: 503 });
    expect(String(caught)).not.toContain("provider-secret-detail");
  });
});
