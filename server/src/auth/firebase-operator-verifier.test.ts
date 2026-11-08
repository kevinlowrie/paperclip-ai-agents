import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createFirebaseOperatorVerifier,
  createProductionFirebaseOperatorVerifier,
  FirebaseOperatorVerificationError,
} from "./firebase-operator-verifier.js";

const firebaseAdminMocks = vi.hoisted(() => {
  const auth = {
    verifyIdToken: vi.fn(),
    getUser: vi.fn(),
  };
  return {
    getApps: vi.fn(() => []),
    initializeApp: vi.fn((_options?: Record<string, unknown>, _name?: string) => ({ name: "synthetic-paperclip-app" })),
    getAuth: vi.fn(() => auth),
    applicationDefault: vi.fn(() => ({ credentialMarker: "synthetic-adc-credential" })),
    cert: vi.fn(() => { throw new Error("credentials must not be accessed by this test"); }),
    auth,
  };
});

vi.mock("firebase-admin/app", () => ({
  getApps: firebaseAdminMocks.getApps,
  initializeApp: firebaseAdminMocks.initializeApp,
  applicationDefault: firebaseAdminMocks.applicationDefault,
  cert: firebaseAdminMocks.cert,
}));

vi.mock("firebase-admin/auth", () => ({ getAuth: firebaseAdminMocks.getAuth }));

const nowMs = Date.UTC(2026, 10, 8, 12, 0, 0);
const nowSeconds = Math.floor(nowMs / 1000);
const projectId = "thl-pclipd-api";
const token = "synthetic.firebase.id-token";

function claims(overrides: Record<string, unknown> = {}) {
  const baseFirebase = {
    sign_in_provider: "google.com",
    sign_in_second_factor: "totp",
    second_factor_identifier: "token-factor-id",
  };
  const firebaseOverride = Object.hasOwn(overrides, "firebase") ? overrides.firebase : undefined;
  const firebase = !Object.hasOwn(overrides, "firebase")
    ? baseFirebase
    : firebaseOverride && typeof firebaseOverride === "object"
      ? { ...baseFirebase, ...(firebaseOverride as Record<string, unknown>) }
      : firebaseOverride;
  const { firebase: _ignoredFirebase, ...topLevelOverrides } = overrides;
  return {
    aud: projectId,
    iss: `https://securetoken.google.com/${projectId}`,
    sub: "operator-uid",
    uid: "operator-uid",
    email: "operator@example.test",
    email_verified: true,
    auth_time: nowSeconds - 120,
    iat: nowSeconds - 60,
    exp: nowSeconds + 300,
    firebase,
    ...topLevelOverrides,
  };
}

function user(overrides: Record<string, unknown> = {}) {
  return {
    uid: "operator-uid",
    disabled: false,
    email: "operator@example.test",
    emailVerified: true,
    tenantId: undefined,
    tokensValidAfterTime: new Date((nowSeconds - 121) * 1000).toUTCString(),
    providerData: [
      { providerId: "google.com", uid: "google-subject", email: "operator@example.test" },
    ],
    multiFactor: {
      enrolledFactors: [
        { factorId: "totp", uid: "enrolled-factor-b" },
        { factorId: "totp", uid: "enrolled-factor-a" },
      ],
    },
    ...overrides,
  };
}

function makeVerifier(options: { claims?: Record<string, unknown>; user?: Record<string, unknown>; reject?: unknown } = {}) {
  const auth = {
    verifyIdToken: vi.fn(async () => {
      if (options.reject) throw options.reject;
      return claims(options.claims);
    }),
    getUser: vi.fn(async () => user(options.user)),
  };
  return {
    auth,
    verifier: createFirebaseOperatorVerifier({ auth, now: () => nowMs }),
  };
}

async function expectSafeFailure(promise: Promise<unknown>, status: 401 | 503) {
  let error: unknown;
  try {
    await promise;
  } catch (caught) {
    error = caught;
  }
  expect(error).toBeInstanceOf(FirebaseOperatorVerificationError);
  expect(error).toMatchObject({ status });
  expect(String(error)).not.toContain(token);
  expect(String(error)).not.toContain("provider-secret");
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllEnvs();
  firebaseAdminMocks.getApps.mockReset().mockReturnValue([]);
  firebaseAdminMocks.initializeApp.mockReset().mockReturnValue({ name: "synthetic-paperclip-app" });
  firebaseAdminMocks.getAuth.mockReset().mockReturnValue(firebaseAdminMocks.auth);
  firebaseAdminMocks.applicationDefault.mockClear();
  firebaseAdminMocks.cert.mockClear();
  firebaseAdminMocks.auth.verifyIdToken.mockReset();
  firebaseAdminMocks.auth.getUser.mockReset();
});

describe("Firebase operator verifier", () => {
  it("verifies with revocation checking and returns a minimal proof with canonical TOTP factors", async () => {
    const { auth, verifier } = makeVerifier();
    const proof = await verifier.verify(token);

    expect(auth.verifyIdToken).toHaveBeenCalledExactlyOnceWith(token, true);
    expect(auth.getUser).toHaveBeenCalledExactlyOnceWith("operator-uid");
    expect(proof).toEqual({
      projectId,
      uid: "operator-uid",
      authTimeSeconds: nowSeconds - 120,
      checkedAtMs: nowMs,
      totpFactors: [
        { factorId: "totp", uid: "enrolled-factor-a" },
        { factorId: "totp", uid: "enrolled-factor-b" },
      ],
    });
    expect(JSON.stringify(proof)).not.toContain(token);
    expect(JSON.stringify(proof)).not.toContain("operator@example.test");
  });

  it("does not require the token second-factor identifier to equal an enrolled factor uid", async () => {
    const { verifier } = makeVerifier();
    await expect(verifier.verify(token)).resolves.toMatchObject({
      totpFactors: expect.arrayContaining([{ factorId: "totp", uid: "enrolled-factor-a" }]),
    });
  });

  it("accepts the exact five-minute auth-time boundary", async () => {
    const { verifier } = makeVerifier({
      claims: { auth_time: nowSeconds - 300 },
      user: { tokensValidAfterTime: new Date((nowSeconds - 301) * 1000).toISOString() },
    });
    await expect(verifier.verify(token)).resolves.toMatchObject({ authTimeSeconds: nowSeconds - 300 });
  });

  it("rejects auth that exceeds five minutes by a fractional second", async () => {
    const auth = {
      verifyIdToken: vi.fn(async () => claims({ auth_time: nowSeconds - 300 })),
      getUser: vi.fn(async () => user()),
    };
    const verifier = createFirebaseOperatorVerifier({ auth, now: () => nowMs + 999 });
    await expectSafeFailure(verifier.verify(token), 401);
  });

  it.each([null, "not-claims", []])("rejects malformed SDK claims safely: %s", async (decoded) => {
    const verifier = createFirebaseOperatorVerifier({
      auth: { verifyIdToken: vi.fn(async () => decoded), getUser: vi.fn(async () => user()) },
      now: () => nowMs,
    });
    await expectSafeFailure(verifier.verify(token), 401);
  });

  it.each([null, "not-a-user", []])("rejects malformed SDK user records safely: %s", async (currentUser) => {
    const verifier = createFirebaseOperatorVerifier({
      auth: { verifyIdToken: vi.fn(async () => claims()), getUser: vi.fn(async () => currentUser) },
      now: () => nowMs,
    });
    await expectSafeFailure(verifier.verify(token), 401);
  });

  it("accepts a non-ASCII Firebase UID within the supported length", async () => {
    const uid = "opérator-uid";
    const { verifier } = makeVerifier({ claims: { sub: uid, uid }, user: { uid } });
    await expect(verifier.verify(token)).resolves.toMatchObject({ uid });
  });

  it.each([
    ["wrong audience", { aud: "other-project" }],
    ["wrong issuer", { iss: "https://securetoken.google.com/other-project" }],
    ["subject and uid mismatch", { uid: "another-uid" }],
    ["missing subject", { sub: "" }],
    ["absent subject", { sub: undefined }],
    ["unverified email", { email_verified: false }],
    ["wrong provider", { firebase: { sign_in_provider: "password" } }],
    ["missing second-factor method", { firebase: { sign_in_second_factor: undefined } }],
    ["phone second-factor method", { firebase: { sign_in_second_factor: "phone" } }],
    ["tenant firebase namespace", { firebase: { tenant: "" } }],
    ["null firebase tenant namespace", { firebase: { tenant: null } }],
    ["missing firebase claims", { firebase: undefined }],
    ["missing auth time", { auth_time: undefined }],
    ["non-integer auth time", { auth_time: nowSeconds - 1.5 }],
    ["boolean auth time", { auth_time: true }],
    ["auth time after token issue", { auth_time: nowSeconds - 20, iat: nowSeconds - 30 }],
    ["auth older than five minutes", { auth_time: nowSeconds - 301 }],
    ["auth time in the future", { auth_time: nowSeconds + 1 }],
    ["issue time in the future", { iat: nowSeconds + 1 }],
    ["string issue time", { iat: String(nowSeconds - 60) }],
    ["boolean issue time", { iat: true }],
    ["expired token", { exp: nowSeconds }],
    ["non-numeric expiry", { exp: "later" }],
    ["missing factor identifier", { firebase: { second_factor_identifier: undefined } }],
    ["padded factor identifier", { firebase: { second_factor_identifier: " factor " } }],
    ["non-printable factor identifier", { firebase: { second_factor_identifier: "factor\n" } }],
    ["oversized factor identifier", { firebase: { second_factor_identifier: "x".repeat(129) } }],
    ["oversized subject", { sub: "u".repeat(129) }],
  ])("rejects malformed identity proof: %s", async (_label, override) => {
    const { verifier } = makeVerifier({ claims: override });
    await expectSafeFailure(verifier.verify(token), 401);
  });

  it.each([
    ["disabled account", { disabled: true }],
    ["unverified current email", { emailVerified: false }],
    ["UID mismatch", { uid: "different-uid" }],
    ["missing Google binding", { providerData: [] }],
    ["tenant namespace", { tenantId: "tenant-a" }],
    ["invalid revocation timestamp", { tokensValidAfterTime: "not-a-date" }],
    ["malformed normalized calendar timestamp", { tokensValidAfterTime: "Mon, 32 Nov 2026 12:00:00 GMT" }],
    ["missing revocation timestamp", { tokensValidAfterTime: undefined }],
    ["future revocation timestamp", { tokensValidAfterTime: new Date(nowMs + 1).toISOString() }],
    ["same-second revocation boundary", { tokensValidAfterTime: new Date((nowSeconds - 120) * 1000).toISOString() }],
    ["no TOTP factors", { multiFactor: { enrolledFactors: [] } }],
    ["duplicate TOTP factor pair", { multiFactor: { enrolledFactors: [
      { factorId: "totp", uid: "same-factor" },
      { factorId: "totp", uid: "same-factor" },
    ] } }],
    ["phone-only enrollment", { multiFactor: { enrolledFactors: [{ factorId: "phone", uid: "factor" }] } }],
    ["blank TOTP uid", { multiFactor: { enrolledFactors: [{ factorId: "totp", uid: "  " }] } }],
  ])("rejects an ineligible current account: %s", async (_label, override) => {
    const { verifier } = makeVerifier({ user: override });
    await expectSafeFailure(verifier.verify(token), 401);
  });

  it("requires a Google provider binding without requiring its display email to match", async () => {
    const { verifier } = makeVerifier({ user: { providerData: [
      { providerId: "google.com", uid: "google-subject", email: "other@example.test" },
    ] } });
    await expect(verifier.verify(token)).resolves.toMatchObject({ uid: "operator-uid" });
  });

  it("snapshots TOTP factors while ignoring additional phone factors", async () => {
    const { verifier } = makeVerifier({ user: { multiFactor: { enrolledFactors: [
      { factorId: "phone", uid: "phone-factor" },
      { factorId: "totp", uid: "totp-factor" },
    ] } } });
    await expect(verifier.verify(token)).resolves.toMatchObject({
      totpFactors: [{ factorId: "totp", uid: "totp-factor" }],
    });
  });

  it("accepts an already-trimmed printable factor identifier while returning no raw claims", async () => {
    const { verifier } = makeVerifier({ claims: { firebase: { second_factor_identifier: "factor-1" } } });
    const proof = await verifier.verify(token);
    expect(proof).not.toHaveProperty("secondFactorIdentifier");
    expect(proof).not.toHaveProperty("email");
    expect(proof).not.toHaveProperty("claims");
  });

  it("classifies SDK revocation as an invalid identity and provider outages as unavailable", async () => {
    await expectSafeFailure(makeVerifier({ reject: Object.assign(new Error("provider-secret"), { code: "auth/id-token-revoked" }) }).verifier.verify(token), 401);
    await expectSafeFailure(makeVerifier({ reject: Object.assign(new Error("provider-secret"), { code: "auth/internal-error" }) }).verifier.verify(token), 503);
  });

  it("rejects an emulator enabled while ID-token verification is in flight", async () => {
    vi.stubEnv("FIREBASE_AUTH_EMULATOR_HOST", "");
    const auth = {
      verifyIdToken: vi.fn(async () => {
        vi.stubEnv("FIREBASE_AUTH_EMULATOR_HOST", "localhost:9099");
        return claims();
      }),
      getUser: vi.fn(async () => user()),
    };
    const verifier = createFirebaseOperatorVerifier({ auth, now: () => nowMs });
    await expectSafeFailure(verifier.verify(token), 503);
    expect(auth.getUser).not.toHaveBeenCalled();
  });

  it("rechecks the authoritative user every time and rejects changed factors", async () => {
    const auth = {
      verifyIdToken: vi.fn(async () => claims()),
      getUser: vi.fn()
        .mockResolvedValueOnce(user())
        .mockResolvedValueOnce(user({ multiFactor: { enrolledFactors: [{ factorId: "totp", uid: "changed" }] } })),
    };
    const verifier = createFirebaseOperatorVerifier({ auth, now: () => nowMs });
    const proof = await verifier.verify(token);
    await expectSafeFailure(verifier.checkUser(proof), 401);
    expect(auth.getUser).toHaveBeenCalledTimes(2);
  });

  it("returns a refreshed checkedAt timestamp only after the user recheck succeeds", async () => {
    let clock = nowMs;
    const auth = { verifyIdToken: vi.fn(async () => claims()), getUser: vi.fn(async () => user()) };
    const verifier = createFirebaseOperatorVerifier({ auth, now: () => clock });
    const proof = await verifier.verify(token);
    clock += 1_000;
    await expect(verifier.checkUser(proof)).resolves.toMatchObject({ checkedAtMs: nowMs + 1_000 });
  });

  it("does not reapply the five-minute fresh-login limit during session user revalidation", async () => {
    let clock = nowMs;
    const auth = { verifyIdToken: vi.fn(async () => claims()), getUser: vi.fn(async () => user()) };
    const verifier = createFirebaseOperatorVerifier({ auth, now: () => clock });
    const proof = await verifier.verify(token);
    clock += 30 * 60 * 1_000;
    await expect(verifier.checkUser(proof)).resolves.toMatchObject({
      uid: "operator-uid",
      checkedAtMs: clock,
    });
  });

  it("rejects post-verification revocation on every user check", async () => {
    const auth = { verifyIdToken: vi.fn(async () => claims()), getUser: vi.fn(async () => user()) };
    const verifier = createFirebaseOperatorVerifier({ auth, now: () => nowMs });
    const proof = await verifier.verify(token);
    auth.getUser.mockResolvedValueOnce(user({ tokensValidAfterTime: new Date(nowMs).toISOString() }));
    await expectSafeFailure(verifier.checkUser(proof), 401);
  });
});

describe("production Firebase verifier", () => {
  it.each(["true", "1", "localhost", "127.0.0.1"]) ("refuses emulator configuration %s at initialization", (emulator) => {
    vi.stubEnv("FIREBASE_AUTH_EMULATOR_HOST", emulator);
    expect(() => createProductionFirebaseOperatorVerifier()).toThrow(FirebaseOperatorVerificationError);
    expect(firebaseAdminMocks.initializeApp).not.toHaveBeenCalled();
    expect(firebaseAdminMocks.getAuth).not.toHaveBeenCalled();
  });

  it("refuses whitespace emulator configuration at initialization", () => {
    vi.stubEnv("FIREBASE_AUTH_EMULATOR_HOST", "   ");
    expect(() => createProductionFirebaseOperatorVerifier()).toThrow(FirebaseOperatorVerificationError);
    expect(firebaseAdminMocks.initializeApp).not.toHaveBeenCalled();
    expect(firebaseAdminMocks.getAuth).not.toHaveBeenCalled();
  });

  it("pins the production project and uses SDK revocation checking with synthetic ADC", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(nowMs);
    vi.stubEnv("FIREBASE_AUTH_EMULATOR_HOST", "");
    vi.stubEnv("FIREBASE_PROJECT_ID", "attacker-selected-project");
    firebaseAdminMocks.auth.verifyIdToken.mockResolvedValue(claims());
    firebaseAdminMocks.auth.getUser.mockResolvedValue(user());
    const verifier = createProductionFirebaseOperatorVerifier();
    await verifier.verify(token);
    expect(firebaseAdminMocks.initializeApp.mock.calls[0]?.[0]).toEqual(expect.objectContaining({ projectId }));
    expect(firebaseAdminMocks.auth.verifyIdToken).toHaveBeenCalledExactlyOnceWith(token, true);
    expect(firebaseAdminMocks.applicationDefault).toHaveBeenCalledExactlyOnceWith();
    expect(firebaseAdminMocks.initializeApp.mock.calls[0]?.[0]).toEqual(expect.objectContaining({
      credential: { credentialMarker: "synthetic-adc-credential" },
    }));
    expect(firebaseAdminMocks.cert).not.toHaveBeenCalled();
  });

  it("checks for an emulator again before SDK calls", async () => {
    vi.stubEnv("FIREBASE_AUTH_EMULATOR_HOST", "");
    firebaseAdminMocks.auth.verifyIdToken.mockResolvedValue(claims());
    firebaseAdminMocks.auth.getUser.mockResolvedValue(user());
    const verifier = createProductionFirebaseOperatorVerifier();
    vi.stubEnv("FIREBASE_AUTH_EMULATOR_HOST", "localhost:9099");
    await expectSafeFailure(verifier.verify(token), 503);
    expect(firebaseAdminMocks.auth.verifyIdToken).not.toHaveBeenCalled();
    expect(firebaseAdminMocks.auth.getUser).not.toHaveBeenCalled();
  });

  it("refuses whitespace emulator configuration after startup before SDK calls", async () => {
    vi.stubEnv("FIREBASE_AUTH_EMULATOR_HOST", "");
    firebaseAdminMocks.auth.verifyIdToken.mockResolvedValue(claims());
    firebaseAdminMocks.auth.getUser.mockResolvedValue(user());
    const verifier = createProductionFirebaseOperatorVerifier();
    vi.stubEnv("FIREBASE_AUTH_EMULATOR_HOST", "   ");
    await expectSafeFailure(verifier.verify(token), 503);
    expect(firebaseAdminMocks.auth.verifyIdToken).not.toHaveBeenCalled();
    expect(firebaseAdminMocks.auth.getUser).not.toHaveBeenCalled();
  });
});
