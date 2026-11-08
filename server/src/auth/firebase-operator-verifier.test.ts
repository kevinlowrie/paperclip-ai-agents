import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createFirebaseOperatorVerifier,
  createProductionFirebaseOperatorVerifier,
  FirebaseOperatorVerificationError,
} from "./firebase-operator-verifier.js";

const nowMs = Date.UTC(2026, 10, 8, 12, 0, 0);
const nowSeconds = Math.floor(nowMs / 1000);
const projectId = "thl-pclipd-api";
const token = "synthetic.firebase.id-token";

function claims(overrides: Record<string, unknown> = {}) {
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
    firebase: {
      sign_in_provider: "google.com",
      second_factor_identifier: "token-factor-id",
      ...((overrides.firebase as Record<string, unknown> | undefined) ?? {}),
    },
    ...overrides,
  };
}

function user(overrides: Record<string, unknown> = {}) {
  return {
    uid: "operator-uid",
    disabled: false,
    email: "operator@example.test",
    emailVerified: true,
    tenantId: undefined,
    tokensValidAfterTime: new Date(nowMs - 10_000).toISOString(),
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

function expectSafeFailure(promise: Promise<unknown>, status: 401 | 503) {
  return promise.then(
    () => {
      throw new Error("expected a safe Firebase verification failure");
    },
    (error: unknown) => {
      expect(error).toBeInstanceOf(FirebaseOperatorVerificationError);
      expect(error).toMatchObject({ status });
      expect(String(error)).not.toContain(token);
      expect(String(error)).not.toContain("provider-secret");
    },
  });
}

afterEach(() => {
  vi.unstubAllEnvs();
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

  it.each([
    ["wrong audience", { aud: "other-project" }],
    ["wrong issuer", { iss: "https://securetoken.google.com/other-project" }],
    ["subject and uid mismatch", { uid: "another-uid" }],
    ["missing subject", { sub: "" }],
    ["unverified email", { email_verified: false }],
    ["wrong provider", { firebase: { sign_in_provider: "password" } }],
    ["missing firebase claims", { firebase: undefined }],
    ["missing auth time", { auth_time: undefined }],
    ["non-integer auth time", { auth_time: nowSeconds - 1.5 }],
    ["auth time after token issue", { auth_time: nowSeconds - 20, iat: nowSeconds - 30 }],
    ["auth older than five minutes", { auth_time: nowSeconds - 301 }],
    ["auth time in the future", { auth_time: nowSeconds + 1 }],
    ["issue time in the future", { iat: nowSeconds + 1 }],
    ["expired token", { exp: nowSeconds }],
    ["non-numeric expiry", { exp: "later" }],
    ["padded factor identifier", { firebase: { second_factor_identifier: " factor " } }],
    ["oversized factor identifier", { firebase: { second_factor_identifier: "x".repeat(129) } }],
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
    ["future revocation timestamp", { tokensValidAfterTime: new Date(nowMs + 1).toISOString() }],
    ["same-second revocation boundary", { tokensValidAfterTime: new Date((nowSeconds - 120) * 1000).toISOString() }],
    ["no TOTP factors", { multiFactor: { enrolledFactors: [] } }],
    ["duplicate TOTP factor pair", { multiFactor: { enrolledFactors: [
      { factorId: "totp", uid: "same-factor" },
      { factorId: "totp", uid: "same-factor" },
    ] } }],
    ["malformed TOTP factor", { multiFactor: { enrolledFactors: [{ factorId: "phone", uid: "factor" }] } }],
    ["blank TOTP uid", { multiFactor: { enrolledFactors: [{ factorId: "totp", uid: "  " }] } }],
  ])("rejects an ineligible current account: %s", async (_label, override) => {
    const { verifier } = makeVerifier({ user: override });
    await expectSafeFailure(verifier.verify(token), 401);
  });

  it("requires a Google provider binding to the verified email", async () => {
    const { verifier } = makeVerifier({ user: { providerData: [
      { providerId: "google.com", uid: "google-subject", email: "other@example.test" },
    ] } });
    await expectSafeFailure(verifier.verify(token), 401);
  });

  it("trims and accepts printable factor identifiers while returning no raw claims", async () => {
    const { verifier } = makeVerifier({ claims: { firebase: { second_factor_identifier: " factor-1 " } } });
    const proof = await verifier.verify(token);
    expect(proof).not.toHaveProperty("secondFactorIdentifier");
    expect(proof).not.toHaveProperty("email");
    expect(proof).not.toHaveProperty("claims");
  });

  it("classifies SDK revocation as an invalid identity and provider outages as unavailable", async () => {
    await expectSafeFailure(makeVerifier({ reject: Object.assign(new Error("provider-secret"), { code: "auth/id-token-revoked" }) }).verifier.verify(token), 401);
    await expectSafeFailure(makeVerifier({ reject: Object.assign(new Error("provider-secret"), { code: "auth/internal-error" }) }).verifier.verify(token), 503);
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
  });

  it("checks for an emulator again before SDK calls", async () => {
    vi.stubEnv("FIREBASE_AUTH_EMULATOR_HOST", "");
    const verifier = createProductionFirebaseOperatorVerifier();
    vi.stubEnv("FIREBASE_AUTH_EMULATOR_HOST", "localhost:9099");
    await expectSafeFailure(verifier.verify(token), 503);
  });
});
