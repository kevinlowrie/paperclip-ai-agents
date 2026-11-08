import { applicationDefault, getApps, initializeApp, type App } from "firebase-admin/app";
import { getAuth, type Auth, type UserRecord } from "firebase-admin/auth";

const PROJECT_ID = "thl-pclipd-api";
const APP_NAME = "paperclip-firebase-operator-verifier-v1";
const MAX_FRESH_AUTH_AGE_SECONDS = 300;
const INVALID_AUTH_CODES = new Set([
  "auth/argument-error",
  "auth/id-token-expired",
  "auth/id-token-revoked",
  "auth/invalid-id-token",
  "auth/user-disabled",
  "auth/user-not-found",
]);

export class FirebaseOperatorVerificationError extends Error {
  readonly status: 401 | 503;

  constructor(status: 401 | 503) {
    super(status === 401 ? "Firebase operator identity is not eligible" : "Firebase operator verification is unavailable");
    this.name = "FirebaseOperatorVerificationError";
    this.status = status;
  }
}

export type FirebaseOperatorProof = {
  projectId: typeof PROJECT_ID;
  uid: string;
  authTimeSeconds: number;
  checkedAtMs: number;
  totpFactors: Array<{ factorId: "totp"; uid: string }>;
};

type AuthClient = {
  verifyIdToken(token: string, checkRevoked?: boolean): Promise<unknown>;
  getUser(uid: string): Promise<unknown>;
};
type VerificationOptions = { auth: AuthClient; now?: () => number };
type IdentityClaims = Record<string, unknown>;
type UserLike = Pick<UserRecord, "uid" | "disabled" | "emailVerified" | "tenantId" | "tokensValidAfterTime" | "providerData" | "multiFactor">;

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function deny(): never {
  throw new FirebaseOperatorVerificationError(401);
}

function unavailable(): never {
  throw new FirebaseOperatorVerificationError(503);
}

function classifyProviderError(error: unknown): never {
  const code = record(error) && typeof error.code === "string" ? error.code : undefined;
  if (code && INVALID_AUTH_CODES.has(code)) deny();
  unavailable();
}

function assertEmulatorOff(): void {
  const host = process.env.FIREBASE_AUTH_EMULATOR_HOST;
  if (typeof host === "string" && host.length > 0) unavailable();
}

function validUid(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 128;
}

function validTime(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function parseUtcTimestamp(value: unknown): number | null {
  if (typeof value !== "string") return null;
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) return null;
  const date = new Date(ms);
  if (value !== date.toUTCString() && value !== date.toISOString()) return null;
  return ms;
}

function assertFreshAndLive(claims: IdentityClaims, nowMs: number): { uid: string; authTimeSeconds: number } {
  if (!Number.isFinite(nowMs) || nowMs < 0) deny();
  const nowSeconds = Math.floor(nowMs / 1000);
  const firebase = claims.firebase;
  if (!record(firebase)) deny();
  if (Object.hasOwn(firebase, "tenant")) deny();

  const uid = claims.sub;
  const authTimeSeconds = claims.auth_time;
  const issuedAt = claims.iat;
  const expiresAt = claims.exp;
  if (!validUid(uid) || claims.uid !== uid) deny();
  if (!validTime(authTimeSeconds) || !validTime(issuedAt) || !validTime(expiresAt)) deny();
  if (authTimeSeconds > issuedAt || authTimeSeconds * 1000 > nowMs || nowMs - authTimeSeconds * 1000 > MAX_FRESH_AUTH_AGE_SECONDS * 1000) deny();
  if (issuedAt > nowSeconds || expiresAt <= nowSeconds || expiresAt <= issuedAt) deny();
  if (claims.aud !== PROJECT_ID || claims.iss !== `https://securetoken.google.com/${PROJECT_ID}`) deny();
  if (claims.email_verified !== true) deny();
  if (firebase.sign_in_provider !== "google.com" || firebase.sign_in_second_factor !== "totp") deny();
  const factorIdentifier = firebase.second_factor_identifier;
  if (typeof factorIdentifier !== "string" || factorIdentifier.length < 1 || factorIdentifier.length > 128 || factorIdentifier.trim() !== factorIdentifier || !/^[\x20-\x7e]+$/.test(factorIdentifier)) deny();
  return { uid, authTimeSeconds };
}

function currentTotpFactors(user: UserLike, uid: string, authTimeSeconds: number, nowMs: number): Array<{ factorId: "totp"; uid: string }> {
  if (user.uid !== uid || user.disabled !== false || user.emailVerified !== true) deny();
  if (user.tenantId !== undefined && user.tenantId !== null) deny();
  if (!Array.isArray(user.providerData) || !user.providerData.some((provider) =>
    record(provider) && provider.providerId === "google.com" && validUid(provider.uid))) deny();

  const validAfterMs = parseUtcTimestamp(user.tokensValidAfterTime);
  if (validAfterMs === null || validAfterMs > nowMs || authTimeSeconds * 1000 <= validAfterMs) deny();

  const enrolled = user.multiFactor?.enrolledFactors;
  if (!Array.isArray(enrolled)) deny();
  const factors: Array<{ factorId: "totp"; uid: string }> = [];
  const seen = new Set<string>();
  for (const factor of enrolled) {
    if (!record(factor) || factor.factorId !== "totp") continue;
    if (!validUid(factor.uid) || factor.uid.trim() !== factor.uid) deny();
    if (seen.has(factor.uid)) deny();
    seen.add(factor.uid);
    factors.push({ factorId: "totp", uid: factor.uid });
  }
  if (factors.length === 0) deny();
  factors.sort((a, b) => a.uid < b.uid ? -1 : a.uid > b.uid ? 1 : 0);
  return factors;
}

function assertProof(proof: unknown, nowMs: number): asserts proof is FirebaseOperatorProof {
  if (!record(proof) || proof.projectId !== PROJECT_ID || !validUid(proof.uid) || !validTime(proof.authTimeSeconds) || !validTime(proof.checkedAtMs)) deny();
  if (!Number.isFinite(nowMs) || nowMs < 0 || proof.checkedAtMs > nowMs || proof.authTimeSeconds * 1000 > proof.checkedAtMs) deny();
  if (!Array.isArray(proof.totpFactors) || proof.totpFactors.length === 0) deny();
  let previous = "";
  for (const factor of proof.totpFactors) {
    if (!record(factor) || factor.factorId !== "totp" || !validUid(factor.uid) || factor.uid.trim() !== factor.uid) deny();
    if (previous && previous >= factor.uid) deny();
    previous = factor.uid;
  }
}

async function lookupUser(auth: AuthClient, uid: string): Promise<UserLike> {
  let user: unknown;
  try {
    user = await auth.getUser(uid);
  } catch (error) {
    assertEmulatorOff();
    classifyProviderError(error);
  }
  if (!record(user)) deny();
  return user as UserLike;
}

export function createFirebaseOperatorVerifier({ auth, now = Date.now }: VerificationOptions) {
  return {
    async verify(token: string): Promise<FirebaseOperatorProof> {
      assertEmulatorOff();
      if (typeof token !== "string" || token.length === 0) deny();
      let decodedClaims: unknown;
      try {
        decodedClaims = await auth.verifyIdToken(token, true);
      } catch (error) {
        assertEmulatorOff();
        classifyProviderError(error);
      }
      assertEmulatorOff();
      if (!record(decodedClaims)) deny();
      const claims = decodedClaims as IdentityClaims;
      const initialNow = now();
      const { uid, authTimeSeconds } = assertFreshAndLive(claims, initialNow);
      assertEmulatorOff();
      const lookupStartedAtMs = now();
      const user = await lookupUser(auth, uid);
      assertEmulatorOff();
      const finalNow = now();
      // Re-evaluate freshness and expiry after both asynchronous SDK calls.
      const verifiedIdentity = assertFreshAndLive(claims, finalNow);
      if (verifiedIdentity.uid !== uid || verifiedIdentity.authTimeSeconds !== authTimeSeconds) deny();
      const totpFactors = currentTotpFactors(user, uid, authTimeSeconds, lookupStartedAtMs);
      return { projectId: PROJECT_ID, uid, authTimeSeconds, checkedAtMs: lookupStartedAtMs, totpFactors };
    },

    async checkUser(proof: unknown): Promise<FirebaseOperatorProof> {
      assertEmulatorOff();
      const lookupStartedAtMs = now();
      assertProof(proof, lookupStartedAtMs);
      const user = await lookupUser(auth, proof.uid);
      assertEmulatorOff();
      const checkedAtMs = lookupStartedAtMs;
      const totpFactors = currentTotpFactors(user, proof.uid, proof.authTimeSeconds, checkedAtMs);
      if (JSON.stringify(totpFactors) !== JSON.stringify(proof.totpFactors)) deny();
      return { projectId: PROJECT_ID, uid: proof.uid, authTimeSeconds: proof.authTimeSeconds, checkedAtMs, totpFactors };
    },
  };
}

function productionApp(): App {
  assertEmulatorOff();
  try {
    const existing = getApps().find((app) => app.name === APP_NAME);
    if (existing) {
      if (existing.options.projectId !== PROJECT_ID) unavailable();
      return existing;
    }
    return initializeApp({ credential: applicationDefault(), projectId: PROJECT_ID }, APP_NAME);
  } catch {
    unavailable();
  }
}

export function createProductionFirebaseOperatorVerifier() {
  const app = productionApp();
  let auth: Auth;
  try {
    auth = getAuth(app);
  } catch {
    unavailable();
  }
  return createFirebaseOperatorVerifier({
    auth: {
      verifyIdToken: (token, checkRevoked) => {
        assertEmulatorOff();
        return auth.verifyIdToken(token, checkRevoked);
      },
      getUser: (uid) => {
        assertEmulatorOff();
        return auth.getUser(uid);
      },
    },
  });
}

export type FirebaseOperatorIdentity = {
  projectId: typeof PROJECT_ID;
  uid: string;
  checkedAtMs: number;
};

/**
 * Current provider-side identity lookup for reviewed local account binding.
 * This deliberately does not require TOTP enrollment: TOTP is checked by the
 * interactive session verifier, while provisioning only proves the Google
 * identity's current UID and eligibility.
 */
export function createProductionFirebaseOperatorIdentityDirectory() {
  const app = productionApp();
  let auth: Auth;
  try {
    auth = getAuth(app);
  } catch {
    unavailable();
  }
  return {
    async lookup(uid: string): Promise<FirebaseOperatorIdentity> {
      assertEmulatorOff();
      if (!validUid(uid) || uid.trim() !== uid) deny();
      const lookupStartedAtMs = Date.now();
      let user: unknown;
      try {
        assertEmulatorOff();
        user = await auth.getUser(uid);
      } catch (error) {
        assertEmulatorOff();
        classifyProviderError(error);
      }
      assertEmulatorOff();
      if (!record(user) || user.uid !== uid || user.disabled !== false || user.emailVerified !== true) deny();
      if (user.tenantId !== undefined && user.tenantId !== null) deny();
      if (!Array.isArray(user.providerData) || !user.providerData.some((provider) =>
        record(provider) && provider.providerId === "google.com" && validUid(provider.uid))) deny();
      return { projectId: PROJECT_ID, uid, checkedAtMs: lookupStartedAtMs };
    },
  };
}
