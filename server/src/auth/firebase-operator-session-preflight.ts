import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes } from "node:crypto";
import express, { type Request, type RequestHandler, type Response } from "express";
import { emitFirebaseOperatorPreflightDenial } from "./firebase-operator-session-observability.js";
import type { FirebaseOperatorAuditSink } from "./firebase-operator-session-observability.js";

const BEGIN = "/api/auth/firebase-session/begin";
const EXCHANGE = "/api/auth/firebase-session/exchange";
const PREFIX = "/api/auth/firebase-session";
const WINDOW_MS = 60_000;
const MAX_RATE_KEYS = 10_000;
type Provenance = { method: "POST"; path: typeof BEGIN | typeof EXCHANGE; origin: string; bodyBytes: number; nonce: string; request: Request };
const provenance = new AsyncLocalStorage<Provenance>();
const capturedLengths = new WeakMap<Request, number>();
type RateBucket = { start: number; count: number };

function reject(res: Response, status: number, reason: "bad_request" | "origin_denied" | "rate_limited", audit?: FirebaseOperatorAuditSink): void {
  emitFirebaseOperatorPreflightDenial(reason, audit);
  res.status(status).set("Cache-Control", "no-store").json({ error: status === 429 ? "Too many requests" : "Request rejected" });
}

function rawHeaderValues(req: Request, name: string): string[] {
  const result: string[] = [];
  for (let index = 0; index < req.rawHeaders.length; index += 2) {
    if (req.rawHeaders[index]?.toLowerCase() === name) result.push(req.rawHeaders[index + 1] ?? "");
  }
  return result;
}

function rawPath(req: Request): string {
  const url = req.originalUrl || req.url;
  const question = url.indexOf("?");
  return question < 0 ? url : url.slice(0, question);
}

function validOrigins(input: ReadonlySet<string>): Map<string, string> {
  if (!(input instanceof Set) || input.size === 0) throw new Error("Firebase session origins must be a finite nonempty set");
  const authorityMap = new Map<string, string>();
  for (const origin of input) {
    if (typeof origin !== "string") throw new Error("Invalid Firebase session origin");
    let parsed: URL;
    try { parsed = new URL(origin); } catch { throw new Error("Invalid Firebase session origin"); }
    if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash || parsed.origin !== origin) {
      throw new Error("Firebase session origins must be canonical HTTPS origins");
    }
    const authority = parsed.host.toLowerCase();
    if (authorityMap.has(authority)) throw new Error("Firebase session origins must have unique authorities");
    authorityMap.set(authority, origin);
  }
  return authorityMap;
}

function consumeRateLimit(buckets: Map<string, RateBucket>, key: string, limit: number, now: number): boolean {
  for (const [bucketKey, bucket] of buckets) if (now - bucket.start >= WINDOW_MS) buckets.delete(bucketKey);
  if (!buckets.has(key) && buckets.size >= MAX_RATE_KEYS) return false;
  const current = buckets.get(key);
  if (!current || now - current.start >= WINDOW_MS) {
    buckets.set(key, { start: now, count: 1 });
    return true;
  }
  current.count += 1;
  return current.count <= limit;
}

/** True only inside the private preflight context for the exact current request. */
export function hasFirebaseOperatorPreAuthProvenance(req: Request, path: typeof BEGIN | typeof EXCHANGE): boolean {
  const current = provenance.getStore();
  return Boolean(current && current.request === req && current.method === "POST" && current.path === path && req.method === "POST" && rawPath(req) === path);
}

export function firebaseOperatorPreAuthRequestHandler(options: {
  trustedOrigins: ReadonlySet<string>;
  maxBodyBytes?: number;
  audit?: FirebaseOperatorAuditSink;
}): RequestHandler {
  const authorityOrigins = validOrigins(options.trustedOrigins);
  const maxBodyBytes = options.maxBodyBytes ?? 4096;
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1 || maxBodyBytes > 4096) throw new Error("Invalid Firebase session body limit");
  const rateBuckets = new Map<string, RateBucket>();
  const parser = express.json({
    limit: maxBodyBytes,
    strict: true,
    type: "application/json",
    verify(req, _res, buffer) { capturedLengths.set(req as Request, buffer.byteLength); },
  });

  return (req, res, next) => {
    const candidatePath = rawPath(req);
    if (!/^\/api\/auth\/firebase-session(?:\/|$)/i.test(candidatePath)) return next();
    const exactPath = candidatePath === BEGIN || candidatePath === EXCHANGE;
    if (!exactPath || (req.originalUrl || req.url).includes("?")) {
      reject(res, 404, "bad_request", options.audit);
      return;
    }
    if (req.method !== "POST") { reject(res, 405, "bad_request", options.audit); return; }

    const originValues = rawHeaderValues(req, "origin");
    const hostValues = rawHeaderValues(req, "host");
    const authorizationValues = rawHeaderValues(req, "authorization");
    const contentTypeValues = rawHeaderValues(req, "content-type");
    const contentLengthValues = rawHeaderValues(req, "content-length");
    const transferEncodingValues = rawHeaderValues(req, "transfer-encoding");
    if (originValues.length > 1 || hostValues.length > 1 || authorizationValues.length > 1 || contentTypeValues.length > 1 || contentLengthValues.length > 1 || transferEncodingValues.length > 1 || (contentLengthValues.length > 0 && transferEncodingValues.length > 0)) {
      reject(res, 400, "bad_request", options.audit); return;
    }
    if (originValues.length === 0 || hostValues.length === 0) { reject(res, 400, "origin_denied", options.audit); return; }
    if (contentTypeValues.length !== 1) { reject(res, 400, "bad_request", options.audit); return; }
    const host = hostValues[0]?.trim();
    const origin = originValues[0];
    const mappedOrigin = host ? authorityOrigins.get(host.toLowerCase()) : undefined;
    if (!mappedOrigin || origin !== mappedOrigin || origin === "null") { reject(res, 403, "origin_denied", options.audit); return; }
    if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(contentTypeValues[0] ?? "")) { reject(res, 415, "bad_request", options.audit); return; }
    const ip = req.socket.remoteAddress;
    if (!ip) { reject(res, 429, "rate_limited", options.audit); return; }
    const now = Date.now();
    const limit = candidatePath === BEGIN ? 10 : 20;
    if (!consumeRateLimit(rateBuckets, `${ip}\u0000${candidatePath}`, limit, now)) { reject(res, 429, "rate_limited", options.audit); return; }

    parser(req, res, (parseError?: unknown) => {
      if (parseError) {
        const status = typeof parseError === "object" && parseError !== null && "status" in parseError && typeof parseError.status === "number" ? parseError.status : 400;
        reject(res, status === 413 ? 413 : 400, "bad_request", options.audit);
        return;
      }
      const capturedBytes = capturedLengths.get(req);
      if (capturedBytes === undefined) { reject(res, 400, "bad_request", options.audit); return; }
      const bodyBytes = capturedBytes;
      if (bodyBytes > maxBodyBytes) { reject(res, 413, "bad_request", options.audit); return; }
      const store: Provenance = { method: "POST", path: candidatePath as typeof BEGIN | typeof EXCHANGE, origin, bodyBytes, nonce: randomBytes(16).toString("hex"), request: req };
      provenance.run(store, next);
    });
  };
}

/** Internal capability used by the plugin; callers cannot manufacture this context. */
export function currentFirebaseOperatorPreAuth(req: Request, path: typeof BEGIN | typeof EXCHANGE) {
  const current = provenance.getStore();
  return hasFirebaseOperatorPreAuthProvenance(req, path) ? current : undefined;
}

/** Internal plugin capability for the current async call chain. */
export function getFirebaseOperatorPreAuthContext(path: typeof BEGIN | typeof EXCHANGE) {
  const current = provenance.getStore();
  return current && hasFirebaseOperatorPreAuthProvenance(current.request, path) ? current : undefined;
}
