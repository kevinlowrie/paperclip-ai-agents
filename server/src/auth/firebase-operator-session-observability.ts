import { randomUUID } from "node:crypto";
import type { BetterAuthOptions } from "better-auth";
import { ROOT_CONTEXT, trace, type Span } from "@opentelemetry/api";
import { logger } from "../middleware/logger.js";

export type FirebaseOperatorAuditEvent = {
  event: "begin" | "exchange" | "preflight" | "better_auth_log_suppressed";
  outcome: "created" | "issued" | "cancelled" | "denied" | "suppressed";
  reason: "accepted" | "cancelled" | "bad_request" | "origin_denied" | "rate_limited" | "transaction_invalid" | "proof_denied" | "binding_denied" | "company_denied" | "session_failed" | "assurance_failed" | "deadline_expired" | "dependency_unavailable" | "internal_failure" | "sdk_message_suppressed";
  correlationId: string;
  sdkLevel?: "debug" | "info" | "warn" | "error";
};

export type FirebaseOperatorAuditSink = (event: FirebaseOperatorAuditEvent) => void;
export type FirebaseOperatorSessionSpan = Span;

const safeAuthLogCallbacks = new WeakSet<Function>();

export function emitFirebaseOperatorAudit(audit: FirebaseOperatorAuditSink | undefined, event: FirebaseOperatorAuditEvent): void {
  try {
    if (audit) audit(event);
    else defaultFirebaseOperatorAudit(event);
  } catch { /* audit sinks cannot affect authentication outcomes */ }
}

function defaultFirebaseOperatorAudit(event: FirebaseOperatorAuditEvent): void {
  const fields = { event: event.event, outcome: event.outcome, reason: event.reason, correlationId: event.correlationId, ...(event.sdkLevel ? { sdkLevel: event.sdkLevel } : {}) };
  if (event.outcome === "denied") logger.warn(fields, "Firebase operator session request denied");
  else if (event.outcome === "cancelled") logger.info(fields, "Firebase operator session request cancelled");
  else if (event.event === "better_auth_log_suppressed") logger.debug(fields, "Better Auth log suppressed");
  else logger.info(fields, "Firebase operator session request completed");
}

export function startFirebaseOperatorSessionSpan(route: "begin" | "exchange" | "preflight"): FirebaseOperatorSessionSpan | undefined {
  try {
    return trace.getTracer("paperclip.firebase-operator-session").startSpan(
      `firebase.operator_session.${route}`,
      { attributes: route === "preflight" ? {} : { "firebase_operator.route": route } },
      ROOT_CONTEXT,
    );
  } catch { return undefined; }
}

export function finishFirebaseOperatorSessionSpan(
  span: FirebaseOperatorSessionSpan | undefined,
  outcome: FirebaseOperatorAuditEvent["outcome"],
  reason: FirebaseOperatorAuditEvent["reason"],
): void {
  if (!span) return;
  try { span.setAttribute("firebase_operator.outcome", outcome); } catch { /* keep the original request outcome */ }
  try { span.setAttribute("firebase_operator.reason", reason); } catch { /* keep the original request outcome */ }
  try { span.end(); } catch { /* keep the original request outcome */ }
}

export function firebaseOperatorSafeAuthOptions(options: BetterAuthOptions, audit?: FirebaseOperatorAuditSink): BetterAuthOptions {
  const callback = (level: "debug" | "info" | "warn" | "error") => {
    emitFirebaseOperatorAudit(audit, {
      event: "better_auth_log_suppressed",
      outcome: "suppressed",
      reason: "sdk_message_suppressed",
      correlationId: randomUUID(),
      sdkLevel: level,
    });
  };
  safeAuthLogCallbacks.add(callback);
  return {
    ...options,
    experimental: { ...options.experimental, instrumentation: { ...options.experimental?.instrumentation, enabled: false } },
    logger: { ...options.logger, disabled: false, log: callback },
  };
}

export function isFirebaseOperatorSafeAuthLogger(callback: unknown): boolean {
  return typeof callback === "function" && safeAuthLogCallbacks.has(callback);
}

export function emitFirebaseOperatorPreflightDenial(
  reason: "bad_request" | "origin_denied" | "rate_limited",
  audit?: FirebaseOperatorAuditSink,
): void {
  const event: FirebaseOperatorAuditEvent = { event: "preflight", outcome: "denied", reason, correlationId: randomUUID() };
  emitFirebaseOperatorAudit(audit, event);
  const span = startFirebaseOperatorSessionSpan("preflight");
  finishFirebaseOperatorSessionSpan(span, "denied", reason);
}
