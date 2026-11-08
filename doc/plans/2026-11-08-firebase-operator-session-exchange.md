# Firebase operator session exchange

Status: implemented as a dormant, fixture-testable Better Auth plugin. The
plugin and preflight are not registered in the production auth instance or
Express app. Production login stays unavailable until the PFS assurance guard
and the remaining activation gates pass.

## Flow

The browser starts a same-origin `POST /api/auth/firebase-session/begin` with
an allowlisted company ID and local return path. The server persists a
five-minute transaction with hashes of independent random browser-binding and
CSRF values, plus the exact configured HTTPS origin and server-held company
and return path. It returns the transaction ID, CSRF state and expiry, and
sets a host-only Secure, HttpOnly, SameSite Strict cookie.

The browser exchanges that transaction at
`POST /api/auth/firebase-session/exchange`, sending the CSRF state in JSON and
the Firebase ID token only in one Authorization Bearer header. A valid request
must match the original browser cookie and exact origin. The server verifies
fresh Google-plus-TOTP proof, resolves an enabled existing UID binding and
current non-admin company membership, then commits a conditional single-use
transaction claim before creating a Paperclip session.

Session creation uses Better Auth 1.7.18 outside the final SQL transaction.
The server preallocates its transient SDK token for cleanup, then serializably
rechecks the binding revision, user, non-admin status, company membership and
proof freshness before inserting the assurance record. Only after that commit
does Better Auth issue the host-only Secure, HttpOnly, SameSite Lax session
cookie with the same eight-hour absolute expiry as the stored session. Failed
issuance leaves the nonce consumed and removes the owned session when one was
created. The response contains only the validated local return path.

Requests pass through an exact-route preflight that checks the raw Host and
Origin pair against a finite static map, rejects ambiguous raw headers and
framing, bounds JSON parsing at 4096 bytes, and rate-limits by socket IP. A
private AsyncLocalStorage capability prevents direct Better Auth mounts and
route variants from reaching the endpoints. Reserved Firebase-session HTTP
logs use a closed projection retaining only request ID, method, fixed route,
and response status.

## Verification and activation boundary

The focused PostgreSQL/Better Auth 1.7.18 and raw HTTP/Pino fixtures cover the
exchange and preflight behavior. This package does not install the plugin in
`better-auth.ts` or mount the preflight in `app.ts`. It does not implement the
PFS-010–014 all-transport assurance guard, management operation, UI, or live
provider acceptance. Keep those as separate reviewed work before activation.
