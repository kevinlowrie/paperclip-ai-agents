# Consumer Firebase TOTP session v1

Status: required first-consumer activation behavior; implementation and real
phone acceptance are outstanding. Homelab owns this supplement to
`consumer-portal-v1.md` and `consumer-workflow-v1.md`. Server, middle and UX
consume a synchronized snapshot. It does not activate team/device onboarding,
operator Paperclip board sessions or a second identity authority.

## User outcome

The first consumer signs in with their Google account on their phone, prepares
an authenticator when needed, completes a TOTP challenge, and then accesses
their own onboarding and approved text-summary workflow. An unfinished or
failed challenge cannot expose tenant data or submit a job. The phone is the
interface; this requirement does not select SMS as the second factor.

## Identity and authorization

- `CFT-001`: Preserve the named Firebase project's production Admin verification,
  exact project issuer/audience/UID checks, expiry, disabled-user and revocation
  handling. Emulator mode remains unavailable. A decoded browser payload or
  test verifier is not production verification. Provider failure remains an
  unavailable service, not an anonymous identity or a skipped MFA check.
- `CFT-002`: Every Firebase-user request to protected portal and workflow routes
  requires server-verified `email_verified: true`,
  `firebase.sign_in_provider: "google.com"`, and
  `firebase.sign_in_second_factor: "totp"`. The reserved `firebase` claim must
  be an object; `second_factor_identifier` must be a nonempty, trimmed printable
  string of at most 128 characters. `auth_time` must be a positive integer
  (not a boolean), no later than the verified token's issued-at time. Existing
  `iat`/`exp` validation remains authoritative. A refreshed token does not
  represent a new authentication time. MFA enrollment metadata alone, an SMS
  factor, a client assertion or a Cloudflare service identity is insufficient.
- `CFT-003`: This first slice uses the project's default Firebase identity
  namespace. Reject a `firebase.tenant` claim rather than interpreting an
  Identity Platform tenant's UID as the default namespace's identity. Supporting
  that separate identity namespace requires its own explicit binding contract.
- `CFT-004`: Missing, malformed or ineligible MFA proof is an unauthenticated
  request using the existing safe 401 error envelope. It must not reach tenant
  lookup, application data, submission, budget reservation or upstream dispatch.
  Apply the gate at the authoritative gateway and the Firebase proxy. Preserve
  independent Cloudflare service-auth verification. This requirement does not
  add Firebase claims to Kubernetes worker/service-account authentication.
- `CFT-005`: TOTP grants no tenant, role or operator authority. Continue current
  project/UID membership authorization on every operation. Display email and
  browser-selected tenant are not membership sources. Preserve same-transaction
  membership revocation, support auditing and all existing payload boundaries.

## Browser enrollment and challenge

- `CFT-006`: Use the existing project's modular Firebase Web SDK and Google
  redirect flow. An authenticated user without usable TOTP proof enters an
  enrollment or reauthentication state before any protected portal request.
  Handle Firebase's multi-factor-required redirect result through its resolver
  and the selected enrolled TOTP hint. Do not silently fall back to another
  factor or turn an MFA error into a signed-in portal state.
- `CFT-007`: Enrollment uses Firebase's authenticated MFA session, generated
  TOTP secret and verified enrollment assertion. Provide a usable manual setup
  key for an authenticator on the same phone. A locally generated QR/deep link
  may supplement it; an external QR service must not receive the secret.
  Invalid/expired codes and recent-login requirements have bounded recoverable
  UI states. Cancellation and sign-out clear challenge, code and enrollment
  material. Do not create an automatic redirect/retry loop.
- `CFT-008`: Enrollment completion alone does not unlock the portal. Refresh
  the Firebase ID token and inspect its resulting MFA proof. If Firebase does
  not issue qualifying proof, require a fresh Google-plus-TOTP sign-in and
  keep protected API calls disabled. Every token supplied to the API is subject
  to current proof checks, including after refresh, sign-out and user changes.
- `CFT-009`: TOTP codes/secrets remain transient UI state and are sent only to
  Firebase's enrollment/challenge APIs. They must not enter application storage,
  the consumer gateway/proxy payloads, HTTP URLs, analytics, logs, screenshots
  or task artifacts. Firebase ID tokens retain the existing bearer-only API
  transport. This supplement creates no app cookies or extra session tokens.
- `CFT-010`: Keep tenant/workflow behavior from the portal contract and its
  response conformance checks. Browser MFA status cannot replace server
  verification. Fail closed when the SDK, account state or project TOTP
  capability is unavailable; explain the next safe action to the user.

## Ownership and acceptance

The server owner derives gateway denial and regression checks; middle owns
proxy denial and upstream-isolation checks; UX owns SDK orchestration,
enrollment/challenge/refresh/cancellation and phone usability. Each owner checks
the declared contract revision and its local behavior; no private source imports
cross repository boundaries. Synthetic claims and SDK fixtures are local
verification only and must never be enabled as a production authentication path.

Deployment requires the intended Google provider and authorized origins, an
Identity Platform/TOTP-capable project configuration, correct runtime identity
for revocation checks, and the existing proxy/Access/gateway deployment seam.
Do not infer those facts from SDK support or a green local test.

Acceptance requires the actual consumer completing Google sign-in and TOTP on
their phone, current scoped membership, onboarding persistence and one real
approved text-summary result with correlated workflow/accounting evidence.
Also prove denied non-MFA/revoked/cross-tenant requests and recovery from an
unavailable downstream. Record operator board sign-in separately. No secret or
one-time code is requested in chat or published as evidence.

## Official interfaces

- [Firebase ID token verification](https://firebase.google.com/docs/auth/admin/verify-id-tokens)
- [Firebase revocation handling](https://firebase.google.com/docs/auth/admin/manage-sessions)
- [Firebase TOTP enrollment and sign-in](https://firebase.google.com/docs/auth/web/totp-mfa)
- [Reserved token claims](https://firebase.google.com/docs/reference/admin/node/firebase-admin.auth.decodedidtoken)
