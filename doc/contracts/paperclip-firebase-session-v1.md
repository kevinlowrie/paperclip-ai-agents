# Paperclip Firebase human session v1

Status: proposed versioned integration contract; no implementation or deployed
login is established by this document. Homelab owns the integration contract;
Paperclip owns its local account, session and company authorization behavior.

## Outcome and boundary

An explicitly enrolled operator completes Google sign-in and TOTP in the
existing default Firebase project, then opens an authorized Paperclip company
with an ordinary Paperclip browser session. An admitted Cloudflare browser
still needs this application authentication. The first operator must be able
to access the existing DME personal company and THL team company using their
separately approved memberships, without becoming an instance administrator.

This contract does not enroll a consumer into a Paperclip board, create a
company, activate team/device onboarding, or replace consumer membership.
`consumer-firebase-totp/v1` remains unchanged: consumer `/api/v1` calls use
Firebase bearer tokens and create no application cookies. This separate
operator flow alone exchanges Firebase proof for a Paperclip cookie. Both
flows retain Firebase as identity authority; Paperclip remains its own company
authorization authority. Neither imports a sibling's private implementation.

## Identity and local authorization

- `PFS-001`: Independently verify the production ID token with the pinned
  default project `thl-pclipd-api` and the Firebase Admin SDK, with revocation
  and disabled-user checking enabled. Verify signature, issuer, audience,
  subject and token times; reject emulator/test verification in production.
  Require the verified Google, email-verification, TOTP, factor-identifier and
  default-namespace proof specified by CFT-001 through CFT-003. The project's
  Google/TOTP settings and runtime verification identity need live proof.
- `PFS-002`: At exchange, verified `auth_time` must also be at most 300 seconds
  old and not in the future. Token refresh does not reset authentication age.
  An old authentication requires fresh Google-plus-TOTP reauthentication.
  This additional operator requirement does not change CFT's consumer rules.
- `PFS-003`: Resolve exactly one enabled, operator-provisioned binding from
  `(project, UID)` to an existing Paperclip user. Give the binding a monotonic
  revision. Email is display data; a matching email must never create or link
  an account. The exchange cannot create users, companies, memberships, agent
  credentials or instance-admin grants. Unknown, conflicting or disabled
  bindings deny access. Provisioning and reassignment require a separate
  authenticated, audited operator action, not this public exchange.
  That provisioner requires an existing authenticated Paperclip instance
  administrator with authority over each affected company. Its reviewed
  dry-run/apply packet identifies the actor, independently verified Firebase
  project/UID, existing target user, exact company IDs/roles and expected
  binding/grant revisions. Compare-and-set changes atomically and retain an
  audit receipt. Rollback disables only the packet's binding and revokes its
  sessions; grant corrections must match expected revisions and preserve
  concurrent/unrelated grants. If no supported provisioner exists, its owner
  must implement one separately; this document does not claim one exists.
- `PFS-004`: Require the selected company's current active Paperclip user
  membership before issuing a session. Resolve company identifiers against
  current server records; neither a caller-selected ID nor a display slug
  grants access. Roles come only from existing Paperclip grants. Consumer
  PostgreSQL membership, Google email/domain, Firebase custom claims, Access
  headers and Paperclip Cloud tenant headers convey no Paperclip role.
  Never use board-claim/bootstrap-admin or workspace-clone tickets for this.

## Browser exchange

Complete Firebase authentication before creating the short-lived application
transaction, so a Google redirect or TOTP enrollment does not exhaust it.
Version 1 uses a finite configured set of operator entry points for the
existing DME and THL company IDs. Reviewed server configuration supplies those
actual IDs. The UI may present the entry points, but the list grants no
membership. Reject an ID outside that set before Firebase lookup. There is no
pre-session membership-enumeration or authenticated-chooser endpoint in v1.
Revalidate active membership at exchange and every protected operation.

The operator Firebase Web SDK must use `inMemoryPersistence`, including the
Google redirect/TOTP round trip. Paperclip stores no browser copies of ID or
refresh tokens. Its ordinary cookie supports reload independently of Firebase
browser persistence. Documented redirect support still needs actual browser
acceptance; do not fall back to persistent token storage to pass that check.

- `PFS-005`: Register same-origin `POST` endpoints
  `/api/auth/firebase-session/begin` and
  `/api/auth/firebase-session/exchange`, only when the server's reviewed
  operator-login configuration is complete. Reject other methods. Check the
  exact configured HTTPS request origin on both endpoints, independently of
  the board mutation guard, which may not see a signed-in actor yet. Reject
  missing, `null`, wildcard, foreign or reflected forwarding-header origins.
  Disable cross-origin credentialed access and apply bounded rate limits.
- `PFS-006`: Begin accepts only a selected company ID and a validated local
  return path. Store those server-side with a cryptographically random browser
  binding of at least 256 bits, a separate CSRF state, and a 300-second expiry.
  Return only transaction metadata/state; set a host-only Secure, HttpOnly,
  SameSite Strict transaction cookie, Path `/`, with no Domain attribute.
  The browser sends the matching state in the exchange request, and its cookie
  must match the stored transaction. Store hashes rather than reusable raw
  browser secrets. State is per browser and origin; another host cannot use it.
- `PFS-007`: Exchange accepts the Firebase ID token only in the Authorization
  Bearer header. Its JSON body identifies the transaction and CSRF state;
  company/return-path values are taken from the stored transaction. Reject
  unknown fields, malformed/oversized bodies and duplicate or ambiguous
  credential/state inputs. No ID token, refresh token, TOTP code or enrollment
  key may enter URLs, redirects, application storage, tracing, logs or reports.
  The Paperclip server receives no Google OAuth access/refresh credential.
- `PFS-008`: Verify the transaction, fresh Firebase proof, explicit binding and
  selected company membership, then consume the transaction atomically once.
  Concurrent or sequential replay cannot mint a second session. Recheck local
  authorization at issuance and serialize it with binding/membership changes,
  or prove an equivalent fail-closed concurrency guarantee. A consumed failed
  exchange requires a new transaction; it must not become a replayable ticket.
- `PFS-009`: Use Better Auth's supported session and cookie APIs. Persist the
  required assurance before exposing a successful cookie; an assurance write
  failure must leave no usable session. The resulting cookie is host-only,
  Secure, HttpOnly and SameSite Lax, with no Domain attribute. Do not implement
  a parallel cookie signer, return a session bearer to JavaScript, or reuse
  Firebase session cookies or the workspace-clone signing trust. Return only
  a safe local navigation target and non-secret session metadata, with
  Cache-Control no-store and Referrer-Policy no-referrer. Clear transaction
  material after consumption and on cancellation.

## Assurance and session lifecycle

- `PFS-010`: A protected server-side assurance record binds the ordinary
  session to the Firebase project/UID, authentication time, binding revision,
  initial proof time, last authoritative status check and activity time. Never
  persist the Firebase token. Existing Better Auth timestamps alone do not
  establish this record. A linked operator's old, password-created or otherwise
  unassured session must not pass the assurance guard. Binding an account must
  invalidate pre-binding browser sessions; password sign-in must not bypass
  the required Firebase assurance. Keep unrelated existing identities intact.
- `PFS-011`: Enforce current enabled local binding/revision and current
  Paperclip membership on every protected request and company switch. Session
  possession grants no new company. A removed selected-company membership
  denies that company's operation even if another company remains authorized.
  Apply the assurance guard to HTTP, websocket/live-event establishment and
  continued delivery, plugin/dynamic routes and other protected transports;
  an already-open stream must not retain revoked authority indefinitely.
  Revalidate current membership before protected delivery intervals and
  revalidate idle streams at most 60 seconds apart. Close a stream within
  60 seconds when checks become stale, unavailable or denied.
- `PFS-012`: Revalidate Firebase user existence, disabled state and token
  revocation against recorded authentication time without retaining the ID
  token. Read the configured project's current Firebase UserRecord; require
  the same UID, an enabled user, verified email and a Google provider binding.
  Parse `tokensValidAfterTime` into valid UTC epoch milliseconds and require
  stored integer `auth_time` seconds multiplied by 1000 to be strictly greater
  than that value. Equality deliberately denies as an application policy,
  not a claim that every SDK uses that boundary. Missing, malformed or future
  validity timestamps deny access.
  An authoritative positive result may be cached for at most 60 seconds,
  without sliding extension from requests. After that, inability to check
  denies protected access; never serve a stale positive during an outage.
  Revocation/disable detection invalidates the linked local session. Reuse only
  a documented SDK/user-record revocation algorithm and test its timestamp
  boundaries. At issuance, record the canonical sorted `(factorId, uid)` pairs
  for current enrolled TOTP factors, with at least one such factor. Compare
  the current set during status checks; any addition, removal or identifier
  change invalidates assurance and requires fresh Google/TOTP authentication
  within the same 60-second bound. Do not compare display names or assume
  `second_factor_identifier` equals a factor-record UID: that mapping is
  unverified, and the snapshot does not identify which factor was used in
  the token. Require live factor-change acceptance before activation.
- `PFS-013`: Enforce an eight-hour absolute lifetime from original session
  creation and a 30-minute idle limit. Cookie refresh cannot extend the absolute
  limit. Persist last interactive activity time server-side; advance it only
  on explicitly designated authorized UI actions such as a company switch or
  command submission. Background reads, polls, keepalives and session refresh
  never advance it. This policy does not claim a request proves human presence.
  Use the
  normal protected Better Auth logout/revocation path. Cancellation, logout,
  expiry, unlink and membership denial have clear recoverable UI states, with
  no automatic sign-in loop or retained enrollment/code material.
- `PFS-014`: Preserve operator sandbox/plugin/environment restrictions, agent
  service-key separation, current company access guards and verified TLS on
  both browser paths. Audit binding/session issuance and denial using bounded
  reason categories and internal correlation IDs, with no token, CSRF/cookie,
  code, key, raw provider error or unnecessary email in log payloads. Treat
  authentication failure as safe 401, authorization denial as safe 403, and
  unavailable verification as 503. No failure may expose a new session cookie
  or protected company payload.

## Acceptance and ownership

Homelab coordinates version/requirements and the composed browser journey.
Paperclip source owns verifier/session/assurance, binding and company guards,
its own sign-in UI and local checks. Server-side owns the pinned source/image,
runtime workload identity, storage migration and deployment. Middle-management
owns Access/origin glue. Client UX owns only its consumer portal; its
source is a behavior reference, not a cross-repository import or a Paperclip
operator login implementation. Register and synchronize an implementation's
declared contract snapshot before changing that seam.
Firebase project/provider/TOTP Terraform ownership remains unresolved until
the incoming design is identified; middle-management's edge ownership does
not imply authority over that unlocated source.

Owners derive checks for all PFS requirements. Observable denial cases include
wrong project/issuer/provider/factor/namespace, stale authentication despite a
refreshed token, revoked/disabled user, missing/ambiguous binding, email
collision, unapproved company, replay and two simultaneous exchanges,
cross-origin/browser state, cookie/assurance write failure, provider outage,
password/pre-link session bypass, absolute/idle expiry and live-stream/company
revocation. Prove that none mint a usable session or disclose protected data.

Live acceptance requires the actual intended operator, verified UID binding and
separate DME/THL grants, real Google/TOTP, normal secure Paperclip cookies,
reload/logout, company switch/denial and ongoing revocation on public and lab
HTTPS origins. Source fixtures do not satisfy these outcomes. The consumer
phone onboarding and real hosted summary remain a separate required journey;
an operator login does not complete it.

## Official interfaces

- [Firebase ID token verification](https://firebase.google.com/docs/auth/admin/verify-id-tokens)
- [Firebase revocation handling](https://firebase.google.com/docs/auth/admin/manage-sessions)
- [Firebase UserRecord](https://firebase.google.com/docs/reference/admin/node/firebase-admin.auth.userrecord)
- [Firebase TOTP](https://firebase.google.com/docs/auth/web/totp-mfa)
- [Firebase browser persistence](https://firebase.google.com/docs/auth/web/auth-state-persistence)
- Paperclip source `1eec8901bbe5e22bb539ab52a089b3497219441f`:
  `server/src/auth/better-auth.ts`, `workspace-login-handoff-plugin.ts`,
  `server/src/middleware/auth.ts`, and `packages/db/src/schema/auth.ts`.
