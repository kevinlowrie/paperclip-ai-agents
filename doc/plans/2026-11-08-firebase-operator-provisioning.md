# Firebase operator provisioning source package

Date: 2026-11-08

This source-only package implements the PFS003, PFS004, and PFS010 identity
directory and reviewed provisioning primitives, with persistent storage needed
by the later PFS008, PFS009, PFS011, PFS012, and PFS013 session work. It does
not issue browser sessions, add routes, activate Firebase authentication, or
change deployment configuration.

## Behavior

`createFirebaseOperatorProvisioner` exposes `dryRun`, `apply`, and `rollback`.
The injectable identity directory is an internal/test seam. The production
factory fixes Firebase Admin to project `thl-pclipd-api` and returns only the
current UID, project, and lookup start time after checking that the UID is
enabled, verified, in the default namespace, and currently has Google as a
provider. It does not require TOTP enrollment; interactive verification keeps
that requirement.

Provisioning uses a trusted in-process board actor with a concrete user ID and
`session` or `board_key` source. Each operation locks and checks the existing
actor and current instance-admin row, then independently checks active
nonviewer membership and `users:manage_permissions` authority in every reviewed
active company. It binds a Firebase UID to an existing non-instance-admin
Paperclip user. It never creates users, companies, accounts, admin roles, or
credentials.

Review packets store normalized intent and full target membership/grant state
digests, expire after five minutes, and can be applied once. Apply rechecks
Firebase identity outside the transaction and all local authority and state
inside a serializable transaction. Role defaults are additive; existing
matching membership roles and custom grants remain intact. Reassignment and
rollback retain the binding row and advance its revision. Apply revokes
ordinary sessions for the old and target user atomically. Rollback disables
only its binding revision and removes packet-owned membership/grant rows only
when the full reviewed post-state still matches; concurrent changes produce a
partial result.

Provisioning events are append-only at the database level. They contain only
bounded outcome details and row IDs; Firebase tokens, provider error text,
emails, and custom grant scope snapshots are not recorded.

## Schema

Migration `0295_loose_ghost_rider.sql` adds:

- `firebase_operator_bindings`, with fixed project, unique project/UID,
  unique enabled user binding, retained positive revision, and a restrictive
  existing-user foreign key.
- `firebase_operator_session_assurance`, a session-cascading storage record
  for the later guard/exchange flow. This package does not issue or accept
  assured sessions.
- `firebase_operator_provision_packets`, with actor, intent, expected binding
  state, target grant-state hash, expiry, one-use lifecycle, and exact inserted
  row IDs for rollback.
- `firebase_operator_provision_events`, protected against update, delete, and
  truncate with SQLSTATE `42501`.

## Verification and limits

Focused disposable PostgreSQL tests exercise the new service against canonical
migrations. Existing Firebase token-verifier tests remain regression coverage.
This is a package implementation result, not phone onboarding acceptance or a
release gate. Session exchange, ongoing API/stream guards, Google/TOTP UI,
deployment activation, and real-provider calls remain out of scope.

Approved test fixture corrections are limited to actor-context coverage,
per-test user/session/grant filtering, provider outage on the fresh apply
lookup after a successful preview lookup, a real prebinding target session for
reassignment, an existing-user expected-state conflict, and seeding the
matching role default before asserting custom-grant preservation.
