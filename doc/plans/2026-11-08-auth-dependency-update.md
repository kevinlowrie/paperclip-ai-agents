# Better Auth dependency update

**Scope:** Pin the server's Better Auth dependency to `1.7.18`, bring the
matching dependency family into the lockfile, and keep the existing Firebase
Admin `14.5.0` dependency locked. This is dependency preparation only; it does
not enable or activate a login flow.

**Status:** Better Auth 1.7.18 schema compatibility migration and focused
regressions pass. The local plugin SDK/shared artifacts were built and the three
invite-route cases pass. Full workspace release checks and runtime activation
remain open.

## Security basis

The private advisory verification records three OSV/GHSA advisories affecting
the installed `better-auth` / `@better-auth/drizzle-adapter` `1.7.2` versions.
The affected semver ranges are fixed at `1.7.7`, so `1.7.2` is within those
ranges and `1.7.18` is above the fixed version. This establishes the dependency
range risk; it does not establish exploitability in Paperclip's plugin or
deployment configuration. No exploit attempt was made.

## Lockfile review

The reviewed bot PR14 input supplied the `1.7.18` package and lockfile family;
the incomplete manifest-only PR10 input was not used. The checkout's base
manifest already declared Firebase Admin `14.5.0`, but its lockfile importer
did not include that dependency. The resulting lock update adds the missing
importer and the canonical pnpm-resolved Firebase Admin closure while retaining
the declared version and existing patch hashes.

The canonical lock contains the Better Auth 1.7.18 family, including
`better-call@1.4.5`, `jose@6.2.15`, `nanostores@1.5.5`, and
`@better-auth/utils@0.5.1`. It keeps the existing Kysely `0.29.5` and Zod
`4.6.5` peer resolutions; both satisfy the updated family ranges. No direct
Kysely or Zod manifest range changed. Existing patched `postgres` and
`embedded-postgres` lock resolutions remain intact.

The isolated Better Auth closure audit reports zero advisories for that
22-package runtime subset. It does not audit the whole workspace or the separate
Firebase Admin closure, and it is not a substitute for the frozen full-workspace
build and signed release checks.

## Verification boundary

An initial test run used Better Auth `1.7.18` and found that the existing
`account.issuer` column was `NOT NULL`, although this SDK version never writes
it. Migration `0296` makes that legacy field nullable, removes its old
issuer/account uniqueness, and adds a local unique index on
`(provider_id, account_id)`. Before any DDL, it takes a
`SHARE ROW EXCLUSIVE` lock and checks for duplicate provider/account pairs; a
collision aborts with SQLSTATE `23505` and a generic message without changing
rows or schema. It does not rewrite, merge, or delete identity data. Existing
issuer values and credential material are retained.

The first bounded 13-file run had 194 passed and 4 failed. The failures were
the historical 0230 fixture retaining the post-0296 index during rewind and
three invite-route tests whose local SDK build outputs were absent. The approved
fixture correction drops the 0296 index when restoring the actual pre-0230
shape. A final six-file PostgreSQL regression run passed all 116 tests: 110
Firebase verifier/directory/provisioning tests, two real Better Auth credential
signup/login tests, and four migration-history/key tests. The three invite-route
cases passed after the local plugin SDK/shared artifact build. DB typecheck and
migration safety checks pass. Direct `tsc --noEmit --project server/tsconfig.json`
passes against Better Auth 1.7.18. The server package typecheck wrapper did not
reach its final tsc step because its runner-vendor prerequisite attempted a Rust
binary build and `cargo` is unavailable; this limitation does not affect the
direct server TypeScript check. Exact commands and output logs are recorded in
the private work-package proof. No provider credentials or production calls
were used.

Rollback to the old `NOT NULL` issuer constraint is intentionally gated on a
reviewed inventory, backfill plan, and backup of all rows where issuer is now
NULL. The local `(provider_id, account_id)` unique index is explicit project
hardening for the 1.7.18 lookup key, not an upstream-required schema change.

Full workspace test/build gates and signed frozen-workspace verification remain
release requirements. This package change alone is not evidence for login
activation, provider acceptance, or production readiness.
