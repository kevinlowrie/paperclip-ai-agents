# Issue-bound run response projection

Status: local implementation with focused tests; not deployed or release-qualified.

## Problem and behavior

Issue-scoped integrations can read a run ledger without permission to read
company-wide run logs. They need a bounded response associated with the exact
issue/run they submitted. The new read-only endpoint is:

`GET /api/issues/:issueId/runs/:runId/final-response`

It uses existing company access and `issue:read` authorization, including the
task-bridge boundary. Missing, foreign and denied issues return the same 404.
The run query requires both the exact company and original context issue ID;
an activity-log association with another issue does not grant output access.
Full-log and company-wide telemetry permissions remain unchanged.

The response uses `issue-run-final-response/v1` and returns company, issue, run
and agent IDs, run status, `source: adapter_summary`, availability and nullable
text. Queued/running runs are pending. Only a succeeded run with a nonempty
string summary of at most 16,384 UTF-8 bytes is available. Missing, malformed,
oversized or unsuccessful results are unavailable. The SQL projection enforces
the bound without fetching logs or the full result blob. No truncation or
fallback to progress, error, stdout or stderr is allowed.

The stored adapter summary is not a workflow-success assertion. Consumers must
qualify their adapter's summary semantics, verify their own persisted request/run
binding and validate any application-specific result. This API does not imply
that every adapter uses summary as the verbatim final assistant message.

Run-secret redaction and configured current-user redaction apply before response
delivery. Redaction failures fail closed. Every response uses no-store. The
endpoint does not accept credentials in queries or expose provider traces,
environment configuration or other run context.

## Verification and remaining gates

Focused route and embedded-Postgres activity-service tests pass (26 cases across
both files: 17 route and 9 service cases). Coverage includes allowed issue-scoped calls, foreign/denied/missing
issue rejection before data reads, wrong run/company/issue, malformed run IDs,
redaction, bounded database projection, UTF-8 size and unsuccessful/pending runs.
Anonymous calls are rejected before issue lookup. A redaction-provider failure
returns an error without the response text. The route tests inject the
access-policy decision; the authorization service's existing task-bridge
regression also passed (one selected test, 65 skipped).

Shared response types, OpenAPI and the UI API client are updated. No UI entry
point, database migration or live configuration change is introduced. Full
typecheck/build, broader auth regressions, independent review and deployed scoped
credential acceptance remain required before release readiness.

Initial full typecheck and build attempts stopped because the shell selected
system Rust 1.93.1, below the locked AWS dependencies' minimum of 1.94.1.
The installed rustup toolchain is newer. A command-local PATH selects it without
changing dependencies or the system toolchain. Full verification is in progress;
focused test results do not imply that all repository checks pass.
