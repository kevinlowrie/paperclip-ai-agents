# Reconcile duplicate legacy execution holds

Status: local fix and regression tests; not deployed.

A cancelled legacy run can acquire more than one settled recovery record.
Reconciling the latest record creates a pending continuation, but an older
record with `automaticRecovery.replay=blocked` still prevents dispatch. Repeated
operator reconciliation could then create more than one delivery owner.

Backport the same-source reconciliation logic from upstream Paperclip commit
`f125b823f4c7c37680ffa788ceee1ab0bc8f44b1`, adapting it to this pinned version's
existing function signature. This is not a new upstream feature proposal.
During an atomic transaction, coalesce legacy holds for the same company,
issue, cause, kind, fingerprint and exact run. Link their evidence to the
selected recovery action, invalidate sibling delivery, and record an audit
event. The selected action alone owns pending continuation delivery. Preserve
records with independent reconciliation, workspace recovery or system recovery
evidence. Existing provider-stop, authority-release and outcome validation
still apply.

The embedded-Postgres regression reproduces the old behavior: one failure and
four passing boundary controls before the fix. The corrected focused run passes
six tests, including the existing pending-continuation regression. The full
related suite passed all 65 tests for the initial local fix. Upstream discovery
then replaced that implementation with the established coalescing behavior and
expanded boundary controls. The final expanded suite passed all 70 tests, and the server typecheck
passed (both exit 0). The fresh worktree required plugin and runner TypeScript artifacts
before typechecking; these artifacts have now been built.
This is source/database-fixture evidence, not a live recovery acceptance result.

No migration or direct operational database edit is included. Review and
deployed acceptance must confirm one continuation owner and preservation of
unrelated holds before release readiness.
