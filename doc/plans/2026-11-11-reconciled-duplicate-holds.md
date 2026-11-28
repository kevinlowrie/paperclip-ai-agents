# Reconcile duplicate legacy execution holds

Status: local fix and regression tests; not deployed.

A cancelled legacy run can acquire more than one settled recovery record.
Reconciling the latest record creates a pending continuation, but an older
record with `automaticRecovery.replay=blocked` still prevents dispatch. Repeated
operator reconciliation could then create more than one delivery owner.

Adapt both same-source recovery changes from [Paperclip #17055 at
`ea42a2e41715c70a6822a25683136e48e35ae811`](https://github.com/paperclipai/paperclip/commit/ea42a2e41715c70a6822a25683136e48e35ae811)
to this pinned release.

- Repeated terminalization reuses a resolved no-replay hold for the same
  company, issue, legacy cause, fingerprint and run. The pinned release
  requires the recorded workspace failure to match the current failure before
  reusing a human decision. Its repair evidence must meet the same trimmed
  length requirement as continuation delivery. A settled automatic hold for
  the same unsafe archive still preserves its no-replay decision.
- After reconciliation, coalesce matching legacy holds of the same kind in
  the transaction that records the decision. Link the sibling evidence to the
  selected recovery action, invalidate sibling delivery, and record an audit
  event. The selected action retains responsibility for continuation delivery,
  including existing explicit delegation. Keep sibling records with independent
  reconciliation, workspace recovery or system recovery evidence. Existing
  provider-stop, authority-release and outcome validation still apply.

The pinned release uses the existing reconciliation signature and delivery
path. The newer upstream implementation also handles workspace-repair-only
reconciliation and notifies three delivery queues in the write transaction.

The embedded PostgreSQL checks cover reuse of a settled hold during repeated
terminalization and coalescing pre-existing duplicate holds after a verified
decision. Boundary cases exercise records that must be preserved. The prior
coalescing-only revision passed the 70-test related suite and server typecheck.
That evidence predates the terminalization change. The checks use local source
and database fixtures.

No migration or direct operational database edit is included. Review and
deployed acceptance must confirm one continuation owner and preservation of
unrelated holds before release readiness.
