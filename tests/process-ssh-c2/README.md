# C2 private native lease source lane

Run node tests/process-ssh-c2/run.mjs with the explicit pinned prepare_native.py
CLI in the paired delivery GREEN child. This lane now selects exactly ten cases
in lease-safety.test.ts: the original three actual-child lease regressions, two
compatibility controls, three malformed/foreign owner cases, and two actual
owned-Postgres lock/CAS races. No source policy mocks, authority callbacks,
provider/model calls or skip fallbacks are used.

The five original case bodies are exact extractions of frozen cc0/native8.
native-handoff.test.ts is retained byte-identical as historical reference only;
its three old injected positive cases are superseded by the real dispatcher
assembly lane, not reported as passing. The original cc0/RED37 worktrees and
public PR6 are immutable. Real temporary SSH listener/process ownership and
HOME/CODEX_HOME checks remain in the original fixture.

GREEN is source-only. Unknown cleanup holds the same selected lease/owner/refs;
fixture oracle teardown is not a production remote-stop claim.
