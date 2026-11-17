# Process SSH synthetic fixtures

These fixtures exercise source boundaries, not authentication or business delivery. They use an explicit private temporary root and a uniquely owned loopback SSH listener with disposable generated keys. They never attach to an operator tunnel or application daemon.

The local sentinel is an actual process side effect: an ignored target cannot pass as a mocked refusal. The bounded remote probe has its own short finite lifetime and records a marker, progress and completion. Test-observed SSH client death is not treated as remote command or application teardown.

All configuration/tracing doubles are limited to the existing configuration read, no-op telemetry, fixture isolation and synthetic transport observation. They do not implement admission, verify a delegation, return stop-success authority, or emulate a provider/model. HOME and CODEX_HOME of the test process stay unchanged. No production owner/controller barrier is supplied here.

Private-input tests invoke the actual runSshCommand with an explicit private_v1 selector. The pre-wire observer captures original argv and exact stdin, refuses unsafe profile text/private canaries with SSH failure255, and never invokes a real wire in that suite. Legacy controls observe existing argv semantics without executing login profiles. A call-ID set, rather than random directory sorting, selects each capture. Synthetic canaries are test data; transport custody is distinct from arbitrary remote program output.

Real SSH characterization requires the existing local filesystem sandbox, unchanged HOME/CODEX_HOME values, an explicit daemon credential-environment allowlist, and verified inaccessible user/system profile paths. A pinned test loader changes only the fixture readiness call and fixture daemon spawn environment; production SSH command builders and adapter targets remain unchanged. Exact loader diff, mounts, source hashes and setup/teardown evidence must be retained. A setup failure is infrastructure-blocked, never semantic RED or successful SSH qualification.
