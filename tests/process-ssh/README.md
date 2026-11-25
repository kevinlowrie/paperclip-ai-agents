# Process/SSH qualification lane

This is an explicit source-test lane. Ordinary Vitest discovery excludes its two server suites; the dedicated adapter test is outside the workspace projects and runs only in this lane. This avoids importing a mandatory-root test or starting SSH fixtures accidentally. The default exclusion rules remain intact. The stable server walker uses the same two exact server paths before sharding.

From the repository root, with installed workspace dependencies:

```sh
node --test tests/process-ssh/lane.test.mjs
pnpm test:process-ssh --lane unit
pnpm test:process-ssh --lane ssh --root-parent /dev/shm
pnpm test:process-ssh --lane all --root-parent /dev/shm
```

`unit` runs the 22 target/local cases plus 19 pre-wire custody cases. `ssh` runs three real-loopback lifecycle controls plus five private-wire/publication/custody regressions. `all` requires all49 cases with zero failures or skips. `--list` prints the fixed selection without running tests. The public script/config is the CI entry; CI placement is a separate maintainer choice. Ordinary/default full CI is not this lane's qualification evidence.

The entry requires a short POSIX temporary parent (at most64 characters; letters/digits, slash, dot, underscore and hyphen), outside the checkout. It creates a canonical private temporary root, binds it before test import, and retains reports/cache/fixture ownership evidence there. It neither assigns nor redirects HOME/CODEX_HOME and never imports the server's setup-supertest. Only unchanged identity/tooling environment is forwarded; ambient credentials are not. No arbitrary test module, provider host or source-pin bypass option is accepted. Roots remain protected and retained on unknown cleanup or runner timeout; an exit status is not a remote cleanup receipt.

The pre-wire lane needs POSIX shell and ssh-keygen. The SSH/all lane additionally requires Linux, procfs, OpenSSH client/server and the existing bubblewrap filesystem sandbox. It fails if tooling/isolation is unavailable; no skip, operator SSH config/agent fallback or unsafe profile-sourcing alternative qualifies. All listeners/keys/probes are disposable fixture-owned loopback resources. A provided HOME/CODEX_HOME must remain unchanged in the actual fixture session; the lane does not rewrite it to make a test pass.

The committed fixture loader pins the reviewed candidate SSH source hash. It differs from the frozen baseline loader only in that hash and permits exactly two unique fixture-startup adaptations: the daemon environment allowlist and actual safe SSH readiness. It never changes production command/target functions, disables the pin, or derives a new acceptable pin from the file under test. Source changes require an explicit reviewed pin update. The original baseline loader and evidence remain intact.

The five supplemental regressions retain real private stdin/env/EOF and argv controls; actual local cancellation/forwarding; immediate and late spawn-bookkeeping rejection; and credential cleanup I/O uncertainty with retained non-serialized ownership references. Independent oracle cleanup in the fault case removes only its exact synthetic retained key folder and cannot make the target assertion pass.

These tests qualify transport/local source behavior. They do not establish managed SSH admission/remote owner cancellation and native lease reconciliation, application daemon/downstream completion, a provider grant, or business delivery. No provider/model/OAuth request is made.
