# Harmonized Branch, Hook, Release & Nomenclature Policy (`dev-branch-policy/v1`)

## 1. Branch Classes & Release Pipeline

All 14 repositories in the Homelab Voltron ecosystem follow a six-stage protected
branch model paired with branch-aware local hooks (`scripts/hook_policy.py`) so
developer agents can iterate rapidly on WIP/worktree/stacked PR branches while
keeping domain baselines and production artifacts strictly gated:

| Branch Class | Local Hook Profile | Required Remote CI & Promotion Gate | Role in Release & Day-2 Operations |
| --- | --- | --- | --- |
| `wip/*`, `feat/*`, `fix/*`, `docs/*`, `codex/*`, `chore/*`, worktree & stacked PR branches | **FAST** (default) | Fast changed-file checks; path-scoped unit/lint checks | Rapid dev-agent iteration inside local gang-leaders (`commit -> push -> sync -> pull -> checkout -> repeat`). Skips full multi-minute `make ci` harness on `pre-push`. |
| `main` (or `master`) | **FULL** | Full domain CI gate + PR review + branch protection | Domain integration baseline. Every repository's `main` enforces the full domain pre-commit and pre-push gate. |
| `testing` | **FULL** | Full domain CI + staging/smoke/contract conformance | Staging and cross-component QA candidate promoted from green `main`. |
| `freeze` | **FULL** | Full domain CI + change-control review | Pre-release freeze branch; accepts only tracked bug/security fixes. |
| `release-candidate` (`rc/*`) | **FULL** | Full domain CI + **A/B rollback, migration & telemetry plan** | Release candidate verification branch. Promotion requires a verified A/B rollback plan, schema/config migration dry-run, and live telemetry/health verification gates. |
| `release` (`release/*`) | **FULL** | Full domain CI + artifact build, pruning, sanitization & provenance | Generic deployable artifacts and container/package images for each subsystem, with extra dev/test material pruned and all code/configs sanitized for public consumption (even when kept private). `prod` pulls immutable artifacts from `release`. |
| `prod` | **FULL** | Full domain CI + immutable digest verification + rollback pin | Internal protected customer-live overlay branch. Pulls digest-pinned artifacts from `release` and applies the production environment overlay for live deployment and day-2 operations. |

## 2. Repository Nomenclature (`*-ops-thl` vs. `thl-*` vs. `hl-*`)

| Nomenclature | Scope & Examples | Governance & Patch Policy |
| --- | --- | --- |
| `{{internal-name}}-ops-thl` | Controlled OSS build forks we own: `pclip-ops-thl` (renamed from `paperclip-operator-private`), and target controlled forks `airoute-ops-thl`, `vibekanban-ops-thl`, `genkit-ops-thl`. | **Fork-and-cherry-pick policy:** track `upstream` read-only, maintain minimal cherry-picked patches on a verified base, and run automated CVE/dependency updates so security patches land via fast version bumps without large rewrites. |
| `thl-*` | Customer-facing THL-branded frontend and substrate glue: `thl-pclipd-api`, `thl-cf-workflows-template`, `do-n8n-template`. | Presented under **TheHomeLab (THL)** branding. Must not expose upstream OSS branding to customers. Validated via substrate/harness checks and deployment templates. |
| `hl-*` & `homie-gang-leader` | Core platform split forks (`hl-server-side`, `hl-middle-mgmt`, `hl-client-delivery`, `hl-client-ux`) and local gang-leader runtime (`homie-gang-leader`). | Governed by `homelab/docs/workspace/REPOSITORY_CONTRACTS.md` and the 3-amigos RED -> GREEN -> CLEAN workflow. |

## 3. OpenViking Agent Awareness vs. SQLite Boundary

- **OpenViking (`openviking-sync/v1`)** is the single authoritative local
  agent-awareness and instruction-sync store inside `homie-gang-leader`
  (`workstation/openviking/context.py`, `viking://~/resources/homie-*.md`).
- **No SQLite Awareness Drift:** Do not create or commit `.sqlite`, `.sqlite3`,
  or `.db` files for agent awareness, instruction caching, or session memory.
  `scripts/hook_policy.py` and `workstation/core/pr_pipeline.py` fail closed if
  SQLite awareness files are introduced.
- **Transactional Service Stores Remain Distinct:** Application-native databases
  (such as K3s PostgreSQL `consumer_authority`, `n8n` internal state, or
  `pclipd-sqlite-mcp` device outbox) are transactional runtime stores, not agent
  awareness memory.

## 4. Repeatable Gang-Leader Agent Onboarding & PR Pipeline

Agents launched inside a local gang-leader workstation onboard and drive PR
slices end-to-end using `homie-gang-leader/workstation/core/pr_pipeline.py`
(`workstation/homie agent-onboard` and `workstation/homie pr-pipeline`):

1. `onboard`: verifies repo instructions (`AGENTS.md`, `dev-branch-policy.md`),
   checks zero SQLite awareness drift, syncs awareness note to OpenViking, and
   confirms branch-aware hook profile (`fast` vs `full`).
2. `pull`: fetches the PR/branch into an isolated task worktree.
3. `own`: records an atomic single-writer claim over declared `owned_paths` and
   syncs the claim note to OpenViking.
4. `commit`: enforces `owned_paths`, rejects backup artifacts/secrets, runs
   `scripts/hook_policy.py pre-commit`, and commits with structured trailers.
5. `push`: runs `scripts/hook_policy.py pre-push`, pushes the branch to the
   remote, updates OpenViking, and emits a mode-`0600` receipt
   (`homie.pr-pipeline-receipt/v1`).
