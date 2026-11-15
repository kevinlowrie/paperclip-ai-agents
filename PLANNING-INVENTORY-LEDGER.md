# Native planning inventory alternative
Owner: kanban_build; isolated branch, local ledger fallback; no Redis lock claimed.
Only new PlanningInventory page and protected company route; no auth/backend changes.
Existing native cookie session and selected company context remain authority.
Read-only first 100 issue rows, explicitly partial authorized view, not full backlog.
No scheduled dates, sprints or dependencies are invented. This is an alternative
native authenticated mount, not a deployed Firebase or Vibe Gantt integration.
No Antigravity or callback files are modified. Independent review required.

Verification command (installed dependencies only):
node node_modules/vitest/vitest.mjs run --config vitest.planning.local.mjs
Five scoped source/rendering tests pass. No browser, real user session, full UI
build, deployed endpoint, cross-company live rejection, or execution receipt
has been verified. No UI Gantt or schedule writes are exposed in this alternative.
Route after normal company selection: existing company prefix + /planning-inventory.
The server must continue enforcing company membership on every request.

Independent source review approved final page SHA0081509eb8119e7d1c5af854fcbc7efa3346e20d2dfa31ffc21f81a8c6b9ddbd.
Seven offline source/rendering tests independently pass. Account/membership
gating, account/company cache keys and noncoalesced native requests address the
review findings. Full UI build/browser lifecycle/live authentication remain
unverified, and this commit is not deployment approval.

Follow-up verification: full native Vite production build passed on candidate
2e425c863 (7670 modules, existing large-chunk/CSS warnings). Eight Chromium
lifecycle assertions pass with real React Query but synthetic identity/API
boundaries: membership gating, delayed prior-account response, same-company
account switch, logout, company switch, and failed refresh clearing.
Run PORTAL_PLAYWRIGHT_MODULE=/path/to/installed/playwright/index.mjs
node scripts/test-planning-inventory-browser.mjs. Loopback only; test server and
browser close afterward. This does not verify deployed authentication or a live
user session. Fixtures are outside production ui/src.

Independent browser-test review approved: eight Chromium checks, zero page errors.
Full UI TypeScript noEmit also passed after linking already-installed React/type
dependencies into the isolated SDK package's ignored node_modules. No packages
downloaded and no shared dependency tree modified. Production page unchanged.
