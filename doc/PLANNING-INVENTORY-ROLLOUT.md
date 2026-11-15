# Native planning inventory: separate UI-only rollout candidate

## Offline artifact receipt
- Source: 4c3e62d08e908685f74e41265dd6c4e12db6d355
- Native base: 2bef22830e8dee4671e41350d69c152a18c921da
- UI change: 2e425c863; subsequent commit contains browser tests only.
- Local archive: pclip-planning-inventory-4c3e62d08-ui.tar.gz
- Archive SHA256: 0ee9ef3eb408f93dadb0395f48ede3f3c1308918cad00caaa82baddcf88909fe
- Archive: 5,765,362 bytes, 428 static files.
- File manifest: pclip-planning-inventory-4c3e62d08-manifest.json
- Manifest SHA256: 34a5d512f73a023886b35dc6d97a2674a1ac8c7ec1f00ec8e5035be574b35ca9
- Both artifacts are local build outputs under /tmp, not uploaded, imported or deployed.
- Full production Vite build and full UI TypeScript passed. Seven source tests
  and eight Chromium lifecycle checks passed, independently reviewed.
- Browser identity/API are synthetic. No live user-session or tenant-isolation
  acceptance is claimed.

## Ownership and boundary
The active rollout is callback-only and belongs to the callback integration
owner. This UI candidate is explicitly separate and must not be folded into that
approval or deployed concurrently. It changes no backend, authentication,
membership, network policy, credentials, storage or deployment configuration.
Do not substitute this old-base bundle for the current deployed UI blindly.

## Before any separate rollout
1. Obtain the callback owner's final deployed image digest and source identity.
2. Compare the current deployed UI source with the base above. If it differs,
   cherry-pick only the reviewed UI source change onto the current UI base in an
   isolated candidate, preserving callback/backend source and existing UI work.
   Re-run build, full TypeScript and all scoped source/browser tests.
3. Produce a new exact artifact manifest if any source/build input differs.
4. Prepare a separate rollback to the prior complete image/static artifact,
   including service-worker/cache compatibility; keep the existing backend.
5. Secure the applicable specific rollout approval. No approval is inferred from
   source review or from the callback-only deployment.

## Live acceptance after an authorized separate rollout
- Use the existing native signed-in board session; no Firebase token reuse.
- Select an authorized company and visit its existing prefix followed by
  /planning-inventory. Verify projects and the bounded first issue page against
  the native server responses.
- Verify no previous company's/account's rows remain on logout, account change,
  denied membership, refresh failure or delayed prior requests.
- Verify unauthenticated and unauthorized company access are denied server-side.
- Check mobile rendering and existing native board routes.
- The view must say partial authorized inventory and unscheduled. Fewer than
  100 rows does not imply exhaustive coverage because actor filtering follows
  server pagination. It must not invent dates, dependencies, sprints or claims
  of worker execution.
- This is a practical read-only inventory milestone, not full Vibe Gantt/CAS,
  natural-language adjustment, Firebase integration or autonomous execution.

## Current blocker
No separate UI rollout has occurred. The post-callback deployed UI identity has
not yet been reconciled, and real signed-in browser acceptance remains pending.
