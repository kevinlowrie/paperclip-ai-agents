# Additive native live-inventory preview
Owner: kanban_live. Requested by Kevin during the November 16 live call: connect the board to live work and provide something visible promptly. Existing Vibe planning prototype and Paperclip bundles preserved.

## Serving preview
https://pclip.thehomelab.net/planning-live.html
Three unique static files added to /app/server/ui-dist in current Paperclip pod on exact image 67150cf. No image, existing file, network, access-control, backend, scheduler or job change. This is TEMPORARY: files are lost on pod replacement. Do not describe it as durable delivery.

Read-only same-origin native session, accessible-company list and company-scoped project/first-100-issue API requests. No synthetic cards, dates, forecasts or completion receipts. Company data is not embedded in static files. No tokens or data stored in browser storage. Explicit selection and partial inventory labels.

## Verification
Independent review approved final JS 575321340622a6f8c8fd315402824e40bd43d8b6ee4028b9fedf3b77a39006ba; HTML ae2a5f9f9b8c5b7531680deb15489ef83049ea38136d686ef026628c2674d96f; CSS 1cf5d8dcea8725742dd13c6ab3850a81036ed8a9fb3e6e61eac2938397d1a4fd.
9 Chromium synthetic auth/API checks passed independently: mobile width, blur clearing, forbidden, logout, cross-company rows, final membership account switch, initial multi-company account switch, new account and GET-only requests. No page errors.
Running server returns exact three assets 200. Authless session401 and accessible-company403. External hostname still protected by Cloudflare Access. Actual signed-in inventory acceptance remains pending.

## Why additive
Built clean UI baseline 2bef22830. CSS matches serving UI, but emitted JS differs from serving index-B0ZDvx9R. Do not replace the existing SPA with the old planning inventory full build. New static files avoid that unsafe replacement and preserve callbacks/wrapper/auth changes.

## Durable next step
Package only these three static files as a narrow reviewed overlay atop current exact serving image, retaining all runtime config/layers. Coordinate import/rollout with gang_lane and obtain applicable specific privileged-helper approval if necessary. Verify live signed-in inventory and tenant denial. Persistent Gantt/CAS and scheduling remain separate unfinished work.
