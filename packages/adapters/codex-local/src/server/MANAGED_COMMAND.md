# Opt-in managed Codex command package

This source change does not deploy a wrapper or change an agent configuration.
It provides an explicit adapter-config `managedCommand` package independent of
the selected project checkout. Without this field, command behavior is unchanged.
The field requires a remote target. It is trusted operator adapter configuration,
not task or workspace content.

Example shape (replace both digest placeholders with reviewed file hashes):

```json
{
  "managedCommand": {
    "sourceDir": "/opt/paperclip/operator-command",
    "entrypoint": "wrapper.mjs",
    "files": [
      {"path":"wrapper.mjs","sha256":"REPLACE_WITH_REVIEWED_64_HEX_SHA256"},
      {"path":"bridge.mjs","sha256":"REPLACE_WITH_REVIEWED_64_HEX_SHA256"}
    ]
  }
}
```

The example sourceDir is not an existing mount. Package files must be available
on the actual Paperclip server runtime that prepares the sandbox. A path on a
developer computer is insufficient. Reverify hashes at packaging and adoption.
Do not include credential files in this package.

Only listed, digest-matching regular-file bytes enter a private run snapshot.
Observed symlinks, traversal and duplicate paths are rejected. Reads and manifest
sizes are bounded. Ancestor checks are not atomic directory containment locks;
immutable hashes bind copied bytes. Unlisted files are not copied. The command
asset preserves sibling imports and has no restore or copy-back callback.

Installation detects the underlying `codex` CLI before assets exist. This is
not wrapper readiness proof. After upload, wrapper preflight and execution use
the same mapped command path and realized target/cwd. Missing assets fail
closed and restore the prepared workspace. They do not use the old command.

An operator wrapper can require a fixed CODEX_HOME, CLI location, or CA file.
Verify those requirements for the actual provider and wrapper; this feature does
not relax them. The sandbox seam test checks a fixture home at
`/workspace/.paperclip-runtime/codex/home` with mock transport. Generic SSH tests
do not establish compatibility with any fixed-home production wrapper.

Adoption requires a reviewed source build, a reviewed package on the server,
and an approved adapter configuration. Inspect existing queued work before any
retry. Verify command and sibling files inside the actual sandbox, authenticated
initialization, and cleanup. Separately verify the real task and durable output.
No live run, credentials, network, scheduler, or runtime configuration changed
as part of this source patch.

