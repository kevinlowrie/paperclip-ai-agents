# Self-host operator policy v1

`PAPERCLIP_OPERATOR_CONFIG` is a self-host policy contract, not a Cloud
identity signal. Its full v1 document is `{ v: 1, mode: "operator",
catalogVersion, features, plugins: { autoInstall }, environments? }`.
Feature and plugin sections are required (empty values are explicit); unknown
keys, unsupported versions, unknown/non-managed feature keys, duplicate or
invalid plugin keys, more than one sandbox environment, an environment whose
provider is not auto-installed, and recursive secret-like config keys fail
closed. Provider credentials are supplied only through process secret
resolution. Parser errors never include rejected credential values.

The parser and runtime selector reject operator config combined with either
Cloud managed config or a nonblank Cloud tenant token, before cache use. The
runtime policy is the direct selected config object, with `mode` distinguishing
`operator` from `cloud`; no wrapper or DB persistence is introduced.

## Guard matrix

| Behavior | Cloud policy | Operator policy |
|---|---|---|
| Experimental feature overlay / catalog defaults | Yes, owner `paperclip-cloud` | Yes, owner `operator` |
| Bundled plugin provisioning and install-source floor | Yes | Yes |
| Adapter code install floor | Yes | Yes |
| Managed environment provisioning, row ownership, edit/delete and marker floor, secret redaction | Yes | Yes |
| Cloud actor/header trust, Cloud tenant company identity, Cloud sign-in/health identity | Yes | No |
| Cloud-only company/import, backup, actor, bootstrap/lifecycle behavior | Yes | No |

No auth/session bridge is established by this policy. Company isolation,
credential separation, secret-like-key rejection, sandbox execution floors,
and egress restrictions remain in force. No schema migration is required.
