# Paperclip MCP Server

Model Context Protocol server for Paperclip.

This package is a thin MCP wrapper over the existing Paperclip REST API. It does
not talk to the database directly and it does not reimplement business logic.

## Authentication

The server reads its configuration from environment variables:

- `PAPERCLIP_API_URL` - Paperclip base URL, for example `http://localhost:3100`
- `PAPERCLIP_API_KEY` - bearer token used for `/api` requests
- `PAPERCLIP_COMPANY_ID` - optional default company for company-scoped tools
- `PAPERCLIP_AGENT_ID` - optional default agent for checkout helpers
- `PAPERCLIP_RUN_ID` - optional run id forwarded on mutating requests

Inside an active heartbeat, Paperclip also injects `PAPERCLIP_RUNTIME_TOOLS_*` variables. They enable the run-scoped `connections_search` and `connection_request` tools and expire with the run.

To enable the routed developer-team tool, configure these variables on the MCP
server process (keep the team key in its secret store; it is never a tool
argument or returned value):

- `PAPERCLIP_MODEL_ROUTER_URL` - internal base URL for the model-router service
- `PAPERCLIP_DEVELOPER_TEAM_URL` - internal base URL for the Paperclip team API
- `PAPERCLIP_DEVELOPER_TEAM_KEY` - bearer credential for that team API

`paperclipRouteDeveloperTask` sends project/task context to the model router,
then dispatches the selected scope to the Paperclip team using one stable
request ID. Classification token/cost receipts are returned with the team job.
The team API passes that ID and an optional external job label through Redis
and worker requests. Worker inference stays behind LiteLLM and carries those
identifiers as request tags. `paperclipDeveloperJobCost` reads the filtered
LiteLLM spend logs through the router; its read key is held by the router and
does not reach the MCP client.

`paperclipMyTodos` combines the authenticated agent's inbox-lite list with its
assigned Paperclip issues. `paperclipListIssues` accepts a `q` filter for
questions such as “what is the status of inbox cleanup?”. These tools are
read-only and use the Paperclip identity configured for this MCP process.

## Usage

```sh
npx -y @paperclipai/mcp-server
```

Or locally in this repo:

```sh
pnpm --filter @paperclipai/mcp-server build
node packages/mcp-server/dist/stdio.js
```

## Tool Surface

Run-scoped connection tools:

- `connections_search`
- `connection_request`

Read tools:

- `paperclipMe`
- `paperclipInboxLite`
- `paperclipMyTodos`
- `paperclipDeveloperJobCost`
- `paperclipListAgents`
- `paperclipGetAgent`
- `paperclipListIssues`
- `paperclipGetIssue`
- `paperclipGetHeartbeatContext`
- `paperclipListComments`
- `paperclipGetComment`
- `paperclipListIssueApprovals`
- `paperclipListDocuments`
- `paperclipGetDocument`
- `paperclipListDocumentRevisions`
- `paperclipListProjects`
- `paperclipGetProject`
- `paperclipGetIssueWorkspaceRuntime`
- `paperclipWaitForIssueWorkspaceService`
- `paperclipListGoals`
- `paperclipGetGoal`
- `paperclipListApprovals`
- `paperclipGetApproval`
- `paperclipGetApprovalIssues`
- `paperclipListApprovalComments`

Write tools:

- `paperclipRouteDeveloperTask`

- `paperclipCreateIssue`
- `paperclipUpdateIssue`
- `paperclipCheckoutIssue`
- `paperclipReleaseIssue`
- `paperclipAddComment`
- `paperclipSuggestTasks`
- `paperclipAskUserQuestions`
- `paperclipRequestConfirmation`
- `paperclipUpsertIssueDocument`
- `paperclipRestoreIssueDocumentRevision`
- `paperclipControlIssueWorkspaceServices`
- `paperclipCreateApproval`
- `paperclipLinkIssueApproval`
- `paperclipUnlinkIssueApproval`
- `paperclipApprovalDecision`
- `paperclipAddApprovalComment`

Escape hatch:

- `paperclipApiRequest`

`paperclipApiRequest` is limited to paths under `/api` and JSON bodies. It is
meant for endpoints that do not yet have a dedicated MCP tool.
