<!-- source-sha256: 5b8249bda78cc33e -->
# 33: Remediation actions for data-at-rest

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M3
Blocked by: 31
Spec: `../spec.md` §4.3 FR-DATA-6; §4.6 quarantine/remediate

## Context
Closing the oversharing that was found.

## Scope
- Actions: revoke anonymous links, remove broad groups, apply labels, quarantine.
- Actions run only with approval according to policy.
- Dry-run + audit log + undo capability where the API supports it.

## Acceptance criteria
- [x] Dry-run vs execution test. *(Two levels. SDK contract (`connectortest`, applies to all connectors): a dry-run changes nothing and gives the same steps for the same state, execution runs exactly those steps, afterwards `ErrNothingToDo`, and undo restores when offered. Per connector: M365 and Drive verify that the dry-run produces not a single write call to the source (including not creating the quarantine folder); S3 against real MinIO. Flow (`remediate.TestDryRunApproveExecute`, Postgres + fake Graph + scanner): the plan is stored without any write, execution = plan, the asset's exposure drops (60 → 6).)*
- [x] Action without approval is rejected. *(A request that has not been approved is never executed by the worker; the requester cannot approve their own request (403); the executor still rejects (`ErrNotApproved`) rows that are "approved" without an approver or with approver = requester (tested by forging rows in the DB); approval of a plan that has since changed at the source → `stale`, no write; a plan not approved within 72 hours → `expired`. A mutation test (executor guard removed) makes the test fail.)*

## Decisions
- **SDK contract**: `Remediate(item, action, dryRun) → Change{Steps, Undo}` and `Undo(item, undo, dryRun)`. Actions: `revoke_anyone_links`, `remove_grants` (used for both "remove broad groups" and external users/domains, with explicit grantees from the asset's ACL), `apply_label`, `quarantine`. Steps are deterministic so plans can be compared before execution. `ErrNothingToDo` and `ErrNotSupported` are distinguished.
- **"According to policy" = four-eyes for every action**: requested by a holder of `data.remediate` (dlp_analyst, security_admin), approved by a holder of `data.remediate.approve` (security_admin, break_glass) who is not the requester. Approval is always on the dry-run plan that was displayed; the worker re-plans right before execution and executes only if the plan is identical. Undo is its own request with the same flow, because it restores exposure. All transitions are audited (request, plan, approve/reject, execute, stale, failed, nothing_to_do).
- **Capabilities per source**:
  - **M365**: all four actions. Undo: users are re-invited, the previous label is restored, files are moved back. Anonymous links and site groups cannot be restored (marked "not restorable" in the plan).
  - **Google Drive**: revoke, remove_grants, quarantine. Undo restores exactly (permissions recreated with the same file URL). Drive labels are not supported yet.
  - **S3/MinIO**: quarantine to a quarantine bucket (`<bucket>/<key>`) with undo. Public access on object storage is set per bucket, so per-object revoke is not supported.
  - **Azure Blob and Compliance API**: not supported (`ErrNotSupported`).
- **Quarantine** = move to the "WANTIMPRES-26 Quarantine" folder/bucket and revoke all explicit sharing except the owner. Inherited permissions are not removed at the item level; the plan fails with a message to remediate the parent folder.
- **Write credentials are separate** from the read-only scan credentials: a second M365 app registration, the `drive` scope for Drive, and separate S3 keys. Without write credentials, the source cannot be remediated.
- After execution, the asset is refreshed (`Scanner.Refresh`): grants, label, flags, and exposure are re-read without changing the path hash or content tag.
- **API** (control-plane):
  - `POST /data/assets/{id}/remediations {action, note}` (`data.remediate`);
  - `GET /data/remediations[?state=&asset_id=]` and `GET /data/remediations/{id}` (`dashboard.read`);
  - `POST /data/remediations/{id}/approve|reject` (`data.remediate.approve`);
  - `POST /data/remediations/{id}/undo` (`data.remediate`).
- The executor runs in `connector-worker` every 30 seconds. Rows are locked (`FOR UPDATE SKIP LOCKED`) so replicas do not execute twice.

## Local verification results (2026-10-05)
- `go test -race ./...` with Postgres, MinIO, and Azurite green; golangci-lint 0 issues (lint found a shadowed `err` in the M365/Drive quarantine, now fixed); `connector-worker` and `control-plane` images build. Not yet tested against a real M365/Google tenant.

## Remaining / follow-up
- A configurable policy matrix (e.g. revoke anonymous link on restricted without approval, or two-level approval for bulk quarantine); currently four-eyes for everything.
- Notification to approvers and to file owners; bulk remediation per container or flag.
- Google Drive labels; Azure quarantine (needs a write SAS) and GCS.
- The DB transaction stays open during the source API call at execution (guarantees a single execution per request); monitor if the API is slow.
- The M365/Drive quarantine folder must have its access restricted by an admin at deploy time (Graph/Drive cannot break inheritance through this API).