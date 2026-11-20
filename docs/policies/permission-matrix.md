# Permission matrix (target policy)

This matrix states **target policy** for Engineering OS. It is **not** currently enforced by Paperclip, OpenClaw, Cursor, GitHub, or this repository alone.

Technical enforcement will require isolated identities, mounts, network controls, tool authorization, and independent credentials.

## Policy values

| Value | Meaning |
|-------|---------|
| `ALLOW_WITHIN_SCOPE` | Allowed only inside an authorized project/task/sandbox scope |
| `APPROVAL_REQUIRED` | Requires an auditable human approval before proceeding |
| `HUMAN_ONLY` | May be performed only by a human Owner (or delegated human process) |
| `DENY` | Forbidden by default |
| `NOT_IMPLEMENTED` | Desired or future control not implemented yet |

## Actors

| Actor | Notes |
|-------|-------|
| Human Owner | Final authority |
| Principal Software Architect | Designs and reviews; does not replace Owner Git authority |
| Paperclip organizational roles | Candidate org/governance layer; provisional |
| OpenClaw executive role | Candidate Owner-facing interface; provisional |
| OpenClaw coordination role | Candidate coordination plane; provisional |
| Cursor ACP executor | Semi-trusted code executor; must run inside sandbox |
| Sandbox enforcement layer | Mandatory technical boundary |
| GitHub/CI integration identity | Integration authority for code checks; not Owner substitute |

## Matrix

| Action | Owner | Architect | Paperclip roles | OpenClaw executive | OpenClaw coordination | Cursor ACP executor | Sandbox layer | GitHub/CI identity |
|--------|-------|-----------|-----------------|--------------------|-----------------------|---------------------|---------------|--------------------|
| Read project metadata | ALLOW_WITHIN_SCOPE | ALLOW_WITHIN_SCOPE | ALLOW_WITHIN_SCOPE | ALLOW_WITHIN_SCOPE | ALLOW_WITHIN_SCOPE | ALLOW_WITHIN_SCOPE | ALLOW_WITHIN_SCOPE | ALLOW_WITHIN_SCOPE |
| Read repository contents | ALLOW_WITHIN_SCOPE | ALLOW_WITHIN_SCOPE | APPROVAL_REQUIRED | APPROVAL_REQUIRED | ALLOW_WITHIN_SCOPE | ALLOW_WITHIN_SCOPE | ALLOW_WITHIN_SCOPE | ALLOW_WITHIN_SCOPE |
| Modify files within authorized sandbox | HUMAN_ONLY / APPROVAL_REQUIRED | APPROVAL_REQUIRED | DENY | DENY | APPROVAL_REQUIRED | ALLOW_WITHIN_SCOPE | ALLOW_WITHIN_SCOPE | DENY |
| Access another project | APPROVAL_REQUIRED | APPROVAL_REQUIRED | DENY | DENY | DENY | DENY | DENY | DENY |
| Access secrets | HUMAN_ONLY | DENY | DENY | DENY | DENY | DENY | DENY | DENY |
| Use network access | APPROVAL_REQUIRED | APPROVAL_REQUIRED | DENY | DENY | APPROVAL_REQUIRED | DENY | DENY | ALLOW_WITHIN_SCOPE |
| Install dependencies | APPROVAL_REQUIRED | APPROVAL_REQUIRED | DENY | DENY | APPROVAL_REQUIRED | DENY | DENY | NOT_IMPLEMENTED |
| Change host configuration | HUMAN_ONLY | DENY | DENY | DENY | DENY | DENY | DENY | DENY |
| Start or stop services | HUMAN_ONLY | DENY | DENY | DENY | DENY | DENY | DENY | DENY |
| Commit | HUMAN_ONLY | DENY | DENY | DENY | DENY | DENY | DENY | DENY |
| Push | HUMAN_ONLY | DENY | DENY | DENY | DENY | DENY | DENY | DENY |
| Create PRs | HUMAN_ONLY | DENY | DENY | DENY | NOT_IMPLEMENTED | DENY | DENY | NOT_IMPLEMENTED |
| Approve PRs | HUMAN_ONLY | DENY | DENY | DENY | DENY | DENY | DENY | DENY |
| Merge | HUMAN_ONLY | DENY | DENY | DENY | DENY | DENY | DENY | DENY |
| Authorize spending | HUMAN_ONLY | DENY | APPROVAL_REQUIRED | DENY | DENY | DENY | DENY | DENY |
| Privilege escalation | HUMAN_ONLY | DENY | DENY | DENY | DENY | DENY | DENY | DENY |

Notes:

1. For MVP, Git write and merge remain `HUMAN_ONLY` even if a future automation identity exists.
2. Cursor ACP executor file modification is `ALLOW_WITHIN_SCOPE` only when an external sandbox is enforcing the scope.
3. `NOT_IMPLEMENTED` entries must not be treated as grants.

## Target policy vs currently enforced behavior

| Area | Target policy | Currently enforced |
|------|---------------|--------------------|
| Contract schemas and examples | Document intent and denials | Documentary only |
| Agent prompts / `AGENTS.md` | Declarative behavior | Not a sandbox |
| External sandbox | Mandatory for autonomous execution | Gate open (`SANDBOX` pending) |
| GitHub merges | Human-only in MVP | Process/policy; Owner-controlled |
| Paperclip / OpenClaw / ACPX | Least privilege via future adapters | Not integrated |

## Enforcement prerequisites

Before treating any row as operationally enforced, Engineering OS needs:

1. Isolated project identities and credentials.
2. Mount and filesystem controls inside an external sandbox.
3. Network default-deny with explicit exception tooling.
4. Tool authorization independent of prompts.
5. Replay-safe approval verification.
6. Evidence that the SANDBOX gate has passed.
