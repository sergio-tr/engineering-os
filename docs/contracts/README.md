# Engineering OS canonical contracts

## Purpose and ownership

These contracts are **Engineering OS-owned data models**. They define the intended shape of project boundaries, agent roles, bounded executions, and human approvals.

They are **not** confirmed native configuration formats for Paperclip, OpenClaw, ACPX, Cursor, or GitHub.

## Version and maturity

| Field | Value |
|-------|--------|
| Contract version | `0.1.0` |
| Schema dialect | JSON Schema Draft 2020-12 |
| Maturity | Provisional |

No backward-compatibility promise is made before an explicit versioning policy is accepted.

## The four models

| Kind | File stem | Role |
|------|-----------|------|
| `ProjectProfile` | `project-profile` | Project identity and authorized boundaries |
| `AgentProfile` | `agent-profile` | Logical agent role and declared capabilities |
| `ExecutionContract` | `execution-contract` | One authorized, bounded execution request |
| `ApprovalContract` | `approval-contract` | Scoped, auditable human decision |

Relationship:

1. A `ProjectProfile` defines isolation and default denials for a project.
2. An `AgentProfile` declares what a logical role may request within assigned projects.
3. An `ExecutionContract` binds one run to project, task, agent, scope, sandbox, and ceilings.
4. An `ApprovalContract` records a human decision related to an execution or privilege request.

## Intent vs enforceable permissions

| Represented in contracts | Not enforced by contracts alone |
|--------------------------|----------------------------------|
| Declared scope and denials | Kernel/container mounts and process isolation |
| Requested tool access | Actual tool authorization |
| Default-deny network policy | Real network controls |
| Approval decision records | Identity proof, replay protection, expiry enforcement |
| Git-write disabled by default | Host Git credentials and hooks |

An agent role is **not** an operating-system identity. An approval record does **not** grant technical access by itself. The sandbox must enforce restrictions independently of prompts and contracts.

## Lifecycle and compatibility

1. Authors propose schema and example changes in an authorized increment.
2. Local validation runs via `scripts/validate_contracts.py`.
3. The Owner integrates changes through human-only Git review.
4. Future adapters may translate canonical contracts into native tool configs **after** PoCs confirm those mappings.

Until a compatibility policy is accepted, treat `0.1.0` as mutable provisional design.

## Approval and authorization limitations

- Approvals cannot bypass the mandatory external sandbox.
- Approvals cannot bypass the MVP human-only merge rule.
- Enforcement components must independently verify identity, authorization, scope, expiry, and replay.

## Expected use by future adapters

Later adapters may map these contracts into Paperclip, OpenClaw, ACPX, Cursor, sandbox, or GitHub settings. Native integration mappings must wait for verified PoCs. Do not assume field-for-field compatibility.

## How to validate

From the repository root:

```bash
python3 -B scripts/validate_contracts.py
```

The script always runs standard-library baseline checks. If the local `jsonschema` package is already installed, it also:

1. Meta-validates each schema with `Draft202012Validator.check_schema()`.
2. Validates each example against its schema with `Draft202012Validator`.
3. Re-validates each example with a `FormatChecker` so `format` keywords (for example `date-time`) are asserted explicitly.

It never installs packages or uses the network. Nested objects that need closed shapes declare their own `additionalProperties: false`; top-level rejection alone does not close nested objects.

## What remains untested

- Runtime adapters and native tool translations.
- Live sandbox enforcement.
- Cryptographic identity for approvers.
- End-to-end orchestration.
- Production budget enforcement.

## Layout

```
docs/contracts/
  README.md
  schemas/
    project-profile.schema.json
    agent-profile.schema.json
    execution-contract.schema.json
    approval-contract.schema.json
  examples/
    project-profile.example.json
    agent-profile.example.json
    execution-contract.example.json
    approval-contract.example.json
```

Examples are synthetic and illustrative. They are not deployment configurations and do not imply an operational platform.
