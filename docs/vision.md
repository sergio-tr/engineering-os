# Product vision — Engineering OS

## Vision

Engineering OS will be a local-first platform for directing software engineering with supervised autonomous agents. The system will manage multiple independent projects through a virtual organization of agents responsible for planning, execution, testing, review, integration, and maintenance.

The value proposition is to increase delivery capacity without surrendering human authority over strategy, risk, budget, and merges.

## User and Owner authority

The human owner (Owner) is the final authority over:

- Strategy and prioritization.
- Budget and cost.
- Risk and sensitive permissions.
- Merge approval.
- Authorization of increments and new tools.

Agents propose and execute within authorized bounds; they do not replace the Owner.

## Multi-project management

Engineering OS must support several independent projects with effective segregation of:

- Code and artifacts.
- Credentials and secrets.
- Agent context and operational memory.
- Budgets and quotas.
- Execution permissions.

Segregation cannot rely only on conventions, prompts, or working directories.

## Full software lifecycle

The system will cover the software lifecycle:

goal → planning → execution → testing → review → integration → maintenance → state reconciliation.

## Supervised autonomy

Autonomy is desirable within clear limits. Critical decisions (security, spend, access, merge, architecture changes) escalate to a human. Automatic continuation happens only after the previous increment’s real integration is verified.

## Main functional requirements

1. Record approved goals and decompose them into tasks.
2. Assign work to agents with budget and scope.
3. Execute code changes in an isolated environment.
4. Run tests and capture evidence.
5. Open or update PRs toward GitHub.
6. Wait for CI checks and human approval.
7. Reconcile state after merge or rejection.
8. Select the next eligible task.

## Main non-functional requirements

1. Local-first, with Owner control over the environment.
2. Least privilege and default-deny.
3. Effective isolation between projects and runs.
4. Persistence and recovery from failure.
5. Idempotency and state reconciliation.
6. Traceability and external evidence.
7. Versioned documentation and decisions.
8. Cost control per task, agent, project, and organization.

No performance figures, monetary budgets, or SLAs are fixed here; they remain out of scope until explicitly agreed.

## MVP scope

The MVP must demonstrate end to end, under human supervision:

**Approved goal → planning → task → controlled execution → tests → PR → CI → human approval → human merge → reconciliation → next eligible task.**

During the MVP, merge is human-only.

## Initial exclusions

Out of initial scope unless later documented otherwise:

- Automerge.
- Fully replacing the human developer.
- A large durable orchestration engine as an early dependency.
- Multi-owner deployment or multi-tenant SaaS.
- Full continuous-operations hardening (planned in M08).
- Full mobile executive experience (planned in M07).
- Adopting OPA, Temporal, or Kubernetes as MVP requirements.

## Reuse-first principle

Before building custom components, Engineering OS must evaluate and reuse existing software (Paperclip, OpenClaw, ACPX, Cursor CLI ACP, GitHub/CI, available sandboxes) whenever it covers the need at acceptable cost and risk.
