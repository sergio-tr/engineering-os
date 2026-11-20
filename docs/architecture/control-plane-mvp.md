# Control Plane MVP (EOS-01 / EOS-02 / EOS-03)

## Purpose

Local-first operational control plane for Engineering OS. This document describes the
implemented MVP application, not a future distributed architecture.

## Boundaries

| Layer | Responsibility |
|-------|----------------|
| Domain | Projects, goals, tasks, executions, approvals, operational events, state machines |
| Application | ControlPlane services, SequentialOrchestrator |
| Infrastructure | SQLite repository, synthetic/disabled adapters |
| Interfaces | CLI (`scripts/eos.py`), localhost HTTP API, static dashboard (`web/`) |

Canonical contract schemas under `docs/contracts/` remain separate. Operational records
do not modify those schemas.

## Persistence

- SQLite via the Python standard library
- Default DB path: `$XDG_DATA_HOME/engineering-os/control-plane.sqlite3` (outside the Git tree)
- Override: `EOS_DB_PATH` or `--db`
- Foreign keys, unique idempotency keys, optimistic versioning on mutating aggregates
- Append-only `operational_events`
- Durable per-project orchestration claims

## Execution policy

- `SyntheticExecutionAdapter`: in-process simulation only (no subprocess, container, Cursor, or ACP)
- `DisabledLiveExecutionAdapter`: always rejects live execution while SANDBOX gate ≠ PASS
- A stored human/synthetic approval is not technical authorization for live ACP
- Success requires configured evidence references; a zero exit alone is insufficient

## Orchestration (EOS-03)

`SequentialOrchestrator`:

1. Selects the next dependency-eligible READY task
2. Claims the project (one active execution by default)
3. Dispatches synthetic work
4. Moves to `AWAITING_INTEGRATION` with simulated PR/CI
5. Requires an explicit synthetic Owner merge decision
6. Reconciles state, clears the claim, unlocks dependents
7. Recovers after process restart without silently duplicating SUCCEEDED work

Simulated merge evidence is labeled `simulated_integration` and is never treated as an
externally verified GitHub merge.

## Adapter map (candidate future wiring)

| Interface | Local MVP | Candidate system |
|-----------|-----------|------------------|
| OrganizationAdapter | LocalOrganizationAdapter | Paperclip |
| CoordinatorAdapter | LocalCoordinatorAdapter | OpenClaw |
| ExecutionAdapter | Synthetic / DisabledLive | ACPX → Cursor CLI ACP |
| EvidenceAdapter | LocalEvidenceAdapter | Local + CI artifacts |
| RepositoryIntegrationAdapter | SimulatedRepositoryIntegrationAdapter | GitHub/CI (read-only observation first) |
| ApprovalProvider | LocalOwnerDecisionProvider | Human Owner decisions |

No live Paperclip, OpenClaw, ACPX, Cursor ACP, or GitHub mutations are started by this MVP.

## Security notes

- HTTP server binds to `127.0.0.1` by default
- Mutation endpoints require CSRF token + Origin checks
- Live ACP controls are not exposed in the UI
- SANDBOX gate remains independently governed; this MVP does not declare SANDBOX PASS

## Assumptions

- Python ≥ 3.10 standard library only (no third-party runtime dependencies)
- Single-operator local use for the MVP
- English repository artifacts; Owner chat may be Spanish
