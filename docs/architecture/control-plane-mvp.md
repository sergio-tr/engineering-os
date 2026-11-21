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

## GitHub read-only integration (EOS-04)

- `GitHubReadOnlyClient` uses the GitHub REST API over HTTPS only (stdlib urllib)
- `GitHubReadOnlyRepositoryAdapter` observes repository/PR/CI/review state
- Synthetic command methods (`simulate_pr`, `record_owner_merge_decision`) are fail-closed on the real adapter
- Connections, explicit execution↔PR links and observations persist in SQLite (no tokens stored)
- Evidence classes distinguish `SYNTHETIC` / `simulated_integration` from `LIVE_READ_ONLY`, `CACHED`, `EXTERNALLY_VERIFIED`, `ERROR`
- Real network sync occurs only when the Owner configures a connection and invokes sync (token via `EOS_GITHUB_TOKEN`)

## ACP / Cursor integration (EOS-06)

Intended path: Engineering OS → SequentialOrchestrator → AcpExecutionAdapter →
OpenClaw ACP backend → ACPX → Cursor CLI ACP.

Implemented locally:

- JSON-RPC ACP protocol helpers (`acp_protocol`) with request correlation and size bounds
- Durable `acp_sessions` / `acp_session_events` in SQLite (separate from task lifecycle)
- `AcpSessionManager` + `AcpExecutionAdapter` with deny-by-default permissions
- `InMemoryAcpTransport` for synthetic end-to-end protocol simulation
- `OpenClawAcpxExecutionTransport` and `CursorAcpAdapter` contracts (no live process spawn)
- `DisabledLiveAcpTransport` rejects live dispatch while SANDBOX ≠ PASS (service + transport)
- CLI: `eos acp status|capabilities|sessions|session|demo-fixture|cancel`
- Dashboard ACP runtime / sessions / timeline panels (SYNTHETIC only; no live ACP button)

Synthetic ACP success is not real Cursor execution. Live OpenClaw→ACPX→Cursor dispatch
remains blocked until an externally enforced sandbox launcher authorizes it.

## ACPX sandbox bridge (EOS-07)

Intended topology: ControlPlane → SequentialOrchestrator → trusted authorization →
OpenClaw/ACPX session control → sandbox-enforced Cursor ACP launcher → rootless Podman →
Cursor ACP inside an isolated OCI environment.

Implemented locally:

- Gateway client over injected transports (`operator.read` scopes; no silent pairing)
- Itemized ACPX/Cursor/sandbox readiness (not a single boolean)
- `SandboxExecutionSpec` + fail-closed Podman argv planner
- Host-side runtime authorization model (issuance disabled outside test fixtures)
- Durable `runtime_preparations` records
- Synthetic bridge demo (`eos acpx demo-fixture --temp`) with mock sandbox + ACP

Critical constraint: OpenClaw ACP harnesses run on the host; `sandbox=require` is not
ACP isolation evidence. Direct host Cursor ACP and unauthenticated launches stay rejected.

## OCI ACP fixture execution (EOS-08)

`PodmanSandboxExecutor` turns sandbox specifications into a process boundary:

- Fixed Podman argv (rootless policy, network none, cap-drop, no-new-privileges, tmpfs)
- NDJSON ACP stdio transport (`OciAcpStdioTransport`) over the process handle
- Minimal Alpine/BusyBox ACP fixture (`fixtures/acp_fixture.sh`) — not Cursor
- Owner triple-gate for real execution: `--execute --allow-phase-b --owner-authorize-runtime-execution`
- Injected process factory for offline tests/demo (no containers in CI)
- Durable `oci_fixture_runs` evidence with provenance `SYNTHETIC_IN_MEMORY` /
  `SYNTHETIC_OCI_EXECUTED` (never `CURSOR_ACP_LIVE`)

HTTP API exposes readiness/history/offline demo only; real OCI launch is CLI/Owner-only.

## Cursor ACP runtime integration (EOS-09)

Preparation path for real Cursor ACP inside the same Podman boundary:

- `containers/cursor-acp/Containerfile` + `image-profile.json` (definition only; no build)
- Command mapping from verified profile (`agent acp` / `cursor-agent acp`)
- Credential provider interface (`CURSOR_API_KEY`) without secret persistence
- Network policy interface (deny-all / unenforced blocked / fixture allowlist)
- Disposable workspace preparation under `/tmp/eos-workspaces`
- ACPX command proposal that routes through the EOS sandbox launcher
- Durable `cursor_preparations` records and offline `eos cursor demo-fixture`

Live Cursor ACP launch remains disabled. SANDBOX is not declared PASS.

## Cursor live readiness (EOS-10)

Operational components required before a controlled Cursor ACP experiment:

- Graceful OCI lifecycle: stdin EOF → SIGTERM → SIGKILL fallback; independent
  `protocol_completed` vs `process_exited_cleanly` / `termination_reason` /
  `cleanup_verified` fields (addresses EOS-08 `exit=-9` attribution)
- Owner image build-plan / inspect / verify with machine-readable evidence
  (no floating `latest`; no automation builds; Cursor install via documented sources)
- Read-only WSL2 preflight with STATIC/HOST/RUNTIME/NOT_TESTED/BLOCKED evidence
- Credential broker: fixture + Owner env-file provider (disabled by default);
  secrets never in SQLite/argv/logs; env injection does not claim peer isolation
- Concrete pasta allowlist egress enforcer for rootless Podman (fail closed if missing)
- Runtime authorization bound to execution/task/workspace/image/command/creds/network
- Cursor OCI launcher + smoke dry-run; execute path requires SANDBOX PASS + host auth
  + Owner triple-gate (HTTP never exposes live execute)
- Orchestrator runtime modes: `SYNTHETIC_IN_MEMORY`, `SYNTHETIC_OCI_EXECUTED`,
  `CURSOR_ACP_LIVE` (last remains blocked until prerequisites)

## Assumptions

- Python ≥ 3.10 standard library only (no third-party runtime dependencies)
- Single-operator local use for the MVP
- English repository artifacts; Owner chat may be Spanish
