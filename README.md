# engineering-os

Management platform for autonomous AI agents

## What Engineering OS is

Engineering OS is a **local-first** platform for autonomous, supervised software engineering. Its goal is to manage multiple independent projects through a virtual organization of agents that plan, execute, test, review, integrate, and maintain software, always under final human authority.

## Current status

Documentary foundation, versioned backlog, and governance contracts are in place.
An **operational MVP control plane** is available for local synthetic workflows
(SQLite + CLI + localhost dashboard). Live Cursor ACP execution remains **disabled**
until the SANDBOX isolation gate is approved.

See [docs/architecture/control-plane-mvp.md](docs/architecture/control-plane-mvp.md).

### Quick start (local MVP)

```bash
# Initialize DB (default: ~/.local/share/engineering-os/control-plane.sqlite3)
python3 scripts/eos.py init

# Idempotent persistent SYNTHETIC demo (visible in the dashboard)
python3 scripts/eos.py seed
# equivalent: python3 scripts/eos.py demo

# Ephemeral demo (temporary DB; for CI/local checks)
python3 scripts/eos.py demo --temp

# Start localhost dashboard (127.0.0.1:8765)
python3 scripts/eos.py serve --host 127.0.0.1 --port 8765

# Run tests (stdlib unittest; no package install required)
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

After `seed`, open http://127.0.0.1:8765 — the overview and project list show persisted
demo data (`proj-eos-mvp-demo`). Re-running `seed` is safe (idempotent).

Synthetic executions and simulated PR/CI/merge checkpoints are labeled **SYNTHETIC**.
They are not real agent runs or real GitHub merges.

### GitHub read-only integration (EOS-04)

```bash
# Offline fixture demonstration (no network)
python3 scripts/eos.py github demo-fixture --temp

# Owner-authorized live read-only sync (optional token for private repos)
export EOS_GITHUB_TOKEN=ghp_readonly_only   # never committed; not stored in SQLite
python3 scripts/eos.py github connect OWNER/REPO --project-id PROJECT_ID
python3 scripts/eos.py github sync --project-id PROJECT_ID
python3 scripts/eos.py github prs --project-id PROJECT_ID
python3 scripts/eos.py github link-pr EXECUTION_ID PR_NUMBER
python3 scripts/eos.py github reconcile EXECUTION_ID
```

Evidence classes: `SYNTHETIC`, `LIVE_READ_ONLY`, `CACHED`, `UNVERIFIED`, `ERROR`,
plus legacy `simulated_integration` for the synthetic orchestrator path.
A simulated merge never counts as an externally verified GitHub merge.
Live Cursor ACP remains disabled while SANDBOX is not PASS.

### Paperclip + OpenClaw (EOS-05)

```bash
# Offline fixture demonstration (no network / no live processes)
python3 scripts/eos.py integrations demo-fixture --temp

# Paperclip (default URL http://127.0.0.1:3100; token never stored)
export EOS_PAPERCLIP_URL=http://127.0.0.1:3100
export EOS_PAPERCLIP_TOKEN=...          # optional; Owner runtime only
export EOS_PAPERCLIP_COMPANY_ID=...
python3 scripts/eos.py paperclip status --company-id COMPANY_ID
python3 scripts/eos.py paperclip sync --company-id COMPANY_ID --project-id PROJECT_ID
python3 scripts/eos.py paperclip agents --company-id COMPANY_ID
python3 scripts/eos.py paperclip issues --company-id COMPANY_ID
python3 scripts/eos.py paperclip link-project LOCAL_PROJECT_ID EXTERNAL_PROJECT_ID --company-id COMPANY_ID
python3 scripts/eos.py paperclip create-issue --company-id COMPANY_ID --title "Draft" --dry-run
python3 scripts/eos.py paperclip create-issue --company-id COMPANY_ID --title "Draft" --apply

# OpenClaw read-only diagnostics (fixed argv; no shell interpolation)
python3 scripts/eos.py openclaw status
python3 scripts/eos.py openclaw refresh
python3 scripts/eos.py openclaw gateway-check

python3 scripts/eos.py integrations status
python3 scripts/eos.py orchestration plan --project-id PROJECT_ID
```

Dashboard Integrations section requires explicit sync/refresh buttons (pages never auto-connect).
Gateway WebSocket RPC transport remains explicitly unavailable until a later authenticated increment.

### ACP / Cursor (EOS-06)

```bash
# Offline synthetic ACP protocol demo (no live Cursor/ACPX)
python3 scripts/eos.py acp demo-fixture --temp

python3 scripts/eos.py acp status
python3 scripts/eos.py acp capabilities
python3 scripts/eos.py acp sessions --project-id PROJECT_ID
python3 scripts/eos.py acp session EXECUTION_ID
python3 scripts/eos.py acp reject-live
python3 scripts/eos.py orchestration simulate-acp --project-id PROJECT_ID
```

Synthetic ACP sessions use real JSON-RPC message handling and durable SQLite
persistence. Live OpenClaw→ACPX→Cursor dispatch remains blocked while SANDBOX is
`NOT_TESTED`. There is no dashboard control that starts live ACP.

### ACPX / sandbox bridge (EOS-07)

```bash
# Offline bridge demo (mock sandbox + synthetic ACP; no containers/agents)
python3 scripts/eos.py acpx demo-fixture --temp

python3 scripts/eos.py runtime status
python3 scripts/eos.py runtime inspect
python3 scripts/eos.py sandbox readiness
python3 scripts/eos.py sandbox plan --execution-id EXECUTION_ID
python3 scripts/eos.py acpx status
python3 scripts/eos.py acpx sessions
```

OpenClaw ACP sessions normally run on the host; Engineering OS routes Cursor through
a sandbox-enforced launcher specification. Real launches remain blocked without
trusted host-side authorization and verified enforcement. A UI `sandbox_gate=PASS`
string alone is not sufficient.

### OCI ACP fixture (EOS-08)

```bash
# Offline injected OCI boundary + real AcpSessionManager (no containers)
python3 scripts/eos.py sandbox demo-fixture --temp

python3 scripts/eos.py sandbox fixture-readiness
python3 scripts/eos.py sandbox fixture-plan
python3 scripts/eos.py sandbox run-acp-fixture --dry-run

# Owner-only real Podman (do not run during automated development):
# python3 scripts/eos.py sandbox run-acp-fixture \
#   --execute --allow-phase-b --owner-authorize-runtime-execution
```

The first real workload is a minimal NDJSON ACP fixture (not Cursor). Provenance is
`SYNTHETIC_OCI_EXECUTED` for real Podman runs and `SYNTHETIC_IN_MEMORY` for injected
tests. `CURSOR_ACP_LIVE` remains unused. HTTP/dashboard never expose real OCI launch.

### Cursor ACP runtime (EOS-09)

```bash
python3 scripts/eos.py cursor demo-fixture --temp
python3 scripts/eos.py cursor status
python3 scripts/eos.py cursor image-plan
python3 scripts/eos.py cursor readiness
python3 scripts/eos.py cursor integration-check
python3 scripts/eos.py runtime requirements
```

Defines a reproducible Cursor OCI image profile (`containers/cursor-acp/`), credential
and network fail-closed boundaries, ACPX launcher command proposal, and workspace
preparation. Live Cursor ACP remains disabled; no image build or credential use in
automation.

## Candidate architecture (provisional)

The priority candidate chain is:

**Paperclip → OpenClaw → ACPX → Cursor CLI ACP → GitHub/CI**

| Layer | Intended role |
|-------|----------------|
| Paperclip | Organization, goals, projects, agents, tasks, budgets, and tracking |
| OpenClaw | Executive interface and project coordination |
| ACPX | Integration between OpenClaw and ACP runners (pending validation) |
| Cursor CLI ACP | First engineering executor |
| External sandbox | Effective isolation per project or run |
| GitHub / CI | Authority over commits, PRs, checks, and merges |

This architecture is **provisional**. It is neither implemented nor validated end to end.

## Principles

1. Reuse existing software before building custom components.
2. Supervised autonomy: humans escalate critical decisions.
3. Effective segregation between projects.
4. Least privilege and default-deny.
5. Separation between declarative instructions and enforceable security controls.
6. Cost control per task, agent, project, and organization.
7. Persistence, idempotency, recovery, and reconciliation.
8. External evidence before declaring tasks done.
9. Human-only merge during the MVP.
10. Versioned documentation and decisions.
11. Automatic continuation only after real integration is verified.
12. Incremental, authorized development.

## Documentation

| Document | Description |
|----------|-------------|
| [AGENTS.md](AGENTS.md) | Declarative behavior policy for agents |
| [docs/vision.md](docs/vision.md) | Product vision, MVP, and exclusions |
| [docs/roadmap.md](docs/roadmap.md) | Milestones, dependencies, and gates |
| [docs/backlog.yaml](docs/backlog.yaml) | Canonical versioned backlog |
| [docs/architecture/baseline.md](docs/architecture/baseline.md) | Provisional architectural baseline |
| [docs/contracts/README.md](docs/contracts/README.md) | Canonical contracts (v0.1.0, provisional) |
| [docs/policies/permission-matrix.md](docs/policies/permission-matrix.md) | Target least-privilege permission matrix |
| [docs/adr/README.md](docs/adr/README.md) | Proposed decision register |
| [docs/adr/ADR-011-canonical-contracts.md](docs/adr/ADR-011-canonical-contracts.md) | ADR-011: versioned canonical contracts |
| [docs/validation/README.md](docs/validation/README.md) | Validation cycle and definition of done |
| [docs/tasks/M00-00.md](docs/tasks/M00-00.md) | Baseline audit (diagnostic) |
| [docs/tasks/M00-01.md](docs/tasks/M00-01.md) | Documentary foundation |
| [docs/tasks/M00-02.md](docs/tasks/M00-02.md) | Versioned canonical contracts |

## Collaboration model

- **Principal architect (chat):** defines scope, reviews evidence, and authorizes the next increment.
- **Cursor (executor agent):** implements only the authorized increment and returns evidence.
- **Human owner:** final authority on strategy, budget, risk, sensitive permissions, commits, PRs, and merges.

## Warning

The local MVP can create projects/goals/tasks, run **synthetic** executions, and show a localhost dashboard. It does **not** enable live Cursor ACP, production agents, or real GitHub merges. SANDBOX remains unapproved for live execution.
