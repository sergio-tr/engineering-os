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
