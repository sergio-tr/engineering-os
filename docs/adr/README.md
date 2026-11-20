# Architecture Decision Records (ADR)

This directory holds the ADR index and individual decision records as they are authorized. This README remains the status index for proposals and ratified decisions.

## How to read statuses

| Status | Meaning |
|--------|---------|
| PROVISIONAL | Useful candidate; subject to change after PoC or review |
| RECOMMENDED | Preferred direction with current rationale; not yet ratified as ACCEPTED unless stated |
| REQUIRES_POC | Must not be adopted operationally without an evidenced proof of concept |
| BLOCKING | **Security or operations requirement that blocks autonomy**; not an ADR ratification state |
| ACCEPTED | Decision ratified for the current scope |
| DEFERRED | Consciously postponed |

**Note:** `BLOCKING` identifies a requirement that must be met (e.g. external isolation). It does not imply the ADR is accepted or implemented.

## Initial index

| ID | Title | Status |
|----|-------|--------|
| ADR-001 | Paperclip as organizational layer | PROVISIONAL |
| ADR-002 | OpenClaw as coordination plane | PROVISIONAL |
| ADR-003 | OpenClaw as executive interface | RECOMMENDED |
| ADR-004 | Cursor CLI ACP via ACPX | REQUIRES_POC |
| ADR-005 | Mandatory external isolation | BLOCKING |
| ADR-006 | GitHub as integration authority | RECOMMENDED |
| ADR-007 | Manual merge initially during MVP | ACCEPTED |
| ADR-008 | Reconciliation via webhook + API | RECOMMENDED |
| ADR-009 | Avoid a large durable engine initially | PROVISIONAL |
| ADR-010 | Cursor Cloud as execution alternative | DEFERRED |
| ADR-011 | [Versioned canonical contracts in the repo](ADR-011-canonical-contracts.md) | RECOMMENDED |
| ADR-012 | OPA / Temporal / Kubernetes as early dependencies | DEFERRED |

## Rules

1. Do not declare `PROVISIONAL` or `REQUIRES_POC` decisions as implemented.
2. An open `BLOCKING` ADR prevents autonomy on real projects.
3. Individual ADR files are added only in authorized increments; ADR-011 is the first detailed record.
4. Any acceptance or rejection is versioned in Git after human integration.
