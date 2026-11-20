# ADR-011 — Versioned Engineering OS canonical contracts

| Field | Value |
|-------|--------|
| ID | ADR-011 |
| Title | Versioned Engineering OS canonical contracts |
| Status | RECOMMENDED |
| Date | 2026-11-20 |

## Context

Engineering OS will coordinate multiple tools (candidate chain: Paperclip → OpenClaw → ACPX → Cursor CLI ACP → GitHub/CI) behind supervised autonomy. Each tool has or will have its own configuration surfaces. Without a shared, versioned contract layer owned by Engineering OS, project boundaries, agent capabilities, execution scope, and approvals risk becoming inconsistent or silently tool-specific.

## Problem

1. Native tool configs are not yet verified as suitable system-of-record formats.
2. Prompts and markdown policies cannot enforce isolation or least privilege.
3. Approvals, agent roles, and executions need explicit, inspectable shapes before adapters exist.
4. Premature binding to one vendor schema would freeze unverified assumptions.

## Decision (proposed)

Maintain **versioned Engineering OS canonical contracts** in this repository:

- `ProjectProfile`
- `AgentProfile`
- `ExecutionContract`
- `ApprovalContract`

Translate those contracts into native tool configurations **only after** integration PoCs verify the mappings.

Initial contract version: `0.1.0` (provisional). JSON Schema Draft 2020-12 is the schema dialect for machine-readable validation.

## Alternatives considered

1. **Use native Paperclip/OpenClaw/Cursor configs as the system of record now** — rejected for now; native compatibility is unproven.
2. **Prompt-only governance** — rejected; declarative text is not enforceable security.
3. **Delay all contracts until after runtime PoCs** — rejected; later PoCs need stable vocabulary and acceptance criteria.
4. **Adopt a large policy engine immediately (e.g. OPA)** — deferred (see ADR-012); too heavy for the current baseline.

## Consequences

Positive:

- Shared vocabulary for scope, denials, approvals, and evidence.
- Local schema/example validation before any runtime exists.
- Clear separation between intent and enforcement.

Negative / costs:

- Dual maintenance until adapters exist.
- Risk of drift if native mappings are delayed.
- Schemas will change before a compatibility policy is accepted.

## Security implications

- Contracts alone do not isolate processes, credentials, or networks.
- Agent profiles are not OS identities.
- Approvals do not grant technical access without independent enforcement checks.
- External sandbox remains mandatory; contracts must not imply cwd/prompt isolation.
- Git write/merge remain human-only during the MVP regardless of approval records.

## Validation required

1. Schema and example baseline validation via `scripts/validate_contracts.py`.
2. Draft 2020-12 validation when a local `jsonschema` package is available.
3. Later PoCs proving adapter fidelity for each target tool.
4. SANDBOX gate before autonomous use on real projects.

## Open questions

1. When should `0.1.0` become a compatibility-stable minor series?
2. What approval identity proof is required beyond logical approver IDs?
3. How will budget ceilings move from abstract units to Owner-approved currency controls?
4. Which native fields are 1:1 mappable versus advisory-only?

## Status

**RECOMMENDED** — not ACCEPTED. Owner ratification remains pending.
