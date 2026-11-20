# Validation, evidence, and definition of done

## Language policy

Repository artifacts and agent instructions must follow the **English-only repository policy** defined in [`AGENTS.md`](../../AGENTS.md). Owner–architect conversations may be in Spanish; that exception does not apply to commits, docs, prompts, identifiers, or review reports stored in the repository.

## Increment authorization cycle

1. The architect defines the increment and the task prompt.
2. The Owner authorizes (explicitly or via documented chat delegation).
3. The agent executes **only** that increment.
4. The agent delivers evidence and stops.
5. The architect reviews results.
6. The Owner integrates in Git (commit/push/PR/merge) or rejects.
7. Only after real integration is verified may the next eligible increment be authorized.

## Task states

Allowed backlog states:

`PLANNED` · `READY` · `RUNNING` · `PASS` · `FAIL` · `BLOCKED` · `NOT_TESTED`

Rules:

- `READY` does not mean Owner-approved.
- `PASS` requires external evidence and review.
- `NOT_TESTED` documents absence of a test, not success.
- `BLOCKED` requires a cause and human or dependency unblock.

## Mandatory evidence

Every increment close-out must provide:

1. Executed scope vs authorized scope.
2. Relevant commands and exit codes.
3. Files touched.
4. Tests and classified outcomes.
5. Risks and blockers.
6. Pending human actions.

## Evidence classes E1–E6

| Class | Meaning |
|-------|---------|
| E1 | Documentary or design claim without execution |
| E2 | Result provided by a third party / prior report |
| E3 | Local read-only observation in this session |
| E4 | Test executed in this session with captured output |
| E5 | Explicit human review of the result |
| E6 | Independent re-run verifiable by the reviewer |

**Prohibition:** do not attribute E6 without a test executed and verifiable by the reviewer. A diagnostic-gate PASS based on a provided report plus chat review is documented as E2+E5, not E6.

## Critical distinction

| Type | Description |
|------|-------------|
| Executed test | Command/action performed in-session with output |
| Provided result | Report or artifact from another session/agent |
| Inferred conclusion | Judgment beyond what was measured; must be labeled |

## Definition of done (documentary)

A documentary increment is ready for human review when:

1. Only authorized files were touched.
2. Content satisfies the task prompt.
3. Local consistency validations were run and reported.
4. No secrets or unnecessary sensitive data were introduced.
5. The agent’s final report is complete.
6. The agent has **not** committed/pushed/PRed.

Integration and final product PASS are decided by the Owner.

## Security gates

Blocking gates (`ACP`, `ACPX`, `SANDBOX`, `PAPERCLIP`, `GITHUB`, `RECOVERY`, `MULTI_PROJECT`) require external evidence. Failing or leaving `SANDBOX` open blocks autonomy on real projects.

## Architect review

The architect:

- checks scope and evidence;
- detects unjustified PASS claims;
- identifies security/privacy risks;
- recommends the Owner accept, reject, or request correction.

## Git integration

Human-only during the MVP: staging, commit, push, PR, and merge.

## Stop criterion

The agent must stop and request review when:

- there is a contradiction between prompt, files, or security;
- permissions or authorization are missing;
- a secret or disclosure risk appears;
- scope would threaten services, other repos, or costs;
- a blocking gate would prevent honest continuation.
