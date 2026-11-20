# M03-02 validation — Independent SANDBOX audit protocol

**This is an audit protocol, not a completed audit report.**

Status of this document: **PLANNED / READY for auditor use**.
SANDBOX gate: **NOT_TESTED**.
Live Cursor ACP: **BLOCKED**.

## 0. Independence checklist (precondition)

| Check | Required answer |
|-------|-----------------|
| Auditor ≠ sole implementer of `scripts/sandbox/*`? | Yes, or document BLOCKED |
| Auditor has read-only access to evidence store + `main` SHAs? | Yes |
| Owner has not pre-declared SANDBOX PASS? | Yes |
| No live ACP / real projects in scope without new written auth? | Yes |

If independence cannot be met, stop and leave SANDBOX `NOT_TESTED` or mark audit `BLOCKED`.

## 1. Repository and baseline freeze

Record:

| Item | Value to fill |
|------|----------------|
| Audit start date (UTC) | |
| `main` SHA at audit start | |
| Expected B2 SHA | `0f68c17501dc1b29e23cf5148189e13679565838` |
| Expected B3 SHA | `b47eb8ba1340aab44d5f234dc58687048c5b6619` |
| M03-01 closure doc SHAs / PR | |
| Evidence manifest path | Owner store `evidence/m03-01/evidence-manifest.sha256` |
| Manifest verification command result | |

Confirm `docs/backlog.yaml` dependency: M03-02 depends on M03-01; M01-01 depends on M03-02.

## 2. Evidence completeness, integrity, provenance, redaction

For each archived file in the M03-01 manifest:

1. Recompute SHA-256; match manifest.
2. Confirm `execution_performed` / test IDs / cleanup fields are internally consistent.
3. Confirm historical B2 userns FAIL and B3 userns PASS both remain distinguishable.
4. Confirm no real secrets, tokens, or unnecessary private paths are present in published docs (store paths may be referenced at high level).
5. Classify each claim as: **enforced behavior**, **inspect observation**, **argv intent**, or **untested**.

Do not accept planned flags as enforcement.

## 3–15. Required audit areas (worksheets)

Complete each section with: Findings / Evidence refs / Verdict (`PASS`/`FAIL`/`NOT_TESTED`/`BLOCKED`) / Gate impact (`mandatory blocker` / `residual risk`).

### 3. Rootless Podman and cgroup delegation

- Rootless verification method
- CPU/memory/pids delegation evidence
- Image pin / `--pull=never`

### 4. Filesystem, mounts, cross-project isolation

- P1–P4 evidence review
- Mount allow-list and RO rootfs

### 5. Secrets, HOME, credential exposure

- P4 canary model
- Env scrub list vs design requirements

### 6. SSH agent and GitHub credential paths

- Confirm whether N6/T4/T5 have **behavioral** negative tests
- If absent: mandatory blocker vs Owner-accepted residual risk (must be explicit)

### 7. Network and DNS denial

- P5 `executed_denied` for IP and DNS; tool-unavailable must not count as deny

### 8. Runtime socket access

- P8 path probes + inspect mounts

### 9. CPU, memory, PIDs, disk, wall-clock

- P6 / P6-B2 attribution quality
- Disk quota: if untested, record gap

### 10. Capabilities, user namespaces, identity mapping

- B2 capability evidence
- B3 host-side map semantics; PID/starttime linkage; marker UID **and** GID
- Confirm in-container `1000 0 1` alone cannot PASS

### 11. Process lifecycle and cleanup

- P7 auto vs forced cleanup
- Residual container checks

### 12. Git write authority and host-side integration

- Confirm executor path cannot push/mutate host git auth
- Align with design: Git writes remain host/Owner plane

### 13. Tampering and false-positive scenarios

- Argv-only PASS prevented?
- Inspect-error ≠ absence?
- Ancestor cgroup metrics rejected?
- PID reuse guards present?

### 14. Reproducibility (WSL2)

- Document environment assumptions
- Note any non-reproducible Owner-only steps

### 15. Future ACP launcher path (no live ACP)

- Review how `run_poc` / design would wrap ACP stdio
- Identify integration gaps **without** starting ACP
- Any runtime probe requires **new** Owner authorization and must stay synthetic

## Threat coverage matrix (mandatory fill)

Copy and complete:

| ID | PoC evidence | Audit verdict | Gate impact |
|----|--------------|---------------|-------------|
| T1 | | | |
| T2 | | | |
| T3 | | | |
| T4 | | | |
| T5 | | | |
| T6 | | | |
| T7 | | | |
| T8 | | | |
| T9 | | | |
| T10 | | | |
| T11 | | | |
| T12 | | | |
| N1 | | | |
| N2 | | | |
| N3 | | | |
| N4 | | | |
| N5 | | | |
| N6 | | | |
| N7 | | | |
| N8 | | | |

## Optional fresh runtime tests

If the auditor requires additional proof:

1. List exact test IDs / probes.
2. Obtain **written Owner authorization** (triple gate or equivalent).
3. Keep synthetic-only scope.
4. Archive new evidence with new filenames (do not overwrite M03-01 history).
5. Record new code SHA.

Do **not** execute those tests while only preparing this protocol.

## Final recommendation template

| Field | Value |
|-------|-------|
| Auditor identity / context | |
| Independence statement | |
| Recommended SANDBOX status | PASS / FAIL / BLOCKED / NOT_TESTED |
| Mandatory blockers | |
| Accepted residual risks (Owner-signed) | |
| Revalidation triggers acknowledged | |
| Owner decision | Accepted / Rejected / Deferred |
| Owner decision date | |

## Explicit unresolved questions (seed list for auditor)

1. Is workspace disk quota a **mandatory** SANDBOX blocker or an accepted residual risk?
2. Are dedicated SSH-agent and GitHub-cred negative tests mandatory before gate PASS?
3. Must host PID/IPC isolation be demonstrated explicitly?
4. What minimum independent reviewer role satisfies the independence rule?
5. What bounded ACP-launcher dry integration (if any) is required before M01-01, still without live ACP to real projects?

## Non-goals of this protocol document

- Declaring SANDBOX PASS
- Unblocking M01-01
- Re-implementing the sandbox
- Rewriting historical evidence
