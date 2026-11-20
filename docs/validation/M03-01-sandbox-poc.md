# M03-01 validation — External sandbox PoC (Phase A)

**Explicit statements:**

- No OCI container was executed.
- No image was pulled.
- No live Cursor ACP session occurred.
- P1–P8 runtime isolation results are **NOT_TESTED**.
- SANDBOX gate remains **NOT_TESTED**.
- `--execute` / `--allow-phase-b` are hard-refused in Phase A.

## M03-00 integration evidence

| Field | Value |
|-------|--------|
| Merge commit on `main` | `3414c7f8c3cc0656f2e170343a6379825900f266` |
| Feature tip parent | `ccbbe91f3107131c4ce8945880805fa6b1fe91a4` |
| Base parent | `d631f406864b7d1f3fbba34d5c2531044a238aab` |
| Subject | `docs: design external sandbox isolation boundaries` |
| Committer | GitHub |
| PR number | Not present in local merge message; not invented |

## Security hardening corrections (Phase A review)

| ID | Finding | Correction |
|----|---------|------------|
| C1 | `podman --version` must not imply rootless | Preflight separates binary / operational / rootless / isolation-untested; Docker rootless requires daemon evidence only |
| C2 | Docker-local images credited Podman readiness | Image stores are runtime-specific; no cross-credit |
| C3 | Shell fallbacks could fake denials | Assertion specs require exit codes, controls, canaries; forbid marker-only PASS |
| C4 | `keep-id` + `--user 65532` ownership risk | Planner omits keep-id; documents fail-closed UID policy gate for Phase B |
| C5 | Fixture roots could target unsafe paths | Approved temp-prefix validation, symlink/repo rejection, marker gating |
| C6 | Execute flags must not launch | Hard refuse of `--execute` / `--allow-phase-b`; no launch path |
| C7 | Fully qualified Podman refs missed | Recognize `docker.io/library/alpine:<tag>` etc.; select exact local refs only |
| C8 | P5 unconditional exit risk | Separate IP/DNS probes; either success FAILs; no unconditional exit PASS |
| C9 | Fixture root still too permissive | Dedicated named subdir, ownership, 0700, marker v1, structure checks |
| C10 | Planned controls as “observed” | Evaluator requires `runtime_observed` evidence; rejects plan copies |

## Environment / runtime capability matrix

| Capability | Observation |
|------------|-------------|
| OS | Ubuntu 22.04 (from os-release) |
| Kernel family | Linux with WSL2 indicators present |
| Podman binary | Present on current host preflight |
| Podman operational / rootless | Operational; rootless verified via `podman info` |
| Podman-local alpine | Not ready (no local image in Podman store) |
| Docker binary | Present |
| Docker rootless (daemon-authoritative) | Not verified |
| Docker context path heuristic | Explicitly **not** used as authority |
| User namespaces / cgroup v2 | Indicators present; enforcement untested |
| Docker-local alpine | Present; does **not** satisfy Podman image readiness |
| Block reason (fail closed) | `podman_rootless_but_no_local_image` |

## P1–P8 status

| ID | Status |
|----|--------|
| P1 | NOT_TESTED |
| P2 | NOT_TESTED |
| P3 | NOT_TESTED |
| P4 | NOT_TESTED |
| P5 | NOT_TESTED |
| P6 | NOT_TESTED |
| P7 | NOT_TESTED |
| P8 | NOT_TESTED |

## Static validation performed

| Check | Result |
|-------|--------|
| AST/syntax of harness modules | Executed |
| `assertions.py` self-check | Executed (temp only) |
| `preflight.py` read-only | Executed |
| `run_poc.py` dry-run | Executed (no containers) |
| Execute-flag refusal | Executed |
| Unsafe fixture-root rejection | Covered in assertions self-check |
| Container launch | Not performed |

## Owner prerequisites for Phase B

1. Provide a daemon-verified rootless runtime (Podman preferred).
2. Ensure a local image exists in **that runtime’s** store (`--pull=never`).
3. Resolve UID/workspace ownership mapping and fail closed if unverified.
4. Authorize a follow-up increment that implements execution + evidence capture.
5. Do not treat Phase A dry-run output as SANDBOX PASS.
