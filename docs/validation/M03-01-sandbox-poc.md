# M03-01 validation — External sandbox PoC (Phase B1 evidence hardening)

**Explicit statements:**

- No OCI container was executed in this corrective pass.
- No image was pulled.
- No live Cursor ACP session occurred.
- P1–P8 runtime isolation results are **NOT_TESTED**.
- SANDBOX gate remains **NOT_TESTED**.
- M03-01 remains **PLANNED**.

## Runtime evidence model

| Layer | Field(s) | May claim enforcement? |
|-------|----------|------------------------|
| 1. Launcher config | `planned_controls` | No (intent only) |
| 2. Executed argv | `launcher_argv_controls`, argv safety scan | No (configuration only) |
| 3. Runtime inspect | `runtime_inspected_controls` via `podman inspect` | Partial (config observed) |
| 4. Behavioral | probes, canaries, OOM/fork/timeout attribution | Required for PASS |

`control_evidence_source` must be `runtime_inspected` or `runtime_inspected_and_behavioral`.
Provenance `argv_scan_only` / `launcher_argv` fails closed.

## P1–P8 assertion requirements

| ID | PASS requires |
|----|----------------|
| P1 | Exit 0 + host workspace file + runtime inspect of mount/RO/user |
| P2 | Probe markers + `CONTAINER_PATH_KIND` in {absent, present_denied} + canary unchanged + inspect |
| P3 | Same path model + no beta marker content + canary unchanged |
| P4 | Same path model + no secret marker content + canary unchanged |
| P5 | `IP_PROBE_STATUS=executed_denied` and `DNS_PROBE_STATUS=executed_denied`; unavailable fails; NETNS + NetworkMode=none |
| P6 | Attributable memory (OOM/cgroup), PIDs (fork denied), wall-clock (host timeout + cleanup); CPU `NOT_TESTED` unless separately proven; no PASS with missing mandatory dimension |
| P7 | Reliable absence after success (`--rm`) and abnormal stop; inspect errors ≠ absence; distinguish auto vs forced cleanup |
| P8 | `SOCKET_VISIBLE=0` + inspect confirms no socket binds |

## Corrections applied (R1–R6)

| ID | Correction |
|----|------------|
| R1 | Separated evidence layers; argv no longer labeled runtime-observed |
| R2 | Removed hard-coded path kinds; container probes emit classification |
| R3 | Probe status enum; missing tools cannot count as denial |
| R4 | Attribution gates for memory/PIDs/wall-clock; CPU NOT_TESTED by default |
| R5 | Named containers, inspect-aware presence, forced cleanup, timeout reaping |
| R6 | Safety constraints preserved; fail-closed not weakened |

## Current host readiness

| Capability | Observation |
|------------|-------------|
| Podman rootless | Verified |
| Exact local alpine/busybox in Podman store | Not ready (`localhost/3.20:latest` rejected) |
| Block reason | `podman_rootless_but_no_local_image` |

## Static validation

| Check | Result |
|-------|--------|
| AST/syntax | Executed |
| assertions self-check | Executed |
| preflight / dry-run | Executed (no containers) |
| Partial Owner gate refusal | Executed |
| Contract validation | Executed |
| Container launch | **Not performed** |

## Owner-only execute (later)

```bash
python3 -B scripts/sandbox/run_poc.py \
  --execute --allow-phase-b --owner-authorize-runtime-execution \
  --tests P1,P2,P3,P4,P5,P6,P7,P8 --json
```

Requires an exact local alpine/busybox ref in the Podman store first.

## Remaining limitations

1. No acceptable Podman-local alpine/busybox image on the current host.
2. CPU quota not attributed in default P6 (explicit `NOT_TESTED`).
3. `userns=keep-id` may not always appear in inspect; not required for P1 PASS.
4. Alpine image toolset may lack DNS utilities → P5 correctly FAILs as unavailable until tooling exists.
5. Runtime execution remains unauthorized for agents in this pass.
