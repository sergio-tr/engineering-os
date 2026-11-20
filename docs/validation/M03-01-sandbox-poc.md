# M03-01 validation — External sandbox PoC (Phase B2 evidence closure)

**Explicit statements:**

- No OCI container was executed in this B2 implementation pass.
- No image was pulled.
- No live Cursor ACP session occurred.
- Historical Owner evidence for P1–P5, P7 and P8 is retained outside this repository path and is **not** rewritten here.
- P6 CPU, `cap_drop_all` process sets, and `userns_keep_id` mapping remain **NOT_TESTED** until Owner-authorized B2 execute.
- SANDBOX gate remains **NOT_TESTED**.
- M03-01 remains **PLANNED**.

## Runtime evidence model

| Layer | Field(s) | May claim enforcement? |
|-------|----------|------------------------|
| 1. Launcher config | `planned_controls` | No (intent only) |
| 2. Executed argv | `launcher_argv_controls`, argv safety scan | No (configuration only) |
| 3. Runtime inspect | `runtime_inspected_controls` via `podman inspect` | Partial (config observed) |
| 4. Behavioral | probes, canaries, OOM/fork/timeout/CPU throttle, Cap*, uid_map | Required for PASS |

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
| P6 | Attributable memory (OOM/cgroup), PIDs (fork denied), wall-clock (host timeout + cleanup), **and** CPU (`cpu.max` matches `--cpus=0.50` + throttle delta on container cgroup); missing CPU → FAIL when required |
| P7 | Reliable absence after success (`--rm`) and abnormal stop; inspect errors ≠ absence; distinguish auto vs forced cleanup |
| P8 | `SOCKET_VISIBLE=0` + inspect confirms no socket binds |

## B2 security evidence schemas

### CPU (`cpu_evidence`)

| Field | Meaning |
|-------|---------|
| `configured_cpus` | Expected quota (0.50) |
| `cpu_max` | Parsed container `cpu.max` (quota/period/cpus_equiv) |
| `cpu_stat_before` / `cpu_stat_after` | Parsed `cpu.stat` samples |
| `cpu_stat_delta` | Deltas for usage/periods/throttled counters |
| `cgroup.path` | Resolved container cgroup directory |
| `container_id` | Linked container identity |
| `attribution` | `quota_and_throttle` or non-PASS reason |

Acceptance: quota matches configured CPUs (tolerance 0.05) **and** `nr_throttled` or `throttled_usec` increases. Empty/missing cgroup → `NOT_TESTED`.

### Capabilities (`capability_evidence`)

| Field | Meaning |
|-------|---------|
| `parsed.fields` | CapInh/Prm/Eff/Bnd/Amb, NoNewPrivs, Seccomp |
| `verdict.status` | PASS / FAIL / NOT_TESTED |
| `verdict.reason` | Attribution note |

Acceptance: CapPrm, CapEff, CapBnd, CapAmb all zero; NoNewPrivs=1. Argv `--cap-drop ALL` alone is not proof.

### User namespace (`userns_evidence`)

| Field | Meaning |
|-------|---------|
| `container_uid` / `container_gid` | Effective IDs inside container |
| `host_uid` / `host_gid` | Launching host identity |
| `uid_map` / `gid_map` | Parsed `/proc/self/{uid,gid}_map` |
| `workspace_owner_uid` / `marker_owner_uid` | Host-side ownership checks |
| `verdict.status` | PASS / FAIL / NOT_TESTED |

Acceptance: euid/egid match host; maps cover that identity; workspace marker owned by host UID. Inspect `userns_keep_id` boolean alone is insufficient.

Top-level execute summary also exposes `security_controls.cap_drop_all` and `security_controls.userns_keep_id`.

## Static validation (this pass)

| Check | Result |
|-------|--------|
| AST/syntax | To be executed in B2 validation |
| assertions self-check (incl. mocked CPU/caps/userns) | To be executed |
| P6 dry-run | To be executed (no containers) |
| Contract validation | To be executed |
| Container launch | **Not performed** |

## Owner-only execute (later; B2 closure)

```bash
python3 -B scripts/sandbox/run_poc.py \
  --execute --allow-phase-b --owner-authorize-runtime-execution \
  --tests P6 --json
```

Archive new `p6.json` separately from historical partial P6 evidence. Do not rewrite prior PASS files for P1–P5/P7/P8.

## Remaining limitations

1. Historical Owner P6 evidence remains CPU-incomplete until a new authorized P6 execute.
2. `userns_keep_id` / `cap_drop_all` may still appear `false` in `podman inspect`; B2 relies on process/cgroup behavioral evidence instead.
3. CPU attribution requires a readable container-scoped cgroup; ancestor counters are rejected.
4. Runtime execution remains unauthorized for agents in this pass.
5. M03-02 independent audit is still required before SANDBOX PASS.
