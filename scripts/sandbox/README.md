# Sandbox PoC harness (M03-01 Phase B3)

Synthetic, fail-closed isolation harness for Engineering OS.

## Evidence layers

1. **Launcher configuration** — planned flags (intent).
2. **Executed argv** — safety-scanned subprocess arguments (**not** enforcement proof).
3. **Runtime inspect** — read-only `podman inspect`.
4. **Behavioral evidence** — probes, canaries, cgroup CPU samples, host-side `/proc/<pid>` maps, Cap*, cleanup.

Do not treat argv scans as independently observed runtime enforcement.

In-container `/proc/self/uid_map` second-column values are **reader-relative**, not unconditional host UIDs. B3 keep-id attribution uses host-side map reads against the live container PID.

## Scope and safety

- Rootless Podman only for execute
- Exact local alpine/busybox image; `--pull=never`
- No user-supplied image/command/mount inputs
- No privileged mode, no runtime socket mounts, network `none`
- `--userns=keep-id` + `--user <host_uid>:<host_gid>`
- Triple Owner gate required to launch containers
- Fixed P1–P8 catalog; optional `--security-identity-only` probe

## Commands

Safe dry-run / unit checks:

```bash
python3 -B scripts/sandbox/assertions.py
python3 -B scripts/sandbox/preflight.py
python3 -B scripts/sandbox/run_poc.py --security-identity-only --json
python3 -B scripts/sandbox/run_poc.py --tests P6 --json
```

Owner-only B3 identity execute (later; launches one synthetic container):

```bash
python3 -B scripts/sandbox/run_poc.py \
  --execute \
  --allow-phase-b \
  --owner-authorize-runtime-execution \
  --security-identity-only \
  --json
```

This mode does **not** mark P6 as executed and does not rerun resource stress probes.

## Assertion highlights

- P6: memory/PIDs/wall-clock/CPU with attributable evidence
- Capabilities: CapPrm/Eff/Bnd/Amb zero + NoNewPrivs=1 from process status
- Userns keep-id: host-side maps + UID/GID ownership; in-container maps alone cannot PASS
- P7: presence checks; inspect errors are not absence

## Status

M03-01 remains **PLANNED**. SANDBOX remains **NOT_TESTED** until Owner-authorized B3 evidence is reviewed and M03-02 audit completes.
