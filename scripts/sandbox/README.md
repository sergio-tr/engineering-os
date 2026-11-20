# Sandbox PoC harness (M03-01 Phase B1)

Synthetic, fail-closed isolation harness for Engineering OS.

## Evidence layers

1. **Launcher configuration** — planned flags (intent).
2. **Executed argv** — safety-scanned subprocess arguments (**not** enforcement proof).
3. **Runtime inspect** — read-only `podman inspect` of the started container.
4. **Behavioral evidence** — probe markers, canaries, attributable limit/cleanup signals.

Do not treat argv scans as independently observed runtime enforcement.

Argv safety inspection covers **launcher options and mount sources only**. Socket path
literals inside the fixed P8 workload script are allowed; mounting Docker/Podman
sockets remains forbidden. Selecting `--tests P1` builds only P1.

## Scope and safety

- Rootless Podman only for execute
- Exact local alpine/busybox image; `--pull=never`
- No user-supplied image/command/mount inputs
- No privileged mode, no runtime socket mounts, network `none`
- `--userns=keep-id` + `--user <host_uid>:<host_gid>`
- Triple Owner gate required to launch containers
- Fixed P1–P8 catalog only

## Commands

Safe dry-run / unit checks:

```bash
python3 -B scripts/sandbox/assertions.py
python3 -B scripts/sandbox/preflight.py
python3 -B scripts/sandbox/run_poc.py --json
```

Owner-only execute (later; launches containers):

```bash
python3 -B scripts/sandbox/run_poc.py \
  --execute \
  --allow-phase-b \
  --owner-authorize-runtime-execution \
  --tests P1,P2,P3,P4,P5,P6,P7,P8 \
  --json
```

## Assertion highlights

- P2–P4: container emits `CONTAINER_PATH_KIND=...`; host canary hashes; generic failures without probe markers cannot PASS
- P5: IP/DNS must be `executed_denied`; `unavailable` fails
- P6: attributable memory/PIDs/wall-clock; CPU may be `NOT_TESTED`
- P7: presence checks; inspect errors are not absence; auto vs forced cleanup recorded

## Status

P1–P8 and SANDBOX remain **NOT_TESTED** until Owner-authorized execute evidence is reviewed.
