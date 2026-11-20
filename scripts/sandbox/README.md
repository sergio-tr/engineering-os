# Sandbox PoC harness (M03-01 Phase A)

Synthetic, fail-closed preparation tooling for the Engineering OS external isolation proof of concept.

## Scope

- Read-only runtime preflight with independent rootless verification.
- Runtime-specific local image discovery (Docker store ≠ Podman store).
- Synthetic fixture helpers with approved disposable-root checks.
- Dry-run launcher that prints sanitized OCI commands and explicit assertion specs for P1–P8.
- **No container execution in Phase A.**
- **`--execute` / `--allow-phase-b` are hard-refused in this increment.**

## Rootless rules

| Runtime | Binary present | Operational | Rootless verified | Local image in same runtime store |
|---------|----------------|-------------|-------------------|-----------------------------------|
| Podman (preferred) | required | `podman info` succeeds | `host.security.rootless` (or equivalent) true | required |
| Docker (fallback) | required | `docker info` succeeds | daemon `Rootless=true` or `name=rootless` security option | required |

Not accepted as rootless proof:

- `podman --version` / `docker --version` alone
- Docker context socket path heuristics alone

## UID / workspace policy (P1 gate)

The planner uses `--user 65532:65532` and **omits** `--userns=keep-id` to avoid encoding an unverified pairing.

Before Phase B execution, ownership mapping must be established and the launcher must fail closed if it cannot verify that the disposable workspace is writable by the selected container user.

## Fixture path safety

`--prepare-fixtures` only accepts a **dedicated** uniquely named subdirectory:

- Name must match `eos-sandbox-poc-<unique>`
- Must resolve under an approved disposable prefix (default: system temp dir)
- Must not be the temp parent directory itself
- Must be owned by the current user with owner-only permissions (0700)
- Symlinked roots or symlink descendants are rejected
- Marker `.eos-sandbox-poc` must contain the expected synthetic v1 content
- Cleanup is allowed only for verified, owned, marked dedicated roots

Optional override: `EOS_SANDBOX_FIXTURE_PREFIX` (must itself resolve under an approved prefix).

## Phase A commands

```bash
python3 scripts/sandbox/assertions.py
python3 scripts/sandbox/preflight.py
python3 scripts/sandbox/preflight.py --json
python3 scripts/sandbox/run_poc.py
python3 scripts/sandbox/run_poc.py --json
```

Optional fixture preparation (no containers):

```bash
python3 scripts/sandbox/run_poc.py --prepare-fixtures --fixture-root /tmp/eos-sandbox-poc-XXXX
```

## Negative-test acceptance (future Phase B)

Evidence must distinguish **planned controls** (launcher intent) from **runtime-observed controls** (independent probes). Copying planned booleans into observed evidence is invalid.

P2–P5 must not PASS from shell fallback strings. Required evidence includes exit status, runtime-observed controls, host canary integrity, and absent-vs-denied classification where applicable.

P5 records IP and DNS probe outcomes separately; either succeeding is FAIL. Planned `--network none` alone is insufficient.

P6 must record separate memory/CPU/PID/tmpfs/wall-clock dimensions; tmpfs-full ≠ memory limit proof.

P7 requires independently observed cleanup; `--rm` intent alone is insufficient.

## Local image references

Preflight recognizes short and fully qualified local refs (for example `alpine:3.20` and `docker.io/library/alpine:3.20`) **within the selected runtime store only**. It never rewrites missing tags to `latest` and never credits another runtime’s image store.

## Phase B

Not authorized here. No working container-launch path is provided in this increment.
