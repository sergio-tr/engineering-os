# M03-01 validation — External sandbox PoC (Phase B3 userns evidence)

**Explicit statements:**

- No OCI container was executed in this B3 implementation pass.
- No image was pulled.
- No live Cursor ACP session occurred.
- Historical B2 evidence (`p6-b2.json`) is retained and **not** rewritten.
- B2 accredited CPU and capabilities; B2 `userns_keep_id` remains FAIL in that archive.
- B3 host-side userns attribution remains **NOT_TESTED** until Owner-authorized execute.
- SANDBOX gate remains **NOT_TESTED**.
- M03-01 remains **PLANNED**.

## B2 defect (mapping semantics)

`id_maps_cover_identity()` treated the second column of an in-container `uid_map` as the launching host UID. That column is reader-relative. Nested rootless Podman can yield `1000 0 1` inside the container while the composed path is still `1000 → 0 → 1000` on the host. B3 rejects in-container maps as host proof.

## B3 host-side evidence model

| Step | Evidence |
|------|----------|
| 1 | Start synthetic identity container (unchanged isolation flags); hold bounded window |
| 2 | Resolve PID via `podman inspect`; link PID ↔ container id |
| 3 | Record `/proc/<pid>/stat` starttime; re-check after sampling (PID-reuse guard) |
| 4 | Read `/proc/<pid>/uid_map`, `gid_map`, `ns/user`, `status` **from the launcher** |
| 5 | Tag maps with `reader_context=launching_host` |
| 6 | Translate container euid/egid through those maps to launching UID/GID |
| 7 | Verify workspace + marker ownership UID **and** GID |
| 8 | Force cleanup; confirm absence |

PASS requires all of the above. Missing/stale/ambiguous evidence → `NOT_TESTED` or `FAIL`. Pattern `1000 0 1` alone never PASS.

## `--security-identity-only`

| Property | Behavior |
|----------|----------|
| Dry-run | Plans probe only; `execution_performed=false`; `p6_executed=false` |
| Execute | Requires triple Owner gate; runs identity probe only |
| Catalog | Does not mark P1–P8 as executed |
| Output | `security_controls` + `security_identity_result` |

## Static validation (this pass)

| Check | Result |
|-------|--------|
| AST/syntax | Executed |
| assertions self-check (nested/host-side cases) | Executed |
| Contract validation | Executed |
| `--security-identity-only` dry-run | Executed (no containers) |
| Container launch | **Not performed** |

## Owner-only execute (later; B3)

```bash
python3 -B scripts/sandbox/run_poc.py \
  --execute --allow-phase-b --owner-authorize-runtime-execution \
  --security-identity-only --json
```

Archive as `p6-b3-userns.json` (or `security-identity-b3.json`) beside historical `p6-b2.json`. Record matching `main` SHA.

## Remaining limitations

1. Host-side `/proc/<pid>` must be readable by the launcher; otherwise fail closed.
2. Nested composition fallback requires an independently proven parent relationship (not assumed from `podman unshare` alone).
3. Historical B2 userns FAIL is preserved for audit trail.
4. M03-02 independent audit still required before SANDBOX PASS.
